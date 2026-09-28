// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  GENKI-PROBER MODULE: TAINT-PLANTER v1.0                              ║
// ║  Automatic taint injection into URL params, forms, inputs, storage,    ║
// ║  cookies, postMessage — then monitors if they flow to dangerous sinks  ║
// ║                                                                        ║
// ║  Strategy: Plant unique canaries per source, then detect reflection    ║
// ║  via DOM observation + sink monitoring from security scanner           ║
// ╚══════════════════════════════════════════════════════════════════════════╝
const fs = require('fs');
const path = require('path');

class TaintPlanter {
  constructor(logger, config) {
    this.logger = logger;
    this.config = config;
    this.findings = [];
    this.canaries = {};
    this.reflections = [];
    this.canaryPrefix = 'GNKTNT';
    this.canaryCounter = 0;
    this.xssPayloads = config.xss_payloads_by_context || {};
    this.plantedPayloads = {};
  }

  // Generate unique canary for tracking
  _canary(source, context) {
    const id = ++this.canaryCounter;
    const canary = `${this.canaryPrefix}${id}`;
    this.canaries[canary] = { id, source, context, time: Date.now() };
    return canary;
  }

  // XSS-flavored canaries (escalating from safe to dangerous)
  _xssCanaries(source, context) {
    const base = this._canary(source, context);
    return {
      safe: base,                                        // Plain text reflection check
      html: `<${base}>`,                                 // HTML injection check
      attr: `"${base}"><img src=x onerror=${base}>`,     // Attribute breakout
      script: `';${base}//`,                             // JS string breakout
      template: `{{${base}}}`,                           // Template injection
      ssti: `${base}\${7*7}`,                            // SSTI check
    };
  }

  // ═══════════════════════════════════════════════════
  // MAIN RUN — called BEFORE security scanner, AFTER crawler
  // ═══════════════════════════════════════════════════
  async run(page, browser, crawlerUrls) {
    this.logger.log('TAINT-PLANTER', 'INFO', 'Starting taint injection across all vectors...');
    const startTime = Date.now();

    // Install taint monitor in page (hooks sinks to detect canary reflection)
    await this._installTaintMonitor(page);

    // 1. Plant taints in URL parameters (navigate with tainted params)
    await this._taintUrlParams(page, crawlerUrls);

    // 2. Plant taints in all form inputs on current page
    await this._taintFormInputs(page);

    // 3. Plant taints in storage (localStorage, sessionStorage)
    await this._taintStorage(page);

    // 4. Plant taints in cookies
    await this._taintCookies(page);

    // 5. Plant taints via postMessage
    await this._taintPostMessage(page);

    // 6. Plant taints in hash/fragment
    await this._taintHashFragment(page);

    // 7. Harvest reflections (check what flowed to sinks)
    await this._harvestReflections(page);

    this._saveResults();

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    this.logger.log('TAINT-PLANTER', 'OK',
      `Planted ${this.canaryCounter} canaries in ${elapsed}s, ` +
      `${this.reflections.length} reflections detected, ${this.findings.length} findings`);
  }

  // ═══════════════════════════════════════════════════
  // TAINT MONITOR — intercepts sinks to check for canary reflection
  // ═══════════════════════════════════════════════════
  async _installTaintMonitor(page) {
    await page.evaluateOnNewDocument((prefix) => {
      window.__GENKI_TAINT = { reflections: [], prefix };

      const checkTaint = (sink, value) => {
        if (!value || typeof value !== 'string') return;
        const hasCanary = value.includes(prefix);
        const hasC2 = value.includes('6u.gg');
        if (hasCanary || hasC2) {
          // Extract which canary reflected
          const matches = value.match(new RegExp(prefix + '\\d+', 'g')) || [];
          matches.forEach(canary => {
            window.__GENKI_TAINT.reflections.push({
              sink, canary, value: value.substring(0, 300),
              url: location.href, time: Date.now(),
              stack: new Error().stack?.split('\n').slice(2, 6).join('\n'),
              payload_execution: false
            });
          });
          if (hasC2 && !hasCanary) {
            window.__GENKI_TAINT.reflections.push({
              sink, canary: '__C2_PAYLOAD__', value: value.substring(0, 500),
              url: location.href, time: Date.now(),
              stack: new Error().stack?.split('\n').slice(2, 6).join('\n'),
              payload_execution: true
            });
          }
        }
      };

      // Hook innerHTML
      const ihDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
      if (ihDesc?.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
          set(val) { checkTaint('innerHTML', val); return ihDesc.set.call(this, val); },
          get() { return ihDesc.get.call(this); }
        });
      }

      // Hook outerHTML
      const ohDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
      if (ohDesc?.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
          set(val) { checkTaint('outerHTML', val); return ohDesc.set.call(this, val); },
          get() { return ohDesc.get.call(this); }
        });
      }

      // Hook document.write
      const _write = document.write;
      document.write = function(html) { checkTaint('document.write', html); return _write.call(this, html); };
      const _writeln = document.writeln;
      document.writeln = function(html) { checkTaint('document.writeln', html); return _writeln.call(this, html); };

      // Hook eval
      const _eval = window.eval;
      window.eval = function(code) { checkTaint('eval', code); return _eval.call(this, code); };

      // Hook Function constructor
      const _Function = Function;
      window.Function = new Proxy(_Function, {
        construct(target, args) { args.forEach(a => checkTaint('Function', a)); return Reflect.construct(target, args); },
        apply(target, thisArg, args) { args.forEach(a => checkTaint('Function', a)); return Reflect.apply(target, thisArg, args); }
      });

      // Hook setTimeout/setInterval with string args
      const _setTimeout = setTimeout;
      window.setTimeout = function(fn, delay) {
        if (typeof fn === 'string') checkTaint('setTimeout', fn);
        return _setTimeout.apply(this, arguments);
      };
      const _setInterval = setInterval;
      window.setInterval = function(fn, delay) {
        if (typeof fn === 'string') checkTaint('setInterval', fn);
        return _setInterval.apply(this, arguments);
      };

      // Hook location assignments
      ['href', 'pathname', 'search', 'hash'].forEach(prop => {
        const desc = Object.getOwnPropertyDescriptor(window.location.__proto__, prop);
        if (desc?.set) {
          try {
            Object.defineProperty(window.location, prop, {
              set(val) { checkTaint('location.' + prop, val); return desc.set.call(this, val); },
              get() { return desc.get.call(this); },
              configurable: true
            });
          } catch(e) {} // location props may not be configurable
        }
      });

      // Hook setAttribute
      const _setAttribute = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function(name, value) {
        const dangerous = ['href', 'src', 'action', 'formaction', 'data', 'srcdoc', 'onclick', 'onerror', 'onload'];
        if (dangerous.includes(name.toLowerCase())) checkTaint('setAttribute.' + name, value);
        return _setAttribute.call(this, name, value);
      };

      // Hook fetch
      const _fetch = window.fetch;
      window.fetch = function(url, init) {
        checkTaint('fetch.url', String(url));
        if (init?.body) checkTaint('fetch.body', String(init.body));
        return _fetch.apply(this, arguments);
      };

      // Hook XHR
      const _xhrOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url) {
        checkTaint('xhr.url', String(url));
        return _xhrOpen.apply(this, arguments);
      };
      const _xhrSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.send = function(body) {
        if (body) checkTaint('xhr.body', String(body));
        return _xhrSend.apply(this, arguments);
      };

      // Hook insertAdjacentHTML
      const _insertAdj = Element.prototype.insertAdjacentHTML;
      Element.prototype.insertAdjacentHTML = function(pos, html) {
        checkTaint('insertAdjacentHTML', html);
        return _insertAdj.call(this, pos, html);
      };

      // Hook WebSocket
      const _WebSocket = window.WebSocket;
      window.WebSocket = function(url, protocols) {
        checkTaint('WebSocket', String(url));
        return protocols ? new _WebSocket(url, protocols) : new _WebSocket(url);
      };
      window.WebSocket.prototype = _WebSocket.prototype;

      // Hook sessionStorage
      const _ssSet = sessionStorage.setItem.bind(sessionStorage);
      sessionStorage.setItem = function(key, value) {
        checkTaint('sessionStorage.setItem', key + '=' + String(value).substring(0, 200));
        return _ssSet(key, value);
      };

      // Hook document.domain
      try {
        const _dd = Object.getOwnPropertyDescriptor(Document.prototype, 'domain') ||
                     Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'domain');
        if (_dd && _dd.set) {
          Object.defineProperty(document, 'domain', {
            set(val) { checkTaint('document.domain', val); return _dd.set.call(this, val); },
            get() { return _dd.get.call(this); }, configurable: true
          });
        }
      } catch(e) {}


      // ── Storage sinks ──
      try {
        const _lsSet = localStorage.setItem.bind(localStorage);
        localStorage.setItem = function(k, v) { checkTaint('localStorage.setItem', k + '=' + String(v).substring(0,200)); return _lsSet(k, v); };
      } catch(e) {}
      try {
        const _ck = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') || Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
        if (_ck && _ck.set) Object.defineProperty(document, 'cookie', {
          set(v) { checkTaint('document.cookie', v); return _ck.set.call(this, v); },
          get() { return _ck.get.call(this); }, configurable: true });
      } catch(e) {}

      // ── postMessage sinks (send side) ──
      try {
        const _pm = window.postMessage;
        window.postMessage = function(msg) { try { checkTaint('window.postMessage', typeof msg === 'string' ? msg : JSON.stringify(msg)); } catch(e){} return _pm.apply(this, arguments); };
      } catch(e) {}
      try {
        const _mpp = MessagePort.prototype.postMessage;
        MessagePort.prototype.postMessage = function(msg) { try { checkTaint('MessagePort.postMessage', typeof msg==='string'?msg:JSON.stringify(msg)); } catch(e){} return _mpp.apply(this, arguments); };
      } catch(e) {}
      try {
        if (window.BroadcastChannel) {
          const _bcp = BroadcastChannel.prototype.postMessage;
          BroadcastChannel.prototype.postMessage = function(msg) { try { checkTaint('BroadcastChannel.postMessage', typeof msg==='string'?msg:JSON.stringify(msg)); } catch(e){} return _bcp.apply(this, arguments); };
        }
      } catch(e) {}
      // Flag message listeners registered WITHOUT an origin check (potential unauth postMessage sink)
      try {
        const _ael = window.addEventListener;
        window.addEventListener = function(type, fn, opts) {
          if (type === 'message' && typeof fn === 'function' && !/\.origin\b/.test(Function.prototype.toString.call(fn))) {
            checkTaint('postMessage.listener.noOriginCheck', String(fn).substring(0,300));
          }
          return _ael.apply(this, arguments);
        };
      } catch(e) {}

      // ── Exfiltration sinks ──
      try { const _sb = navigator.sendBeacon && navigator.sendBeacon.bind(navigator);
        if (_sb) navigator.sendBeacon = function(url, data) { checkTaint('navigator.sendBeacon', String(url)); if (data) checkTaint('sendBeacon.body', String(data)); return _sb(url, data); }; } catch(e) {}
      try { if (window.EventSource) { const _es = window.EventSource; window.EventSource = function(url, cfg) { checkTaint('EventSource', String(url)); return new _es(url, cfg); }; window.EventSource.prototype = _es.prototype; } } catch(e) {}
      try { if (window.RTCDataChannel) { const _rd = RTCDataChannel.prototype.send; RTCDataChannel.prototype.send = function(d) { checkTaint('RTCDataChannel.send', String(d)); return _rd.apply(this, arguments); }; } } catch(e) {}
      try { if (navigator.clipboard && navigator.clipboard.writeText) { const _cw = navigator.clipboard.writeText.bind(navigator.clipboard); navigator.clipboard.writeText = function(t) { checkTaint('clipboard.writeText', String(t)); return _cw(t); }; } } catch(e) {}

      // ── Navigation sinks (methods) ──
      try { const _la = location.assign.bind(location); location.assign = function(u) { checkTaint('location.assign', String(u)); return _la(u); }; } catch(e) {}
      try { const _lr = location.replace.bind(location); location.replace = function(u) { checkTaint('location.replace', String(u)); return _lr(u); }; } catch(e) {}
      try { const _wo = window.open; window.open = function(u) { checkTaint('window.open', String(u)); return _wo.apply(this, arguments); }; } catch(e) {}
      try { const _ps = history.pushState.bind(history); history.pushState = function(s,t,u) { if (u) checkTaint('history.pushState', String(u)); return _ps(s,t,u); }; } catch(e) {}
      try { const _rs = history.replaceState.bind(history); history.replaceState = function(s,t,u) { if (u) checkTaint('history.replaceState', String(u)); return _rs(s,t,u); }; } catch(e) {}

      // ── Element src/href/srcdoc property setters (script/img/iframe/anchor) ──
      [['HTMLScriptElement','src','script.src'],['HTMLScriptElement','text','script.text'],['HTMLImageElement','src','img.src'],
       ['HTMLIFrameElement','src','iframe.src'],['HTMLIFrameElement','srcdoc','iframe.srcdoc'],['HTMLAnchorElement','href','anchor.href'],
       ['HTMLBaseElement','href','base.href'],['HTMLFormElement','action','form.action'],['HTMLObjectElement','data','object.data'],
       ['HTMLEmbedElement','src','embed.src'],['HTMLSourceElement','src','source.src']].forEach(([iface, prop, label]) => {
        try {
          const proto = window[iface] && window[iface].prototype; if (!proto) return;
          const d = Object.getOwnPropertyDescriptor(proto, prop); if (!d || !d.set) return;
          Object.defineProperty(proto, prop, { set(v) { checkTaint(label, String(v)); return d.set.call(this, v); }, get() { return d.get.call(this); }, configurable: true });
        } catch(e) {}
      });

      // ── HTML-parsing sinks ──
      try { const _ccf = Range.prototype.createContextualFragment; Range.prototype.createContextualFragment = function(h) { checkTaint('Range.createContextualFragment', String(h)); return _ccf.call(this, h); }; } catch(e) {}
      try { const _dp = DOMParser.prototype.parseFromString; DOMParser.prototype.parseFromString = function(s, t) { if (t && String(t).includes('html')) checkTaint('DOMParser.parseFromString', String(s)); return _dp.apply(this, arguments); }; } catch(e) {}
      try { if (Element.prototype.setHTML) { const _sh = Element.prototype.setHTML; Element.prototype.setHTML = function(h) { checkTaint('Element.setHTML', String(h)); return _sh.apply(this, arguments); }; } } catch(e) {}
      // shadowRoot.innerHTML
      try { const shd = Object.getOwnPropertyDescriptor(window.ShadowRoot && ShadowRoot.prototype || {}, 'innerHTML'); if (shd && shd.set) Object.defineProperty(ShadowRoot.prototype, 'innerHTML', { set(v){ checkTaint('shadowRoot.innerHTML', v); return shd.set.call(this,v); }, get(){ return shd.get.call(this); }, configurable:true }); } catch(e) {}

      // ── Worker / ServiceWorker injection sinks ──
      try { const _W = window.Worker; if (_W) { window.Worker = function(u, o) { checkTaint('Worker', String(u)); return new _W(u, o); }; window.Worker.prototype = _W.prototype; } } catch(e) {}
      try { const _SW = window.SharedWorker; if (_SW) { window.SharedWorker = function(u, o) { checkTaint('SharedWorker', String(u)); return new _SW(u, o); }; window.SharedWorker.prototype = _SW.prototype; } } catch(e) {}
      try { if (navigator.serviceWorker && navigator.serviceWorker.register) { const _reg = navigator.serviceWorker.register.bind(navigator.serviceWorker); navigator.serviceWorker.register = function(u, o) { checkTaint('serviceWorker.register', String(u)); return _reg(u, o); }; } } catch(e) {}

      // ── Dynamic <script> injection via appendChild/insertBefore/replaceWith ──
      ['appendChild','insertBefore','replaceChild'].forEach(m => {
        try {
          const _orig = Node.prototype[m];
          Node.prototype[m] = function(node) {
            try { if (node && node.tagName === 'SCRIPT' && (node.src || node.textContent)) checkTaint('dom.dynamicScript.' + m, node.src || node.textContent); } catch(e) {}
            return _orig.apply(this, arguments);
          };
        } catch(e) {}
      });

      // ── Trusted Types policy creation (CSP-bypass indicator) ──
      try { if (window.trustedTypes && trustedTypes.createPolicy) { const _tp = trustedTypes.createPolicy.bind(trustedTypes); trustedTypes.createPolicy = function(name, rules) { checkTaint('trustedTypes.createPolicy', String(name)); return _tp(name, rules); }; } } catch(e) {}

      // ── Prototype-pollution sinks ──
      try {
        const _assign = Object.assign;
        Object.assign = function(t, ...srcs) { srcs.forEach(s => { if (s && typeof s === 'object') Object.keys(s).forEach(k => { if (k === '__proto__' || k === 'constructor' || k === 'prototype') checkTaint('pp.Object.assign.' + k, String(s[k])); }); }); return _assign.apply(this, arguments); };
      } catch(e) {}
      try {
        const _parse = JSON.parse;
        JSON.parse = function(txt, rev) { if (typeof txt === 'string' && /"__proto__"|"constructor"|"prototype"/.test(txt)) checkTaint('pp.JSON.parse', txt.substring(0,300)); return _parse.apply(this, arguments); };
      } catch(e) {}
      // Detect Object.prototype pollution after taint (canary key on the base prototype)
      try {
        setInterval(() => { try { const o = {}; for (const k in o) { if (String(o[k]).includes(prefix)) checkTaint('pp.Object.prototype.polluted', k + '=' + o[k]); } } catch(e) {} }, 2000);
      } catch(e) {}

      // ── CSS injection sinks ──
      try {
        if (window.CSSStyleSheet && CSSStyleSheet.prototype.insertRule) {
          const _ir = CSSStyleSheet.prototype.insertRule;
          CSSStyleSheet.prototype.insertRule = function(rule, index) { checkTaint('css.insertRule', String(rule)); return _ir.apply(this, arguments); };
        }
      } catch(e) {}
      try {
        if (window.CSSStyleDeclaration) {
          const _ct = Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype, 'cssText');
          if (_ct && _ct.set) Object.defineProperty(CSSStyleDeclaration.prototype, 'cssText', {
            set(v) { checkTaint('css.cssText', String(v)); return _ct.set.call(this, v); },
            get() { return _ct.get.call(this); }, configurable: true });
        }
      } catch(e) {}

      // ── Console info-leak sinks ──
      try { const _cl = console.log; console.log = function(...args) { try { checkTaint('console.log', args.map(a => typeof a === 'string' ? a : (()=>{try{return JSON.stringify(a);}catch(e){return String(a);}})()).join(' ')); } catch(e){} return _cl.apply(this, arguments); }; } catch(e) {}
      try { const _ce = console.error; console.error = function(...args) { try { checkTaint('console.error', args.map(a => typeof a === 'string' ? a : (()=>{try{return JSON.stringify(a);}catch(e){return String(a);}})()).join(' ')); } catch(e){} return _ce.apply(this, arguments); }; } catch(e) {}

      // ── WebSocket message SEND (URL already hooked above) ──
      try {
        if (window.WebSocket && _WebSocket.prototype.send) {
          const _wsSend = _WebSocket.prototype.send;
          _WebSocket.prototype.send = function(data) { try { checkTaint('websocket.send', typeof data === 'string' ? data : String(data)); } catch(e){} return _wsSend.apply(this, arguments); };
        }
      } catch(e) {}

      // ── Navigation API (navigation.navigate) ──
      try {
        if (window.navigation && typeof navigation.navigate === 'function') {
          const _nav = navigation.navigate.bind(navigation);
          navigation.navigate = function(u, o) { checkTaint('navigation.navigate', String(u)); return _nav(u, o); };
        }
      } catch(e) {}

      // ── fetch request HEADERS via Headers.prototype.append/set ──
      try {
        if (window.Headers) {
          const _hAppend = Headers.prototype.append;
          Headers.prototype.append = function(name, value) { checkTaint('headers.append', String(name) + ': ' + String(value)); return _hAppend.apply(this, arguments); };
          const _hSet = Headers.prototype.set;
          Headers.prototype.set = function(name, value) { checkTaint('headers.set', String(name) + ': ' + String(value)); return _hSet.apply(this, arguments); };
        }
      } catch(e) {}
      // Inspect init.headers passed directly to fetch (plain object / array / Headers)
      try {
        const _fetch2 = window.fetch;
        window.fetch = function(url, init) {
          try {
            if (init && init.headers) {
              const h = init.headers;
              let flat = '';
              if (typeof h.forEach === 'function' && !Array.isArray(h)) { h.forEach((v, k) => { flat += k + ': ' + v + '\n'; }); }
              else if (Array.isArray(h)) { flat = h.map(pair => (pair || []).join(': ')).join('\n'); }
              else if (typeof h === 'object') { flat = Object.keys(h).map(k => k + ': ' + h[k]).join('\n'); }
              if (flat) checkTaint('fetch.headers', flat);
            }
          } catch(e) {}
          return _fetch2.apply(this, arguments);
        };
      } catch(e) {}

      // ── setAttributeNS (xlink:href in SVG use/image — bypasses setAttribute hook) ──
      try {
        const _setAttrNS = Element.prototype.setAttributeNS;
        Element.prototype.setAttributeNS = function(ns, name, value) {
          try { const ln = String(name).toLowerCase(); if (ln.includes('href') || ln.includes('src') || ln.includes('action')) checkTaint('setAttributeNS', String(value)); } catch(e) {}
          return _setAttrNS.apply(this, arguments);
        };
      } catch(e) {}

      // MutationObserver for DOM reflection detection
      const observer = new MutationObserver((mutations) => {
        for (const m of mutations) {
          if (m.type === 'childList') {
            m.addedNodes.forEach(node => {
              if (node.nodeType === 1) { // Element
                const html = node.outerHTML || '';
                if (html.includes(prefix)) {
                  checkTaint('dom_mutation', html);
                }
              }
            });
          } else if (m.type === 'attributes') {
            const val = m.target.getAttribute(m.attributeName) || '';
            if (val.includes(prefix)) checkTaint('attr_mutation.' + m.attributeName, val);
          }
        }
      });
      // Start observing after a short delay (let page initialize)
      setTimeout(() => {
        observer.observe(document.documentElement || document.body, {
          childList: true, attributes: true, subtree: true, characterData: true
        });
      }, 1000);

    }, this.canaryPrefix);

    this.logger.log('TAINT-PLANTER', 'INFO', 'Taint monitor installed (58 sink hooks: DOM/HTML, nav, storage, postMessage, exfil, workers, element-src, CSS-injection, console-leak, websocket-send, navigation-API, fetch-headers, setAttributeNS, prototype-pollution + DOM mutation observer)');
  }

  // ═══════════════════════════════════════════════════
  // 1. URL PARAMETER TAINTING
  // ═══════════════════════════════════════════════════
  async _taintUrlParams(page, crawlerUrls) {
    const currentUrl = page.url();
    let tainted = 0;

    // Parse current URL params and inject canaries
    try {
      const u = new URL(currentUrl);
      if (u.searchParams.toString()) {
        for (const [key, val] of u.searchParams) {
          const canary = this._canary('url_param', key);
          u.searchParams.set(key, canary);
          tainted++;
        }
        // Navigate with tainted params
        try {
          await page.goto(u.toString(), { waitUntil: 'networkidle2', timeout: 15000 });
          await new Promise(r => setTimeout(r, 2000)); // Wait for JS execution
        } catch(e) {}
      }
    } catch(e) {}

    // Also test common injectable params on current page
    const testParams = ['q', 'search', 'query', 'id', 'page', 'url', 'redirect', 'next', 'return',
      'returnUrl', 'callback', 'cb', 'ref', 'src', 'dest', 'target', 'path', 'file',
      'template', 'lang', 'locale', 'theme', 'view', 'action', 'type', 'name', 'value'];

    try {
      const u = new URL(currentUrl);
      for (const param of testParams) {
        if (!u.searchParams.has(param)) {
          u.searchParams.set(param, this._canary('injected_param', param));
          tainted++;
        }
      }
      // Navigate with injected params (quick check)
      try {
        await page.goto(u.toString(), { waitUntil: 'domcontentloaded', timeout: 10000 });
        await new Promise(r => setTimeout(r, 1500));
      } catch(e) {}
    } catch(e) {}

    // Plant real XSS payloads from arsenal (alongside canaries)
    const realPayloads = this.xssPayloads;
    if (realPayloads && Object.keys(realPayloads).length > 0) {
      let planted = 0;
      try {
        const u = new URL(currentUrl);
        const contextKey = 'html_text';
        const payloads = realPayloads[contextKey] || realPayloads[Object.keys(realPayloads)[0]] || [];
        const targetParams = Array.from(u.searchParams.keys());
        const highValue = targetParams.length > 0 ? targetParams : ['q', 'search', 'id', 'name'];
        for (const param of highValue.slice(0, 3)) {
          for (const payload of payloads.slice(0, 2)) {
            const testUrl = new URL(currentUrl);
            testUrl.searchParams.set(param, payload);
            const tag = `xss_${param}_${Date.now()}`;
            this.plantedPayloads[tag] = { param, payload, url: testUrl.toString() };
            try {
              await page.goto(testUrl.toString(), { waitUntil: 'domcontentloaded', timeout: 10000 });
              await new Promise(r => setTimeout(r, 1500));
              planted++;
            } catch(e) {}
          }
        }
      } catch(e) {}
      this.logger.log('TAINT-PLANTER', 'INFO', `Planted ${planted} real XSS payloads from arsenal`);
    }

    this.logger.log('TAINT-PLANTER', 'INFO', `Tainted ${tainted} URL parameters`);
  }

  // ═══════════════════════════════════════════════════
  // 2. FORM INPUT TAINTING
  // ═══════════════════════════════════════════════════
  async _taintFormInputs(page) {
    const tainted = await page.evaluate((prefix, counter) => {
      let count = 0;
      const inputs = document.querySelectorAll('input, textarea, select, [contenteditable]');
      inputs.forEach(el => {
        const id = ++counter;
        const canary = prefix + id;
        const name = el.name || el.id || el.type || 'unknown';
        if (el.tagName === 'SELECT') {
          // For selects, try setting value to canary if possible
          const opt = document.createElement('option');
          opt.value = canary; opt.text = canary;
          el.appendChild(opt); el.value = canary;
        } else if (el.getAttribute('contenteditable') !== null) {
          el.innerHTML = canary;
        } else if (el.type !== 'hidden' && el.type !== 'submit' && el.type !== 'button' &&
                   el.type !== 'file' && el.type !== 'checkbox' && el.type !== 'radio') {
          el.value = canary;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
          el.dispatchEvent(new Event('keyup', { bubbles: true }));
        }
        count++;
      });

      // Also taint hidden inputs (potential SSRF/redirect vectors)
      document.querySelectorAll('input[type="hidden"]').forEach(el => {
        const id = ++counter;
        el.value = prefix + id;
        count++;
      });

      return count;
    }, this.canaryPrefix, this.canaryCounter);

    this.canaryCounter += tainted;
    this.logger.log('TAINT-PLANTER', 'INFO', `Tainted ${tainted} form inputs`);
  }

  // ═══════════════════════════════════════════════════
  // 3. STORAGE TAINTING (localStorage + sessionStorage)
  // ═══════════════════════════════════════════════════
  async _taintStorage(page) {
    const tainted = await page.evaluate((prefix, counter) => {
      let count = 0;
      // Plant canaries into existing storage keys
      [localStorage, sessionStorage].forEach((store, si) => {
        const storeName = si === 0 ? 'localStorage' : 'sessionStorage';
        for (let i = 0; i < store.length; i++) {
          const key = store.key(i);
          const id = ++counter;
          const canary = prefix + id;
          // Append canary to existing value (don't destroy app state)
          const orig = store.getItem(key);
          store.setItem(key, orig + canary);
          count++;
        }
        // Also plant in common keys
        ['token', 'user', 'config', 'settings', 'debug', 'theme', 'lang', 'redirect_url'].forEach(k => {
          if (!store.getItem(k)) {
            const id = ++counter;
            store.setItem(k, prefix + id);
            count++;
          }
        });
      });
      return count;
    }, this.canaryPrefix, this.canaryCounter);

    this.canaryCounter += tainted;
    this.logger.log('TAINT-PLANTER', 'INFO', `Tainted ${tainted} storage entries`);
  }

  // ═══════════════════════════════════════════════════
  // 4. COOKIE TAINTING
  // ═══════════════════════════════════════════════════
  async _taintCookies(page) {
    const tainted = await page.evaluate((prefix, counter) => {
      let count = 0;
      // Plant canary cookies
      const testCookies = ['genki_taint', 'debug', 'theme', 'lang', 'tracking', 'ref'];
      testCookies.forEach(name => {
        const id = ++counter;
        document.cookie = `${name}=${prefix}${id}; path=/; SameSite=Lax`;
        count++;
      });
      return count;
    }, this.canaryPrefix, this.canaryCounter);

    this.canaryCounter += tainted;
    this.logger.log('TAINT-PLANTER', 'INFO', `Tainted ${tainted} cookies`);
  }

  // ═══════════════════════════════════════════════════
  // 5. POSTMESSAGE TAINTING
  // ═══════════════════════════════════════════════════
  async _taintPostMessage(page) {
    const canary = this._canary('postMessage', 'window');
    await page.evaluate((canary) => {
      // Send tainted postMessage to self (tests if any handler reflects it)
      const payloads = [
        canary,
        JSON.stringify({ type: 'config', data: canary }),
        JSON.stringify({ action: 'update', value: canary }),
        JSON.stringify({ html: '<img src=x onerror=' + canary + '>' }),
      ];
      payloads.forEach(p => {
        try { window.postMessage(p, '*'); } catch(e) {}
      });
      // Also send to all iframes
      document.querySelectorAll('iframe').forEach(f => {
        try { f.contentWindow.postMessage(canary, '*'); } catch(e) {}
      });
    }, canary);
    this.logger.log('TAINT-PLANTER', 'INFO', 'Sent tainted postMessages to window + iframes');
  }

  // ═══════════════════════════════════════════════════
  // 6. HASH/FRAGMENT TAINTING
  // ═══════════════════════════════════════════════════
  async _taintHashFragment(page) {
    const canary = this._canary('hash', 'fragment');
    try {
      const url = page.url();
      const u = new URL(url);
      u.hash = canary;
      await page.goto(u.toString(), { waitUntil: 'domcontentloaded', timeout: 8000 });
      await new Promise(r => setTimeout(r, 1500));
    } catch(e) {}
    this.logger.log('TAINT-PLANTER', 'INFO', `Hash fragment tainted: #${canary}`);
  }

  // ═══════════════════════════════════════════════════
  // 7. HARVEST REFLECTIONS
  // ═══════════════════════════════════════════════════
  async _harvestReflections(page) {
    try {
      const results = await page.evaluate((prefix) => {
        const data = { reflections: [], domReflections: [] };
        // Get monitored reflections
        if (window.__GENKI_TAINT?.reflections) {
          data.reflections = window.__GENKI_TAINT.reflections;
        }
        // Also scan entire DOM for canary presence and real C2 payload reflection
        const bodyHtml = document.documentElement.outerHTML;
        const canaryRx = new RegExp(prefix + '\\d+', 'g');
        const domMatches = bodyHtml.match(canaryRx) || [];
        if (bodyHtml.includes('6u.gg')) {
          data.c2Reflected = true;
          const c2Idx = bodyHtml.indexOf('6u.gg');
          data.c2Context = bodyHtml.substring(Math.max(0, c2Idx - 80), c2Idx + 100);
        }
        // Find context of each reflection
        domMatches.forEach(canary => {
          const idx = bodyHtml.indexOf(canary);
          const context = bodyHtml.substring(Math.max(0, idx - 50), idx + canary.length + 50);
          // Determine if it's in a dangerous context
          const inScript = /<script[^>]*>[^<]*/.test(bodyHtml.substring(Math.max(0, idx - 200), idx));
          const inAttr = /=\s*["'][^"']*$/.test(bodyHtml.substring(Math.max(0, idx - 100), idx));
          const inHref = /href\s*=\s*["'][^"']*$/.test(bodyHtml.substring(Math.max(0, idx - 100), idx));
          data.domReflections.push({
            canary, context: context.replace(/</g, '&lt;'),
            inScript, inAttr, inHref,
            dangerous: inScript || inHref
          });
        });
        return data;
      }, this.canaryPrefix);

      // Process sink reflections
      for (const r of results.reflections) {
        const canaryInfo = this.canaries[r.canary] || { source: 'unknown', context: 'unknown' };
        // ── FP Filter: Skip taint flows from prober's own injection URLs ──
        const flowUrl = r.url || url;
        if (flowUrl.startsWith('data:') || flowUrl.startsWith('blob:') || flowUrl.startsWith('javascript:')) {
          this.logger.log('TAINT-PLANTER', 'DEBUG', `Skipped self-injection taint flow on ${flowUrl.substring(0, 60)}`);
          continue;
        }
        const severity = ['eval', 'Function', 'innerHTML', 'document.write', 'location.href'].includes(r.sink) ? 'critical' : 'high';
        // Dedup taint flows
        if (!this._taintSeen) this._taintSeen = new Set();
        const tKey = `taint:${canaryInfo.source}:${canaryInfo.context}:${r.sink}`;
        if (this._taintSeen.has(tKey)) continue;
        this._taintSeen.add(tKey);
        const finding = {
          type: 'taint_flow', severity, sink: r.sink,
          source: canaryInfo.source, context: canaryInfo.context,
          canary: r.canary, value: r.value?.substring(0, 200),
          url: flowUrl, stack: r.stack
        };
        this.findings.push(finding);
        this.reflections.push(finding);
        this.logger.log('TAINT-PLANTER', 'FIND', `[HIGH] TAINT FLOW: ${canaryInfo.source}(${canaryInfo.context}) → ${r.sink}`,
          r.value?.substring(0, 120));
      }

      // Process DOM reflections (deduplicated)
      for (const r of results.domReflections) {
        // ── FP Filter: Skip reflections from prober's own injection pages ──
        if (url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('javascript:')) {
          this.logger.log('TAINT-PLANTER', 'DEBUG', `Skipped self-reflection on ${url.substring(0, 60)}`);
          continue;
        }
        // ── FP Filter: Skip batch-canary self-reflections (prober's redirect scripts) ──
        if (r.context) {
          const canaryCount = (r.context.match(/GNKTNT\d+/g) || []).length;
          if (canaryCount >= 3) {
            this.logger.log('TAINT-PLANTER', 'DEBUG', `Skipped batch-canary self-reflection (${canaryCount} canaries in context)`);
            continue;
          }
          if (r.context.includes('data:text/html') || r.context.includes('data%3Atext')) {
            this.logger.log('TAINT-PLANTER', 'DEBUG', `Skipped data:text/html self-reflection`);
            continue;
          }
        }
        const canaryInfo = this.canaries[r.canary] || { source: 'unknown', context: 'unknown' };
        if (r.dangerous) {
          if (!this._reflSeen) this._reflSeen = new Set();
          const rKey = `refl:${canaryInfo.source}:${canaryInfo.context}:${r.inScript?'SCRIPT':r.inHref?'HREF':'ATTR'}`;
          if (this._reflSeen.has(rKey)) continue;
          this._reflSeen.add(rKey);
          const finding = {
            type: 'dom_reflection', severity: r.inScript ? 'critical' : 'high',
            source: canaryInfo.source, context: canaryInfo.context,
            canary: r.canary, inScript: r.inScript, inAttr: r.inAttr, inHref: r.inHref,
            domContext: r.context, url: url
          };
          this.findings.push(finding);
          this.reflections.push(finding);
          this.logger.log('TAINT-PLANTER', 'FIND', `[HIGH] DOM Reflection: ${canaryInfo.source}(${canaryInfo.context}) → ${r.inScript ? 'SCRIPT' : r.inHref ? 'HREF' : 'ATTR'}`,
            r.context);
        }
      }

      // Report real C2 payload reflections
      if (results.c2Reflected) {
        const finding = {
          type: 'c2_payload_reflection', severity: 'critical',
          source: 'xss_arsenal', context: 'url_param',
          c2Context: (results.c2Context || '').substring(0, 300),
          payload_execution: true, url: page.url()
        };
        this.findings.push(finding);
        this.reflections.push(finding);
        this.logger.log('TAINT-PLANTER', 'FIND', '[CRITICAL] Real XSS payload reflected with 6u.gg callback',
          (results.c2Context || '').substring(0, 120));
      }

      // Report payload_execution events from sink monitors
      const execEvents = results.reflections.filter(r => r.payload_execution);
      for (const ev of execEvents) {
        const finding = {
          type: 'c2_payload_execution', severity: 'critical',
          sink: ev.sink, value: (ev.value || '').substring(0, 300),
          payload_execution: true, url: ev.url,
          stack: ev.stack
        };
        this.findings.push(finding);
        this.logger.log('TAINT-PLANTER', 'FIND', `[CRITICAL] C2 payload reached sink: ${ev.sink}`,
          (ev.value || '').substring(0, 120));
      }

      this.logger.log('TAINT-PLANTER', 'INFO',
        `Harvested: ${results.reflections.length} sink flows, ${results.domReflections.length} DOM reflections` +
        (results.c2Reflected ? ', C2 payload REFLECTED' : '') +
        (execEvents.length ? `, ${execEvents.length} C2 execution events` : ''));
    } catch(e) {
      this.logger.log('TAINT-PLANTER', 'WARN', `Harvest error: ${e.message.substring(0, 80)}`);
    }
  }

  _saveResults() {
    fs.writeFileSync(path.join(this.config.outputDir, 'taint-results.json'), JSON.stringify({
      canaries: this.canaries,
      reflections: this.reflections,
      findings: this.findings,
      plantedPayloads: this.plantedPayloads,
      stats: {
        planted: this.canaryCounter,
        reflected: this.reflections.length,
        realPayloadsPlanted: Object.keys(this.plantedPayloads).length,
        c2Executions: this.findings.filter(f => f.payload_execution).length
      }
    }, null, 2));
  }

  summary() {
    return {
      canariesPlanted: this.canaryCounter,
      reflectionsDetected: this.reflections.length,
      findings: this.findings.length,
    };
  }
  getFindings() { return this.findings; }
}

module.exports = TaintPlanter;
