// GENKI-PROBER MODULE: SECURITY SCANNER
// Integrated: GENKI IAST Taint Tracking + DOM Invader Sink/Source + Prototype Pollution
// Runtime vulnerability detection via Puppeteer CDP
const fs   = require('fs');
const path = require('path');
const http  = require('http');
const https = require('https');

class SecurityScanner {
  constructor(logger, config) {
    this.logger = logger;
    this.config = config;
    this.findings = [];
    this.sinkHits = [];
    this.ppResults = [];
    this.taintFlows = [];
    this.cspIssues = [];
    this.headerIssues = [];
    this.cspDefenseLevel = 'unknown'; // Set during CSP analysis: weak|moderate|strong
  }

  // The massive evaluateOnNewDocument script that hooks everything
  _buildHookScript() {
    return `
    (() => {
      // ══════════════════════════════════════════════════
      // GENKI SECURITY HOOKS — Injected before page load
      // ══════════════════════════════════════════════════
      const __GENKI = {
        sinks: [],
        sources: [],
        taintFlows: [],
        ppHits: [],
        evalCalls: [],
        errors: [],
        canary: 'gENk1_' + Math.random().toString(36).substring(2, 10),
      };
      window.__GENKI_SCAN = __GENKI;

      // ── SINK RANKING (from DOM Invader) ──
      const SINK_RANK = {
        'eval': 1, 'Function': 2, 'setTimeout_string': 3, 'setInterval_string': 4,
        'document.write': 5, 'document.writeln': 6,
        'innerHTML': 7, 'outerHTML': 8, 'insertAdjacentHTML': 9,
        'script.src': 10, 'script.textContent': 11,
        'location.href': 12, 'location.assign': 13, 'location.replace': 14,
        'window.open': 15, 'iframe.src': 16, 'iframe.srcdoc': 17,
        'jQuery.html': 18, 'jQuery.append': 19, 'jQuery.globalEval': 20,
        'element.setAttribute_event': 21, 'fetch': 22, 'xhr.open': 23,
        'Worker': 24, 'SharedWorker': 25, 'import': 26,
        'a.href': 27, 'form.action': 28, 'input.formAction': 29,
        'object.data': 30, 'embed.src': 31,
        'Range.createContextualFragment': 32,
        'crypto.subtle.importKey': 33,
        'Notification': 34, 'webkitNotifications': 35,
        'RegExp': 36, 'DOMParser.parseFromString': 37,
        'document.cookie_set': 38,
        'postMessage': 39, 'localStorage.setItem': 40,
      };

      function reportSink(name, value, stack) {
        const entry = {
          sink: name, value: String(value).substring(0, 500),
          rank: SINK_RANK[name] || 99,
          stack: stack || (new Error()).stack?.substring(0, 1000),
          url: location.href, time: Date.now(),
          hasTaint: String(value).includes(__GENKI.canary),
        };
        __GENKI.sinks.push(entry);
        if (entry.hasTaint) {
          __GENKI.taintFlows.push({ source: 'canary', sink: name, value: entry.value, stack: entry.stack });
        }
      }

      // ── 1. EVAL FAMILY ──
      const _eval = window.eval;
      window.eval = function(code) {
        reportSink('eval', code); __GENKI.evalCalls.push(String(code).substring(0, 500));
        return _eval.apply(this, arguments);
      };
      const _Function = window.Function;
      window.Function = new Proxy(_Function, {
        construct(target, args) { reportSink('Function', args.join(',')); return Reflect.construct(target, args); },
        apply(target, thisArg, args) { reportSink('Function', args.join(',')); return Reflect.apply(target, thisArg, args); }
      });

      // ── 2. TIMER SINKS (string arguments only) ──
      ['setTimeout', 'setInterval'].forEach(fn => {
        const orig = window[fn];
        window[fn] = function(code, ...rest) {
          if (typeof code === 'string') reportSink(fn + '_string', code);
          return orig.apply(this, [code, ...rest]);
        };
      });

      // ── 3. DOCUMENT.WRITE ──
      const _write = document.write.bind(document);
      const _writeln = document.writeln.bind(document);
      document.write = function(html) { reportSink('document.write', html); return _write(html); };
      document.writeln = function(html) { reportSink('document.writeln', html); return _writeln(html); };

      // ── 4. INNERHTML / OUTERHTML ──
      ['innerHTML', 'outerHTML'].forEach(prop => {
        const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
        if (desc && desc.set) {
          const origSet = desc.set;
          Object.defineProperty(Element.prototype, prop, {
            set(val) {
              if (val && typeof val === 'string') {
                reportSink(prop, val);
                // Check for script tags or event handlers being injected
                if (/<script|javascript:|on\\w+\\s*=/i.test(val)) {
                  reportSink(prop + '_dangerous', val);
                }
              }
              return origSet.call(this, val);
            },
            get: desc.get, configurable: true, enumerable: true
          });
        }
      });

      // insertAdjacentHTML
      const _insertAdj = Element.prototype.insertAdjacentHTML;
      Element.prototype.insertAdjacentHTML = function(pos, html) {
        reportSink('insertAdjacentHTML', html);
        return _insertAdj.call(this, pos, html);
      };

      // ── 5. LOCATION SINKS ──
      ['href','pathname','search','hash','protocol','host','hostname','port'].forEach(prop => {
        try {
          const desc = Object.getOwnPropertyDescriptor(Location.prototype, prop) || 
                       Object.getOwnPropertyDescriptor(location.__proto__, prop);
          if (desc && desc.set) {
            const origSet = desc.set;
            Object.defineProperty(location, prop, {
              set(val) { reportSink('location.' + prop, val); return origSet.call(this, val); },
              get: desc.get, configurable: true
            });
          }
        } catch(e) {} // location props are tricky
      });
      ['assign','replace'].forEach(method => {
        const orig = location[method]?.bind(location);
        if (orig) location[method] = function(url) { reportSink('location.' + method, url); return orig(url); };
      });

      // ── 6. WINDOW.OPEN ──
      const _open = window.open;
      window.open = function(url, ...rest) { reportSink('window.open', url); return _open.apply(this, [url, ...rest]); };

      // ── 7. FETCH / XHR ──
      const _fetch = window.fetch;
      window.fetch = function(input, init) {
        const url = typeof input === 'string' ? input : input?.url;
        reportSink('fetch', url + (init?.body ? ' BODY:' + String(init.body).substring(0, 200) : ''));
        return _fetch.apply(this, arguments);
      };
      const _xhrOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url) {
        reportSink('xhr.open', method + ' ' + url);
        return _xhrOpen.apply(this, arguments);
      };

      // ── 8. SCRIPT.SRC ──
      const scriptSrcDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
      if (scriptSrcDesc && scriptSrcDesc.set) {
        const origSet = scriptSrcDesc.set;
        Object.defineProperty(HTMLScriptElement.prototype, 'src', {
          set(val) { reportSink('script.src', val); return origSet.call(this, val); },
          get: scriptSrcDesc.get, configurable: true
        });
      }

      // ── 9. IFRAME.SRC / SRCDOC ──
      ['src', 'srcdoc'].forEach(prop => {
        const desc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, prop);
        if (desc && desc.set) {
          const origSet = desc.set;
          Object.defineProperty(HTMLIFrameElement.prototype, prop, {
            set(val) { reportSink('iframe.' + prop, val); return origSet.call(this, val); },
            get: desc.get, configurable: true
          });
        }
      });

      // ── 10. SETATTRIBUTE (event handlers) ──
      const _setAttribute = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function(name, value) {
        const lower = name.toLowerCase();
        if (lower.startsWith('on') || lower === 'href' || lower === 'src' || lower === 'action' || lower === 'formaction' || lower === 'data' || lower === 'srcdoc') {
          reportSink('element.setAttribute.' + lower, value);
        }
        return _setAttribute.call(this, name, value);
      };

      // ── 11. JQUERY HOOKS ──
      function hookJQuery() {
        const jq = window.jQuery || window.$;
        if (!jq || !jq.fn) return;
        ['html','append','prepend','after','before','replaceWith','wrapAll','wrapInner','wrap'].forEach(method => {
          const orig = jq.fn[method];
          if (!orig) return;
          jq.fn[method] = function(val) {
            if (typeof val === 'string') reportSink('jQuery.' + method, val);
            return orig.apply(this, arguments);
          };
        });
        if (jq.globalEval) {
          const _ge = jq.globalEval;
          jq.globalEval = function(code) { reportSink('jQuery.globalEval', code); return _ge.apply(this, arguments); };
        }
      }
      if (document.readyState === 'complete' || document.readyState === 'interactive') hookJQuery();
      else document.addEventListener('DOMContentLoaded', hookJQuery);
      // Retry after a delay (jQuery might load async)
      setTimeout(hookJQuery, 2000);
      setTimeout(hookJQuery, 5000);

      // ── 12. POSTMESSAGE ──
      const _postMsg = window.postMessage.bind(window);
      window.postMessage = function(msg, origin, transfer) {
        reportSink('postMessage', JSON.stringify(msg)?.substring(0, 500) + ' → ' + origin);
        return _postMsg(msg, origin, transfer);
      };
      // Listen for incoming messages
      window.addEventListener('message', function(e) {
        __GENKI.sources.push({
          type: 'postMessage', origin: e.origin,
          data: JSON.stringify(e.data)?.substring(0, 500),
          time: Date.now()
        });
      });

      // ── 13. PROTOTYPE POLLUTION DETECTION ──
      // Monitor Object.prototype for unexpected additions
      const _protoKeys = new Set(Object.getOwnPropertyNames(Object.prototype));
      const ppCheckInterval = setInterval(() => {
        const currentKeys = Object.getOwnPropertyNames(Object.prototype);
        for (const key of currentKeys) {
          if (!_protoKeys.has(key)) {
            __GENKI.ppHits.push({
              property: key,
              value: String(Object.prototype[key]).substring(0, 200),
              time: Date.now(),
              stack: (new Error()).stack?.substring(0, 500)
            });
          }
        }
      }, 1000);
      // Clean up after 30 seconds
      setTimeout(() => clearInterval(ppCheckInterval), 30000);

      // Also inject PP canaries via URL
      // These will be picked up if any code does unsafe merge/assign
      try {
        const ppTestObj = {};
        ppTestObj.__proto__.GENKI_PP_TEST = 'polluted';
        if (({}).GENKI_PP_TEST === 'polluted') {
          __GENKI.ppHits.push({ property: 'GENKI_PP_TEST', value: 'polluted', type: 'direct_proto_write', time: Date.now() });
        }
        delete Object.prototype.GENKI_PP_TEST;
      } catch(e) {}

      // ── 14. COOKIE SINK ──
      const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
      if (cookieDesc && cookieDesc.set) {
        const origSet = cookieDesc.set;
        Object.defineProperty(document, 'cookie', {
          set(val) { reportSink('document.cookie_set', val); return origSet.call(this, val); },
          get: cookieDesc.get, configurable: true
        });
      }

      // ── 15. STORAGE SINKS ──
      const _setItem = Storage.prototype.setItem;
      Storage.prototype.setItem = function(key, val) {
        if (String(val).includes(__GENKI.canary)) reportSink('localStorage.setItem', key + '=' + val);
        return _setItem.apply(this, arguments);
      };

      // ── 16. WORKER SINK ──
      if (window.Worker) {
        const _Worker = window.Worker;
        window.Worker = new Proxy(_Worker, {
          construct(target, args) { reportSink('Worker', args[0]); return Reflect.construct(target, args); }
        });
      }

      // ── 17. DOM PARSER ──
      const _parseFromString = DOMParser.prototype.parseFromString;
      DOMParser.prototype.parseFromString = function(str, type) {
        if (type?.includes('html')) reportSink('DOMParser.parseFromString', str);
        return _parseFromString.apply(this, arguments);
      };

      // ── WEBSOCKET SINK ──
      const _WebSocket = window.WebSocket;
      window.WebSocket = function(url, protocols) {
        reportSink('WebSocket', url);
        return protocols ? new _WebSocket(url, protocols) : new _WebSocket(url);
      };
      window.WebSocket.prototype = _WebSocket.prototype;
      window.WebSocket.CONNECTING = _WebSocket.CONNECTING;
      window.WebSocket.OPEN = _WebSocket.OPEN;
      window.WebSocket.CLOSING = _WebSocket.CLOSING;
      window.WebSocket.CLOSED = _WebSocket.CLOSED;

      // ── SESSIONSTORAGE SINK ──
      const _ssSetItem = sessionStorage.setItem.bind(sessionStorage);
      sessionStorage.setItem = function(key, value) {
        reportSink('sessionStorage.setItem', key + '=' + String(value).substring(0, 200));
        return _ssSetItem(key, value);
      };

      // ── DOCUMENT.DOMAIN SINK ──
      try {
        const _domainDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'domain') ||
                            Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'domain');
        if (_domainDesc && _domainDesc.set) {
          Object.defineProperty(document, 'domain', {
            set(val) { reportSink('document.domain', val); return _domainDesc.set.call(this, val); },
            get() { return _domainDesc.get.call(this); }, configurable: true
          });
        }
      } catch(e) {}

      // ── IMPORTSCRIPTS SINK (Service Worker context) ──
      if (typeof importScripts === 'function') {
        const _importScripts = importScripts;
        self.importScripts = function() {
          Array.from(arguments).forEach(function(url) { reportSink('importScripts', url); });
          return _importScripts.apply(self, arguments);
        };
      }

      // ── TRUSTED TYPES SINK (if supported) ──
      if (window.trustedTypes && window.trustedTypes.createPolicy) {
        try {
          window.trustedTypes.createPolicy('genki-monitor', {
            createHTML: function(input) { reportSink('trustedTypes.createHTML', input.substring(0, 200)); return input; },
            createScript: function(input) { reportSink('trustedTypes.createScript', input.substring(0, 200)); return input; },
            createScriptURL: function(input) { reportSink('trustedTypes.createScriptURL', input); return input; }
          });
        } catch(e) {} // Policy may already exist
      }

      // ── NAVIGATION API SINK (modern browsers) ──
      if (window.navigation && window.navigation.navigate) {
        const _navNavigate = window.navigation.navigate.bind(window.navigation);
        window.navigation.navigate = function(url, opts) {
          reportSink('navigation.navigate', url);
          return _navNavigate(url, opts);
        };
      }

      // ── SOURCE TRACKING ──
      // Collect user-controllable input sources
      __GENKI.sources.push(
        { type: 'location.href', value: location.href },
        { type: 'location.hash', value: location.hash },
        { type: 'location.search', value: location.search },
        { type: 'document.referrer', value: document.referrer },
        { type: 'document.cookie', value: document.cookie?.substring(0, 200) },
        { type: 'window.name', value: window.name },
      );

    })();`;
  }

  async run(page, browser, urls) {
    this.logger.log('SECURITY', 'INFO', `Scanning ${urls.length} pages for vulnerabilities...`);
    this._jsonEndpointsSeen = []; // collect JSON POST endpoints for SSPP testing
    
    // Scan up to 10 pages
    const toScan = urls.slice(0, 10);
    
    for (const url of toScan) {
      const sPage = await browser.newPage();
      if (this.config.cookies.length) {
        for (const c of this.config.cookies) await sPage.setCookie(c);
      }
      
      // Inject hooks BEFORE navigation
      await sPage.evaluateOnNewDocument(this._buildHookScript());
      
      try {
        // Navigate
        const resp = await sPage.goto(url, { waitUntil: 'networkidle2', timeout: this.config.timeout });
        await this._sleep(3000); // Wait for dynamic content
        
        // ── CHECK SECURITY HEADERS ──
        if (resp) {
          const headers = resp.headers();
          this._checkSecurityHeaders(url, headers);
        }
        
        // ── COLLECT HOOK RESULTS ──
        const scanResults = await sPage.evaluate(() => {
          return {
            ...(window.__GENKI_SCAN || {}),
            endpoints: window.__GENKI_ENDPOINTS__ || [],
          };
        });

        // Collect JSON POST endpoints for SSPP testing
        (scanResults.endpoints || []).forEach(ep => {
          if ((ep.method === 'POST' || ep.method === 'PUT' || ep.method === 'PATCH') &&
              ep.body && ep.body.startsWith('{') &&
              !this._jsonEndpointsSeen.some(e => e.url === ep.url)) {
            this._jsonEndpointsSeen.push({ url: ep.url, body: ep.body });
          }
        });
        
        // Process sink hits
        if (scanResults.sinks?.length) {
          this.logger.log('SECURITY', 'WARN', `${scanResults.sinks.length} sink hits on ${url.substring(0, 80)}`);
          
          // Deduplicate and rank
          const uniqueSinks = new Map();
          scanResults.sinks.forEach(s => {
            const key = s.sink + ':' + s.value.substring(0, 100);
            if (!uniqueSinks.has(key) || s.rank < uniqueSinks.get(key).rank) {
              uniqueSinks.set(key, s);
            }
          });
          
          [...uniqueSinks.values()].sort((a, b) => a.rank - b.rank).forEach(s => {
            const severity = s.rank <= 5 ? 'critical' : s.rank <= 15 ? 'high' : s.rank <= 25 ? 'medium' : 'low';
            if (s.hasTaint) {
              this.logger.log('SECURITY', 'FIND', `[CRITICAL] TAINT FLOW: Source → ${s.sink} | ${s.value.substring(0, 200)}`);
              this.findings.push({ type: 'taint_flow', severity: 'critical', url, sink: s.sink, value: s.value, stack: s.stack });
            } else {
              this.sinkHits.push({ url, ...s, severity });
            }
          });
        }
        
        // Process PP hits (deduplicated)
        if (scanResults.ppHits?.length) {
          if (!this._ppSeen) this._ppSeen = new Set();
          scanResults.ppHits.forEach(pp => {
            const ppKey = `${pp.property}:${String(pp.value).substring(0, 50)}`;
            if (this._ppSeen.has(ppKey)) return;
            this._ppSeen.add(ppKey);
            // Skip GENKI's own test canary properties from final findings
            if (pp.property === 'GENKI_PP_TEST' || String(pp.property).startsWith('__genki_pp_')) return;
            this.logger.log('SECURITY', 'FIND', `[HIGH] Prototype Pollution: Object.prototype.${pp.property} | ${pp.value}`);
            this.findings.push({ type: 'prototype_pollution', severity: 'high', url, ...pp });
          });
        }
        
        // Process taint flows
        if (scanResults.taintFlows?.length) {
          scanResults.taintFlows.forEach(tf => {
            this.logger.log('SECURITY', 'FIND', `[CRITICAL] Taint Flow: ${tf.source} → ${tf.sink} | ${tf.value.substring(0, 200)}`);
            this.findings.push({ type: 'taint_flow', severity: 'critical', url, ...tf });
          });
        }
        
        // Process eval calls
        if (scanResults.evalCalls?.length) {
          this.logger.log('SECURITY', 'WARN', `${scanResults.evalCalls.length} eval() calls detected on ${url.substring(0, 80)}`);
          scanResults.evalCalls.forEach(code => {
            this.findings.push({ type: 'eval_usage', severity: 'medium', url, code: code.substring(0, 500) });
          });
        }
        
        // ── ACTIVE PP TEST via URL params ──
        await this._testPrototypePollution(sPage, url, browser);
        
      } catch (e) {
        this.logger.log('SECURITY', 'WARN', `Error scanning ${url.substring(0, 80)}: ${e.message.substring(0, 100)}`);
      }
      
      await sPage.close();
    }

    // ── ACTIVE SSPP TEST — server-side prototype pollution ──────────────
    // Run AFTER all page scans; use JSON endpoints discovered from XHR/fetch logs
    const jsonEndpoints = this._jsonEndpointsSeen || [];
    if (jsonEndpoints.length > 0) {
      this.logger.log('SECURITY', 'INFO', `SSPP active testing on ${jsonEndpoints.length} JSON endpoints...`);
      await this._testSSPP(jsonEndpoints, this.config.cookies);
    }
    
    this.logger.log('SECURITY', 'OK', `Security scan complete: ${this.findings.length} findings, ${this.sinkHits.length} sink hits`);
  }

  _checkSecurityHeaders(url, headers) {
    const checks = [
      { header: 'content-security-policy', missing: 'No CSP header', severity: 'medium' },
      { header: 'x-frame-options', missing: 'No X-Frame-Options (clickjacking)', severity: 'low' },
      { header: 'x-content-type-options', missing: 'No X-Content-Type-Options', severity: 'low' },
      { header: 'strict-transport-security', missing: 'No HSTS header', severity: 'medium' },
      { header: 'x-xss-protection', missing: 'No X-XSS-Protection', severity: 'info' },
      { header: 'referrer-policy', missing: 'No Referrer-Policy', severity: 'info' },
      { header: 'permissions-policy', missing: 'No Permissions-Policy', severity: 'info' },
    ];
    
    checks.forEach(check => {
      if (!headers[check.header]) {
        this.headerIssues.push({ url, ...check });
        if (check.severity !== 'info') {
          this.findings.push({ type: 'missing_header', severity: check.severity, url, header: check.header, detail: check.missing });
        }
      }
    });
    
    // CSP analysis (with strict-dynamic + nonce awareness)
    const csp = headers['content-security-policy'];
    if (csp) {
      const dangerous = ["'unsafe-inline'", "'unsafe-eval'", "data:", "blob:", "*"];
      const directives = csp.split(';').map(d => d.trim());

      // ── Detect defensive CSP features ──
      const hasStrictDynamic = csp.includes("'strict-dynamic'");
      const hasNonce = /'nonce-[A-Za-z0-9+/=]+'/i.test(csp);
      const hasHash = /'sha(256|384|512)-[A-Za-z0-9+/=]+'/i.test(csp);
      this.cspDefenseLevel = (hasStrictDynamic && (hasNonce || hasHash)) ? 'strong'
        : (hasNonce || hasHash) ? 'moderate' : hasStrictDynamic ? 'moderate' : 'weak';

      directives.forEach(d => {
        dangerous.forEach(dng => {
          if (d.includes(dng)) {
            let severity;
            if (dng === "'unsafe-inline'" && hasStrictDynamic) {
              // CSP3: strict-dynamic negates unsafe-inline
              severity = 'info';
            } else if (dng === "'unsafe-eval'") {
              severity = hasStrictDynamic ? 'low' : 'medium';
            } else if (dng === "'unsafe-inline'") {
              severity = 'medium';
            } else {
              severity = (this.cspDefenseLevel === 'strong') ? 'info' : 'low';
            }

            this.cspIssues.push({ url, directive: d, dangerous: dng, severity, cspDefenseLevel: this.cspDefenseLevel });
            this.findings.push({
              type: 'csp_weakness', severity, url, directive: d, dangerous: dng,
              cspDefenseLevel: this.cspDefenseLevel,
              note: hasStrictDynamic ? `strict-dynamic present — ${dng} may be negated in CSP3 browsers` : undefined
            });
            this.logger.log('SECURITY', 'WARN', `CSP weakness: ${dng} in "${d.substring(0, 80)}" [defense: ${this.cspDefenseLevel}]`);
          }
        });
      });

      this.logger.log('SECURITY', 'INFO', `CSP defense: ${this.cspDefenseLevel} (strict-dynamic: ${hasStrictDynamic}, nonce: ${hasNonce}, hash: ${hasHash})`);
    }
  }

  async _testPrototypePollution(page, baseUrl, browser) {
    // Test PP via URL hash and query params
    const ppPayloads = [
      { param: '__proto__[GENKI_PP]=1', type: 'hash' },
      { param: '__proto__.GENKI_PP=1', type: 'hash' },
      { param: 'constructor[prototype][GENKI_PP]=1', type: 'hash' },
    ];
    
    for (const payload of ppPayloads) {
      const testPage = await browser.newPage();
      if (this.config.cookies.length) {
        for (const c of this.config.cookies) await testPage.setCookie(c);
      }
      
      await testPage.evaluateOnNewDocument(this._buildHookScript());
      
      try {
        const testUrl = payload.type === 'hash' 
          ? `${baseUrl}#${payload.param}`
          : `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}${payload.param}`;
        
        await testPage.goto(testUrl, { waitUntil: 'networkidle2', timeout: 15000 });
        await this._sleep(2000);
        
        const polluted = await testPage.evaluate(() => {
          return ({}).GENKI_PP !== undefined ? String(({}).GENKI_PP) : null;
        });
        
        if (polluted) {
          this.logger.log('SECURITY', 'FIND', `[CRITICAL] Prototype Pollution CONFIRMED via ${payload.type}: ${payload.param} | Object.prototype.GENKI_PP = ${polluted}`);
          this.findings.push({ type: 'prototype_pollution_confirmed', severity: 'critical', url: baseUrl, payload: payload.param, result: polluted });
        }
      } catch (e) { /* timeout is OK */ }
      
      await testPage.close();
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // SERVER-SIDE PROTOTYPE POLLUTION ACTIVE TESTER
  // Gareth Heyes "status" technique + 3 more: json spaces, content-type, etag
  //
  // Flow per endpoint:
  //   1. INJECT  → POST body with __proto__:{status:510} appended
  //   2. TRIGGER → POST malformed body {,} to fire error handler
  //   3. VERIFY  → check response for 510 / "statusCode":510
  //   4. NULLIFY → POST body with __proto__:{status:0} to clean up
  //   5. RECHECK → POST {,} again — if 510 gone = CONFIRMED SSPP
  // ═══════════════════════════════════════════════════════════════════════
  async _testSSPP(jsonEndpoints, cookies) {
    if (!jsonEndpoints || jsonEndpoints.length === 0) return;

    // Build cookie header string from config cookies
    const cookieHeader = (cookies || []).map(c => `${c.name}=${c.value}`).join('; ');

    // SSPP techniques to try (in order of reliability)
    const TECHNIQUES = [
      {
        name:    'status_510',
        desc:    'Pollute __proto__.status → Express/Koa error handler reflects 510',
        inject:  (base) => base.replace(/}$/, ',"__proto__":{"status":510}}'),
        nullify: (base) => base.replace(/}$/, ',"__proto__":{"status":0}}'),
        trigger: '{,}',
        check:   (status, body) => status === 510 || body.includes('"statusCode":510') || body.includes('"status":510'),
        recheck: (status, body) => status === 510 || body.includes('"statusCode":510') || body.includes('"status":510'),
      },
      {
        name:    'json_spaces_express',
        desc:    'Pollute __proto__["json spaces"] → Express JSON.stringify indentation',
        inject:  (base) => base.replace(/}$/, ',"__proto__":{"json spaces":27}}'),
        nullify: (base) => base.replace(/}$/, ',"__proto__":{"json spaces":0}}'),
        trigger: '{}',
        check:   (_s, body) => /\n {27}/.test(body),
        recheck: (_s, body) => /\n {27}/.test(body),
      },
      {
        name:    'content_type_fastify',
        desc:    'Pollute __proto__["content-type"] → Fastify reflects in Content-Type header',
        inject:  (base) => base.replace(/}$/, ',"__proto__":{"content-type":"text/html;gnksspp;"}}'),
        nullify: (base) => base.replace(/}$/, ',"__proto__":{"content-type":"application/json"}}'),
        trigger: '{}',
        check:   (_s, body, headers) => (headers['content-type'] || '').includes('gnksspp'),
        recheck: (_s, body, headers) => (headers['content-type'] || '').includes('gnksspp'),
      },
      {
        name:    'etag_express',
        desc:    'Pollute __proto__.etag → Express disables ETag, 304 becomes 200',
        inject:  (base) => base.replace(/}$/, ',"__proto__":{"etag":false}}'),
        nullify: (base) => base.replace(/}$/, ',"__proto__":{"etag":true}}'),
        trigger: '{}',
        check:   null, // requires baseline comparison — skip auto-verify for now
        recheck: null,
      },
      {
        name:    'constructor_proto',
        desc:    'constructor.prototype path — alternative to __proto__',
        inject:  (base) => base.replace(/}$/, ',"constructor":{"prototype":{"status":510}}}'),
        nullify: (base) => base.replace(/}$/, ',"constructor":{"prototype":{"status":0}}}'),
        trigger: '{,}',
        check:   (status, body) => status === 510 || body.includes('"statusCode":510') || body.includes('"status":510'),
        recheck: (status, body) => status === 510 || body.includes('"statusCode":510') || body.includes('"status":510'),
      },
    ];

    // Native HTTP POST helper (no deps)
    const httpPost = (urlStr, body, extraHeaders = {}) => new Promise((resolve) => {
      try {
        const u = new URL(urlStr);
        const isHttps = u.protocol === 'https:';
        const lib = isHttps ? https : http;
        const data = Buffer.from(body, 'utf8');
        const reqHeaders = {
          'Content-Type':   'application/json',
          'Content-Length': data.length,
          'User-Agent':     this.config.userAgent || 'Mozilla/5.0 (GENKI-PROBER)',
          ...extraHeaders,
        };
        if (cookieHeader) reqHeaders['Cookie'] = cookieHeader;
        Object.assign(reqHeaders, this.config.extraHeaders || {});

        const req = lib.request({
          hostname: u.hostname,
          port:     u.port || (isHttps ? 443 : 80),
          path:     u.pathname + u.search,
          method:   'POST',
          headers:  reqHeaders,
          rejectUnauthorized: false,
        }, (res) => {
          let raw = '';
          res.on('data', d => raw += d);
          res.on('end', () => resolve({ status: res.statusCode, body: raw, headers: res.headers }));
        });
        req.on('error', (e) => resolve({ status: -1, body: '', headers: {}, error: e.message }));
        req.setTimeout(8000, () => { req.destroy(); resolve({ status: -1, body: '', headers: {}, error: 'timeout' }); });
        req.write(data);
        req.end();
      } catch(e) {
        resolve({ status: -1, body: '', headers: {}, error: e.message });
      }
    });

    // ── Infrastructure endpoint blacklist — skip telemetry, CDN, analytics ──
    const INFRA_ENDPOINT_PATTERNS = [
      /\/_data\/v\d+\//i,               // Telemetry proxy (Mixpanel, etc.)
      /\/cdn-cgi\//i,                    // Cloudflare infrastructure
      /\/metrics\b/i,                    // Metrics endpoints
      /\/health\b/i,                     // Health checks
      /\/ping\b/i,                       // Ping endpoints
      /\/tracking\b/i,                   // Tracking pixels
      /\/analytics\b/i,                  // Analytics
      /\/beacon\b/i,                     // Beacon endpoints
      /\/collect\b/i,                    // Data collection
      /\/rum\b/i,                        // Real User Monitoring
      /\/mp\/track/i,                    // Mixpanel track
      /\/mp\/flags/i,                    // Mixpanel flags
      /\.well-known\//i,                 // Well-known
      /\/api\/log_?metric/i,             // Logging endpoints
      /\/api\/log\b/i,                   // Log endpoints
      /appsflyer/i,                      // AppsFlyer SDK
      /sentry\.io/i,                     // Sentry error tracking
      /\/cdn-cgi\/challenge-platform/i,  // Cloudflare challenge
      /\/cdn-cgi\/rum/i,                 // Cloudflare RUM
    ];

    // Test each JSON endpoint
    for (const ep of jsonEndpoints.slice(0, 15)) { // cap at 15 endpoints
      const url  = ep.url || ep;
      const base = ep.body || '{}';

      // Only test endpoints that received JSON bodies (confirmed JSON API)
      if (!base.startsWith('{') && !base.startsWith('[')) continue;

      // ── FP Filter: Skip infrastructure/telemetry endpoints ──
      try {
        const urlPath = new URL(url).pathname;
        if (INFRA_ENDPOINT_PATTERNS.some(p => p.test(urlPath) || p.test(url))) {
          this.logger.log('SECURITY', 'DEBUG', `SSPP skip (infra): ${urlPath}`);
          continue;
        }
      } catch(_) {}

      this.logger.log('SECURITY', 'INFO', `SSPP testing: ${url.substring(0, 80)}`);

      for (const tech of TECHNIQUES) {
        if (!tech.check) continue; // skip etag (needs baseline comparison logic)

        try {
          // Step 1: INJECT
          const injectBody = tech.inject(base);
          const injectResp = await httpPost(url, injectBody);
          if (injectResp.status === -1) break; // endpoint unreachable, skip

          // Step 2: TRIGGER — send malformed/empty body to fire error handler
          const triggerResp = await httpPost(url, tech.trigger);

          // Step 3: VERIFY
          if (!tech.check(triggerResp.status, triggerResp.body, triggerResp.headers)) continue;

          // Step 3.5: CAUSALITY CHECK — verify the trigger response differs from a clean baseline
          const baselineResp = await httpPost(url, '{}');
          if (baselineResp.status === triggerResp.status &&
              baselineResp.body === triggerResp.body) {
            // Endpoint returns same response regardless — static responder, not vulnerable
            this.logger.log('SECURITY', 'DEBUG',
              `SSPP causality FAILED [${tech.name}]: ${url.substring(0,60)} — static responder (baseline == trigger)`);
            continue;
          }

          // Step 4: NULLIFY — clean up pollution
          await httpPost(url, tech.nullify(base));

          // Step 5: RECHECK — if pollution cleared, confirmed SSPP
          const recheckResp = await httpPost(url, tech.trigger);
          const stillPolluted = tech.recheck(recheckResp.status, recheckResp.body, recheckResp.headers);

          if (!stillPolluted) {
            // ✅ CONFIRMED — pollution injected, verified, then cleaned
            const finding = {
              type:       'sspp_confirmed',
              severity:   'high',
              confidence: 'firm',
              name:       `Server-Side Prototype Pollution (${tech.name})`,
              url,
              technique:  tech.name,
              desc:       tech.desc,
              proof: {
                inject:   { body: injectBody.substring(0, 200) },
                trigger:  { body: tech.trigger, status: triggerResp.status, bodySnip: triggerResp.body.substring(0, 200) },
                nullify:  { body: tech.nullify(base).substring(0, 200) },
                recheck:  { status: recheckResp.status, bodySnip: recheckResp.body.substring(0, 200) },
              },
              cwe:         'CWE-1321',
              remediation: 'Use Object.create(null) for merge targets. Filter __proto__, constructor, prototype keys in user input.',
            };
            this.findings.push(finding);
            this.logger.log('SECURITY', 'FIND', `[HIGH] 🔴 SSPP CONFIRMED [${tech.name}]: ${url.substring(0, 80)}`,
              `inject→${triggerResp.status} → nullify → recheck=${recheckResp.status} (cleared = confirmed)`);
          } else {
            // Possible but not confirmed (persistent pollution or false positive)
            this.logger.log('SECURITY', 'WARN',
              `⚠️  SSPP Possible [${tech.name}]: ${url.substring(0,80)} — verify manually`);
            this.findings.push({
              type: 'sspp_possible', severity: 'medium', confidence: 'tentative',
              name: `Possible SSPP (${tech.name})`, url, technique: tech.name, desc: tech.desc,
              cwe: 'CWE-1321',
            });
          }

        } catch(e) {
          this.logger.log('SECURITY', 'WARN', `SSPP test error [${tech.name}] ${url.substring(0,60)}: ${e.message}`);
        }
      }
    }
  }

  summary() {
    return {
      findings: this.findings.length,
      sinkHits: this.sinkHits.length,
      taintFlows: this.taintFlows.length,
      ppResults: this.ppResults.length,
      cspIssues: this.cspIssues.length,
      headerIssues: this.headerIssues.length,
      bySeverity: {
        critical: this.findings.filter(f => f.severity === 'critical').length,
        high: this.findings.filter(f => f.severity === 'high').length,
        medium: this.findings.filter(f => f.severity === 'medium').length,
        low: this.findings.filter(f => f.severity === 'low').length,
      }
    };
  }

  getFindings() { return this.findings; }
  getCspDefenseLevel() { return this.cspDefenseLevel; }
  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}
module.exports = SecurityScanner;
