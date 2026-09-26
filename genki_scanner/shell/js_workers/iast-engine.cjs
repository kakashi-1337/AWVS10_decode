#!/usr/bin/env node
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  GENKI-PROBER — iast-engine.cjs v3.0                                   ║
// ║  IAST Runtime Analysis Engine — Node.js Orchestrator                   ║
// ║  Browser-side: genki-taint (full engine) + missing hook extensions     ║
// ║  Node-side: catalog loading, finding collection, reporting             ║
// ║  GENKI-TECH LABS | ANBU BLACK OPS SECURITY                             ║
// ╚══════════════════════════════════════════════════════════════════════════╝

'use strict';

const fs   = require('fs');
const path = require('path');

// ─────────────────────────────────────────────────────────────────────────────
// MISSING HOOKS EXTENSION
// These supplement genki-taint.txt. Injected alongside it.
// ─────────────────────────────────────────────────────────────────────────────

const MISSING_HOOKS_SCRIPT = `
(function __genkiIastExtensions() {
  'use strict';

  // Guard: only run once
  if (window.__GENKI_IAST_EXT_LOADED__) return;
  window.__GENKI_IAST_EXT_LOADED__ = true;

  // Re-use helpers from genki-taint if available, else stub
  const _report = typeof maybeReportTaintedValue === 'function'
    ? maybeReportTaintedValue
    : (val, info) => { try { window.__GENKI_SCAN = window.__GENKI_SCAN||{sinks:[]}; window.__GENKI_SCAN.sinks.push({sink: info.sink||'?', value: String(val).slice(0,200), ts: Date.now()}); } catch(_){} };

  const _match = typeof matchesTaint === 'function'
    ? matchesTaint
    : (v) => null;

  const _getDomPath = typeof getDomPath === 'function'
    ? getDomPath
    : (el) => { try { return el && el.tagName ? el.tagName.toLowerCase() + (el.id ? '#'+el.id : '') : null; } catch(_){ return null; } };

  // ── 1. MutationObserver wrapper ──────────────────────────────────────────
  // Detects: dynamic <script> injection, dangerous attribute changes,
  //          src/href/action/srcdoc set on newly-added elements
  try {
    const _OrigMO = window.MutationObserver;
    window.MutationObserver = function __genkiMO(callback) {
      const wrappedCallback = function(mutations, observer) {
        for (const mutation of mutations) {
          // Track added nodes
          if (mutation.type === 'childList') {
            mutation.addedNodes.forEach(node => {
              if (node.nodeType !== 1) return; // element nodes only
              const tag = (node.tagName || '').toLowerCase();

              // Dynamic <script> injection — HIGH risk
              if (tag === 'script') {
                const src  = node.src  || '';
                const text = node.textContent || '';
                const m = src ? _match(src) : _match(text);
                if (m || src || text) {
                  _report(src || text, {
                    type: 'dom-dynamic-script-inject',
                    sink: 'MutationObserver.script',
                    sinkId: 'dom.mutationObserver.script',
                    ruleId: 'mutation_observer_script'
                  }, {
                    element: node,
                    tag: 'script',
                    src: src.slice(0, 200),
                    domPath: _getDomPath(node),
                    value: (src || text).slice(0, 200)
                  }, m);
                }
              }

              // <link rel="stylesheet"> with user-controlled href
              if (tag === 'link') {
                const href = node.href || node.getAttribute('href') || '';
                const m2 = _match(href);
                if (m2) {
                  _report(href, {
                    type: 'dom-dynamic-link-inject',
                    sink: 'MutationObserver.link',
                    sinkId: 'dom.mutationObserver.link',
                    ruleId: 'mutation_observer_script'
                  }, { element: node, tag: 'link', value: href.slice(0, 200) }, m2);
                }
              }

              // <meta http-equiv="refresh"> / <base href>
              if (tag === 'meta' || tag === 'base') {
                const content = node.getAttribute('content') || node.getAttribute('href') || '';
                if (/url=/i.test(content) || tag === 'base') {
                  const m3 = _match(content);
                  if (m3) {
                    _report(content, {
                      type: 'dom-meta-redirect',
                      sink: 'MutationObserver.meta',
                      sinkId: 'dom.mutationObserver.script',
                      ruleId: 'mutation_observer_script'
                    }, { element: node, tag, value: content.slice(0, 200) }, m3);
                  }
                }
              }
            });
          }

          // Track attribute changes on existing elements
          if (mutation.type === 'attributes') {
            const el  = mutation.target;
            const attr = (mutation.attributeName || '').toLowerCase();
            const val  = el.getAttribute && el.getAttribute(mutation.attributeName) || '';
            const dangerousAttrs = ['src','href','action','formaction','srcdoc','data','on'];
            const isDangerous = dangerousAttrs.some(d => attr === d || attr.startsWith('on'));
            if (isDangerous && val) {
              const m4 = _match(val);
              if (m4) {
                _report(val, {
                  type: 'dom-attr-mutation',
                  sink: 'MutationObserver.attr.' + attr,
                  sinkId: 'dom.mutation',
                  ruleId: 'dom_mutation_xss'
                }, {
                  element: el,
                  attribute: attr,
                  tag: (el.tagName||'').toLowerCase(),
                  value: val.slice(0, 200)
                }, m4);
              }
            }
          }
        }
        return callback.call(this, mutations, observer);
      };
      return new _OrigMO(wrappedCallback);
    };
    window.MutationObserver.prototype = _OrigMO.prototype;
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('MutationObserver');
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('MutationObserver: ' + e.message);
  }

  // ── 2. Shadow DOM — attachShadow() ───────────────────────────────────────
  // Hooks shadowRoot.innerHTML / shadowRoot.appendChild after attach
  try {
    const _origAttachShadow = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function __genkiShadow(init) {
      const shadowRoot = _origAttachShadow.call(this, init);

      // Hook innerHTML on the shadow root
      const _shadowInnerHTMLDesc = Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'innerHTML')
        || Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');

      if (_shadowInnerHTMLDesc && _shadowInnerHTMLDesc.set) {
        Object.defineProperty(shadowRoot, 'innerHTML', {
          configurable: true,
          get: function() { return _shadowInnerHTMLDesc.get.call(this); },
          set: function(val) {
            const m = _match(val);
            if (m) {
              _report(val, {
                type: 'xss-via-shadowRoot.innerHTML',
                sink: 'shadowRoot.innerHTML',
                sinkId: 'dom.shadowRoot.innerHTML',
                ruleId: 'shadow_dom_innerhtml_xss'
              }, {
                element: this.host,
                domPath: _getDomPath(this.host),
                value: String(val).slice(0, 300)
              }, m);
            }
            return _shadowInnerHTMLDesc.set.call(this, val);
          }
        });
      }
      return shadowRoot;
    };
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('attachShadow');
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('attachShadow: ' + e.message);
  }

  // ── 3. CSS Injection ──────────────────────────────────────────────────────
  // 3a. CSSStyleSheet.insertRule()
  try {
    const _origInsertRule = CSSStyleSheet.prototype.insertRule;
    CSSStyleSheet.prototype.insertRule = function __genkiInsertRule(rule, index) {
      const m = _match(rule);
      if (m) {
        _report(rule, {
          type: 'css-injection',
          sink: 'CSSStyleSheet.insertRule',
          sinkId: 'css.insertRule',
          ruleId: 'css_inject_rule'
        }, { value: String(rule).slice(0, 300) }, m);
      }
      return _origInsertRule.call(this, rule, index);
    };
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('CSSStyleSheet.insertRule');
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('CSSStyleSheet.insertRule: ' + e.message);
  }

  // 3b. element.style.cssText (setter)
  try {
    const _cssTextDesc = Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype, 'cssText');
    if (_cssTextDesc && _cssTextDesc.set) {
      Object.defineProperty(CSSStyleDeclaration.prototype, 'cssText', {
        configurable: true,
        enumerable:   _cssTextDesc.enumerable,
        get: function() { return _cssTextDesc.get.call(this); },
        set: function(val) {
          const m = _match(val);
          // Only report if contains expression(), behavior:, or tainted value
          if (m || /expression\\s*\\(|behavior\\s*:/i.test(val)) {
            _report(val, {
              type: 'css-injection',
              sink: 'element.style.cssText',
              sinkId: 'css.cssText',
              ruleId: 'css_inject_csstext'
            }, { value: String(val).slice(0, 300) }, m);
          }
          return _cssTextDesc.set.call(this, val);
        }
      });
      window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('cssText');
    }
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('cssText: ' + e.message);
  }

  // 3c. element.setAttribute('style', ...) — already caught by genki-taint setAttribute hook
  //     but add explicit CSS expression check
  try {
    const _origSetAttr = Element.prototype.setAttribute;
    const _patchedSetAttr = Element.prototype.setAttribute; // may already be patched
    Element.prototype.setAttribute = function __genkiSetAttrCss(name, value) {
      if ((name || '').toLowerCase() === 'style' && typeof value === 'string') {
        if (/expression\\s*\\(|behavior\\s*:|url\\s*\\(/i.test(value)) {
          const m = _match(value);
          _report(value, {
            type: 'css-injection',
            sink: 'element.setAttribute.style',
            sinkId: 'css.cssText',
            ruleId: 'css_inject_csstext'
          }, { element: this, attribute: 'style', tag: this.tagName, value: value.slice(0, 300) }, m);
        }
      }
      return _patchedSetAttr.call(this, name, value);
    };
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('setAttribute.style');
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('setAttribute.style: ' + e.message);
  }

  // ── 4. document.domain assignment ────────────────────────────────────────
  try {
    const _domainDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'domain')
      || Object.getOwnPropertyDescriptor(document, 'domain');
    if (_domainDesc && _domainDesc.set && _domainDesc.configurable) {
      Object.defineProperty(Document.prototype, 'domain', {
        configurable: true,
        enumerable:   _domainDesc.enumerable,
        get: _domainDesc.get ? function() { return _domainDesc.get.call(this); } : undefined,
        set: function(val) {
          // document.domain assignment relaxes same-origin — always interesting
          const m = _match(val);
          _report(val || '', {
            type: 'document-domain-relaxation',
            sink: 'document.domain',
            sinkId: 'nav.document.domain',
            ruleId: 'document_domain_relaxation'
          }, {
            newDomain: String(val),
            currentDomain: document.domain,
            value: String(val)
          }, m);
          if (_domainDesc.set) return _domainDesc.set.call(this, val);
        }
      });
      window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('document.domain');
    }
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('document.domain: ' + e.message);
  }

  // ── 5. Trusted Types — bypass detection ──────────────────────────────────
  // If trustedTypes API exists, wrap createPolicy to detect bypass attempts
  try {
    if (window.trustedTypes && typeof window.trustedTypes.createPolicy === 'function') {
      const _origCreatePolicy = window.trustedTypes.createPolicy.bind(window.trustedTypes);
      window.trustedTypes.createPolicy = function __genkiTTP(name, rules, options) {
        // Log the policy creation — especially "default" policy which overrides enforcement
        const isDefault = name === 'default';
        _report(name, {
          type: 'trusted-types-bypass',
          sink: 'trustedTypes.createPolicy',
          sinkId: 'trustedTypes.createPolicy',
          ruleId: 'trusted_types_bypass'
        }, {
          policyName: name,
          isDefaultPolicy: isDefault,
          hasCreateHTML: !!(rules && rules.createHTML),
          hasCreateScript: !!(rules && rules.createScript),
          value: name
        }, null);
        return _origCreatePolicy(name, rules, options);
      };
      window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('trustedTypes.createPolicy');
    }
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('trustedTypes: ' + e.message);
  }

  // ── 6. document.open() ───────────────────────────────────────────────────
  try {
    const _origDocOpen = document.open.bind(document);
    document.open = function __genkiDocOpen(url, name, features) {
      if (url) {
        const m = _match(url);
        _report(url, {
          type: 'document-open-sink',
          sink: 'document.open',
          sinkId: 'document.open',
          ruleId: 'document_open_xss'
        }, { value: String(url).slice(0, 300), name, features }, m);
      }
      return _origDocOpen.apply(document, arguments);
    };
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('document.open');
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('document.open: ' + e.message);
  }

  // ── 7. Attr.prototype.value ──────────────────────────────────────────────
  // Catches jQuery.attr() internal path + direct Attr node manipulation
  try {
    const _attrValueDesc = Object.getOwnPropertyDescriptor(Attr.prototype, 'value');
    if (_attrValueDesc && _attrValueDesc.set && _attrValueDesc.configurable) {
      Object.defineProperty(Attr.prototype, 'value', {
        configurable: true,
        enumerable:   _attrValueDesc.enumerable,
        get: function() { return _attrValueDesc.get.call(this); },
        set: function(val) {
          const m = _match(val);
          if (m) {
            const attrName = (this.name || '').toLowerCase();
            _report(val, {
              type: 'attr-value-xss',
              sink: 'Attr.value.' + attrName,
              sinkId: 'attr.value',
              ruleId: 'attr_value_xss'
            }, {
              attributeName: this.name,
              ownerElement: this.ownerElement ? this.ownerElement.tagName : 'unknown',
              value: String(val).slice(0, 300)
            }, m);
          }
          return _attrValueDesc.set.call(this, val);
        }
      });
      window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('Attr.value');
    }
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('Attr.value: ' + e.message);
  }

  // ── 8. Range.createContextualFragment ───────────────────────────────────
  // Direct XSS sink — creates live DOM from HTML string
  try {
    const _origCCF = Range.prototype.createContextualFragment;
    Range.prototype.createContextualFragment = function __genkiCCF(fragment) {
      const m = _match(fragment);
      if (m) {
        _report(fragment, {
          type: 'xss-via-createContextualFragment',
          sink: 'Range.createContextualFragment',
          sinkId: 'dom.innerHTML',  // same severity as innerHTML
          ruleId: 'dom_innerhtml_xss'
        }, { value: String(fragment).slice(0, 300) }, m);
      }
      return _origCCF.call(this, fragment);
    };
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('Range.createContextualFragment');
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('Range.createContextualFragment: ' + e.message);
  }

  // ── 9. Prototype Pollution traps (from dom-invader.txt) ─────────────────
  // Sets getter/setter traps on Object.prototype for known PP identifiers
  try {
    const PP_TECHNIQUES = [
      { identifiers: ['__pp_a42e5579', '__pp_dcb52823'], source: '__proto__' },
      { identifiers: ['__pp_ijnjH',   '__pp_bxlDr'   ], source: 'constructor.prototype' },
    ];
    // Canary-style: put known-harmless property traps
    const PP_TRAP_KEYS = [
      '__proto_trap__', 'constructor_trap__', 'gadget', 'merge', 'extend',
      'assign', 'defaults', 'mixin', 'cloneDeep', 'clone',
    ];
    PP_TRAP_KEYS.forEach(key => {
      try {
        Object.defineProperty(Object.prototype, '__genki_pp_' + key, {
          configurable: true,
          enumerable:   false,
          get: function() { return this['___val_' + key]; },
          set: function(val) {
            // If this is Object.prototype itself being set, it's PP
            if (this === Object.prototype) {
              _report(String(val).slice(0, 200), {
                type: 'prototype-pollution',
                sink: 'Object.prototype.' + key,
                sinkId: 'pp.__proto__',
                ruleId: 'proto_pollution_detected'
              }, { pollutedKey: key, value: String(val).slice(0, 200) }, null);
              (window.__GENKI_SCAN = window.__GENKI_SCAN||{ppHits:[]});
              if (!Array.isArray(window.__GENKI_SCAN.ppHits)) window.__GENKI_SCAN.ppHits = [];
              window.__GENKI_SCAN.ppHits.push({key: key, value: String(val).slice(0,200), source: 'prototype-pollution', sink: 'Object.prototype.' + key, stack: new Error().stack ? new Error().stack.split('\\n').slice(1,4).join(' | ') : '', ts: Date.now()});
            }
            this['___val_' + key] = val;
          }
        });
      } catch(_) {}
    });
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('PP_traps');
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('PP_traps: ' + e.message);
  }

  // ── 10. DOMParser.parseFromString ────────────────────────────────────────
  // Indirect sink: parsed HTML can be inserted into live DOM
  try {
    const _origDOMParser = DOMParser.prototype.parseFromString;
    DOMParser.prototype.parseFromString = function __genkiDOMParser(str, type) {
      if ((type||'').includes('html')) {
        const m = _match(str);
        if (m) {
          _report(str, {
            type: 'xss-via-DOMParser',
            sink: 'DOMParser.parseFromString',
            sinkId: 'dom.innerHTML',
            ruleId: 'dom_innerhtml_xss'
          }, { value: String(str).slice(0, 300), mimeType: type }, m);
        }
      }
      return _origDOMParser.call(this, str, type);
    };
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('DOMParser.parseFromString');
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('DOMParser: ' + e.message);
  }

  // ── 11. document.implementation.createHTMLDocument ───────────────────────
  try {
    const _origCreateHTML = document.implementation.createHTMLDocument.bind(document.implementation);
    document.implementation.createHTMLDocument = function __genkiCreateHTMLDoc(title) {
      const m = _match(title);
      if (m) {
        _report(title, {
          type: 'xss-via-createHTMLDocument',
          sink: 'document.implementation.createHTMLDocument',
          sinkId: 'dom.innerHTML',
          ruleId: 'dom_innerhtml_xss'
        }, { value: String(title||'').slice(0, 300) }, m);
      }
      return _origCreateHTML.apply(document.implementation, arguments);
    };
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('createHTMLDocument');
  } catch(e) {
    window.__GENKI_HOOKS && window.__GENKI_HOOKS.errors.push('createHTMLDocument: ' + e.message);
  }

  // ── 12. jQuery hooks (if present at injection time or after load) ─────────
  function hookJQuery(jq) {
    if (!jq || !jq.fn || jq.__genki_hooked__) return;
    jq.__genki_hooked__ = true;

    // jQuery.html()
    const _origHtml = jq.fn.html;
    if (_origHtml) {
      jq.fn.html = function(val) {
        if (val !== undefined && typeof val === 'string') {
          const m = _match(val);
          if (m) {
            _report(val, {
              type: 'xss-via-jQuery.html',
              sink: 'jQuery.html',
              sinkId: 'dom.innerHTML',
              ruleId: 'dom_innerhtml_xss'
            }, { value: val.slice(0, 300) }, m);
          }
        }
        return _origHtml.apply(this, arguments);
      };
    }

    // jQuery.append/prepend/before/after
    ['append','prepend','before','after','insertAfter','insertBefore','replaceWith','wrap','wrapAll'].forEach(fn => {
      const _orig = jq.fn[fn];
      if (!_orig) return;
      jq.fn[fn] = function(content) {
        if (typeof content === 'string') {
          const m = _match(content);
          if (m) {
            _report(content, {
              type: 'xss-via-jQuery.' + fn,
              sink: 'jQuery.' + fn,
              sinkId: 'dom.mutation',
              ruleId: 'dom_mutation_xss'
            }, { value: content.slice(0, 300) }, m);
          }
        }
        return _orig.apply(this, arguments);
      };
    });

    // jQuery.attr()
    const _origAttr = jq.fn.attr;
    if (_origAttr) {
      jq.fn.attr = function(name, val) {
        if (val !== undefined && typeof val === 'string') {
          const m = _match(val);
          if (m) {
            _report(val, {
              type: 'xss-via-jQuery.attr',
              sink: 'jQuery.attr.' + name,
              sinkId: 'attr.value',
              ruleId: 'attr_value_xss'
            }, { attribute: name, value: val.slice(0, 300) }, m);
          }
        }
        return _origAttr.apply(this, arguments);
      };
    }

    // jQuery.prop()
    const _origProp = jq.fn.prop;
    if (_origProp) {
      jq.fn.prop = function(name, val) {
        if (val !== undefined && typeof val === 'string') {
          const dangerousProps = ['innerHTML','outerHTML','href','src','action','srcdoc'];
          if (dangerousProps.includes(name)) {
            const m = _match(val);
            if (m) {
              _report(val, {
                type: 'xss-via-jQuery.prop.' + name,
                sink: 'jQuery.prop.' + name,
                sinkId: name.includes('HTML') ? 'dom.innerHTML' : 'attr.value',
                ruleId: name.includes('HTML') ? 'dom_innerhtml_xss' : 'attr_value_xss'
              }, { property: name, value: val.slice(0, 300) }, m);
            }
          }
        }
        return _origProp.apply(this, arguments);
      };
    }

    window.__GENKI_HOOKS && window.__GENKI_HOOKS.active.push('jQuery');
  }

  // Try to hook jQuery immediately, and again on DOMContentLoaded
  try { if (window.jQuery) hookJQuery(window.jQuery); } catch(_) {}
  try { if (window.$) hookJQuery(window.$); } catch(_) {}
  document.addEventListener('DOMContentLoaded', () => {
    try { if (window.jQuery) hookJQuery(window.jQuery); } catch(_) {}
    try { if (window.$) hookJQuery(window.$); } catch(_) {}
  });

  // ── 13. Auto-fire events (from dom-invader.txt) ───────────────────────────
  // Fires mouse/keyboard events on elements with inline handlers
  // Helps trigger hidden XSS that only fires on interaction
  function autoFireEvents() {
    if (window.__GENKI_EVENTS_FIRED__) return;
    window.__GENKI_EVENTS_FIRED__ = true;

    // hashchange — triggers hash-based routing
    try { window.dispatchEvent(new HashChangeEvent('hashchange')); } catch(_) {}

    const allEls = document.querySelectorAll('*');
    let fired = 0;
    allEls.forEach(el => {
      if (!el || el.__genki_fired__) return;
      try {
        const handlers = ['onclick','onmouseover','onmousedown','onmouseup','onkeydown','onkeypress','onkeyup','onfocus'];
        let didFire = false;
        handlers.forEach(h => {
          if (el[h]) {
            try {
              if (h.startsWith('onclick') || h.startsWith('onmouse')) {
                el.dispatchEvent(new MouseEvent(h.slice(2), { bubbles:true, cancelable:true }));
              } else if (h.startsWith('onkey')) {
                const evt = new Event(h.slice(2)); evt.keyCode = evt.which = 13;
                el.dispatchEvent(evt);
              } else {
                el.dispatchEvent(new Event(h.slice(2), { bubbles:true }));
              }
              didFire = true;
            } catch(_) {}
          }
        });
        if (didFire) { el.__genki_fired__ = true; fired++; }
      } catch(_) {}
    });

    // Reset forms to avoid side effects
    try { Array.from(document.forms).forEach(f => { try { f.reset(); } catch(_) {} }); } catch(_) {}
    if (window.__GENKI_HOOKS) window.__GENKI_HOOKS.active.push('autoFireEvents:' + fired);
  }

  // Fire after page load + extra delay for SPAs
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(autoFireEvents, 1500));
  } else {
    setTimeout(autoFireEvents, 1500);
  }
  window.addEventListener('load', () => setTimeout(autoFireEvents, 2000));

  // ── 14. Input surface logger ──────────────────────────────────────────────
  // Logs ALL forms, inputs, selects, textareas — passive discovery
  // Runs after DOMContentLoaded to get the full surface
  function logInputSurface() {
    const surface = window.__GENKI_INPUT_SURFACE__ = window.__GENKI_INPUT_SURFACE__ || {
      forms: [], inputs: [], apiEndpoints: [], ts: Date.now()
    };

    // Forms
    Array.from(document.forms).forEach((form, i) => {
      const fields = Array.from(form.elements).map(el => ({
        name:  el.name  || el.id   || el.getAttribute('name') || null,
        type:  el.type  || el.tagName.toLowerCase(),
        id:    el.id    || null,
        value: el.value ? '[has-value]' : null,
      })).filter(f => f.name || f.id);

      surface.forms.push({
        index:  i,
        action: form.action  || null,
        method: (form.method || 'GET').toUpperCase(),
        id:     form.id      || null,
        fields,
        xpath:  typeof __genkiXPath === 'function' ? __genkiXPath(form) : null,
      });
    });

    // Standalone inputs not inside forms
    document.querySelectorAll('input:not(form *), textarea:not(form *), select:not(form *), [contenteditable]').forEach(el => {
      surface.inputs.push({
        tag:   el.tagName.toLowerCase(),
        name:  el.name  || el.id   || null,
        type:  el.type  || null,
        id:    el.id    || null,
        placeholder: el.placeholder || null,
        xpath: typeof __genkiXPath === 'function' ? __genkiXPath(el) : null,
      });
    });

    // URL params as discovered sources
    const params = [];
    new URLSearchParams(location.search).forEach((v, k) => params.push(k));
    if (location.hash) params.push('hash:' + location.hash.slice(1, 30));
    if (params.length) {
      surface.apiEndpoints.push({
        url:    location.href.slice(0, 200),
        params,
        method: 'GET',
        source: 'url',
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', logInputSurface);
  } else {
    setTimeout(logInputSurface, 500);
  }

  // SPA re-scan on navigation
  try {
    const _origHistPush = history.pushState;
    history.pushState = function() {
      const r = _origHistPush.apply(this, arguments);
      setTimeout(logInputSurface, 800);
      return r;
    };
    window.addEventListener('popstate', () => setTimeout(logInputSurface, 500));
  } catch(_) {}

})(); // end __genkiIastExtensions
`;

// ─────────────────────────────────────────────────────────────────────────────
// Node.js Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

class IastEngine {
  constructor(logger, config) {
    this.logger  = logger;
    this.config  = config;
    this.outDir  = path.join(config.outputDir, 'iast');
    this.catalog = null;

    // Accumulated findings from all pages
    this._findings = [];
    this._inputSurface = { forms: [], inputs: [], apiEndpoints: [] };
    this._hookStatus  = {};
    this._pagesInstrumented = 0;
    this._summary = {
      pagesInstrumented: 0, findingsTotal: 0,
      byCategory: {}, bySeverity: { critical:0, high:0, medium:0, low:0, info:0 },
      inputForms: 0, inputFields: 0, apiEndpoints: 0,
    };

    this._loadCatalog();
  }

  _loadCatalog() {
    const catalogPath = path.join(__dirname, 'iast-catalog.json');
    try {
      this.catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
      this.logger.log('IAST-ENGINE', 'OK', `Catalog loaded: ${this.catalog.modules.length} modules`);
    } catch(e) {
      this.logger.log('IAST-ENGINE', 'WARN', `Catalog not found at ${catalogPath} — findings will be unclassified`);
      this.catalog = { modules: [] };
    }
  }

  // ── setup(page) ───────────────────────────────────────────────────────────
  // Call this on every new page (or use browser.on('targetcreated'))
  // Installs genki-taint + missing hook extensions via evaluateOnNewDocument
  async setup(page) {
    try {
      // 1. Inject IAST modules catalog into page context (used by genki-taint reportFinding)
      const catalogJson = JSON.stringify(this.catalog);
      await page.evaluateOnNewDocument((catJson) => {
        // Pre-populate modules so genki-taint's IAST_MODULES loads immediately
        window.__GENKI_IAST_PRELOADED_MODULES__ = JSON.parse(catJson);
        // genki-taint checks for ptk_background_iast2content_modules message
        // We also respond to the requestModulesFromBackground postMessage
        window.addEventListener('message', (evt) => {
          if (evt.data && evt.data.channel === 'ptk_content_iast_request_modules') {
            window.postMessage({
              channel: 'ptk_background_iast2content_modules',
              iastModules: window.__GENKI_IAST_PRELOADED_MODULES__
            }, '*');
          }
        });
        // Deliver immediately too
        setTimeout(() => {
          window.postMessage({
            channel: 'ptk_background_iast2content_modules',
            iastModules: window.__GENKI_IAST_PRELOADED_MODULES__
          }, '*');
        }, 0);
      }, catalogJson);

      // 2. Install missing hook extensions
      await page.evaluateOnNewDocument(MISSING_HOOKS_SCRIPT);

      this._pagesInstrumented++;
      this.logger.log('IAST-ENGINE', 'OK', 'Hooks installed on page (evaluateOnNewDocument)');
    } catch(e) {
      this.logger.log('IAST-ENGINE', 'WARN', `setup() error: ${e.message}`);
    }
  }

  // ── collectFromPage(page, url) ────────────────────────────────────────────
  // Pull findings + input surface from a live page context
  async collectFromPage(page, url) {
    try {
      const data = await page.evaluate(() => {
        // Collect genki-taint findings from localStorage buffer
        let findings = [];
        try {
          const buf = JSON.parse(localStorage.getItem('ptk_iast_buffer') || '[]');
          findings = buf.filter(m => m && m.ptk_iast === 'finding_report').map(m => m.finding);
          localStorage.removeItem('ptk_iast_buffer');
        } catch(_) {}

        // Also collect from __GENKI_SCAN (legacy hooks in genki-prober IAST core)
        const scan = window.__GENKI_SCAN || {};

        return {
          findings,
          scanSinks:    (scan.sinks         || []).filter(s => s && s.hasTaint),
          evalCalls:    (scan.evalCalls      || []),
          fetchCalls:   (scan.fetchCalls     || []),
          xhrCalls:     (scan.xhrCalls       || []),
          postMessages: (scan.postMessages   || []),
          ppHits:        Array.isArray(scan.ppHits) ? scan.ppHits : [],
          hookStatus:   window.__GENKI_HOOKS || {},
          inputSurface: window.__GENKI_INPUT_SURFACE__ || { forms:[], inputs:[], apiEndpoints:[] },
          taintGraph:   window.__IAST_TAINT_GRAPH__    || {},
          taintSources: window.__IAST_TAINTED__         || {},
          endpoints:   window.__GENKI_ENDPOINTS__    || [],
          websockets:  window.__GENKI_WEBSOCKETS__   || [],
          ppTraps:     window.__GENKI_PP_TRAPS_INSTALLED__ || [],
          ppResults:   window.__GENKI_PP_RESULTS__   || null,
          ppRuntime:   window.__GENKI_PP_RUNTIME__   || [],   // JSON.parse + Object.assign hooks
          ssrVars:     window.__GENKI_SSR_VARS__     || {},   // SSR props inspector results
        };
      });

      // Process structured genki-taint findings
      if (data.findings && data.findings.length) {
        data.findings.forEach(f => {
          this._addFinding({
            url,
            type:       f.type     || 'iast',
            severity:   f.severity || 'medium',
            category:   f.category || f.meta?.category || 'unknown',
            sink:       f.sink     || f.sinkId || '?',
            sinkId:     f.sinkId   || null,
            ruleId:     f.ruleId   || null,
            ruleName:   f.ruleName || null,
            source:     f.source   || null,
            matched:    f.matched  || null,
            flow:       f.context?.flow || [],
            context:    f.context  || {},
            meta:       f.meta     || {},
            ts:         f.timestamp || Date.now(),
          });
        });
      }

      // Process legacy __GENKI_SCAN sinks
      data.scanSinks.forEach(s => {
        this._addFinding({
          url, type: 'iast-scan', severity: 'high', category: 'dom-xss',
          sink: s.sink, source: s.source || 'unknown', matched: s.value,
          context: { element: s.element, stack: s.stack }, ts: s.ts || Date.now(),
        });
      });

      // Merge input surface
      if (data.inputSurface) {
        this._inputSurface.forms.push(...(data.inputSurface.forms || []));
        this._inputSurface.inputs.push(...(data.inputSurface.inputs || []));
        this._inputSurface.apiEndpoints.push(...(data.inputSurface.apiEndpoints || []));
        this._summary.inputForms    += (data.inputSurface.forms?.length || 0);
        this._summary.inputFields   += (data.inputSurface.inputs?.length || 0);
        this._summary.apiEndpoints  += (data.inputSurface.apiEndpoints?.length || 0);
      }

      // Log hook status
      if (data.hookStatus?.active?.length) {
        this._hookStatus[url] = data.hookStatus.active;
      }

      // Merge discovered endpoints (from __GENKI_ENDPOINTS__)
      if (data.endpoints?.length) {
        for (const ep of data.endpoints) {
          const epEntry = { url: ep.url, method: ep.method, body: ep.body,
            type: ep.type, status: ep.status, contentType: ep.contentType, discoveredAt: url };
          this._inputSurface.apiEndpoints.push(epEntry);
        }
        this._summary.apiEndpoints += data.endpoints.length;
        this.logger.log('IAST-ENGINE', 'INFO',
          `  Endpoints captured: ${data.endpoints.length} (fetch/XHR) | WebSockets: ${data.websockets?.length || 0}`);
      }

      // WebSocket tracking
      if (data.websockets?.length) {
        if (!this._inputSurface.websockets) this._inputSurface.websockets = [];
        this._inputSurface.websockets.push(...data.websockets);
      }

      // PP trap status
      if (data.ppTraps?.length && !this._ppTrapsLogged) {
        this._ppTrapsLogged = true;
        this.logger.log('IAST-ENGINE', 'OK',
          `  PP traps installed: ${data.ppTraps.length} gadget keys monitored on Object.prototype`);
      }

      // PP pollution hits — include runtime hook events
      if (data.ppHits && data.ppHits.length > 0) {
        this.logger.log('IAST-ENGINE', 'WARN',
          `  🔴 PP HITS: ${data.ppHits.length} pollution events detected!`);
        data.ppHits.forEach(hit => {
          this.logger.log('IAST-ENGINE', 'WARN',
            `    └─ key=${hit.key} sink=${hit.sink} value=${(hit.value||'').slice(0,80)} source=${hit.source}`);
        });
      }

      // Process PP runtime events (JSON.parse / Object.assign hooks)
      if (data.ppRuntime && data.ppRuntime.length) {
        this.logger.log('IAST-ENGINE', 'WARN',
          `  🔴 PP RUNTIME: ${data.ppRuntime.length} events — JSON.parse/Object.assign/postMessage/SSR`);
        data.ppRuntime.forEach(ev => {
          this._findings.push({
            type:     'pp_runtime',
            severity: ev.kind.includes('sensitive') ? 'high' : 'critical',
            category: 'prototype-pollution',
            source:   ev.kind,
            detail:   ev.detail,
            stack:    ev.stack,
            url:      url,
            ts:       ev.ts,
            cwe:      'CWE-1321',
            desc:     `Runtime PP event: ${ev.kind}`,
          });
        });
      }

      // SSR vars — log sensitive exposures
      if (data.ssrVars && Object.keys(data.ssrVars).length) {
        const fworks = Object.keys(data.ssrVars);
        this.logger.log('IAST-ENGINE', 'INFO', `  SSR vars detected: ${fworks.join(', ')}`);
      }

      // Log taint sources discovered
      const srcCount = Object.keys(data.taintSources || {}).length;
      if (srcCount) {
        this.logger.log('IAST-ENGINE', 'INFO',
          `  Taint sources: ${srcCount} | Forms: ${data.inputSurface?.forms?.length || 0} | ` +
          `Inputs: ${data.inputSurface?.inputs?.length || 0} | PP hits: ${(data.ppHits||[]).length}`);
      }

      // ── Save runtime snapshot to disk ──────────────────────────────────
      // All taint sources, globals, hooks, taint graph — full runtime state
      if (srcCount > 0 || Object.keys(data.taintGraph || {}).length > 0) {
        const snapshotDir = path.join(this.outDir, 'snapshots');
        if (!fs.existsSync(snapshotDir)) fs.mkdirSync(snapshotDir, { recursive: true });
        const slug = url.replace(/[^a-z0-9]/gi, '_').slice(0, 60);
        const snapshot = {
          url,
          taintSources:  data.taintSources,
          taintGraph:    data.taintGraph,
          hookStatus:    data.hookStatus,
          evalCalls:     data.evalCalls,
          fetchCalls:    data.fetchCalls,
          xhrCalls:      data.xhrCalls,
          postMessages:  data.postMessages,
          ppHits:        data.ppHits,
          ts:            Date.now(),
        };
        fs.writeFileSync(
          path.join(snapshotDir, `snap-${slug}-${Date.now()}.json`),
          JSON.stringify(snapshot, null, 2)
        );
      }

      // ── Collect runtime globals + configs + secrets ─────────────────────
      const runtimeData = await page.evaluate(() => {
        return {
          globals:    window.__GENKI_GLOBALS__      || {},
          injPoints:  window.__GENKI_INJECTION_POINTS__ || {},
          genki_scan: window.__GENKI_SCAN           || {},
          // SSR framework data
          nextData:   window.__NEXT_DATA__           || null,
          nuxtData:   window.__NUXT__                || null,
          reduxState: window.__REDUX_STATE__ || window.__PRELOADED_STATE__ || null,
          apolloState:window.__APOLLO_STATE__        || null,
          ppResults:  window.__GENKI_PP_RESULTS__    || null,
        };
      }).catch(() => ({}));

      if (runtimeData && (Object.keys(runtimeData.globals || {}).length > 0 || runtimeData.nextData)) {
        const runtimeDir = path.join(this.outDir, 'runtime');
        if (!fs.existsSync(runtimeDir)) fs.mkdirSync(runtimeDir, { recursive: true });
        const slug = url.replace(/[^a-z0-9]/gi, '_').slice(0, 60);
        fs.writeFileSync(
          path.join(runtimeDir, `runtime-${slug}-${Date.now()}.json`),
          JSON.stringify(runtimeData, null, 2)
        );
        // Log any interesting SSR / config data found
        if (runtimeData.nextData) {
          const q = Object.keys(runtimeData.nextData.query || {});
          const pp = Object.keys(runtimeData.nextData.props?.pageProps || {});
          this.logger.log('IAST-ENGINE', 'INFO',
            `  Next.js: query=[${q.slice(0,5).join(',')}] pageProps=[${pp.slice(0,5).join(',')}]`);
        }
        if (runtimeData.ppResults?.gadgetsFound?.length) {
          this.logger.log('IAST-ENGINE', 'WARN',
            `  PP gadgets from runtime: ${runtimeData.ppResults.gadgetsFound.length} found`);
        }
      }

    } catch(e) {
      this.logger.log('IAST-ENGINE', 'WARN', `collectFromPage(${url}) error: ${e.message}`);
    }
  }

  _addFinding(f) {
    // Dedup by sink+source+url
    const key = `${f.url}|${f.sink}|${f.source}|${f.matched?.slice?.(0,30)}`;
    if (this._findings.some(x => `${x.url}|${x.sink}|${x.source}|${x.matched?.slice?.(0,30)}` === key)) return;

    this._findings.push(f);
    this._summary.findingsTotal++;

    const sev = (f.severity || 'info').toLowerCase();
    this._summary.bySeverity[sev] = (this._summary.bySeverity[sev] || 0) + 1;
    const cat = f.category || 'unknown';
    this._summary.byCategory[cat] = (this._summary.byCategory[cat] || 0) + 1;

    const icon = { critical:'🔴', high:'🟠', medium:'🟡', low:'🔵', info:'⚪' }[sev] || '⚫';
    this.logger.log('IAST-ENGINE', 'FIND',
      `${icon} [${sev.toUpperCase()}] ${f.type} — ${f.sink} — source: ${String(f.source||'?').slice(0,40)} @ ${(f.url||'').slice(0,60)}`);
  }

  // ── writeReport() ─────────────────────────────────────────────────────────
  writeReport() {
    if (!fs.existsSync(this.outDir)) fs.mkdirSync(this.outDir, { recursive: true });

    this._summary.pagesInstrumented = this._pagesInstrumented;

    // Main findings report
    const report = {
      summary:     this._summary,
      findings:    this._findings,
      inputSurface:this._inputSurface,
      hookStatus:  this._hookStatus,
      ts:          new Date().toISOString(),
    };
    fs.writeFileSync(
      path.join(this.outDir, 'iast-report.json'),
      JSON.stringify(report, null, 2)
    );

    // Separate high/critical for quick triage
    const highCrit = this._findings.filter(f => ['critical','high'].includes((f.severity||'').toLowerCase()));
    if (highCrit.length) {
      fs.writeFileSync(
        path.join(this.outDir, 'iast-high-critical.json'),
        JSON.stringify(highCrit, null, 2)
      );
    }

    // Input surface (forms + endpoints)
    fs.writeFileSync(
      path.join(this.outDir, 'input-surface.json'),
      JSON.stringify(this._inputSurface, null, 2)
    );

    // Human-readable summary
    let txt = `IAST FINDINGS SUMMARY\n${'='.repeat(60)}\n`;
    txt += `Total: ${this._summary.findingsTotal}\n`;
    txt += `CRITICAL: ${this._summary.bySeverity.critical}  HIGH: ${this._summary.bySeverity.high}  `;
    txt += `MEDIUM: ${this._summary.bySeverity.medium}  LOW: ${this._summary.bySeverity.low}\n\n`;
    txt += `BY CATEGORY:\n`;
    Object.entries(this._summary.byCategory).sort((a,b)=>b[1]-a[1]).forEach(([cat,n]) => {
      txt += `  ${cat}: ${n}\n`;
    });
    txt += `\nINPUT SURFACE:\n`;
    txt += `  Forms: ${this._summary.inputForms}  Fields: ${this._summary.inputFields}  API endpoints: ${this._summary.apiEndpoints}\n\n`;
    if (this._findings.length) {
      txt += `TOP FINDINGS:\n`;
      highCrit.slice(0, 20).forEach(f => {
        txt += `  [${(f.severity||'?').toUpperCase()}] ${f.type}\n`;
        txt += `    Sink:    ${f.sink}\n`;
        txt += `    Source:  ${f.source}\n`;
        txt += `    URL:     ${(f.url||'').slice(0,80)}\n\n`;
      });
    }
    fs.writeFileSync(path.join(this.outDir, 'iast-summary.txt'), txt);

    this.logger.log('IAST-ENGINE', 'OK',
      `Report written → iast/ (${this._summary.findingsTotal} findings, ` +
      `C:${this._summary.bySeverity.critical} H:${this._summary.bySeverity.high})`
    );
  }

  // ── Public getters ────────────────────────────────────────────────────────
  getFindings()     { return this._findings; }
  getInputSurface() { return this._inputSurface; }
  getSummary()      { return this._summary; }
  summary()         { return this._summary; }   // alias for orchestrator
  getApiEndpoints() { return this._inputSurface.apiEndpoints; }
  getAllForms()      { return this._inputSurface.forms; }
  // run() is not needed (orchestrator calls setup/collectFromPage/writeReport directly)
  // but add stub so class check passes
  async run() { return; }
}

module.exports = IastEngine;
