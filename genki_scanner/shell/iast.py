"""
IAST Engine for Genki Shell
Browser-based taint tracking + DOM sink monitoring via Playwright CDP.
Injects canaries, hooks sinks, detects source-to-sink data flow.
Integrates: taint-planter, DOM invader, mutation fuzzer.
"""
import asyncio
import json
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


# ---------------------------------------------------------------------------
# Taint Monitor JS -- hooks dangerous DOM sinks and watches for canary flow
# ---------------------------------------------------------------------------

_TAINT_MONITOR_JS = """\
(function() {
    'use strict';
    if (window.__GENKI_TAINT) return;

    window.__GENKI_TAINT = {
        reflections: [],
        canaryPrefix: 'GNKTNT',
        active: true
    };

    var T = window.__GENKI_TAINT;

    function hasCanary(val) {
        if (typeof val !== 'string') return false;
        return val.indexOf(T.canaryPrefix) !== -1;
    }

    function extractCanaries(val) {
        var re = new RegExp(T.canaryPrefix + '\\\\d+', 'g');
        return (val.match(re) || []);
    }

    function logReflection(sink, value, context) {
        if (!T.active) return;
        var canaries = extractCanaries(String(value));
        if (canaries.length === 0) return;
        T.reflections.push({
            sink: sink,
            value: String(value).substring(0, 2048),
            canaries: canaries,
            context: context || '',
            url: location.href,
            timestamp: Date.now()
        });
    }

    /* --- innerHTML / outerHTML --- */
    var origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (origInnerHTML && origInnerHTML.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(v) {
                if (hasCanary(v)) logReflection('innerHTML', v, this.tagName);
                return origInnerHTML.set.call(this, v);
            },
            get: origInnerHTML.get,
            configurable: true
        });
    }

    var origOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (origOuterHTML && origOuterHTML.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(v) {
                if (hasCanary(v)) logReflection('outerHTML', v, this.tagName);
                return origOuterHTML.set.call(this, v);
            },
            get: origOuterHTML.get,
            configurable: true
        });
    }

    /* --- document.write / writeln --- */
    var origWrite = document.write.bind(document);
    var origWriteln = document.writeln.bind(document);
    document.write = function() {
        var args = Array.prototype.slice.call(arguments);
        args.forEach(function(a) {
            if (hasCanary(a)) logReflection('document.write', a, 'document');
        });
        return origWrite.apply(document, args);
    };
    document.writeln = function() {
        var args = Array.prototype.slice.call(arguments);
        args.forEach(function(a) {
            if (hasCanary(a)) logReflection('document.writeln', a, 'document');
        });
        return origWriteln.apply(document, args);
    };

    /* --- eval --- */
    var origEval = window.eval;
    window.eval = function(code) {
        if (hasCanary(code)) logReflection('eval', code, 'js');
        return origEval.call(window, code);
    };

    /* --- Function constructor --- */
    var OrigFunction = Function;
    try {
        window.Function = function() {
            var args = Array.prototype.slice.call(arguments);
            var body = args.length > 0 ? args[args.length - 1] : '';
            if (hasCanary(body)) logReflection('Function', body, 'js');
            return OrigFunction.apply(this, args);
        };
        window.Function.prototype = OrigFunction.prototype;
    } catch(e) {}

    /* --- setTimeout / setInterval with string args --- */
    var origSetTimeout = window.setTimeout;
    var origSetInterval = window.setInterval;
    window.setTimeout = function(fn) {
        if (typeof fn === 'string' && hasCanary(fn))
            logReflection('setTimeout', fn, 'js');
        return origSetTimeout.apply(window, arguments);
    };
    window.setInterval = function(fn) {
        if (typeof fn === 'string' && hasCanary(fn))
            logReflection('setInterval', fn, 'js');
        return origSetInterval.apply(window, arguments);
    };

    /* --- location.href / assign / replace --- */
    try {
        var origAssign = location.assign.bind(location);
        var origReplace = location.replace.bind(location);
        location.assign = function(url) {
            if (hasCanary(url)) logReflection('location.assign', url, 'url');
            return origAssign(url);
        };
        location.replace = function(url) {
            if (hasCanary(url)) logReflection('location.replace', url, 'url');
            return origReplace(url);
        };
    } catch(e) {}

    /* --- window.open --- */
    var origOpen = window.open;
    window.open = function(url) {
        if (url && hasCanary(url)) logReflection('window.open', url, 'url');
        return origOpen.apply(window, arguments);
    };

    /* --- setAttribute for dangerous attrs --- */
    var dangerAttrs = ['src', 'href', 'action', 'formaction', 'srcdoc', 'data', 'codebase'];
    var origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
        if (dangerAttrs.indexOf(name.toLowerCase()) !== -1 && hasCanary(value))
            logReflection('setAttribute.' + name, value, this.tagName);
        return origSetAttribute.call(this, name, value);
    };

    /* --- insertAdjacentHTML --- */
    var origInsertAdj = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, text) {
        if (hasCanary(text)) logReflection('insertAdjacentHTML', text, this.tagName);
        return origInsertAdj.call(this, position, text);
    };

    /* --- DOMParser.parseFromString --- */
    var origParse = DOMParser.prototype.parseFromString;
    DOMParser.prototype.parseFromString = function(str, type) {
        if (hasCanary(str)) logReflection('DOMParser.parseFromString', str, type);
        return origParse.call(this, str, type);
    };

    /* --- postMessage --- */
    var origPostMessage = window.postMessage.bind(window);
    window.postMessage = function(msg) {
        var s = typeof msg === 'string' ? msg : JSON.stringify(msg);
        if (hasCanary(s)) logReflection('postMessage', s, 'message');
        return origPostMessage.apply(window, arguments);
    };

    /* --- WebSocket.send --- */
    var origWsSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function(data) {
        if (hasCanary(String(data))) logReflection('WebSocket.send', String(data), 'websocket');
        return origWsSend.call(this, data);
    };

    /* --- fetch URL params --- */
    var origFetch = window.fetch;
    window.fetch = function(input) {
        var url = typeof input === 'string' ? input : (input && input.url ? input.url : '');
        if (hasCanary(url)) logReflection('fetch', url, 'network');
        return origFetch.apply(window, arguments);
    };

    /* --- XMLHttpRequest.open --- */
    var origXhrOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        if (hasCanary(url)) logReflection('XMLHttpRequest.open', url, 'network');
        return origXhrOpen.apply(this, arguments);
    };
})();
"""


# ---------------------------------------------------------------------------
# DOM Invader JS -- deeper sink coverage with exploitability tagging
# ---------------------------------------------------------------------------

_DOM_INVADER_JS = """\
(function() {
    'use strict';
    if (window.__ANBU_DOM_INVADER_LOG) return;

    window.__ANBU_DOM_INVADER_LOG = [];
    var LOG = window.__ANBU_DOM_INVADER_LOG;
    var CANARY_PREFIX = 'GNKTNT';

    function hasCanary(val) {
        if (typeof val !== 'string') return false;
        return val.indexOf(CANARY_PREFIX) !== -1;
    }

    function extractCanaries(val) {
        var re = new RegExp(CANARY_PREFIX + '\\\\d+', 'g');
        return (val.match(re) || []);
    }

    function getStack() {
        try { throw new Error(); } catch(e) { return e.stack || ''; }
    }

    function logSink(type, source, sink, canary, context, exploitable, evidence, element) {
        LOG.push({
            type: type,
            source: source,
            sink: sink,
            canary: canary,
            context: context || '',
            exploitable: !!exploitable,
            evidence: String(evidence || '').substring(0, 2048),
            element: element ? {
                tag: element.tagName || '',
                id: element.id || '',
                className: element.className || ''
            } : null,
            callStack: getStack(),
            timestamp: Date.now()
        });
    }

    /* --- innerHTML / outerHTML --- */
    var origInner = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (origInner && origInner.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(v) {
                if (hasCanary(v)) {
                    var canaries = extractCanaries(v);
                    var hasScript = /<script[^>]*>/i.test(v) || /on\\w+\\s*=/i.test(v);
                    canaries.forEach(function(c) {
                        logSink('dom-xss', 'taint', 'innerHTML', c, 'html',
                                hasScript, v, this);
                    }.bind(this));
                }
                return origInner.set.call(this, v);
            },
            get: origInner.get,
            configurable: true
        });
    }

    var origOuter = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (origOuter && origOuter.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(v) {
                if (hasCanary(v)) {
                    var canaries = extractCanaries(v);
                    canaries.forEach(function(c) {
                        logSink('dom-xss', 'taint', 'outerHTML', c, 'html',
                                true, v, this);
                    }.bind(this));
                }
                return origOuter.set.call(this, v);
            },
            get: origOuter.get,
            configurable: true
        });
    }

    /* --- document.write --- */
    var origWrite = document.write.bind(document);
    document.write = function() {
        Array.prototype.slice.call(arguments).forEach(function(a) {
            if (hasCanary(a)) {
                extractCanaries(a).forEach(function(c) {
                    logSink('dom-xss', 'taint', 'document.write', c, 'html', true, a, null);
                });
            }
        });
        return origWrite.apply(document, arguments);
    };

    /* --- eval / Function --- */
    var origEval = window.eval;
    window.eval = function(code) {
        if (hasCanary(code)) {
            extractCanaries(code).forEach(function(c) {
                logSink('code-injection', 'taint', 'eval', c, 'js', true, code, null);
            });
        }
        return origEval.call(window, code);
    };

    var OrigFunction = Function;
    try {
        window.Function = function() {
            var args = Array.prototype.slice.call(arguments);
            var body = args.length > 0 ? args[args.length - 1] : '';
            if (hasCanary(body)) {
                extractCanaries(body).forEach(function(c) {
                    logSink('code-injection', 'taint', 'Function', c, 'js', true, body, null);
                });
            }
            return OrigFunction.apply(this, args);
        };
        window.Function.prototype = OrigFunction.prototype;
    } catch(e) {}

    /* --- setTimeout / setInterval (string form) --- */
    var origST = window.setTimeout;
    var origSI = window.setInterval;
    window.setTimeout = function(fn) {
        if (typeof fn === 'string' && hasCanary(fn)) {
            extractCanaries(fn).forEach(function(c) {
                logSink('code-injection', 'taint', 'setTimeout', c, 'js', true, fn, null);
            });
        }
        return origST.apply(window, arguments);
    };
    window.setInterval = function(fn) {
        if (typeof fn === 'string' && hasCanary(fn)) {
            extractCanaries(fn).forEach(function(c) {
                logSink('code-injection', 'taint', 'setInterval', c, 'js', true, fn, null);
            });
        }
        return origSI.apply(window, arguments);
    };

    /* --- location manipulation --- */
    try {
        var origAssign = location.assign.bind(location);
        var origReplace = location.replace.bind(location);
        location.assign = function(url) {
            if (hasCanary(url)) {
                extractCanaries(url).forEach(function(c) {
                    logSink('open-redirect', 'taint', 'location.assign', c, 'url', true, url, null);
                });
            }
            return origAssign(url);
        };
        location.replace = function(url) {
            if (hasCanary(url)) {
                extractCanaries(url).forEach(function(c) {
                    logSink('open-redirect', 'taint', 'location.replace', c, 'url', true, url, null);
                });
            }
            return origReplace(url);
        };
    } catch(e) {}

    /* --- window.open --- */
    var origWOpen = window.open;
    window.open = function(url) {
        if (url && hasCanary(url)) {
            extractCanaries(url).forEach(function(c) {
                logSink('open-redirect', 'taint', 'window.open', c, 'url', true, url, null);
            });
        }
        return origWOpen.apply(window, arguments);
    };

    /* --- setAttribute --- */
    var dangerAttrs = ['src', 'href', 'action', 'formaction', 'srcdoc'];
    var origSetAttr = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
        if (dangerAttrs.indexOf(name.toLowerCase()) !== -1 && hasCanary(value)) {
            extractCanaries(value).forEach(function(c) {
                logSink('attr-injection', 'taint', 'setAttribute.' + name, c, 'attribute',
                        name === 'srcdoc' || name === 'src', value, this);
            }.bind(this));
        }
        return origSetAttr.call(this, name, value);
    };

    /* --- postMessage listener tracking --- */
    var origAddEL = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, fn, opts) {
        if (type === 'message' && typeof fn === 'function') {
            var wrapped = function(e) {
                var data = typeof e.data === 'string' ? e.data : JSON.stringify(e.data);
                if (hasCanary(data)) {
                    extractCanaries(data).forEach(function(c) {
                        logSink('postmessage-xss', 'postMessage', 'message-handler', c,
                                'message', true, data, null);
                    });
                }
                return fn.call(this, e);
            };
            return origAddEL.call(this, type, wrapped, opts);
        }
        return origAddEL.call(this, type, fn, opts);
    };

    /* --- MutationObserver for dynamic script/link injection --- */
    try {
        var observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(m) {
                m.addedNodes.forEach(function(node) {
                    if (node.nodeType !== 1) return;
                    if (node.tagName === 'SCRIPT') {
                        var src = node.src || node.textContent || '';
                        if (hasCanary(src)) {
                            extractCanaries(src).forEach(function(c) {
                                logSink('dom-xss', 'mutation', 'script-inject', c,
                                        'html', true, src, node);
                            });
                        }
                    }
                    if (node.tagName === 'LINK' && node.rel === 'stylesheet') {
                        var href = node.href || '';
                        if (hasCanary(href)) {
                            extractCanaries(href).forEach(function(c) {
                                logSink('css-injection', 'mutation', 'link-inject', c,
                                        'attribute', false, href, node);
                            });
                        }
                    }
                });
            });
        });
        observer.observe(document.documentElement || document.body || document,
                         {childList: true, subtree: true});
    } catch(e) {}

    /* --- Shadow DOM innerHTML hooks --- */
    try {
        var origAttachShadow = Element.prototype.attachShadow;
        Element.prototype.attachShadow = function(init) {
            var shadow = origAttachShadow.call(this, init);
            var shadowInnerDesc = Object.getOwnPropertyDescriptor(
                ShadowRoot.prototype, 'innerHTML'
            );
            if (shadowInnerDesc && shadowInnerDesc.set) {
                var origShadowSet = shadowInnerDesc.set;
                Object.defineProperty(shadow, 'innerHTML', {
                    set: function(v) {
                        if (hasCanary(v)) {
                            extractCanaries(v).forEach(function(c) {
                                logSink('dom-xss', 'shadow-dom', 'shadowRoot.innerHTML',
                                        c, 'html', true, v, null);
                            });
                        }
                        return origShadowSet.call(this, v);
                    },
                    get: shadowInnerDesc.get,
                    configurable: true
                });
            }
            return shadow;
        };
    } catch(e) {}

    /* --- CSS injection via insertRule --- */
    try {
        var origInsertRule = CSSStyleSheet.prototype.insertRule;
        CSSStyleSheet.prototype.insertRule = function(rule, index) {
            if (hasCanary(rule)) {
                extractCanaries(rule).forEach(function(c) {
                    logSink('css-injection', 'taint', 'insertRule', c, 'css', false, rule, null);
                });
            }
            return origInsertRule.call(this, rule, index);
        };
    } catch(e) {}
})();
"""


# ---------------------------------------------------------------------------
# TaintTracker - manages canary injection and reflection detection
# ---------------------------------------------------------------------------

class TaintTracker:
    """
    Manages canary injection into page sources and monitors DOM sinks for
    canary reflection. Uses Playwright page.evaluate() for runtime hooks
    and CDP integration where needed.
    """

    CANARY_PREFIX = "GNKTNT"

    def __init__(self, verbose=False):
        self.canaries = {}       # canary_id -> {source, context, url, timestamp}
        self.reflections = []    # raw reflection entries from the browser
        self.findings = []       # classified findings
        self.counter = 0
        self.verbose = verbose

    def generate_canary(self, source, context=""):
        """
        Return a unique canary string like GNKTNT1, GNKTNT2, etc.
        Registers the canary with its source metadata.
        """
        self.counter += 1
        canary = f"{self.CANARY_PREFIX}{self.counter}"
        self.canaries[canary] = {
            "source": source,
            "context": context,
            "timestamp": time.time(),
        }
        if self.verbose:
            print(f"  [IAST] Canary {canary} -> source={source} ctx={context}")
        return canary

    def get_taint_monitor_script(self):
        """Return the JavaScript IIFE that hooks all dangerous DOM sinks."""
        return _TAINT_MONITOR_JS

    def get_dom_invader_script(self):
        """Return the JavaScript IIFE for the DOM Invader hooks."""
        return _DOM_INVADER_JS

    async def inject_taint_hooks(self, page):
        """
        Inject taint monitor and DOM invader scripts into the page context.
        Must be called BEFORE page navigation so the hooks are in place when
        the page's own scripts run (uses add_init_script / evaluateOnNewDocument).
        """
        combined = self.get_taint_monitor_script() + "\n" + self.get_dom_invader_script()
        try:
            await page.add_init_script(combined)
        except Exception as exc:
            if self.verbose:
                print(f"  [IAST] add_init_script failed, falling back to evaluate: {exc}")
            try:
                await page.evaluate(combined)
            except Exception as exc2:
                if self.verbose:
                    print(f"  [IAST] evaluate fallback also failed: {exc2}")

    async def plant_url_param_taints(self, page, urls):
        """
        For each URL, append canary values to every existing query parameter
        (and inject a few default params), then navigate to harvest reflections.
        """
        default_params = ["q", "search", "query", "url", "redirect", "next",
                          "return", "callback", "id", "page"]

        for url in urls:
            parsed = urlparse(url)
            existing = parse_qs(parsed.query, keep_blank_values=True)

            tainted_params = {}

            # Taint existing params
            for param_name in existing:
                canary = self.generate_canary("url_param", param_name)
                tainted_params[param_name] = canary

            # Inject default params that aren't already present
            for param_name in default_params:
                if param_name not in existing:
                    canary = self.generate_canary("url_param_injected", param_name)
                    tainted_params[param_name] = canary

            tainted_query = urlencode(tainted_params)
            tainted_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, tainted_query, parsed.fragment,
            ))

            if self.verbose:
                print(f"  [IAST] Navigating with tainted URL: {tainted_url}")

            try:
                await page.goto(tainted_url, wait_until="domcontentloaded", timeout=15000)
                await page.wait_for_timeout(1000)
            except Exception as exc:
                if self.verbose:
                    print(f"  [IAST] Navigation failed for {tainted_url}: {exc}")

    async def plant_form_taints(self, page):
        """
        Find all form inputs on the page and fill them with canary values.
        Covers text inputs, textareas, selects, and hidden fields.
        """
        try:
            form_inputs = await page.evaluate("""\
                (function() {
                    var inputs = [];
                    document.querySelectorAll(
                        'input, textarea, select, [contenteditable="true"]'
                    ).forEach(function(el) {
                        inputs.push({
                            tag: el.tagName.toLowerCase(),
                            type: (el.type || '').toLowerCase(),
                            name: el.name || el.id || '',
                            id: el.id || ''
                        });
                    });
                    return inputs;
                })()
            """)
        except Exception:
            form_inputs = []

        for i, inp in enumerate(form_inputs):
            canary = self.generate_canary(
                "form_input",
                f"{inp['tag']}[{inp['name'] or inp['id'] or i}]",
            )
            selector = None
            if inp["id"]:
                selector = f"#{inp['id']}"
            elif inp["name"]:
                selector = f"[name='{inp['name']}']"

            if not selector:
                continue

            try:
                if inp["tag"] in ("input", "textarea"):
                    input_type = inp.get("type", "text")
                    if input_type in ("text", "search", "url", "email", "tel",
                                      "password", "hidden", ""):
                        await page.fill(selector, canary)
                    elif input_type == "number":
                        await page.fill(selector, "12345")
                elif inp["tag"] == "select":
                    # Leave selects as-is; can't usefully taint dropdown values
                    pass
                else:
                    # contenteditable
                    await page.evaluate(
                        f"document.querySelector('{selector}').textContent = '{canary}'"
                    )
            except Exception:
                pass

    async def plant_storage_taints(self, page):
        """Plant canaries in localStorage and sessionStorage keys."""
        storage_keys = ["token", "user", "session", "auth", "redirect_url",
                        "return_to", "next", "callback", "data", "config"]
        for key in storage_keys:
            canary = self.generate_canary("localStorage", key)
            try:
                await page.evaluate(
                    f"try {{ localStorage.setItem('{key}', '{canary}'); }} catch(e) {{}}"
                )
            except Exception:
                pass

            canary_s = self.generate_canary("sessionStorage", key)
            try:
                await page.evaluate(
                    f"try {{ sessionStorage.setItem('{key}', '{canary_s}'); }} catch(e) {{}}"
                )
            except Exception:
                pass

    async def plant_cookie_taints(self, page):
        """Plant canaries in document.cookie for common cookie names."""
        cookie_names = ["token", "session", "user", "auth", "redirect",
                        "return_url", "next", "lang", "theme", "prefs"]
        for name in cookie_names:
            canary = self.generate_canary("cookie", name)
            try:
                await page.evaluate(
                    f"document.cookie = '{name}={canary}; path=/; SameSite=Lax';"
                )
            except Exception:
                pass

    async def plant_postmessage_taints(self, page):
        """Send postMessage with canary payloads to the page window."""
        payloads = [
            {"type": "config", "data": self.generate_canary("postMessage", "config")},
            {"type": "auth", "token": self.generate_canary("postMessage", "auth")},
            self.generate_canary("postMessage", "raw_string"),
        ]
        for payload in payloads:
            try:
                payload_json = json.dumps(payload) if isinstance(payload, dict) else f'"{payload}"'
                await page.evaluate(f"window.postMessage({payload_json}, '*');")
            except Exception:
                pass

    async def harvest_reflections(self, page):
        """
        Collect reflections from both the taint monitor and DOM invader logs,
        then parse and classify each one.
        """
        # Harvest taint monitor reflections
        try:
            taint_reflections = await page.evaluate("""\
                (function() {
                    return window.__GENKI_TAINT
                        ? window.__GENKI_TAINT.reflections.splice(0)
                        : [];
                })()
            """)
        except Exception:
            taint_reflections = []

        # Harvest DOM invader log
        try:
            invader_log = await page.evaluate("""\
                (function() {
                    return window.__ANBU_DOM_INVADER_LOG
                        ? window.__ANBU_DOM_INVADER_LOG.splice(0)
                        : [];
                })()
            """)
        except Exception:
            invader_log = []

        self.reflections.extend(taint_reflections)
        self.reflections.extend(invader_log)

        # Classify each new reflection
        for ref in taint_reflections + invader_log:
            finding = self.classify_finding(ref)
            if finding:
                self.findings.append(finding)

        if self.verbose:
            print(f"  [IAST] Harvested {len(taint_reflections)} taint reflections, "
                  f"{len(invader_log)} invader logs")

        return self.findings

    def classify_finding(self, reflection):
        """
        Classify a reflection by context and assign severity.

        Categories:
          html    -> XSS (DOM-based cross-site scripting)
          js      -> Code injection (eval/Function/setTimeout sinks)
          url     -> Open redirect (location/window.open sinks)
          attribute -> Attribute injection (setAttribute sinks)
          message -> postMessage XSS
          css     -> CSS injection

        Severity:
          critical - exploitable code injection or DOM XSS with script evidence
          high     - DOM XSS without confirmed script context, open redirects
          medium   - attribute injection, postMessage flows
          low      - CSS injection, informational reflections
        """
        sink = reflection.get("sink", "")
        context = reflection.get("context", "")
        exploitable = reflection.get("exploitable", False)
        finding_type = reflection.get("type", "")

        # Determine category
        if context in ("js",) or sink in ("eval", "Function", "setTimeout", "setInterval"):
            category = "js"
        elif context in ("html",) or sink in ("innerHTML", "outerHTML",
                                               "document.write", "document.writeln",
                                               "insertAdjacentHTML",
                                               "shadowRoot.innerHTML"):
            category = "html"
        elif context in ("url",) or sink in ("location.assign", "location.replace",
                                              "window.open"):
            category = "url"
        elif context in ("attribute",) or sink.startswith("setAttribute"):
            category = "attribute"
        elif context in ("message",):
            category = "message"
        elif context in ("css",):
            category = "css"
        elif context in ("network",):
            category = "network"
        else:
            category = "other"

        # Determine severity
        if category == "js":
            severity = "critical"
        elif category == "html":
            severity = "critical" if exploitable else "high"
        elif category == "url":
            severity = "high"
        elif category in ("message", "attribute"):
            severity = "medium"
        elif category == "css":
            severity = "low"
        elif category == "network":
            severity = "medium"
        else:
            severity = "low"

        # Map canaries back to their sources
        canaries = reflection.get("canaries", [])
        canary = reflection.get("canary", "")
        if canary and canary not in canaries:
            canaries.append(canary)

        sources = []
        for c in canaries:
            if c in self.canaries:
                sources.append(self.canaries[c])

        return {
            "category": category,
            "severity": severity,
            "sink": sink,
            "context": context,
            "exploitable": exploitable,
            "canaries": canaries,
            "sources": sources,
            "evidence": reflection.get("evidence", reflection.get("value", "")),
            "url": reflection.get("url", ""),
            "element": reflection.get("element"),
            "call_stack": reflection.get("callStack", ""),
            "timestamp": reflection.get("timestamp", 0),
            "finding_type": finding_type or f"taint-{category}",
        }


# ---------------------------------------------------------------------------
# MutationFuzzer - runtime variable mutation via CDP
# ---------------------------------------------------------------------------

class MutationFuzzer:
    """
    Mutates runtime variables to detect authorization and logic flaws.
    Uses CDP Runtime.evaluate to locate and alter in-memory state, then
    observes whether the mutation causes a behavioral change in network
    requests or DOM state.
    """

    MUTATION_PRESETS = {
        "idor": [
            {"pattern": r"(?:user_?id|uid|account_?id|profile_?id)", "mutations": [
                {"op": "increment", "delta": 1},
                {"op": "increment", "delta": -1},
                {"op": "set", "value": "1"},
                {"op": "set", "value": "0"},
                {"op": "set", "value": "admin"},
            ]},
            {"pattern": r"(?:order_?id|invoice_?id|doc_?id|file_?id)", "mutations": [
                {"op": "increment", "delta": 1},
                {"op": "increment", "delta": -1},
                {"op": "set", "value": "1"},
            ]},
        ],
        "privilege": [
            {"pattern": r"(?:is_?admin|is_?staff|is_?superuser|role)", "mutations": [
                {"op": "set", "value": True},
                {"op": "set", "value": "admin"},
                {"op": "set", "value": "superuser"},
                {"op": "toggle"},
            ]},
            {"pattern": r"(?:can_?edit|can_?delete|can_?write|permission|access_?level)",
             "mutations": [
                {"op": "set", "value": True},
                {"op": "set", "value": 999},
                {"op": "set", "value": "admin"},
            ]},
        ],
        "financial": [
            {"pattern": r"(?:price|amount|total|cost|quantity|qty|discount)", "mutations": [
                {"op": "set", "value": 0},
                {"op": "set", "value": -1},
                {"op": "set", "value": 0.01},
                {"op": "set", "value": 99999999},
            ]},
        ],
    }

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.mutations_applied = []
        self.network_baseline = []

    async def _capture_network_state(self, page):
        """Snapshot the current set of pending/completed network requests."""
        try:
            return await page.evaluate("""\
                (function() {
                    if (!window.__GENKI_NET_LOG) return [];
                    return window.__GENKI_NET_LOG.slice(-50);
                })()
            """)
        except Exception:
            return []

    async def fuzz_runtime_vars(self, page, preset="idor"):
        """
        Use CDP Runtime.evaluate to find and mutate runtime variables
        matching the given preset patterns.

        Returns a list of mutations that were applied.
        """
        rules = self.MUTATION_PRESETS.get(preset, [])
        if not rules:
            if self.verbose:
                print(f"  [IAST] Unknown mutation preset: {preset}")
            return []

        # Capture baseline network state
        self.network_baseline = await self._capture_network_state(page)

        applied = []

        for rule in rules:
            pattern = rule["pattern"]
            mutations = rule["mutations"]

            # Scan window-level properties for matches
            scan_js = f"""\
                (function() {{
                    var pattern = new RegExp({json.dumps(pattern)}, 'i');
                    var found = [];
                    function scan(obj, path, depth) {{
                        if (depth > 3 || !obj || typeof obj !== 'object') return;
                        try {{
                            var keys = Object.keys(obj);
                        }} catch(e) {{ return; }}
                        for (var i = 0; i < keys.length && i < 200; i++) {{
                            var k = keys[i];
                            if (pattern.test(k)) {{
                                try {{
                                    found.push({{
                                        path: path + '.' + k,
                                        key: k,
                                        value: obj[k],
                                        type: typeof obj[k]
                                    }});
                                }} catch(e) {{}}
                            }}
                            if (typeof obj[k] === 'object' && obj[k] !== null) {{
                                scan(obj[k], path + '.' + k, depth + 1);
                            }}
                        }}
                    }}
                    scan(window, 'window', 0);
                    return found;
                }})()
            """

            try:
                matches = await page.evaluate(scan_js)
            except Exception:
                matches = []

            for match in matches:
                for mutation in mutations:
                    op = mutation["op"]
                    path = match["path"]
                    original_value = match["value"]

                    if op == "set":
                        new_value = json.dumps(mutation["value"])
                        mutate_js = f"{path} = {new_value};"
                    elif op == "increment":
                        delta = mutation.get("delta", 1)
                        mutate_js = f"{path} = {path} + {delta};"
                    elif op == "toggle":
                        mutate_js = f"{path} = !{path};"
                    else:
                        continue

                    try:
                        await page.evaluate(mutate_js)
                        entry = {
                            "preset": preset,
                            "path": path,
                            "key": match["key"],
                            "original": original_value,
                            "mutation_op": op,
                            "mutation_js": mutate_js,
                            "timestamp": time.time(),
                        }
                        applied.append(entry)
                        if self.verbose:
                            print(f"  [IAST] Mutated {path}: {op}")
                    except Exception as exc:
                        if self.verbose:
                            print(f"  [IAST] Mutation failed {path}: {exc}")

                    # Restore original value
                    try:
                        restore_val = json.dumps(original_value)
                        await page.evaluate(f"{path} = {restore_val};")
                    except Exception:
                        pass

        self.mutations_applied.extend(applied)
        return applied

    async def track_effects(self, page):
        """
        Compare network requests before and after mutation.
        Returns list of mutations that caused behavioral changes.
        """
        current_network = await self._capture_network_state(page)

        baseline_urls = {r.get("url", "") for r in self.network_baseline if isinstance(r, dict)}
        current_urls = {r.get("url", "") for r in current_network if isinstance(r, dict)}

        new_requests = current_urls - baseline_urls

        effects = []
        if new_requests:
            effects.append({
                "type": "new_network_requests",
                "urls": list(new_requests),
                "count": len(new_requests),
                "mutations_applied": len(self.mutations_applied),
            })

        if self.verbose and effects:
            print(f"  [IAST] Detected {len(new_requests)} new network requests after mutations")

        return effects


# ---------------------------------------------------------------------------
# Top-level scan entry point
# ---------------------------------------------------------------------------

async def _run_iast_scan_async(target_url, verbose=False):
    """
    Internal async implementation of the IAST scan pipeline.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("  [IAST] WARNING: playwright is not installed. "
              "Install with: pip install playwright && playwright install chromium")
        return {
            "target": target_url,
            "error": "playwright not installed",
            "findings": [],
            "reflections": [],
            "mutations": [],
        }

    tracker = TaintTracker(verbose=verbose)
    fuzzer = MutationFuzzer(verbose=verbose)

    findings = []
    mutations = []
    effects = []

    async with async_playwright() as pw:
        browser = None
        try:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                java_script_enabled=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )

            page = await context.new_page()

            # Inject taint hooks BEFORE navigation
            if verbose:
                print(f"  [IAST] Injecting taint hooks...")
            await tracker.inject_taint_hooks(page)

            # Also inject a simple network logger so MutationFuzzer can track requests
            await page.add_init_script("""\
                (function() {
                    window.__GENKI_NET_LOG = [];
                    var origFetch = window.fetch;
                    window.fetch = function(input) {
                        var url = typeof input === 'string'
                            ? input : (input && input.url ? input.url : '');
                        window.__GENKI_NET_LOG.push({
                            url: url, method: 'fetch', ts: Date.now()
                        });
                        return origFetch.apply(window, arguments);
                    };
                    var origXhrOpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url) {
                        window.__GENKI_NET_LOG.push({
                            url: url, method: method, ts: Date.now()
                        });
                        return origXhrOpen.apply(this, arguments);
                    };
                })();
            """)

            # Navigate to target
            if verbose:
                print(f"  [IAST] Navigating to {target_url}")
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            except Exception as exc:
                if verbose:
                    print(f"  [IAST] Initial navigation error (continuing): {exc}")

            # Wait for page scripts to settle
            await page.wait_for_timeout(2000)

            # Plant taints across all vectors
            if verbose:
                print(f"  [IAST] Planting taints...")

            await tracker.plant_form_taints(page)
            await tracker.plant_storage_taints(page)
            await tracker.plant_cookie_taints(page)
            await tracker.plant_postmessage_taints(page)

            # URL param taints (navigate with tainted params)
            await tracker.plant_url_param_taints(page, [target_url])

            # Wait for sinks to fire
            await page.wait_for_timeout(3000)

            # Trigger any click handlers / form submissions that might flush data to sinks
            try:
                await page.evaluate("""\
                    (function() {
                        document.querySelectorAll('button, [type="submit"], a[href]')
                            .forEach(function(el, i) {
                                if (i < 5) {
                                    try { el.click(); } catch(e) {}
                                }
                            });
                    })()
                """)
                await page.wait_for_timeout(1000)
            except Exception:
                pass

            # Harvest reflections
            if verbose:
                print(f"  [IAST] Harvesting reflections...")
            findings = await tracker.harvest_reflections(page)

            # Run mutation fuzzer
            if verbose:
                print(f"  [IAST] Running mutation fuzzer...")
            for preset in ("idor", "privilege", "financial"):
                preset_mutations = await fuzzer.fuzz_runtime_vars(page, preset=preset)
                mutations.extend(preset_mutations)

            effects = await fuzzer.track_effects(page)

            await page.close()
            await context.close()

        except Exception as exc:
            if verbose:
                print(f"  [IAST] Scan error: {exc}")
            findings = tracker.findings
        finally:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass

    # Summary
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "target": target_url,
        "findings": findings,
        "reflections": tracker.reflections,
        "mutations": mutations,
        "mutation_effects": effects,
        "canaries_planted": tracker.counter,
        "severity_counts": severity_counts,
        "summary": {
            "total_findings": len(findings),
            "total_reflections": len(tracker.reflections),
            "total_mutations": len(mutations),
            "total_effects": len(effects),
        },
    }


def run_iast_scan(target_url, verbose=False):
    """
    Top-level entry point: launch Playwright, inject taint hooks, navigate to
    target, plant canaries across all vectors, wait for page to settle, harvest
    reflections, classify findings, and return results.

    Returns a dict with keys:
      target, findings, reflections, mutations, mutation_effects,
      canaries_planted, severity_counts, summary
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already inside an event loop (e.g. Jupyter) -- create a task
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(
                asyncio.run, _run_iast_scan_async(target_url, verbose=verbose)
            ).result()
    else:
        return asyncio.run(_run_iast_scan_async(target_url, verbose=verbose))
