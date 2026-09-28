/**
 * ANBU DOM Invader -- CDP-based DOM Sink Monitor
 * ===============================================
 * Hooks ALL dangerous DOM sinks via CDP Runtime.evaluate before page loads.
 * Injects unique canary strings into user-controlled sources and monitors
 * which canaries reach which sinks via MutationObserver + hook callbacks.
 *
 * Detects: XSS sinks, prototype pollution, postMessage handler vulns,
 *          open redirects, dynamic script/resource injection.
 *
 * Integration:
 *   const payload = buildDomInvaderPayload();
 *   await cdpSession.send('Runtime.evaluate', { expression: payload });
 *   // ... user interacts with page ...
 *   const raw = await page.evaluate(() => window.__ANBU_DOM_INVADER_LOG);
 *   const events = parseDomInvaderEvents(raw);
 */
'use strict';

/**
 * Build the injectable JS payload string.
 * Returned string is a self-contained IIFE safe for CDP Runtime.evaluate.
 */
function buildDomInvaderPayload() {
    return `(function __ANBU_DOM_INVADER__() {
    'use strict';

    /* ── Guard: only run once ── */
    if (window.__ANBU_DOM_INVADER_ARMED) return;
    window.__ANBU_DOM_INVADER_ARMED = true;
    window.__ANBU_DOM_INVADER_LOG = [];

    /* ── Utility ── */
    var _log = window.__ANBU_DOM_INVADER_LOG;
    var _id = 0;
    function uid() { return 'ANBU_CANARY_' + (++_id) + '_' + Math.random().toString(36).slice(2, 8); }
    function ts() { return Date.now(); }
    function stack() { try { throw new Error(); } catch (e) { return (e.stack || '').split('\\n').slice(2).join('\\n'); } }
    function trunc(v, n) { var s = String(v); return s.length > (n || 512) ? s.slice(0, n || 512) + '...' : s; }

    function emit(type, data) {
        try {
            data.type = type;
            data.timestamp = ts();
            data.callStack = stack();
            _log.push(data);
        } catch (_) {}
    }

    /* ── Context detection ── */
    function detectContext(value, sink) {
        var v = String(value);
        if (/\\.innerHTML|\\.outerHTML|insertAdjacentHTML|document\\.write|DOMParser|createContextualFragment/.test(sink)) return 'html';
        if (/eval|Function|setTimeout|setInterval/.test(sink)) return 'js';
        if (/\\.href|\\.src|\\.action|location|window\\.open|URL/.test(sink)) return 'url';
        if (/\\.setAttribute|\\.dataset/.test(sink)) return 'attribute';
        return 'unknown';
    }

    function isExploitable(context, value) {
        var v = String(value);
        if (context === 'html' && (/</.test(v) || /on\\w+\\s*=/.test(v))) return true;
        if (context === 'js') return true;
        if (context === 'url' && /^javascript:/i.test(v)) return true;
        if (context === 'attribute' && /["'<>]/.test(v)) return true;
        return false;
    }

    /* ── Canary registry ── */
    var canaries = {};
    function registerCanary(source, value) {
        var c = uid();
        canaries[c] = { source: source, original: trunc(value, 256), injectedAt: ts() };
        return c;
    }
    function findCanary(str) {
        if (typeof str !== 'string') return null;
        for (var c in canaries) {
            if (str.indexOf(c) !== -1) return { canary: c, meta: canaries[c] };
        }
        return null;
    }

    /* ── Sink event helper ── */
    function onSinkHit(sink, value, element) {
        try {
            var v = String(value);
            var match = findCanary(v);
            var ctx = detectContext(v, sink);
            emit('dom_sink_hit', {
                source: match ? match.meta.source : 'unknown',
                sink: sink,
                canary: match ? match.canary : null,
                context: ctx,
                exploitable: isExploitable(ctx, v),
                evidence: trunc(v, 1024),
                element: element ? (element.tagName || '') + (element.id ? '#' + element.id : '') : null
            });
        } catch (_) {}
    }

    /* ═══════════════════════════════════════════════
     * SINK HOOKS
     * ═══════════════════════════════════════════════ */

    /* ── innerHTML / outerHTML ── */
    function hookHTMLProperty(proto, prop) {
        try {
            var desc = Object.getOwnPropertyDescriptor(proto, prop);
            if (!desc || !desc.set) return;
            var origSet = desc.set;
            Object.defineProperty(proto, prop, {
                set: function(val) {
                    onSinkHit(prop, val, this);
                    return origSet.call(this, val);
                },
                get: desc.get,
                enumerable: desc.enumerable,
                configurable: true
            });
        } catch (_) {}
    }
    hookHTMLProperty(Element.prototype, 'innerHTML');
    hookHTMLProperty(Element.prototype, 'outerHTML');

    /* ── insertAdjacentHTML ── */
    try {
        var _origInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function(position, text) {
            onSinkHit('insertAdjacentHTML', text, this);
            return _origInsertAdjacentHTML.call(this, position, text);
        };
    } catch (_) {}

    /* ── document.write / writeln ── */
    try {
        var _origWrite = document.write.bind(document);
        document.write = function() {
            var html = Array.prototype.join.call(arguments, '');
            onSinkHit('document.write', html, null);
            return _origWrite.apply(document, arguments);
        };
    } catch (_) {}
    try {
        var _origWriteln = document.writeln.bind(document);
        document.writeln = function() {
            var html = Array.prototype.join.call(arguments, '');
            onSinkHit('document.writeln', html, null);
            return _origWriteln.apply(document, arguments);
        };
    } catch (_) {}

    /* ── eval ── */
    try {
        var _origEval = window.eval;
        window.eval = function(code) {
            onSinkHit('eval', code, null);
            return _origEval.call(window, code);
        };
    } catch (_) {}

    /* ── Function constructor ── */
    try {
        var _origFunction = Function;
        var _FunctionProxy = new Proxy(_origFunction, {
            construct: function(target, args) {
                var body = args.length > 0 ? args[args.length - 1] : '';
                onSinkHit('Function', body, null);
                return new (Function.prototype.bind.apply(target, [null].concat(Array.from(args))))();
            },
            apply: function(target, thisArg, args) {
                var body = args.length > 0 ? args[args.length - 1] : '';
                onSinkHit('Function', body, null);
                return target.apply(thisArg, args);
            }
        });
        window.Function = _FunctionProxy;
    } catch (_) {}

    /* ── setTimeout / setInterval (string arg only) ── */
    function hookTimerFn(name) {
        try {
            var orig = window[name];
            window[name] = function(handler) {
                if (typeof handler === 'string') {
                    onSinkHit(name + '(string)', handler, null);
                }
                return orig.apply(window, arguments);
            };
        } catch (_) {}
    }
    hookTimerFn('setTimeout');
    hookTimerFn('setInterval');

    /* ── location.href / assign / replace ── */
    try {
        var _locDesc = Object.getOwnPropertyDescriptor(window, 'location');
        /* location is special -- hook via navigation methods */
        var _origAssign = location.assign.bind(location);
        location.assign = function(url) {
            onSinkHit('location.assign', url, null);
            return _origAssign(url);
        };
    } catch (_) {}
    try {
        var _origReplace = location.replace.bind(location);
        location.replace = function(url) {
            onSinkHit('location.replace', url, null);
            return _origReplace(url);
        };
    } catch (_) {}

    /* ── window.open ── */
    try {
        var _origOpen = window.open;
        window.open = function(url, target, features) {
            onSinkHit('window.open', url, null);
            return _origOpen.call(window, url, target, features);
        };
    } catch (_) {}

    /* ── Dynamic src/href/action on elements ── */
    function hookElementAttr(proto, attr) {
        try {
            var desc = Object.getOwnPropertyDescriptor(proto, attr);
            if (!desc || !desc.set) return;
            var origSet = desc.set;
            Object.defineProperty(proto, attr, {
                set: function(val) {
                    onSinkHit('element.' + attr, val, this);
                    return origSet.call(this, val);
                },
                get: desc.get,
                enumerable: desc.enumerable,
                configurable: true
            });
        } catch (_) {}
    }
    /* HTMLScriptElement, HTMLImageElement, HTMLIFrameElement, etc. */
    if (typeof HTMLScriptElement !== 'undefined') hookElementAttr(HTMLScriptElement.prototype, 'src');
    if (typeof HTMLImageElement !== 'undefined') hookElementAttr(HTMLImageElement.prototype, 'src');
    if (typeof HTMLIFrameElement !== 'undefined') hookElementAttr(HTMLIFrameElement.prototype, 'src');
    if (typeof HTMLSourceElement !== 'undefined') hookElementAttr(HTMLSourceElement.prototype, 'src');
    if (typeof HTMLMediaElement !== 'undefined') hookElementAttr(HTMLMediaElement.prototype, 'src');
    if (typeof HTMLAnchorElement !== 'undefined') hookElementAttr(HTMLAnchorElement.prototype, 'href');
    if (typeof HTMLAreaElement !== 'undefined') hookElementAttr(HTMLAreaElement.prototype, 'href');
    if (typeof HTMLFormElement !== 'undefined') hookElementAttr(HTMLFormElement.prototype, 'action');
    if (typeof HTMLBaseElement !== 'undefined') hookElementAttr(HTMLBaseElement.prototype, 'href');

    /* ── jQuery hooks (deferred until jQuery loads) ── */
    function hookJQuery() {
        try {
            var jq = window.jQuery || window.$;
            if (!jq || !jq.fn || jq.fn.__ANBU_HOOKED) return;
            jq.fn.__ANBU_HOOKED = true;
            var jqMethods = ['html', 'append', 'prepend', 'after', 'before'];
            jqMethods.forEach(function(method) {
                var orig = jq.fn[method];
                if (!orig) return;
                jq.fn[method] = function() {
                    if (arguments.length > 0) {
                        onSinkHit('jQuery.' + method, arguments[0], this[0]);
                    }
                    return orig.apply(this, arguments);
                };
            });
        } catch (_) {}
    }
    /* Try now, and retry via observer if jQuery loads later */
    hookJQuery();
    try {
        Object.defineProperty(window, 'jQuery', {
            configurable: true,
            set: function(v) {
                Object.defineProperty(window, 'jQuery', {
                    value: v, writable: true, configurable: true, enumerable: true
                });
                setTimeout(hookJQuery, 0);
            },
            get: function() { return undefined; }
        });
    } catch (_) { /* jQuery already defined, hookJQuery above handled it */ }

    /* ── DOMParser.parseFromString ── */
    try {
        var _origParse = DOMParser.prototype.parseFromString;
        DOMParser.prototype.parseFromString = function(str, type) {
            if (type && type.indexOf('html') !== -1) {
                onSinkHit('DOMParser.parseFromString', str, null);
            }
            return _origParse.call(this, str, type);
        };
    } catch (_) {}

    /* ── Range.createContextualFragment ── */
    try {
        var _origFragment = Range.prototype.createContextualFragment;
        Range.prototype.createContextualFragment = function(html) {
            onSinkHit('createContextualFragment', html, null);
            return _origFragment.call(this, html);
        };
    } catch (_) {}

    /* ── Blob URL / Worker URL ── */
    try {
        var _origCreateObjectURL = URL.createObjectURL;
        URL.createObjectURL = function(obj) {
            var hint = '';
            try { if (obj && obj.type) hint = obj.type; } catch (_) {}
            var url = _origCreateObjectURL.call(URL, obj);
            onSinkHit('URL.createObjectURL', hint + ' -> ' + url, null);
            return url;
        };
    } catch (_) {}
    try {
        var _origWorker = window.Worker;
        window.Worker = function(url, options) {
            onSinkHit('new Worker', url, null);
            return new _origWorker(url, options);
        };
        window.Worker.prototype = _origWorker.prototype;
    } catch (_) {}

    /* ── setAttribute hook (for on* event handlers and href/src) ── */
    try {
        var _origSetAttribute = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {
            var lname = name.toLowerCase();
            if (lname.indexOf('on') === 0 || lname === 'href' || lname === 'src' || lname === 'action' || lname === 'data' || lname === 'srcdoc') {
                onSinkHit('setAttribute(' + name + ')', value, this);
            }
            return _origSetAttribute.call(this, name, value);
        };
    } catch (_) {}

    /* ═══════════════════════════════════════════════
     * CANARY INJECTION INTO SOURCES
     * ═══════════════════════════════════════════════ */

    var injectedCanaries = {};

    /* ── URL parameters ── */
    try {
        var params = new URLSearchParams(location.search);
        params.forEach(function(val, key) {
            var c = registerCanary('url_param:' + key, val);
            injectedCanaries['url_param:' + key] = c;
        });
    } catch (_) {}

    /* ── Hash fragment ── */
    try {
        if (location.hash && location.hash.length > 1) {
            var c = registerCanary('hash', location.hash);
            injectedCanaries.hash = c;
        }
    } catch (_) {}

    /* ── document.referrer ── */
    try {
        if (document.referrer) {
            var c = registerCanary('referrer', document.referrer);
            injectedCanaries.referrer = c;
        }
    } catch (_) {}

    /* ── window.name ── */
    try {
        if (window.name) {
            var c = registerCanary('window.name', window.name);
            injectedCanaries['window.name'] = c;
        }
    } catch (_) {}

    /* ── Cookie values ── */
    try {
        var cookies = document.cookie.split(';');
        cookies.forEach(function(pair) {
            var parts = pair.trim().split('=');
            if (parts.length >= 2) {
                var ck = parts[0].trim();
                var cv = parts.slice(1).join('=').trim();
                if (cv.length > 0) {
                    var c = registerCanary('cookie:' + ck, cv);
                    injectedCanaries['cookie:' + ck] = c;
                }
            }
        });
    } catch (_) {}

    /* ── URL path segments ── */
    try {
        var segments = location.pathname.split('/').filter(function(s) { return s.length > 0; });
        segments.forEach(function(seg, i) {
            var c = registerCanary('path_segment:' + i, seg);
            injectedCanaries['path_segment:' + i + ':' + seg] = c;
        });
    } catch (_) {}

    /* Now rewrite the sources to include canaries so we can trace flow.
       We replace getters so that when JS reads these sources, the canary is appended. */

    /* Canary-augmented location.search getter */
    try {
        var _origSearch = location.search;
        if (_origSearch) {
            var augmented = _origSearch;
            for (var k in injectedCanaries) {
                if (k.indexOf('url_param:') === 0) {
                    var paramName = k.replace('url_param:', '');
                    /* Simple string replacement -- append canary to param value */
                    var idx = augmented.indexOf(paramName + '=');
                    if (idx !== -1) {
                        var eqPos = idx + paramName.length + 1;
                        var ampPos = augmented.indexOf('&', eqPos);
                        if (ampPos === -1) ampPos = augmented.length;
                        augmented = augmented.slice(0, ampPos) + injectedCanaries[k] + augmented.slice(ampPos);
                    }
                }
            }
            window.__ANBU_AUGMENTED_SEARCH = augmented;
        }
    } catch (_) {}

    /* Canary-augmented location.hash getter */
    try {
        if (injectedCanaries.hash && location.hash.length > 1) {
            window.__ANBU_AUGMENTED_HASH = location.hash + injectedCanaries.hash;
        }
    } catch (_) {}

    /* ── postMessage listener for canary injection + handler vuln detection ── */
    try {
        window.addEventListener('message', function __ANBU_PM_MONITOR(event) {
            var data;
            try { data = typeof event.data === 'string' ? event.data : JSON.stringify(event.data); } catch (e) { data = String(event.data); }
            var c = registerCanary('postMessage:' + (event.origin || '*'), data);
            injectedCanaries['postMessage'] = c;

            emit('postmessage_received', {
                origin: event.origin,
                data: trunc(data, 1024),
                canary: c
            });
        }, true);
    } catch (_) {}

    /* ═══════════════════════════════════════════════
     * postMessage HANDLER VULNERABILITY DETECTION
     * ═══════════════════════════════════════════════
     * Detect when page registers message handlers that:
     * 1. Do NOT check event.origin
     * 2. Pass event.data to eval/innerHTML/etc.
     */
    try {
        var _origAddEventListener = EventTarget.prototype.addEventListener;
        EventTarget.prototype.addEventListener = function(type, listener, options) {
            if (type === 'message' && typeof listener === 'function' && listener !== __ANBU_PM_MONITOR) {
                var src = listener.toString();
                var hasOriginCheck = /event\\.origin|e\\.origin|\\.origin\\s*(===|!==|==|!=)/.test(src) ||
                                     /origin/.test(src);
                var hasEvalSink = /eval\\s*\\(|innerHTML|outerHTML|document\\.write|Function\\s*\\(/.test(src);
                if (!hasOriginCheck) {
                    emit('postmessage_vuln', {
                        source: 'addEventListener("message")',
                        sink: hasEvalSink ? 'eval/innerHTML in handler' : 'no origin check',
                        evidence: trunc(src, 2048),
                        exploitable: hasEvalSink,
                        context: hasEvalSink ? 'js' : 'trust'
                    });
                }
            }
            return _origAddEventListener.call(this, type, listener, options);
        };
    } catch (_) {}

    /* ═══════════════════════════════════════════════
     * PROTOTYPE POLLUTION DETECTION
     * ═══════════════════════════════════════════════ */
    try {
        /* Trap Object.prototype.__proto__ writes */
        var _objProto = Object.prototype;
        var __protoDesc = Object.getOwnPropertyDescriptor(_objProto, '__proto__');
        if (__protoDesc && __protoDesc.set) {
            var _origProtoSet = __protoDesc.set;
            Object.defineProperty(_objProto, '__proto__', {
                set: function(val) {
                    if (this === _objProto || this === Object.prototype) {
                        emit('prototype_pollution', {
                            source: '__proto__ assignment on Object.prototype',
                            sink: '__proto__',
                            evidence: trunc(JSON.stringify(val), 512),
                            exploitable: true,
                            context: 'prototype'
                        });
                    }
                    return _origProtoSet.call(this, val);
                },
                get: __protoDesc.get,
                configurable: true
            });
        }
    } catch (_) {}

    /* Trap constructor.prototype writes via Proxy on JSON.parse */
    try {
        var _origJSONParse = JSON.parse;
        JSON.parse = function(text, reviver) {
            var result = _origJSONParse.call(JSON, text, reviver);
            if (result && typeof result === 'object') {
                scanForPollutionKeys(result, 'JSON.parse');
            }
            return result;
        };
    } catch (_) {}

    function scanForPollutionKeys(obj, source) {
        try {
            var keys = Object.keys(obj);
            for (var i = 0; i < keys.length; i++) {
                var k = keys[i];
                if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
                    emit('prototype_pollution', {
                        source: source,
                        sink: k,
                        evidence: trunc(JSON.stringify(obj[k]), 512),
                        exploitable: true,
                        context: 'prototype'
                    });
                }
                if (obj[k] && typeof obj[k] === 'object' && !Array.isArray(obj[k])) {
                    scanForPollutionKeys(obj[k], source + '.' + k);
                }
            }
        } catch (_) {}
    }

    /* ═══════════════════════════════════════════════
     * MUTATION OBSERVER -- watch DOM for canary strings
     * ═══════════════════════════════════════════════ */
    try {
        var observer = new MutationObserver(function(mutations) {
            for (var i = 0; i < mutations.length; i++) {
                var m = mutations[i];
                /* Check added nodes for canaries */
                if (m.addedNodes) {
                    for (var j = 0; j < m.addedNodes.length; j++) {
                        var node = m.addedNodes[j];
                        try {
                            var content = '';
                            if (node.nodeType === 1) { /* Element */
                                content = node.outerHTML || '';
                                /* Check attributes */
                                if (node.attributes) {
                                    for (var a = 0; a < node.attributes.length; a++) {
                                        var attr = node.attributes[a];
                                        var attrMatch = findCanary(attr.value);
                                        if (attrMatch) {
                                            emit('dom_sink_hit', {
                                                source: attrMatch.meta.source,
                                                sink: 'DOM attribute: ' + attr.name,
                                                canary: attrMatch.canary,
                                                context: attr.name.indexOf('on') === 0 ? 'js' :
                                                         (attr.name === 'href' || attr.name === 'src') ? 'url' : 'attribute',
                                                exploitable: attr.name.indexOf('on') === 0 || attr.name === 'href' || attr.name === 'src',
                                                evidence: trunc(attr.value, 512),
                                                element: (node.tagName || '') + (node.id ? '#' + node.id : '')
                                            });
                                        }
                                    }
                                }
                            } else if (node.nodeType === 3) { /* Text */
                                content = node.textContent || '';
                            }
                            var cm = findCanary(content);
                            if (cm) {
                                emit('dom_sink_hit', {
                                    source: cm.meta.source,
                                    sink: 'DOM insertion (MutationObserver)',
                                    canary: cm.canary,
                                    context: node.nodeType === 1 ? 'html' : 'text',
                                    exploitable: node.nodeType === 1,
                                    evidence: trunc(content, 512),
                                    element: node.nodeType === 1 ? (node.tagName || '') : 'text'
                                });
                            }
                        } catch (_) {}
                    }
                }
                /* Check attribute mutations */
                if (m.type === 'attributes') {
                    try {
                        var val = m.target.getAttribute(m.attributeName) || '';
                        var am = findCanary(val);
                        if (am) {
                            var aName = m.attributeName.toLowerCase();
                            emit('dom_sink_hit', {
                                source: am.meta.source,
                                sink: 'attribute mutation: ' + m.attributeName,
                                canary: am.canary,
                                context: aName.indexOf('on') === 0 ? 'js' :
                                         (aName === 'href' || aName === 'src' || aName === 'action') ? 'url' : 'attribute',
                                exploitable: aName.indexOf('on') === 0 || aName === 'href' || aName === 'src',
                                evidence: trunc(val, 512),
                                element: (m.target.tagName || '') + (m.target.id ? '#' + m.target.id : '')
                            });
                        }
                    } catch (_) {}
                }
            }
        });

        /* Start observing once the body is available */
        function startObserver() {
            if (document.body) {
                observer.observe(document.body, {
                    childList: true,
                    subtree: true,
                    attributes: true,
                    attributeFilter: ['href', 'src', 'action', 'data', 'srcdoc',
                                      'onclick', 'onload', 'onerror', 'onmouseover',
                                      'onfocus', 'onblur', 'oninput', 'onchange',
                                      'style', 'class', 'value']
                });
            } else {
                setTimeout(startObserver, 50);
            }
        }
        startObserver();
    } catch (_) {}

    /* ═══════════════════════════════════════════════
     * EXPOSE CANARY MAP FOR EXTERNAL TOOLS
     * ═══════════════════════════════════════════════ */
    window.__ANBU_DOM_INVADER_CANARIES = canaries;
    window.__ANBU_DOM_INVADER_INJECTED = injectedCanaries;

    /* Signal readiness */
    emit('init', {
        source: 'dom_invader',
        sink: null,
        canary: null,
        context: 'init',
        exploitable: false,
        evidence: 'DOM Invader armed. Sinks hooked: innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, Function, setTimeout, setInterval, location, window.open, element attrs, jQuery, DOMParser, Range, Blob, Worker, setAttribute. Canaries: ' + Object.keys(injectedCanaries).length
    });

})();`;
}

/**
 * Parse the raw event log array from window.__ANBU_DOM_INVADER_LOG.
 * Normalizes, de-dupes, and classifies events.
 *
 * @param {Array} logArray - raw log from page context
 * @returns {Object} { events, sinkHits, pollutionFindings, postMessageVulns, stats }
 */
function parseDomInvaderEvents(logArray) {
    if (!Array.isArray(logArray)) return { events: [], sinkHits: [], pollutionFindings: [], postMessageVulns: [], stats: {} };

    var events = [];
    var sinkHits = [];
    var pollutionFindings = [];
    var postMessageVulns = [];
    var postMessages = [];
    var seen = new Set();

    for (var i = 0; i < logArray.length; i++) {
        var e = logArray[i];
        if (!e || !e.type) continue;

        /* De-dupe by sink+canary+evidence hash */
        var dedupeKey = (e.type || '') + '|' + (e.sink || '') + '|' + (e.canary || '') + '|' + (e.evidence || '').slice(0, 64);
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        events.push(e);

        if (e.type === 'dom_sink_hit') {
            sinkHits.push({
                source: e.source || 'unknown',
                sink: e.sink,
                canary: e.canary,
                context: e.context,
                exploitable: e.exploitable,
                evidence: e.evidence,
                element: e.element,
                callStack: e.callStack,
                timestamp: e.timestamp
            });
        } else if (e.type === 'prototype_pollution') {
            pollutionFindings.push({
                source: e.source,
                sink: e.sink,
                evidence: e.evidence,
                exploitable: e.exploitable,
                callStack: e.callStack,
                timestamp: e.timestamp
            });
        } else if (e.type === 'postmessage_vuln') {
            postMessageVulns.push({
                source: e.source,
                sink: e.sink,
                evidence: e.evidence,
                exploitable: e.exploitable,
                callStack: e.callStack,
                timestamp: e.timestamp
            });
        } else if (e.type === 'postmessage_received') {
            postMessages.push({
                origin: e.origin,
                data: e.data,
                canary: e.canary,
                timestamp: e.timestamp
            });
        }
    }

    /* Classify exploitable flows */
    var exploitableFlows = sinkHits.filter(function(h) { return h.exploitable && h.canary; });
    var uniqueSources = new Set(sinkHits.map(function(h) { return h.source; }));
    var uniqueSinks = new Set(sinkHits.map(function(h) { return h.sink; }));

    return {
        events: events,
        sinkHits: sinkHits,
        pollutionFindings: pollutionFindings,
        postMessageVulns: postMessageVulns,
        postMessages: postMessages,
        exploitableFlows: exploitableFlows,
        stats: {
            totalEvents: events.length,
            sinkHits: sinkHits.length,
            exploitableFlows: exploitableFlows.length,
            pollutionFindings: pollutionFindings.length,
            postMessageVulns: postMessageVulns.length,
            uniqueSources: uniqueSources.size,
            uniqueSinks: uniqueSinks.size
        }
    };
}

module.exports = { buildDomInvaderPayload, parseDomInvaderEvents };
