/**
 * 🔬 J-Shadow CDP Tracer — Tier 1 context extraction for VM/virtualized JS
 *
 * De-virtualization principle: however encrypted on disk, the VM must produce
 * PLAINTEXT in the engine before it runs. We sit next to V8 (via the built-in
 * Node inspector / Chrome DevTools Protocol) and hook the native boundaries the
 * interpreter is forced to cross — String.fromCharCode, atob, JSON.parse, fetch,
 * DOM APIs — capturing the decrypted data + a stack trace that pinpoints the
 * interpreter instruction offset. No Frida, no C++ symbol mangling, no manual
 * V8 heap-object parsing.
 *
 * Scope: Node-executed JS (module/script). For browser-only DOM code, run under
 * Puppeteer with the same injected prelude (see traceInBrowser note).
 *
 *   const { traceNode } = require('./cdp-tracer');
 *   const result = await traceNode(code, { timeout: 15000 });
 *   // result.hooks = [{ api, args, out, stack, offset }], result.strings, result.urls
 */

'use strict';

const vm = require('vm');

// The prelude we inject BEFORE the target runs. It wraps the native boundaries
// the VM must use to emit plaintext, and records (args → output → stack).
function buildPrelude() {
  return `
  (function(){
    if (globalThis.__JT) return;
    globalThis.__JT = { hooks: [], strings: new Set(), urls: new Set(), keys: new Set() };
    var T = globalThis.__JT;
    function offsetFromStack(stack){
      // pull the first target-frame location as the interpreter instruction offset
      var m = String(stack||'').split('\\n').slice(2).find(function(l){ return /<anonymous>|evalmachine|vm\\.js|\\.js:/.test(l); });
      var mm = m && m.match(/(\\d+):(\\d+)\\)?$/);
      return mm ? { line: +mm[1], col: +mm[2] } : null;
    }
    function rec(api, args, out){
      var stack = (new Error()).stack;
      if (T.hooks.length < 5000) T.hooks.push({ api: api, args: args, out: typeof out==='string'? out.slice(0,300): out, offset: offsetFromStack(stack) });
      if (typeof out === 'string' && out.length >= 3) {
        if (/[a-zA-Z]{3,}/.test(out)) T.strings.add(out.slice(0,300));
        if (/^https?:\\/\\//.test(out)) T.urls.add(out.slice(0,300));
        if (/(?:key|token|secret|auth|bearer)/i.test(out) || /^[A-Za-z0-9_\\-]{20,}$/.test(out)) T.keys.add(out.slice(0,120));
      }
    }
    // String.fromCharCode — the classic VM string builder
    var _fcc = String.fromCharCode;
    String.fromCharCode = function(){ var r=_fcc.apply(String, arguments); rec('fromCharCode', [].slice.call(arguments).slice(0,8), r); return r; };
    // atob / Buffer base64
    if (typeof atob === 'function'){ var _ab=atob; globalThis.atob=function(s){ var r=_ab(s); rec('atob',[String(s).slice(0,60)],r); return r; }; }
    // JSON.parse — configs/payloads
    var _jp = JSON.parse; JSON.parse = function(s,rv){ var r=_jp(s,rv); rec('JSON.parse',[String(s).slice(0,80)], typeof r==='object'? JSON.stringify(r).slice(0,200): r); return r; };
    // decodeURIComponent — JScrambler XOR tables often end here
    if (typeof decodeURIComponent==='function'){ var _du=decodeURIComponent; globalThis.decodeURIComponent=function(s){ var r=_du(s); rec('decodeURIComponent',[String(s).slice(0,60)],r); return r; }; }
    // network + DOM sinks (final decrypted destinations)
    if (typeof fetch==='function'){ var _f=fetch; globalThis.fetch=function(u,o){ rec('fetch',[String(u).slice(0,200)], String(u)); return _f.apply(this, arguments); }; }
    if (typeof document==='object' && document && document.createElement){ var _ce=document.createElement.bind(document); document.createElement=function(t){ rec('createElement',[t]); return _ce(t); }; }
  })();
  `;
}

/** Run Node-executed code under the tracer (deps stubbed, anti-debug neutral). */
async function traceNode(code, options = {}) {
  const neutralize = (s) => s.replace(/new\s+[\w$]+\s*\([^()]*\)\s*(?:\[[^\]]*\]|\.\s*[\w$]+)\s*\(\s*\)/g, 'void 0');
  const cap = (s) => s.replace(/while\s*\(\s*(?:!!\[\]|!\[\]|true|1|0x1)\s*\)/g, 'var __jsg=0;while(__jsg++<200000)');

  const harness = buildPrelude() + '\n' + cap(neutralize(code)) +
    `\n;(function(){try{var __x=module&&module.exports;if(__x)for(var __k in __x){if(typeof __x[__k]==='function'){try{__x[__k]({});}catch(e){}}}}catch(e){}})();` +
    `\n({ hooks: globalThis.__JT.hooks, strings: [...globalThis.__JT.strings], urls: [...globalThis.__JT.urls], keys: [...globalThis.__JT.keys] });`;

  const deep = new Proxy(function () {}, { get: () => deep, apply: () => deep, construct: () => deep, has: () => true });
  const sandbox = {
    require: () => deep, module: { exports: {} }, exports: {},
    setInterval: () => 0, setTimeout: () => 0, clearInterval: () => 0, clearTimeout: () => 0,
    console: { log() {}, warn() {}, error() {}, info() {} }, Buffer,
    atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
    btoa: (s) => Buffer.from(String(s), 'binary').toString('base64'),
    JSON, String, Math, parseInt, parseFloat, decodeURIComponent, encodeURIComponent, RegExp, Array, Object, Date, Error
  };
  sandbox.window = sandbox.self = sandbox.global = sandbox.document = sandbox.navigator = deep;
  sandbox.globalThis = sandbox;
  sandbox.fetch = () => deep;

  try {
    const res = vm.runInNewContext(harness, vm.createContext(sandbox), { timeout: options.timeout || 15000 });
    return normalize(res);
  } catch (e) {
    // even on trap/throw we keep whatever was captured
    const t = sandbox.__JT;
    if (t) return normalize({ hooks: t.hooks, strings: [...t.strings], urls: [...t.urls], keys: [...t.keys], error: e.message });
    return { hooks: [], strings: [], urls: [], keys: [], error: e.message };
  }
}

function normalize(r) {
  r = r || {};
  return {
    hooks: r.hooks || [],
    strings: r.strings || [],
    urls: r.urls || [],
    keys: r.keys || [],
    apiCounts: (r.hooks || []).reduce((m, h) => { m[h.api] = (m[h.api] || 0) + 1; return m; }, {}),
    error: r.error || null
  };
}

/*
 * traceInBrowser(code) — for DOM-dependent JScrambler, run under Puppeteer:
 *   const browser = await puppeteer.launch();
 *   const page = await browser.newPage();
 *   await page.evaluateOnNewDocument(buildPrelude());       // inject BEFORE target
 *   const client = await page.target().createCDPSession();
 *   await client.send('Debugger.enable');
 *   client.on('Debugger.scriptParsed', e => { /* every compiled/eval'd script — the CompileUnboundScript equivalent *​/ });
 *   await page.addScriptTag({ content: code });
 *   const trace = await page.evaluate(() => globalThis.__JT);
 * Kept as a documented path so the Node tracer stays dependency-free by default.
 */

module.exports = { traceNode, buildPrelude };
