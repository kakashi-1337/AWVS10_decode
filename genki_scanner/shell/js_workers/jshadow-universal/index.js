/**
 * 🥷 J-SHADOW UNIVERSAL v1.6 — the router that makes it universal
 *
 * One entry point. It fingerprints the file (patterns.json + AST recon), then
 * routes to the engine that is provably best for that family, escalating from
 * static → dynamic (sandbox instrument+hook) → AI only when needed, and learns
 * the result back into patterns.json.
 *
 *   const { deobfuscate } = require('./index');
 *   const r = await deobfuscate(code, { filename, aiKey, verbose });
 *
 * Routing (from the superiority matrix):
 *   obfuscator.io + RC4/rotation/self-defend → core dynamic (instrument+hook)   [PROVEN]
 *   jscrambler                               → JScramblerUniversal / V11
 *   webpack / bundlers                        → core webpack splitter
 *   packers / esoteric                        → core unpack + fold
 *   fallback                                  → core static
 *   leftovers after all tiers                 → AI (needs key; otherwise notify)
 *
 * v1.6 CHANGELOG (measured on 4 real RC4 modules + fresh unseen obfuscator.io):
 *   #3 preProcess made PARSE-SAFE — hex/unicode transforms were corrupting
 *      obfuscator.io self-defending string literals ('[\'|"]...'), which broke
 *      the rename tier on EVERY file (0 idents renamed). Now every transform is
 *      reverted if it fails to parse. + smart-renamer parses with errorRecovery.
 *   #2 JSIR Const Bindings + transitive proxy resolution (buildResolver) —
 *      resolves OBJ.PROP const-object reads AND folds proxy chains
 *      (proxy→proxy→base, incl. proxies that hoist a local const-object) down to
 *      a base decoder + concrete args. Fixed 70–834 unresolved calls / file.
 *   #2b 100% call-site COVERAGE — statically enumerate every resolvable call
 *      site and evaluate it directly against the live (rotated) decoders in the
 *      sandbox, instead of only recording strings that executed at runtime.
 *   #4 dead-scaffolding strip — after inlining, remove the string array(s),
 *      base decoders, all proxies, rotation IIFE(s), self-defending once-wrappers
 *      and now-unreferenced const-index objects (fixpoint). Output 0.18–0.43x.
 *   + detectDecoders is multi-array aware (files bundling several systems).
 *   Result: all 4 samples → 0 remaining decoder-calls, valid JS, readable logic.
 *   Remaining _0x are app-level local var names (recovered only by the AI tier).
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const JShadowCore = require('./modules/jshadow-core');      // PROVEN engine (RC4/rotation/proxy/fold/rename)
const { recon } = require('./modules/recon-ast');           // AST-shape + entropy fingerprint
let advancedRecon; try { advancedRecon = require('./modules/advanced-recon').advancedRecon; } catch (e) { advancedRecon = null; } // trap detection + family classifier

let babel, traverse, t, generate;
try {
  babel = require('@babel/core');
  traverse = require('@babel/traverse').default;
  t = require('@babel/types');
  generate = require('@babel/generator').default;
} catch (e) {}

// ── patterns.json signature DB (self-learning) ──
const DB_PATH = path.join(__dirname, 'patterns.json');
function loadDB() { try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); } catch (e) { return null; } }
function saveDB(db) { try { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); return true; } catch (e) { return false; } }

/** Call AI for leftover cleanup. Supports Gemini, OpenAI, Ollama. */
async function callAI(code, apiKey, provider, model, profile, ollamaUrl) {
  const snippet = code.length > 6000 ? code.slice(0, 3000) + '\n/* ... truncated ... */\n' + code.slice(-2000) : code;
  const prompt = `You are a JavaScript security researcher. The following code has been partially deobfuscated. 
Please rename any remaining obfuscated identifiers (like _0x1a2b, a0_0x4295) to meaningful names based on their usage context.
Also clean up any remaining anti-debug/self-defending boilerplate that is not part of the app logic.
Return ONLY the cleaned JavaScript code, no explanation.

Detected family: ${profile.familyLabel}
Encodings: ${profile.encodings.join(', ') || 'none'}

Code:\n\`\`\`javascript\n${snippet}\n\`\`\``;

  if (provider === 'ollama') {
    const url = (ollamaUrl || 'http://localhost:11434') + '/api/generate';
    const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'llama3', prompt, stream: false }) });
    const data = await resp.json();
    const cleaned = extractCodeBlock(data.response || '');
    return { code: cleaned || code, provider: 'ollama', changes: 'renamed' };
  }

  if (provider === 'openai') {
    const resp = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
      body: JSON.stringify({ model: model || 'gpt-4o-mini', messages: [{ role: 'user', content: prompt }], max_tokens: 8192, temperature: 0.1 }) });
    const data = await resp.json();
    const cleaned = extractCodeBlock(data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content || '');
    return { code: cleaned || code, provider: 'openai', changes: 'renamed' };
  }

  // Default: Gemini
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model || 'gemini-2.0-flash'}:generateContent?key=${apiKey}`;
  const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.1, maxOutputTokens: 8192 } }) });
  const data = await resp.json();
  const text = data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts && data.candidates[0].content.parts[0] && data.candidates[0].content.parts[0].text || '';
  const cleaned = extractCodeBlock(text);
  return { code: cleaned || code, provider: 'gemini', changes: 'renamed' };
}

function extractCodeBlock(text) {
  const m = text.match(/```(?:javascript|js)?\s*\n([\s\S]*?)\n```/);
  return m ? m[1].trim() : (text.includes('function ') || text.includes('var ') || text.includes('const ') ? text.trim() : null);
}

/** Pre-process: lightweight transforms for simple obfuscation layers.
 *  PARSE-SAFE: obfuscator.io self-defending code embeds regex-like string
 *  literals with escaped quotes ('[\'|"].+[\'|"];? *}') that naive
 *  hex/unicode/concat regexes can corrupt (stripping the \ off \'), which then
 *  breaks EVERY downstream pass. So every transform is gated on the result
 *  still parsing — if a step would corrupt the file, it is reverted (Dave's
 *  rule: never ship garbage). */
function preProcess(code) {
  const parses = (s) => {
    if (!babel) return true; // no parser available → can't verify, allow
    try { babel.parse(s, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } }); return true; }
    catch (e) { return false; }
  };
  // apply fn; keep the result only if it changed AND still parses
  const step = (c, fn) => { let next; try { next = fn(c); } catch (e) { return c; } return (next !== c && parses(next)) ? next : c; };

  let c = code;
  // 1. eval(unescape(...)) — unpack
  c = step(c, s => s.replace(/eval\s*\(\s*unescape\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\)/g, (m, enc) => {
    try { return decodeURIComponent(enc); } catch (e) { return m; }
  }));
  // 2. eval(atob(...)) — base64 unpack
  c = step(c, s => s.replace(/eval\s*\(\s*atob\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)\s*\)/g, (m, b64) => {
    try { return Buffer.from(b64, 'base64').toString('utf8'); } catch (e) { return m; }
  }));
  // 3. Hex escapes: \x68\x65 → he. Escape-aware inner match + skip any literal
  //    that contains escaped quotes (self-defending regex strings).
  c = step(c, s => s.replace(/(["'`])((?:[^"'`\\]|\\.)*?\\x[0-9a-fA-F]{2}(?:[^"'`\\]|\\.)*?)\1/g, (m, q, inner) => {
    if (/\\['"]/.test(inner)) return m;
    try { return q + inner.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) + q; } catch (e) { return m; }
  }));
  // 4. Unicode escapes: \u0068 → h. Same guards.
  c = step(c, s => s.replace(/(["'`])((?:[^"'`\\]|\\.)*?\\u[0-9a-fA-F]{4}(?:[^"'`\\]|\\.)*?)\1/g, (m, q, inner) => {
    if (/\\['"]/.test(inner)) return m;
    try { return q + inner.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) + q; } catch (e) { return m; }
  }));
  // 5. Simple string concatenation: "a" + "b" → "ab" (no escapes in operands).
  for (let i = 0; i < 5; i++) {
    const next = step(c, s => s.replace(/(["'])([^"'\\]*)\1\s*\+\s*(["'])([^"'\\]*)\3/g, (m, q1, s1, q2, s2) => q1 + s1 + s2 + q1));
    if (next === c) break;
    c = next;
  }
  return c;
}

/** Universal check: does the code still have obfuscated identifiers?
 *  Not just _0x — also short random-looking names (a0_0x..., _$, single-char
 *  vars used excessively, hex-heavy names, etc.). */
function hasObfuscatedNames(code) {
  // Pattern 1: _0x style (obfuscator.io / javascript-obfuscator)
  if (/_0x[0-9a-f]{4,}/i.test(code)) return true;
  // Pattern 2: a0_0x style (obfuscator.io variant)
  if (/\ba\d+_0x[0-9a-f]+/i.test(code)) return true;
  // Pattern 3: very short random names used excessively (minified leftovers)
  const shortNames = code.match(/\b[a-zA-Z_$]{1,2}\d{0,2}\b/g) || [];
  if (shortNames.length > 200) return true;  // excessive short names = still obfuscated
  // Pattern 4: JScrambler namespace patterns
  if (/\b[A-Za-z]\d[A-Za-z]{2,4}\b/.test(code) && /\.\w{1,3}\s*=\s*\(function/.test(code)) return true;
  return false;
}

/** Best-effort plaintext extraction for VM/virtualized code we can't fully decode. */
function extractPlaintext(code) {
  const strings = [...new Set((code.match(/["'`]([\x20-\x7E]{4,120})["'`]/g) || [])
    .map(s => s.slice(1, -1))
    .filter(s => /[a-zA-Z]{3,}/.test(s) && !/^[\\x0-9a-f]+$/i.test(s)))].slice(0, 300);
  const urls = [...new Set((code.match(/https?:\/\/[^\s"'`)]+/g) || []))].slice(0, 100);
  const keyRe = /(?:api[_-]?key|secret|token|password|auth|bearer|private[_-]?key)["'\s:=]+([A-Za-z0-9_\-./+=]{8,})/gi;
  const keys = []; let m; while ((m = keyRe.exec(code)) && keys.length < 50) keys.push(m[0].slice(0, 80));
  return { strings, urls, keys };
}

/** Stable hash of the decoder functions' shape (survives renaming). */
function computeShapeHash(code, baseNames) {
  if (!babel || !baseNames.length) return null;
  let ast; try { ast = babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } }); } catch (e) { return null; }
  let src = '';
  traverse(ast, { FunctionDeclaration(p) { const n = p.node.id && p.node.id.name; if (baseNames.includes(n)) { try { src += generate(p.node, { compact: true }).code; } catch (e) {} } } });
  if (!src) return null;
  const norm = src
    .replace(/_0x[0-9a-fA-F]+|[A-Za-z_$][\w$]*/g, 'ID')
    .replace(/0x[0-9a-fA-F]+|\d+/g, 'N')
    .replace(/(["'])(?:\\.|(?!\1).)*\1/g, 'S')
    .replace(/\s+/g, '');
  return require('crypto').createHash('sha1').update(norm).digest('hex').slice(0, 16);
}

/** Fingerprint using patterns.json families + AST recon; return a merged profile. */
function fingerprint(code) {
  const profile = recon(code);                 // AST-based (family, encodings, antiDebug, structure, strategy)
  // Advanced recon layer: trap detection (pre-execution safety), encoding/bundler/
  // VM/JScrambler classification, multi-layer stacking, and novelty scoring. This
  // COMPLEMENTS the proven obfuscator.io path — it never overrides a working route,
  // it enriches the profile (traps to neutralize, honest family/route for the rest).
  if (advancedRecon) {
    try {
      const adv = profile.advanced = advancedRecon(code);
      profile.traps = adv.traps || [];
      profile.neutralizePlan = adv.neutralizePlan || [];
      profile.novelty = adv.novelty;
      profile.advFamily = adv.family;
      profile.advConfidence = adv.confidence;
      // cross-check: if the legacy recon found nothing but advanced classified a
      // non-obfuscator family (packer/vm/jscrambler/esoteric/bundler), adopt it.
      if (adv.family && adv.family !== 'obfuscator_io' && (!profile.strategy || profile.strategy === 'static')) {
        profile.advRoute = adv.route;
      }
    } catch (e) { profile.traps = profile.traps || []; }
  }
  // recon's single-pass decoder scan can miss decoders declared before the array;
  // recompute with the robust two-pass detector so the shape hash is reliable.
  const baseNames = detectDecoders(code);
  if (baseNames.length) profile.structure.decoders = baseNames;
  if (!profile.shapeHash) profile.shapeHash = computeShapeHash(code, baseNames);
  const db = loadDB();
  const dbHits = [];
  if (db && db.patterns) {
    for (const [group, families] of Object.entries(db.patterns)) {
      for (const [famName, fam] of Object.entries(families)) {
        if (!fam.signatures) continue;
        let score = 0;
        for (const sig of fam.signatures) {
          try {
            const ok = sig.type === 'literal'
              ? code.includes(sig.pattern)
              : new RegExp(sig.pattern, sig.multiline ? 'm' : '').test(code);
            if (ok) score += sig.weight || 0.5;
          } catch (e) {}
        }
        if (score >= 0.8) dbHits.push({ group, family: famName, score: +score.toFixed(2), handler: fam.handler });
      }
    }
  }
  dbHits.sort((a, b) => b.score - a.score);
  profile.dbHits = dbHits;
  profile.dbFamily = dbHits[0] || null;

  // ── SELF-LEARNING lookup: have we seen this exact decoder shape before? ──
  // If yes, reuse the learned route instantly (skip guessing) and mark it.
  profile.learnedHit = null;
  if (db && db.fingerprints && profile.shapeHash && db.fingerprints[profile.shapeHash]) {
    const fp = db.fingerprints[profile.shapeHash];
    profile.learnedHit = fp;
    profile.confidence = Math.min(0.99, (profile.confidence || 0.5) + 0.15);
  }

  // Family decision: learned shape > strong DB hit > AST recon
  if (profile.learnedHit && profile.learnedHit.route) {
    profile.route = profile.learnedHit.route;
  } else if (profile.isVM) {
    profile.route = 'virtualized';
  } else if (profile.strategy === 'jscrambler') {
    profile.route = 'jscrambler';
  } else if (dbHits.length) {
    const top = dbHits[0];
    // Strategy-determined routes (unpack/debundle) take priority unless the dbHit
    // is genuinely that family — prevents a false-positive jscrambler hit from
    // overriding a correctly identified packer/webpack.
    if (profile.strategy === 'unpack_then_static' || profile.strategy === 'debundle') {
      profile.route = profile.strategy === 'debundle' ? 'webpack' : 'esoteric';
    } else if (top.family.includes('jscrambler') && profile.family !== 'packer_eval') {
      profile.route = 'jscrambler';
    } else if (top.group === 'bundlers') {
      profile.route = 'webpack';
    } else if (top.group === 'encodings' && /jsfuck|jjencode|aaencode/.test(top.family)) {
      profile.route = 'esoteric';
    } else {
      profile.route = profile.strategy === 'dynamic' ? 'obfuscator_dynamic' : 'obfuscator_static';
    }
  } else {
    profile.route = profile.strategy === 'virtualized' ? 'virtualized'
      : profile.strategy === 'jscrambler' ? 'jscrambler'
      : profile.strategy === 'dynamic' ? 'obfuscator_dynamic'
      : profile.strategy === 'debundle' ? 'webpack'
      : profile.strategy === 'unpack_then_static' ? 'esoteric'
      : 'obfuscator_static';
  }
  return profile;
}

/** Recognize a proxy/wrapper function and return its forwarded call.
 *  Handles obfuscator.io proxies that hoist a LOCAL const-object before the
 *  return (function p(a,b){ const OBJ={...}; return decoder(b-OBJ.x, a); }) as
 *  well as arrow expression bodies — the missing case that broke deep chains. */
function extractProxyForward(fnNode) {
  let retCall = null;
  if (fnNode.body && fnNode.body.type === 'BlockStatement') {
    const stmts = fnNode.body.body;
    if (!stmts || !stmts.length) return null;
    const last = stmts[stmts.length - 1];
    if (!t.isReturnStatement(last) || !last.argument) return null;
    for (let i = 0; i < stmts.length - 1; i++) if (!t.isVariableDeclaration(stmts[i])) return null; // only const/var hoists allowed before the return
    retCall = last.argument;
  } else if (fnNode.body) {
    retCall = fnNode.body; // arrow: => call(...)
  }
  if (!retCall || !t.isCallExpression(retCall) || !t.isIdentifier(retCall.callee)) return null;
  return { callee: retCall.callee.name, args: retCall.arguments, params: (fnNode.params || []).map(p => p && p.name) };
}

/** Unified resolver: const-object member reads (JSIR Const Bindings) + transitive
 *  proxy-chain folding down to a base decoder + concrete args. Used by BOTH the
 *  coverage collector and the backfill replacer so they agree on every call site. */
function buildResolver(ast, baseNames) {
  const nameSet = new Set(baseNames);
  const objMap = new Map(), objAmb = new Set();
  traverse(ast, { VariableDeclarator(p) {
    if (!t.isIdentifier(p.node.id) || !t.isObjectExpression(p.node.init)) return;
    const on = p.node.id.name;
    for (const pr of p.node.init.properties) {
      if (!t.isObjectProperty(pr)) continue;
      const k = t.isIdentifier(pr.key) ? pr.key.name : (t.isStringLiteral(pr.key) ? pr.key.value : null);
      if (k == null) continue;
      let v;
      if (t.isStringLiteral(pr.value) || t.isNumericLiteral(pr.value) || t.isBooleanLiteral(pr.value)) v = pr.value.value;
      else if (t.isUnaryExpression(pr.value) && pr.value.operator === '-' && t.isNumericLiteral(pr.value.argument)) v = -pr.value.argument.value;
      else continue;
      const mk = on + '\u0000' + k;
      if (objMap.has(mk) && objMap.get(mk) !== v) objAmb.add(mk); else objMap.set(mk, v);
    }
  }});
  const memberVal = (n) => {
    if (!t.isMemberExpression(n) || !t.isIdentifier(n.object)) return undefined;
    let k = null;
    if (!n.computed && t.isIdentifier(n.property)) k = n.property.name;
    else if (n.computed && t.isStringLiteral(n.property)) k = n.property.value;
    if (k == null) return undefined;
    const mk = n.object.name + '\u0000' + k;
    return (!objAmb.has(mk) && objMap.has(mk)) ? objMap.get(mk) : undefined;
  };
  const ews = (n, subst) => {
    if (n == null) return undefined;
    if (t.isNumericLiteral(n) || t.isStringLiteral(n) || t.isBooleanLiteral(n)) return n.value;
    if (t.isIdentifier(n) && subst && n.name in subst) return subst[n.name];
    if (t.isMemberExpression(n)) return memberVal(n);
    if (t.isUnaryExpression(n) && n.operator === '-') { const v = ews(n.argument, subst); return v === undefined ? undefined : -v; }
    if (t.isBinaryExpression(n)) {
      const l = ews(n.left, subst); if (l === undefined) return undefined;
      const r = ews(n.right, subst); if (r === undefined) return undefined;
      switch (n.operator) { case '+': return l + r; case '-': return l - r; case '*': return l * r; case '|': return l | r; case '&': return l & r; case '^': return l ^ r; case '>>': return l >> r; case '<<': return l << r; case '>>>': return l >>> r; default: return undefined; }
    }
    return undefined;
  };
  const proxies = new Map();
  traverse(ast, {
    FunctionDeclaration(p) { if (!p.node.id) return; const pf = extractProxyForward(p.node); if (pf) proxies.set(p.node.id.name, pf); },
    VariableDeclarator(p) { const init = p.node.init; if ((!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init)) || !t.isIdentifier(p.node.id)) return; const pf = extractProxyForward(init); if (pf) proxies.set(p.node.id.name, pf); }
  });
  const resolveToBase = (name, argVals, depth) => {
    if (depth > 8) return null;
    if (nameSet.has(name)) return { d: name, args: argVals };
    const px = proxies.get(name); if (!px) return null;
    const subst = {}; for (let i = 0; i < px.params.length && i < argVals.length; i++) subst[px.params[i]] = argVals[i];
    const fwd = []; for (const a of px.args) { const v = ews(a, subst); if (v === undefined) return null; fwd.push(v); }
    return resolveToBase(px.callee, fwd, depth + 1);
  };
  const isTarget = (name) => nameSet.has(name) || proxies.has(name);
  const resolveCall = (callNode) => {
    const cal = callNode.callee; if (!t.isIdentifier(cal) || !isTarget(cal.name)) return null;
    const argVals = []; for (const a of callNode.arguments) { const v = ews(a, null); if (v === undefined) return null; argVals.push(v); }
    const base = resolveToBase(cal.name, argVals, 0); if (!base) return null;
    return { d: base.d, args: base.args, key: base.d + '\u0000' + JSON.stringify(base.args) };
  };
  return { resolveCall, proxies, memberVal };
}

/** Strip obfuscator.io scaffolding that is DEAD after all string calls are
 *  inlined: the string-array provider, the base decoders, every proxy wrapper,
 *  the rotation IIFE, and self-defending/anti-debug IIFEs. Then fixpoint-remove
 *  any binding left unreferenced (dead const-index objects, orphan helpers).
 *  Runs ONLY after backfill got decoder-calls to ~0, so removal is safe.
 *  This is the #4 gap: strings decoded but machinery kept → output stayed huge. */
function stripScaffolding(code, baseNames) {
  if (!babel) return code;
  let ast; try { ast = babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } }); } catch (e) { return code; }
  const nameSet = new Set(baseNames);

  // (a) locate ALL string-array providers (a file may bundle several systems)
  const arrayNames = new Set();
  traverse(ast, { 'FunctionDeclaration|VariableDeclarator'(p) {
    let arr = null, name = null;
    if (p.isFunctionDeclaration() && p.node.id) {
      name = p.node.id.name; const b = p.node.body.body || [];
      const ret = b.find(s => t.isReturnStatement(s)); if (ret && t.isArrayExpression(ret.argument)) arr = ret.argument;
      if (!arr) for (const s of b) if (t.isVariableDeclaration(s)) { const d = s.declarations.find(d => t.isArrayExpression(d.init)); if (d) { arr = d.init; break; } }
    } else if (p.isVariableDeclarator() && t.isIdentifier(p.node.id) && t.isArrayExpression(p.node.init)) { name = p.node.id.name; arr = p.node.init; }
    if (arr && arr.elements.length >= 10 && arr.elements.filter(e => e && t.isStringLiteral(e)).length >= arr.elements.length * 0.6) arrayNames.add(name);
  }});

  // (b) collect proxy names transitively (fn body = `return decoderOrProxy(...)`)
  const proxyNames = new Set();
  const isDP = (nm) => nameSet.has(nm) || proxyNames.has(nm);
  let grew = true;
  while (grew) {
    grew = false;
    traverse(ast, {
      FunctionDeclaration(p) { const fn = p.node; if (!fn.id || proxyNames.has(fn.id.name)) return; const b = fn.body && fn.body.body; if (!b || b.length !== 1 || !t.isReturnStatement(b[0])) return; const r = b[0].argument; if (t.isCallExpression(r) && t.isIdentifier(r.callee) && isDP(r.callee.name)) { proxyNames.add(fn.id.name); grew = true; } },
      VariableDeclarator(p) { const init = p.node.init; if ((!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init)) || !t.isIdentifier(p.node.id) || proxyNames.has(p.node.id.name)) return; const b = init.body && (t.isBlockStatement(init.body) ? init.body.body : null); if (!b || b.length !== 1 || !t.isReturnStatement(b[0])) return; const r = b[0].argument; if (t.isCallExpression(r) && t.isIdentifier(r.callee) && isDP(r.callee.name)) { proxyNames.add(p.node.id.name); grew = true; } }
    });
  }

  const removable = new Set([...nameSet, ...proxyNames, ...arrayNames]);
  const antiDbgSig = /constructor|toString|search|while|RegExp|debugg|__proto__|apply/;

  // (c) remove self-executing obfuscation ExpressionStatements
  traverse(ast, { ExpressionStatement(p) {
    const e = p.node.expression;
    // rotation IIFE: (function(a,b){...})(arrayName, N)
    if (t.isCallExpression(e) && (t.isFunctionExpression(e.callee) || t.isArrowFunctionExpression(e.callee)) && e.arguments.some(a => t.isIdentifier(a) && arrayNames.has(a.name))) { p.remove(); return; }
    // bare anti-debug call: IDENT();  where IDENT = onceWrap(this, function(){...antidbg...})
    if (t.isCallExpression(e) && t.isIdentifier(e.callee) && e.arguments.length === 0) {
      const b = p.scope.getBinding(e.callee.name);
      if (b && b.path && t.isVariableDeclarator(b.path.node) && t.isCallExpression(b.path.node.init)) {
        let src = ''; try { src = generate(b.path.node.init).code; } catch (e2) {}
        if (antiDbgSig.test(src)) { try { b.path.remove(); } catch (e2) {} p.remove(); return; }
      }
    }
    // inline self-invoked anti-debug: (function(){...})() referencing removable only
    if (t.isCallExpression(e) && (t.isFunctionExpression(e.callee) || t.isArrowFunctionExpression(e.callee)) && e.arguments.length === 0) {
      let src = ''; try { src = generate(e).code; } catch (e2) {}
      if (/setInterval|debugg|constructor\(.{0,40}return/.test(src) && src.length < 4000) { p.remove(); return; }
    }
  }});

  // (d) remove decls of decoders, proxies, array provider
  traverse(ast, {
    FunctionDeclaration(p) { if (p.node.id && removable.has(p.node.id.name)) p.remove(); },
    VariableDeclarator(p) { if (t.isIdentifier(p.node.id) && removable.has(p.node.id.name)) p.remove(); }
  });

  // (e) fixpoint: drop bindings left unreferenced (dead const-index objects, orphans)
  // pure IIFE once-wrapper: function(){ let f=true; return function(){...}; }()
  const isPureOnceWrapper = (init) => {
    if (!t.isCallExpression(init) || init.arguments.length) return false;
    const fn = init.callee;
    if (!t.isFunctionExpression(fn) && !t.isArrowFunctionExpression(fn)) return false;
    const b = fn.body && fn.body.body; if (!b) return false;
    return b.some(s => t.isReturnStatement(s) && (t.isFunctionExpression(s.argument) || t.isArrowFunctionExpression(s.argument)));
  };
  let pass = 0, changed = true;
  while (changed && pass++ < 8) {
    changed = false;
    traverse(ast, { Program(pp) { pp.scope.crawl(); } });
    traverse(ast, {
      FunctionDeclaration(p) { const n = p.node.id && p.node.id.name; if (!n) return; const b = p.scope.getBinding(n); if (b && !b.referenced) { p.remove(); changed = true; } },
      VariableDeclarator(p) {
        if (!t.isIdentifier(p.node.id)) return; const n = p.node.id.name; const b = p.scope.getBinding(n);
        if (b && !b.referenced) { const init = p.node.init; if (init == null || t.isObjectExpression(init) || t.isFunctionExpression(init) || t.isArrowFunctionExpression(init) || t.isArrayExpression(init) || t.isStringLiteral(init) || t.isNumericLiteral(init) || t.isBooleanLiteral(init) || t.isIdentifier(init) || isPureOnceWrapper(init)) { p.remove(); changed = true; } }
      }
    });
  }

  try { return generate(ast, { compact: false, comments: true }).code; } catch (e) { return code; }
}

/** Statically enumerate EVERY resolvable decoder call site (direct + proxy),
 *  resolve args via const-bindings, and transitively fold proxy chains down to
 *  a base decoder + concrete args. Returns [{ d: baseName, args: [...] }] deduped.
 *  This gives the dynamic decoder 100% call-site COVERAGE (not just the strings
 *  that happened to execute during the dry-run) — the fix for the 189-call-sites
 *  vs 103-recorded-strings coverage gap. */
function collectDecoderCalls(code, baseNames) {
  if (!babel || !baseNames.length) return [];
  let ast; try { ast = babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } }); } catch (e) { return []; }
  const { resolveCall } = buildResolver(ast, baseNames);
  const out = [], seen = new Set();
  traverse(ast, { CallExpression(p) {
    const r = resolveCall(p.node); if (!r) return;
    if (seen.has(r.key)) return; seen.add(r.key); out.push({ d: r.d, args: r.args });
  }});
  return out;
}

// ── Dynamic decode: run the file's OWN decoders (instrument + hook + trigger) ──
// This is the proven approach that cracked RC4 + rotation + self-defending modules.
function dynamicDecode(code, baseNames, deadline) {
  if (!babel || !baseNames.length) return { map: {}, count: 0 };
  const neutralize = (s) => s.replace(/new\s+[\w$]+\s*\([^()]*\)\s*(?:\[[^\]]*\]|\.\s*[\w$]+)\s*\(\s*\)/g, 'void 0');
  const cap = (s) => s.replace(/while\s*\(\s*(?:!!\[\]|!\[\]|true|1|0x1)\s*\)/g, 'var __jsg=0;while(__jsg++<8000)');

  // IMPORTANT: run the ORIGINAL (minified) code as-is. Re-parsing/pretty-printing
  // rewrites the anti-debug self-check function so its .toString() no longer
  // matches its own regex — which flips it into the recursion trap (decode with a
  // bad key → "URI malformed") and corrupts every string. Minified, the check is
  // benign, so we only neutralize the explicit trap call and cap rotation loops.
  const wraps = baseNames.map(d =>
    `var __o_${d}=${d};${d}=function(){var r=__o_${d}.apply(this,arguments);try{globalThis.__JR[${JSON.stringify(d)}+"\\u0000"+JSON.stringify([].slice.call(arguments))]=String(r);}catch(e){}return r;};`
  ).join('');
  // 100% COVERAGE: statically-collected call sites, evaluated directly against
  // the live (rotated) decoders — catches strings never hit at runtime.
  const callList = collectDecoderCalls(code, baseNames);
  const fnMap = '{' + baseNames.map(d => `${JSON.stringify(d)}:__o_${d}`).join(',') + '}';
  const directEval = callList.length
    ? `try{var __FNS=${fnMap};var __CALLS=${JSON.stringify(callList)};for(var __i=0;__i<__CALLS.length;__i++){var __c=__CALLS[__i];var __fn=__FNS[__c.d];if(__fn){try{globalThis.__JR[__c.d+"\\u0000"+JSON.stringify(__c.args)]=String(__fn.apply(null,__c.args));}catch(e){}}}}catch(e){}`
    : '';
  const harness = cap(neutralize(code)) + `\n;(function(){try{globalThis.__JR={};${wraps}` +
    `try{var __x=module&&module.exports;if(__x)for(var __k in __x){if(typeof __x[__k]==="function"){try{__x[__k]({});}catch(e){}}}}catch(e){}` +
    directEval +
    `}catch(e){globalThis.__ERR=e&&e.message;}})();globalThis.__JR;`;

  const deep = new Proxy(function () {}, { get: () => deep, apply: () => deep, construct: () => deep, has: () => true });
  const sb = { require: () => deep, module: { exports: {} }, exports: {}, setInterval: () => 0, setTimeout: () => 0, clearInterval: () => 0, clearTimeout: () => 0, console: { log() {}, warn() {}, error() {}, info() {} }, Buffer,
    // Node globals that obfuscated modules may reference before reaching decoder hooks
    process: { env: {}, platform: 'linux', arch: 'x64', version: 'v22.0.0', versions: {}, argv: [], cwd: () => '/', exit: () => {}, on: () => deep, nextTick: (fn) => { try { fn(); } catch(e){} } },
    __dirname: '/', __filename: '/index.js'
  };
  sb.window = sb.self = sb.global = sb.document = sb.navigator = deep; sb.globalThis = sb;

  let map = {};
  try {
    const budget = Math.max(3000, Math.min(30000, (deadline || Date.now() + 30000) - Date.now()));
    const res = vm.runInNewContext(harness, vm.createContext(sb), { timeout: budget });
    if (res && typeof res === 'object') for (const k of Object.keys(res)) if (typeof res[k] === 'string') map[k] = res[k];
  } catch (e) { map = sb.__JR || {}; }
  return { map, count: Object.keys(map).length };
}

/** Detect base decoder names — UNIVERSAL: any function that references the
 *  string-array provider and transforms its output (decode/decrypt/lookup).
 *  Not tied to specific APIs like charCodeAt — recognizes the SHAPE:
 *  "function that takes the array, does something to it, and returns a string."
 */
function detectDecoders(code) {
  if (!babel) return [];
  let ast; try { ast = babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } }); } catch (e) { return []; }

  // Phase 1: find ALL string-array providers (a file may bundle several
  //          independent obfuscation systems, each with its own array+decoder).
  const arrayNames = new Set();
  traverse(ast, {
    'FunctionDeclaration|VariableDeclarator'(p) {
      let arr = null, name = null;
      if (p.isFunctionDeclaration() && p.node.id) {
        name = p.node.id.name; const b = p.node.body.body || [];
        const ret = b.find(s => t.isReturnStatement(s)); if (ret && t.isArrayExpression(ret.argument)) arr = ret.argument;
        if (!arr) for (const s of b) if (t.isVariableDeclaration(s)) { const d = s.declarations.find(d => t.isArrayExpression(d.init)); if (d) { arr = d.init; break; } }
      } else if (p.isVariableDeclarator() && t.isIdentifier(p.node.id) && t.isArrayExpression(p.node.init)) { name = p.node.id.name; arr = p.node.init; }
      if (arr && arr.elements.length >= 10 && arr.elements.filter(e => e && t.isStringLiteral(e)).length >= arr.elements.length * 0.6) arrayNames.add(name);
    }
  });
  if (!arrayNames.size) return [];
  const refsAnyArray = (src) => { for (const a of arrayNames) if (src.includes(a)) return true; return false; };

  // Phase 2: any function that references ANY array AND has decode-like behavior.
  // Universal signals (not tied to specific APIs):
  //   - references the array provider by name
  //   - has a return statement (produces output)
  //   - body contains ANY of: charCodeAt, fromCharCode, decodeURIComponent, atob,
  //     XOR (^), modulo (% 256), indexOf, charAt, String[], Buffer, for-loop over chars,
  //     or is short (wrapper/proxy that calls another decoder)
  const DECODE_SIGNALS = /charCodeAt|fromCharCode|decodeURIComponent|atob|btoa|String\[|charAt|indexOf|\\^|%\s*256|Buffer\.from|unescape|escape|substr/;
  const decoders = new Set();
  traverse(ast, {
    FunctionDeclaration(p) {
      const n = p.node.id && p.node.id.name;
      if (!n || arrayNames.has(n)) return;
      let src; try { src = generate(p.node, { compact: true }).code; } catch (e) { return; }
      if (!refsAnyArray(src)) return;
      // Signal 1: has decode-like operations
      if (DECODE_SIGNALS.test(src)) { decoders.add(n); return; }
      // Signal 2: short function that calls the array + does index arithmetic (wrapper/proxy)
      if (src.length < 500 && /return\s/.test(src) && /\[\s*[\w$]+\s*[\-+]/.test(src)) { decoders.add(n); return; }
      // Signal 3: has a caching pattern (memoization object) — common in obfuscator.io/JScrambler
      if (/\{\}\s*;|===\s*undefined|\.hasOwnProperty/.test(src)) { decoders.add(n); return; }
    }
  });
  return [...decoders];
}

/** Backfill decoder(idx,key) call sites from a decode map.
 *  ENHANCED: also resolves PROXY calls — wrapper functions that call the base
 *  decoder with offset arithmetic (e.g. fn(a,b){return decoder(b+0x3b5,a)}).
 *  This is the #1 gap: 33 proxied calls with 0 direct after static inlining. */
function backfill(ast, baseNames, map) {
  // Uses the shared transitive resolver: every call site (direct base OR a proxy
  // chain, possibly with hoisted local const-objects) folds to a base decoder +
  // concrete args; if that key is in the decode map, replace the call with the
  // literal string. This unifies Phase A-D and fixes deep proxy chains.
  const { resolveCall } = buildResolver(ast, baseNames);
  let c = 0;
  traverse(ast, { CallExpression(p) {
    const r = resolveCall(p.node); if (!r) return;
    if (Object.prototype.hasOwnProperty.call(map, r.key)) { p.replaceWith(t.stringLiteral(map[r.key])); c++; }
  }});
  // Fallback: any remaining direct base calls whose args babel can fold.
  let changed = true, pass = 0;
  while (changed && pass++ < 3) {
    changed = false;
    traverse(ast, { CallExpression(p) {
      const cal = p.node.callee; if (!t.isIdentifier(cal) || !baseNames.includes(cal.name)) return;
      try {
        const evArgs = [];
        for (const argPath of p.get('arguments')) { const ev = argPath.evaluate(); if (!ev.confident) return; evArgs.push(ev.value); }
        const key = cal.name + '\u0000' + JSON.stringify(evArgs);
        if (Object.prototype.hasOwnProperty.call(map, key)) { p.replaceWith(t.stringLiteral(map[key])); c++; changed = true; }
      } catch (e) {}
    }});
  }
  return c;
}

function evalExprWithSubst(node, subst, memberVal) {
  if (t.isNumericLiteral(node)) return node.value;
  if (t.isStringLiteral(node)) return node.value;
  if (t.isBooleanLiteral(node)) return node.value;
  if (t.isIdentifier(node) && node.name in subst) return subst[node.name];
  if (memberVal && t.isMemberExpression(node)) { const v = memberVal(node); if (v !== undefined) return v; }
  if (t.isUnaryExpression(node) && node.operator === '-') { const v = evalExprWithSubst(node.argument, subst, memberVal); return v !== undefined ? -v : undefined; }
  if (t.isBinaryExpression(node)) {
    const l = evalExprWithSubst(node.left, subst, memberVal); if (l === undefined) return undefined;
    const r = evalExprWithSubst(node.right, subst, memberVal); if (r === undefined) return undefined;
    switch (node.operator) {
      case '+': return l + r; case '-': return l - r; case '*': return l * r;
      case '|': return l | r; case '&': return l & r; case '^': return l ^ r;
      case '>>': return l >> r; case '<<': return l << r; case '>>>': return l >>> r;
      default: return undefined;
    }
  }
  return undefined; // can't resolve
}

/**
 * Universal deobfuscate. Returns { code, profile, tiers, decoded, leftover, needsAI }.
 */
async function deobfuscate(code, options = {}) {
  const onProgress = options.onProgress || (() => {});
  const log = options.verbose ? (m) => process.stderr.write(m + '\n') : () => {};
  const deadline = Date.now() + (options.timeout || 45000);

  // ═══ PHASE 0: INTERNALIZE (silent) — study the input before showing anything ═══
  // The user sees only a spinner here. J-Shadow reconstructs the profile, checks
  // its learned memory, and dry-runs the decoder to VERIFY before committing.
  onProgress({ phase: 'analyzing', message: 'studying the encoded input…', spinner: true });

  const profile = fingerprint(code);
  const baseNames = detectDecoders(code);

  // Dry-run the dynamic decoder internally to confirm the plan actually works.
  let decodeMap = {};
  if (baseNames.length && (profile.route === 'obfuscator_dynamic' || (profile.learnedHit && /dynamic/.test(profile.learnedHit.route)))) {
    onProgress({ phase: 'analyzing', message: 'tracing the decoder + rotation…', spinner: true });
    const dyn = dynamicDecode(code, baseNames, deadline);
    decodeMap = dyn.map;
  }

  // Verify the internalization: did we recover meaningful strings? do they look sane?
  const decodedCount = Object.keys(decodeMap).length;
  const sample = Object.values(decodeMap).slice(0, 40).join('');
  const printableRatio = sample.length ? (sample.match(/[\x09\x0A\x0D\x20-\x7E]/g) || []).length / sample.length : 1;
  const planViable = baseNames.length === 0 || decodedCount > 0;
  const verified = printableRatio >= 0.85;

  onProgress({
    phase: 'ready',
    message: profile.learnedHit ? 'recognized (learned) — decoding…' : 'analysis complete — decoding…',
    plan: { family: profile.familyLabel, route: profile.route, decoders: baseNames, antiDebug: profile.antiDebug, requires: profile.requires },
    learned: !!profile.learnedHit,
    decodedCount, verified
  });

  log(`🔍 family=${profile.familyLabel} route=${profile.route} score=${profile.score} reason=${profile.reason}`);
  if (profile.learnedHit) log(`🧠 recognized shape ${profile.shapeHash} (seen ${profile.learnedHit.seen}x, rate ${profile.learnedHit.successRate})`);
  if (profile.requires && profile.requires.length) log(`📎 requires: ${profile.requires.join(', ')}`);

  const tiers = [];
  let current = code;

  // ═══ PHASE 1: EXECUTE (now the user sees real progress) ═══

  // VM / virtualization (JScrambler VM, control-flow flattening): a decoder hook
  // does NOT work here — the logic lives in a bytecode+interpreter. Be honest:
  // do best-effort partial extraction (plaintext strings/URLs/keys) and report
  // that full recovery needs opcode mapping + CFG reconstruction.
  if (profile.route === 'virtualized') {
    onProgress({ phase: 'decoding', step: 'runtime trace (CDP native-boundary hooks)' });
    let trace = { hooks: [], strings: [], urls: [], keys: [], apiCounts: {} };
    try {
      const { traceNode } = require('./modules/cdp-tracer');   // Tier-1: sit next to V8, hook native sinks
      trace = await traceNode(code, { timeout: Math.max(6000, deadline - Date.now()) });
    } catch (e) { log('  cdp trace error: ' + e.message.slice(0, 60)); }
    const statik = extractPlaintext(code);
    const partial = {
      strings: [...new Set([...(trace.strings || []), ...statik.strings])].slice(0, 400),
      urls: [...new Set([...(trace.urls || []), ...statik.urls])].slice(0, 150),
      keys: [...new Set([...(trace.keys || []), ...statik.keys])].slice(0, 80),
      apiTrace: trace.apiCounts || {},
      hooks: (trace.hooks || []).length
    };
    tiers.push('vm_cdp_trace');
    try { const r = await core.process(code, { dynamic: false, rename: false }); current = r.code; } catch (e) {}
    const guardrails = { sizeRatio: +(current.length / Math.max(1, code.length)).toFixed(2), ok: true, warnings: [
      'VM/virtualization detected — full de-virtualization (opcode map + CFG recovery) not attempted; Tier-1 runtime context extracted via CDP native-boundary tracing.'
    ] };
    return {
      code: current, profile,
      plan: { family: profile.familyLabel, route: 'virtualized', decoders: [], rotation: false, antiDebug: profile.antiDebug, requires: profile.requires, strategy: profile.reason },
      guardrails, tiers, decodeMap: {}, decoded: 0, partial, leftover: -1, needsAI: true,
      aiHint: `VM-virtualized. Tier-1 runtime trace: ${partial.hooks} native-boundary hits → ${partial.strings.length} strings, ${partial.urls.length} urls, ${partial.keys.length} key-like. Full logic recovery needs opcode map + CFG reconstruction.`
    };
  }

  if (profile.route === 'jscrambler') {
    onProgress({ phase: 'decoding', step: 'jscrambler' });
    try {
      const { JScramblerUniversal } = require('./modules/JScramblerUniversal');
      const js = new JScramblerUniversal({ verbose: false });
      const r = await js.crack(current);
      if (r && (r.cleanCode || r.code)) { current = r.cleanCode || r.code; tiers.push('jscrambler_universal'); }
    } catch (e) { log('  jscrambler module error: ' + e.message.slice(0, 60)); }
  }

  // ═══ PRE-PROCESS: lightweight transforms that don't need the full engine ═══
  // These handle simple obfuscation layers that wrap the real code.
  current = preProcess(current);

  const core = new JShadowCore({ timeout: Math.max(4000, deadline - Date.now()), rename: false });
  onProgress({ phase: 'decoding', step: 'static' });
  try { const r = await core.process(current, { dynamic: false, rename: false }); current = r.code; tiers.push('static'); log(`  static: ${r.transformations} transforms`); }
  catch (e) { log('  static error: ' + e.message.slice(0, 60)); }

  if (decodedCount > 0) {
    onProgress({ phase: 'decoding', step: 'dynamic', decoded: decodedCount });
    tiers.push('dynamic');
    try {
      const r2 = await core.process(current, { dynamic: false, rename: false });
      let ast2 = babel.parse(r2.code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
      const filled = backfill(ast2, baseNames, decodeMap);
      current = generate(ast2, { compact: false, comments: true }).code;
      const r3 = await core.process(current, { dynamic: false, rename: false });
      current = r3.code;
      log(`  dynamic: ${decodedCount} strings, backfilled ${filled}`);
      // strip dead scaffolding now that decoder calls are inlined
      try {
        const before = current.length;
        const stripped = stripScaffolding(current, baseNames);
        // guardrail: keep strip only if it still parses AND didn't nuke the file
        if (stripped && stripped.length > 0 && stripped.length < before && babel) {
          babel.parse(stripped, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
          current = stripped;
          tiers.push('strip');
          log(`  strip: ${before} → ${current.length} bytes`);
        }
      } catch (e) { log('  strip skipped: ' + e.message.slice(0, 50)); }
    } catch (e) { log('  backfill error: ' + e.message.slice(0, 60)); }
  }

  onProgress({ phase: 'decoding', step: 'rename' });
  try {
    const { SmartMinifiedRenamer } = require('./modules/smart-renamer');
    const sr = new SmartMinifiedRenamer();
    const rr = await sr.rename(current, {});
    if (rr && rr.code) { current = rr.code; tiers.push('smart_rename'); log(`  renamed ${rr.stats && rr.stats.renamed || 0}`); }
  } catch (e) {
    try { const r = await core.process(current, { dynamic: false, rename: true }); current = r.code; tiers.push('core_rename'); } catch (e2) {}
  }

  // Leftover check → AI notify
  let leftover = 0;
  if (babel) {
    try {
      const chk = babel.parse(current, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true } });
      const ns = new Set(baseNames);
      traverse(chk, { CallExpression: (p) => { if (t.isIdentifier(p.node.callee) && ns.has(p.node.callee.name)) leftover++; } });
    } catch (e) {}
  }
  const needsAI = leftover > 0 || hasObfuscatedNames(current);

  // ═══ PRIORITY 3: AI CLEANUP TIER (optional — only when aiKey provided) ═══
  // Cleans up leftover obfuscated identifiers that deterministic passes can't resolve.
  let aiUsed = false;
  if (needsAI && options.aiKey) {
    onProgress({ phase: 'decoding', step: 'AI cleanup' });
    try {
      const aiResult = await callAI(current, options.aiKey, options.aiProvider || 'gemini', options.aiModel, profile);
      if (aiResult && aiResult.code && aiResult.code.length > current.length * 0.3) {
        current = aiResult.code;
        aiUsed = true;
        tiers.push('ai_cleanup');
        log(`  AI cleanup: ${aiResult.provider} — ${aiResult.changes || 'applied'}`);
      }
    } catch (e) { log('  AI cleanup error: ' + e.message.slice(0, 60)); }
  } else if (needsAI && options.ollamaUrl) {
    onProgress({ phase: 'decoding', step: 'AI cleanup (Ollama)' });
    try {
      const aiResult = await callAI(current, null, 'ollama', options.ollamaModel || 'llama3', profile, options.ollamaUrl);
      if (aiResult && aiResult.code && aiResult.code.length > current.length * 0.3) {
        current = aiResult.code;
        aiUsed = true;
        tiers.push('ai_cleanup_ollama');
        log(`  AI cleanup: Ollama — ${aiResult.changes || 'applied'}`);
      }
    } catch (e) { log('  AI cleanup error: ' + e.message.slice(0, 60)); }
  }

  // ── Guardrails (Dave's rule: a bad decode balloons the file — stop, don't ship garbage) ──
  const sizeRatio = +(current.length / Math.max(1, code.length)).toFixed(2);
  const guardrails = { sizeRatio, ok: true, warnings: [] };
  const isBundleRoute = profile.route === 'webpack';
  if (sizeRatio > 3 && !isBundleRoute) {
    guardrails.ok = false;
    guardrails.warnings.push(`output ${sizeRatio}x larger than input — likely wrong decode (rotation/array mis-resolve). Reverting to input.`);
    current = code; // don't emit garbage
  }
  if (profile.antiDebug.length && profile.route.includes('dynamic') && Object.keys(decodeMap).length === 0) {
    guardrails.warnings.push('anti-debug present and dynamic recovered 0 strings — trap likely blocked execution; not fabricating output.');
  }

  // Decode plan (what recon decided + how it attacked it)
  const plan = {
    family: profile.familyLabel,
    route: profile.route,
    decoders: baseNames,
    rotation: profile.structure.rotation,
    antiDebug: profile.antiDebug,
    requires: profile.requires,
    strategy: profile.reason
  };
  // advanced recon intelligence (foundation for enterprise-grade phase)
  if (profile.advanced) {
    plan.classified = { family: profile.advFamily, confidence: profile.advConfidence, novelty: profile.novelty };
    plan.encodingLayers = (profile.advanced.encodings || []).map(e => e.id);
    plan.bundler = profile.advanced.bundler ? profile.advanced.bundler.label : null;
    plan.jscramblerFeatures = (profile.advanced.jscrambler.features || []).map(f => f.id);
    plan.vm = profile.advanced.vm.detected ? { type: profile.advanced.vm.type, markers: profile.advanced.vm.markers } : null;
    plan.stacked = profile.advanced.layers.stacked;
    plan.traps = (profile.traps || []).map(t => ({ id: t.id, severity: t.severity }));
    plan.neutralizePlan = profile.neutralizePlan || [];
  }

  // ── Learn back into patterns.json (the demi-ML memory) ──
  const db = loadDB();
  if (db) {
    db.statistics = db.statistics || { successfulDeobfuscations: 0, failedDeobfuscations: 0, patternsLearned: 0 };
    db.fingerprints = db.fingerprints || {};
    db.learned = db.learned || [];

    const success = Object.keys(decodeMap).length > 0 || (guardrails.ok && tiers.length > 1);
    if (success) db.statistics.successfulDeobfuscations = (db.statistics.successfulDeobfuscations || 0) + 1;
    else if (guardrails.ok === false) db.statistics.failedDeobfuscations = (db.statistics.failedDeobfuscations || 0) + 1;

    // Remember this decoder shape -> the route that worked (instant next time)
    // UNIVERSAL: captures enough features to recognize the same obfuscator family
    // across different files, not just the exact same decoder name.
    // When there's no decoder (simple obfuscation), use a structural content hash.
    const learnHash = profile.shapeHash || (profile.score > 0
      ? require('crypto').createHash('sha1').update(
          [profile.family, profile.strategy, profile.encodings.join(','), profile.antiDebug.join(','), profile.structure.stringArray, profile.structure.rotation].join('|')
        ).digest('hex').slice(0, 16)
      : null);
    if (learnHash) {
      const prev = db.fingerprints[learnHash] || {
        seen: 0, ok: 0,
        family: profile.family,
        route: profile.route,
        // Universal features (not tied to specific names):
        features: {
          arrayLen: profile.structure.arrayLen || 0,
          hasRotation: !!profile.structure.rotation,
          decoderCount: baseNames.length,
          encodings: profile.encodings || [],
          antiDebug: profile.antiDebug || [],
          isVM: !!profile.isVM,
          entropy: profile.entropy || 0,
          score: profile.score || 0
        }
      };
      prev.seen += 1;
      if (success) prev.ok += 1;
      prev.family = profile.family;
      prev.route = profile.route;
      prev.features = prev.features || {};
      prev.features.arrayLen = profile.structure.arrayLen || prev.features.arrayLen;
      prev.features.hasRotation = !!profile.structure.rotation;
      prev.features.decoderCount = baseNames.length;
      prev.features.encodings = profile.encodings || [];
      prev.features.antiDebug = profile.antiDebug || [];
      prev.features.isVM = !!profile.isVM;
      prev.successRate = +(prev.ok / prev.seen).toFixed(2);
      prev.lastSeen = new Date().toISOString();
      db.fingerprints[learnHash] = prev;
      if (prev.seen === 1) db.statistics.patternsLearned = (db.statistics.patternsLearned || 0) + 1;
    }

    // Update the matched family's confidence/success in the signature DB
    if (profile.dbFamily) {
      const fam = db.patterns[profile.dbFamily.group] && db.patterns[profile.dbFamily.group][profile.dbFamily.family];
      if (fam) {
        fam.detectionCount = (fam.detectionCount || 0) + 1;
        const ok = fam.successCount = (fam.successCount || 0) + (success ? 1 : 0);
        fam.successRate = +(ok / fam.detectionCount).toFixed(2);
        fam.confidence = +Math.min(0.99, (fam.confidence || 0) + 0.02).toFixed(2);
      }
    }

    db.lastUpdated = new Date().toISOString();
    saveDB(db);
  }

  return {
    code: current,
    profile,
    plan,
    guardrails,
    tiers,
    decodeMap,
    decoded: Object.keys(decodeMap).length,
    leftover,
    needsAI,
    aiHint: needsAI && !options.aiKey ? 'Leftover obfuscation remains. Provide aiKey (Gemini/OpenAI) or Ollama for full cleanup.' : null
  };
}

module.exports = { deobfuscate, fingerprint, dynamicDecode, detectDecoders };

// ── CLI ──
if (require.main === module) {
  const argv = process.argv.slice(2);
  const input = argv.find(a => !a.startsWith('-'));
  const oIdx = argv.indexOf('-o'); const output = oIdx !== -1 ? argv[oIdx + 1] : null;
  const verbose = argv.includes('-v') || argv.includes('--verbose');
  const stdinMode = argv.includes('--stdin') || !input;
  const aiKeyIdx = argv.indexOf('--ai-key'); const aiKey = aiKeyIdx !== -1 ? argv[aiKeyIdx + 1] : process.env.JSHADOW_AI_KEY;
  const aiProvIdx = argv.indexOf('--ai-provider'); const aiProvider = aiProvIdx !== -1 ? argv[aiProvIdx + 1] : 'gemini';
  const ollamaIdx = argv.indexOf('--ollama'); const ollamaUrl = ollamaIdx !== -1 ? (argv[ollamaIdx + 1] || 'http://localhost:11434') : null;

  // stdin JSON mode: read {"source": "...", "filename": "..."} from stdin
  const readStdin = () => new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => data += chunk);
    process.stdin.on('end', () => resolve(data));
    setTimeout(() => resolve(data), 5000);
  });

  const run = async () => {
    let code, filename;
    if (stdinMode && !input) {
      const raw = await readStdin();
      try {
        const parsed = JSON.parse(raw);
        code = parsed.source || parsed.code || raw;
        filename = parsed.filename || 'stdin.js';
      } catch (e) {
        code = raw;
        filename = 'stdin.js';
      }
    } else if (input) {
      code = fs.readFileSync(input, 'utf8');
      filename = input;
    } else {
      console.error('Usage: node index.js <file.js> [-o out.js] [-v] [--stdin]');
      process.exit(1);
    }
    return { code, filename };
  };

  run().then(({ code, filename }) => {
    const spin = ['|','/','-','\\'];
    let si = 0, spinner = null, curMsg = 'studying the encoded input...';
    const startSpin = () => { if (!process.stderr.isTTY) return; spinner = setInterval(() => process.stderr.write(`\r${spin[si++ % spin.length]} ${curMsg}       `), 80); };
    const stopSpin = () => { if (spinner) { clearInterval(spinner); spinner = null; if (process.stderr.isTTY) process.stderr.write('\r' + ' '.repeat(70) + '\r'); } };

    const onProgress = (ev) => {
      if (ev.phase === 'analyzing') { curMsg = ev.message; if (!spinner) startSpin(); if (!process.stderr.isTTY) process.stderr.write('... ' + ev.message + '\n'); }
      else if (ev.phase === 'ready') { stopSpin(); process.stderr.write(`${ev.learned ? '[L]' : '[R]'} ${ev.message}\n`); if (ev.plan) process.stderr.write(`   family=${ev.plan.family} route=${ev.plan.route}${ev.plan.antiDebug.length ? ' anti-debug=' + ev.plan.antiDebug.join(',') : ''}\n`); }
      else if (ev.phase === 'decoding') { process.stderr.write(`   > ${ev.step}${ev.decoded ? ' (' + ev.decoded + ' strings)' : ''}\n`); }
    };

    return deobfuscate(code, { filename, verbose: false, onProgress, aiKey, aiProvider, ollamaUrl }).then(r => {
      stopSpin();
      // JSON output mode for subprocess integration
      if (stdinMode && !output) {
        const out = {
          code: r.code,
          deobfuscated: r.code !== code,
          family: r.profile.familyLabel,
          route: r.plan.strategy,
          tiers: r.tiers,
          decoded: r.decoded,
          sizeRatio: r.guardrails.sizeRatio,
          warnings: r.guardrails.warnings,
        };
        if (r.partial) {
          out.strings = r.partial.strings.length;
          out.urls = r.partial.urls;
          out.keys = r.partial.keys;
        }
        process.stdout.write(JSON.stringify(out));
      } else {
        process.stderr.write(`\n-- J-Shadow Universal --\n`);
        process.stderr.write(`  family : ${r.profile.familyLabel}${r.profile.learnedHit ? ' (learned)' : ''}\n`);
        process.stderr.write(`  plan   : ${r.plan.strategy}${r.plan.antiDebug.length ? ' | anti-debug: ' + r.plan.antiDebug.join(',') : ''}\n`);
        if (r.plan.requires.length) process.stderr.write(`  requires: ${r.plan.requires.join(', ')}\n`);
        process.stderr.write(`  tiers  : ${r.tiers.join(' > ')}\n`);
        process.stderr.write(`  decoded: ${r.decoded} strings | size ${r.guardrails.sizeRatio}x\n`);
        for (const w of r.guardrails.warnings) process.stderr.write(`  [!] ${w}\n`);
        if (r.partial) {
          process.stderr.write(`  partial: ${r.partial.strings.length} strings / ${r.partial.urls.length} urls / ${r.partial.keys.length} key-like\n`);
          if (r.partial.urls.length) process.stderr.write(`     urls: ${r.partial.urls.slice(0, 5).join(', ')}${r.partial.urls.length > 5 ? ' ...' : ''}\n`);
          if (r.partial.keys.length) process.stderr.write(`     keys: ${r.partial.keys.slice(0, 3).join(' | ')}\n`);
        }
        if (r.aiHint) process.stderr.write(`  [i] ${r.aiHint}\n`);
        if (output) { fs.writeFileSync(output, r.code); process.stderr.write(`  [ok] wrote ${output}\n`); }
        else process.stdout.write(r.code);
      }
    });
  }).catch(e => { process.stderr.write('[ERR] ' + (e.stack || e.message || e) + '\n'); process.exit(1); });
}
