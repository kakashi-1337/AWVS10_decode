'use strict';
/**
 * 🥷 J-SHADOW ADVANCED RECON + TRAP DETECTION  (v1.6 foundation module)
 *
 * The recon foundation for enterprise-grade deobfuscation. It does NOT reverse
 * VM/CFF (that is the later devirt phase) — it IDENTIFIES, FINGERPRINTS, and
 * flags TRAPS so the pipeline can route honestly and sandbox safely.
 *
 * Everything here is name-INDEPENDENT: detection keys on structural/AST shapes
 * and character-set invariants, never on randomized identifier names, because
 * every serious obfuscator randomizes names (and JScrambler is polymorphic).
 *
 * Design follows the research staging:
 *   Stage 1 (deterministic): encoding char-sets, packer tuple, obfuscator.io
 *                            preludes, bundler runtimes — near-100% precision.
 *   Stage 2 (structural):    JScrambler feature classes, VM dispatcher/handlers,
 *                            multi-layer decode→sink chains, entropy triage.
 *   Stage 3 (scoring):       confidence + "obfuscated-but-unknown" novelty.
 *   Safety:                  anti-analysis TRAP detection BEFORE any dynamic run.
 *
 *   const { advancedRecon } = require('./advanced-recon');
 *   const r = advancedRecon(code);   // → structured profile (see bottom)
 */

let babel, traverse, t, gen;
try {
  babel = require('@babel/core');
  traverse = require('@babel/traverse').default;
  t = require('@babel/types');
  gen = require('@babel/generator').default;
} catch (e) { /* regex-only fallback */ }

const parse = (code) => {
  if (!babel) return null;
  try { return babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true, allowImportExportEverywhere: true } }); }
  catch (e) { return null; }
};
const src = (node) => { try { return gen(node, { compact: true }).code; } catch (e) { return ''; } };

// ───────────────────────────────────────────────────────────────────────────
// 1. ENCODING DETECTORS  (char-set invariants — highest precision, name-free)
// ───────────────────────────────────────────────────────────────────────────
// level: 'family' = the whole file IS this encoding (JSFuck/AAEncode/JJEncode);
//        'layer'  = a sub-encoding used inside another family (hex/base64/etc.)
const FAMILY_ENCODINGS = new Set(['jsfuck', 'aaencode', 'jjencode']);
function detectEncodings(code) {
  const out = [];
  const push = (id, label, confidence, note) => out.push({ id, label, confidence, note, level: FAMILY_ENCODINGS.has(id) ? 'family' : 'layer' });

  // JSFuck: only []()!+ (+ whitespace). Measure ratio over a non-string sample.
  const noStr = code.replace(/(["'])(?:\\.|(?!\1).)*\1/g, '').replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
  if (noStr.length > 40) {
    const jsfuckChars = (noStr.match(/[\[\]()!+]/g) || []).length;
    const ratio = jsfuckChars / noStr.replace(/\s/g, '').length;
    if (ratio > 0.9) push('jsfuck', 'JSFuck (6-char alphabet)', 0.99, `ratio ${ratio.toFixed(3)}`);
    else if (ratio > 0.75) push('jsfuck_like', 'JSFuck-like (heavy []()!+ )', 0.7, `ratio ${ratio.toFixed(3)}`);
  }
  // AAEncode: fixed kaomoji header.
  if (/ﾟωﾟﾉ|ﾟΘﾟ|ﾟДﾟ|\(ﾟｰﾟ\)/.test(code)) push('aaencode', 'AAEncode (kaomoji)', 0.98, 'kaomoji tokens present');
  // JJEncode: global $=~[] seed + symbol chains.
  if (/[\$_]\s*=\s*~\[\]\s*;/.test(code) && /[\$_]{2,}/.test(code)) push('jjencode', 'JJEncode (symbol)', 0.95, '$=~[] seed');
  // Escapes.
  if (/\\x[0-9a-fA-F]{2}/.test(code)) push('hex_escape', 'hex escapes \\xHH', 0.9);
  if (/\\u\{[0-9a-fA-F]+\}/.test(code)) push('unicode_cp_escape', 'code-point escapes \\u{..}', 0.9);
  else if (/\\u[0-9a-fA-F]{4}/.test(code)) push('unicode_escape', 'unicode escapes \\uHHHH', 0.9);
  if (/\\[0-3][0-7]{2}/.test(code)) push('octal_escape', 'octal escapes \\NNN', 0.6);
  // Char-code builders.
  if (/String\.fromCharCode\s*\(/.test(code)) push('fromcharcode', 'String.fromCharCode builder', 0.85);
  if (/\.charCodeAt\s*\(/.test(code)) push('charcodeat', 'charCodeAt reconstruction', 0.6);
  // Base-N.
  if (/\batob\s*\(/.test(code)) push('base64_atob', 'atob() base64 decode', 0.9);
  if (/["'][A-Za-z0-9+/]{24,}={0,2}["']/.test(code)) push('base64_blob', 'base64 blob literal', 0.6);
  if (/["'][A-Za-z0-9+/]{60,}={0,2}["']/.test(code) && /[a-z]/.test(code) && /[A-Z]/.test(code)) push('custom_base64_alphabet', 'possible custom base64 alphabet', 0.4);
  if (/["'][A-Z2-7]{24,}={0,6}["']/.test(code)) push('base32', 'base32 blob', 0.4);
  if (/<~[\s\S]{8,}~>/.test(code)) push('ascii85', 'Ascii85/Base85 (<~ ~>)', 0.7);
  // URL/percent.
  if (/\bunescape\s*\(|\bdecodeURIComponent\s*\(/.test(code) && /%[0-9a-fA-F]{2}/.test(code)) push('percent_encoding', 'URL/percent encoding', 0.75);
  // Numeric base tricks.
  if (/\b0b[01]{4,}\b/.test(code)) push('binary_literal', 'binary numeric literals', 0.5);
  if (/\b0o[0-7]{2,}\b|\b0[0-7]{3,}\b/.test(code)) push('octal_literal', 'octal numeric literals', 0.4);
  if (/\b1e1000\b|\b0x1p/.test(code)) push('numeric_trick', 'numeric edge trick (Infinity/hex-float)', 0.4);
  return out;
}

// ───────────────────────────────────────────────────────────────────────────
// 2. BUNDLER DETECTORS  (runtime-signature — name-free)
// ───────────────────────────────────────────────────────────────────────────
function detectBundler(code) {
  const tests = [
    { id: 'webpack', label: 'webpack', re: /__webpack_require__|__webpack_modules__|webpackJsonp|webpackChunk/, conf: 0.95 },
    { id: 'browserify', label: 'Browserify', re: /function\s+\w?\(\w,\w,\w\)\{function\s+\w\(\w,\w\)|typeof\s+require\s*==\s*["']function["'][\s\S]{0,80}!\w\[\w\]/, conf: 0.75 },
    { id: 'parcel', label: 'Parcel', re: /parcelRequire|require\s*=\s*\(function\s*\([\s\S]{0,40}\bcache\b/, conf: 0.8 },
    { id: 'esbuild', label: 'esbuild', re: /__commonJS|__toESM|__esm\b|__export\s*\(|__defProp\s*\(/, conf: 0.85 },
    { id: 'amd_requirejs', label: 'RequireJS/AMD', re: /\bdefine\s*\(\s*\[[^\]]*\]\s*,\s*function|\brequire\s*\(\s*\[[^\]]*\]\s*,/, conf: 0.7 },
    { id: 'systemjs', label: 'SystemJS', re: /System\.register\s*\(\s*\[/, conf: 0.9 },
    { id: 'rollup_iife', label: 'Rollup (IIFE)', re: /\(function\s*\([^)]*\)\s*\{[\s\S]{0,40}['"]use strict['"][\s\S]{0,200}Object\.defineProperty\(\w+,\s*['"]__esModule['"]/, conf: 0.4 }
  ];
  for (const b of tests) if (b.re.test(code)) return { id: b.id, label: b.label, confidence: b.conf };
  return null;
}

// ───────────────────────────────────────────────────────────────────────────
// 2b. PACKER DETECTION  (eval(function(p,a,c,k,e,d/r)) tuple — name-free)
// ───────────────────────────────────────────────────────────────────────────
function detectPacker(code) {
  // Dean Edwards / p.a.c.k.e.r: key on the parameter TUPLE, not the wrapper name
  // (attackers rename the function). Allow eval OR any call wrapping it.
  if (/function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/.test(code))
    return { id: 'packer_pack', label: 'Dean Edwards p.a.c.k.e.r', confidence: 0.92, note: '(p,a,c,k,e,d/r) tuple' };
  // generic eval-based self-extractor: eval( <call returning string> )
  if (/eval\s*\(\s*(function|\w+\s*\()/.test(code) && /\.split\s*\(\s*['"]\|['"]\s*\)/.test(code))
    return { id: 'packer_generic', label: 'generic eval self-extractor', confidence: 0.6, note: 'eval + split("|") dictionary' };
  return null;
}

// ───────────────────────────────────────────────────────────────────────────
// 2c. OBFUSCATOR.IO STRUCTURAL DETECTION  (three-prelude shape, name-free)
// ───────────────────────────────────────────────────────────────────────────
function detectObfuscatorIO(code, ast, features) {
  let arrayFn = false, rotation = false, shiftedFetch = false, arrayLen = 0, callController = false;
  if (ast) {
    let arrName = null;
    traverse(ast, {
      'FunctionDeclaration|VariableDeclarator'(p) {
        if (arrName) return; let arr = null, name = null;
        if (p.isFunctionDeclaration() && p.node.id) { name = p.node.id.name; const b = p.node.body.body || []; const r = b.find(s => t.isReturnStatement(s)); if (r && t.isArrayExpression(r.argument)) arr = r.argument; if (!arr) for (const s of b) if (t.isVariableDeclaration(s)) { const d = s.declarations.find(d => t.isArrayExpression(d.init)); if (d) { arr = d.init; break; } } }
        else if (p.isVariableDeclarator() && t.isIdentifier(p.node.id) && t.isArrayExpression(p.node.init)) { name = p.node.id.name; arr = p.node.init; }
        if (arr && arr.elements.length >= 10 && arr.elements.filter(e => e && t.isStringLiteral(e)).length >= arr.elements.length * 0.6) { arrName = name; arrayFn = true; arrayLen = arr.elements.length; }
      }
    });
    // Self-redefining array-provider shape (obfuscator.io core, ANY array size):
    //   function F(){ const a=[...]; F=function(){return a}; return F(); }
    if (!arrayFn) {
      traverse(ast, {
        FunctionDeclaration(p) {
          if (arrName) return;
          const fnName = p.node.id && p.node.id.name; if (!fnName) return;
          const b = p.node.body.body || [];
          let hasArr = null, selfReassign = false;
          for (const s of b) {
            if (t.isVariableDeclaration(s)) { const d = s.declarations.find(d => t.isArrayExpression(d.init)); if (d) hasArr = d.init; }
            if (t.isExpressionStatement(s) && t.isAssignmentExpression(s.expression) && t.isIdentifier(s.expression.left, { name: fnName })) selfReassign = true;
          }
          if (hasArr && selfReassign && hasArr.elements.length >= 3 && hasArr.elements.every(e => e && t.isStringLiteral(e))) {
            arrName = fnName; arrayFn = true; arrayLen = hasArr.elements.length;
          }
        }
      });
    }
    if (arrName) {
      traverse(ast, {
        ExpressionStatement(p) { const s = src(p.node); if (s.includes(arrName) && /push|shift/.test(s) && /parseInt|while/.test(s)) rotation = true; },
        FunctionDeclaration(p) { const s = src(p.node); if (s.includes(arrName) && /-\s*(0x[0-9a-f]+|\d+)/.test(s)) shiftedFetch = true; }
      });
    }
    // call-controller wrapper: IDENT(this, function(){...}) — selfDefending/debugProtection
    traverse(ast, {
      CallExpression(p) {
        const a = p.node.arguments;
        if (t.isIdentifier(p.node.callee) && a.length >= 2 && t.isThisExpression(a[0]) && (t.isFunctionExpression(a[1]) || t.isArrowFunctionExpression(a[1]))) callController = true;
      }
    });
  }
  const preludes = (arrayFn ? 1 : 0) + (rotation ? 1 : 0) + (shiftedFetch ? 1 : 0);
  const hexNaming = features && features.hexIdentifierRatio > 0.3;
  let confidence = 0;
  if (preludes === 3) confidence = 0.95;
  else if (arrayFn && rotation) confidence = hexNaming ? 0.85 : 0.7;
  else if (arrayFn && (shiftedFetch || callController)) confidence = 0.8;      // rotate-off / small variants
  else if (arrayFn && hexNaming) confidence = 0.6;
  else if (callController && hexNaming) confidence = 0.55;                      // self-defend-only signal
  return { detected: confidence >= 0.55, confidence, preludes: { arrayFn, rotation, shiftedFetch, callController }, arrayLen };
}

// ───────────────────────────────────────────────────────────────────────────
// 2d. JS-CONFUSER DETECTION  (2nd most common per Google CASCADE — name-free)
// ───────────────────────────────────────────────────────────────────────────
function detectJSConfuser(code, ast, features) {
  const markers = [];
  // (a) whole-program wrapped in a Function-constructor string: Function("x","var ...")
  const fnCtorWrap = /\bFunction\s*\(\s*(["'])[A-Za-z0-9_$]{3,}\1\s*,\s*(["'])var\s/.test(code) || /\bFunction\s*\(\s*(["'])[\s\S]{200,}\1\s*\)/.test(code);
  if (fnCtorWrap) markers.push('Function-constructor program wrapper');
  // (b) JS-Confuser magic constants (golden ratio / SHA-256 init — its PRNG/hash)
  const magic = /0x9e3779b9|0x6a09e667|0x243f6a88|0xbb67ae85|0x3c6ef372/.test(code);
  if (magic) markers.push('SHA/golden-ratio magic constants');
  // (c) mixed-case random identifiers (NOT obfuscator.io hex-only naming)
  const ids = code.match(/\b[A-Za-z_$][\w$]{4,}\b/g) || [];
  const mixedRandom = ids.filter(id => /[a-z]/.test(id) && /[A-Z]/.test(id) && /\d/.test(id) && !/^(function|return|window|document|require|module|exports|prototype|constructor|undefined)$/.test(id));
  const mixedRatio = ids.length ? mixedRandom.length / ids.length : 0;
  if (mixedRatio > 0.15) markers.push(`mixed-case random idents (${(mixedRatio * 100).toFixed(0)}%)`);
  // (d) countermeasures / integrity global
  if (/global\s*\[|globalThis\s*\[|\btypeof\s+\w+\s*===?\s*["']undefined["'][\s\S]{0,40}Function/.test(code)) markers.push('global-integrity guard');

  let confidence = 0;
  if (fnCtorWrap && magic) confidence = 0.9;
  else if (fnCtorWrap && mixedRatio > 0.15) confidence = 0.8;
  else if (magic && mixedRatio > 0.2) confidence = 0.7;
  else if (fnCtorWrap) confidence = 0.55;
  return { detected: confidence >= 0.55, confidence, markers };
}

// ───────────────────────────────────────────────────────────────────────────
// 3. JSCRAMBLER FEATURE DETECTION  (the "other functions" — structural classes)
//    Polymorphic → key on behavior CLASSES, not fixed snippets.
// ───────────────────────────────────────────────────────────────────────────
function detectJScramblerFeatures(code, ast) {
  const features = [];
  const add = (id, label, confidence, note) => features.push({ id, label, confidence, note });

  // Domain lock: hostname compared to embedded constant, gating logic.
  if (/location\s*(\.|\[)\s*['"]?(hostname|host|href|origin)/.test(code) && /===|==|indexOf|match|test\(/.test(code))
    add('domain_lock', 'Domain/URL lock', 0.7, 'location.hostname compared to constant');
  // Date lock: Date compared to a plausible 13-digit JS epoch (ms), close together.
  if (/(new\s+Date\s*\(|Date\s*\.\s*now|getTime\s*\(\s*\))[\s\S]{0,60}[<>]=?[\s\S]{0,10}\b1[0-9]{12}\b|\b1[0-9]{12}\b[\s\S]{0,10}[<>]=?[\s\S]{0,60}(getTime|Date\.now)/.test(code))
    add('date_lock', 'Date/expiry lock', 0.6, 'Date compared to epoch-ms constant');
  // Browser / OS lock.
  if (/navigator\s*(\.|\[)\s*['"]?(userAgent|platform|appVersion|vendor|language)/.test(code) && /test\(|indexOf|match|===/.test(code))
    add('browser_lock', 'Browser/OS lock', 0.6, 'navigator fingerprint gate');
  // Self-defending: source-integrity via toString / RegExp on function text.
  if (/(RegExp|\/.*\/)\s*[\s\S]{0,40}\.test\s*\(\s*\w+\s*(\+\s*['"][^'"]*['"])?\s*\)|\bFunction\b[\s\S]{0,30}toString|\btoString\s*\(\s*\)\s*[\s\S]{0,20}(search|test|replace)/.test(code))
    add('self_defending', 'Self-defending (source integrity)', 0.65, 'toString/RegExp self-check');
  // String concealing: many bracketed property/string accesses via a namespace object.
  const bracketAccess = (code.match(/\w+\[\s*['"][a-zA-Z_$][\w$]*['"]\s*\]/g) || []).length;
  if (bracketAccess > 30) add('string_concealing', 'String concealing (bracket-access heavy)', 0.5, `${bracketAccess} bracketed accesses`);
  // JScrambler namespace/method-decoder shape (.f= pattern & known domain-lock int).
  if (/\b\w+\.f\s*=\s*(function|\()/.test(code)) add('jscrambler_ns', 'JScrambler namespace-decoder (.f=)', 0.55, '.f= method decoder');
  if (/\[189638\]|\[0x2e526\]/.test(code)) add('jscrambler_domainlock_const', 'JScrambler domain-lock constant', 0.6, 'known domain-lock literal');
  return features;
}

// ───────────────────────────────────────────────────────────────────────────
// 4. VM / VIRTUALIZATION STRUCTURAL DETECTION  (detect, don't reverse)
// ───────────────────────────────────────────────────────────────────────────
function detectVM(code, ast) {
  const markers = [];
  let dispatcher = false, bytecode = false, handlers = 0, stackOps = 0, regOps = 0, vpc = false;

  // regex-level first (cheap)
  if (/switch\s*\(\s*\w+(\[\s*\w+(\+\+|--)?\s*\]|\.\w+)\s*\)/.test(code)) dispatcher = true;
  if (/\[(?:\s*-?\d+\s*,){40,}/.test(code)) bytecode = true;

  if (ast) {
    traverse(ast, {
      // dispatcher: switch inside a while/for(;;) loop with many cases
      SwitchStatement(p) {
        const cases = p.node.cases.length;
        let inLoop = false, cur = p.parentPath;
        for (let i = 0; i < 6 && cur; i++, cur = cur.parentPath) {
          if (cur.isWhileStatement() || cur.isForStatement() || cur.isDoWhileStatement()) { inLoop = true; break; }
        }
        if (inLoop && cases >= 5) { dispatcher = true; if (cases > handlers) handlers = cases; }
      },
      // VPC-style: obj.prop++ or idx++ used as a program counter feeding member access
      UpdateExpression(p) {
        const a = p.node.argument;
        if (t.isIdentifier(a) || t.isMemberExpression(a)) {
          const parent = p.parentPath && p.parentPath.node;
          if (parent && (t.isMemberExpression(parent) || t.isSwitchStatement(p.parentPath.parentPath && p.parentPath.parentPath.node))) vpc = true;
        }
      },
      CallExpression(p) {
        const c = p.node.callee;
        if (t.isMemberExpression(c) && t.isIdentifier(c.property)) {
          if (c.property.name === 'pop' || c.property.name === 'push') stackOps++;
        }
      },
      // register-array writes: X[<num/var>] = ...   (many of them)
      AssignmentExpression(p) {
        const l = p.node.left;
        if (t.isMemberExpression(l) && l.computed && (t.isNumericLiteral(l.property) || t.isIdentifier(l.property))) regOps++;
      }
    });
  }

  if (dispatcher) markers.push('switch-in-loop dispatcher');
  if (bytecode) markers.push('large numeric bytecode array');
  if (vpc) markers.push('virtual program counter');
  if (stackOps >= 8) markers.push(`stack ops (${stackOps})`);
  if (regOps >= 20) markers.push(`indexed register writes (${regOps})`);

  const detected = (dispatcher && (bytecode || handlers >= 8)) || (dispatcher && vpc && (stackOps >= 8 || regOps >= 20));
  let vmType = 'unknown';
  if (detected) vmType = stackOps > regOps ? 'stack-based' : (regOps > stackOps ? 'register-based' : 'unknown');
  return { detected, type: vmType, handlers, markers, confidence: detected ? (bytecode ? 0.7 : 0.5) : (dispatcher ? 0.25 : 0) };
}

// ───────────────────────────────────────────────────────────────────────────
// 5. ANTI-ANALYSIS TRAP DETECTION  (BEFORE dynamic run → neutralize plan)
// ───────────────────────────────────────────────────────────────────────────
function detectTraps(code, ast) {
  const traps = [];
  const add = (id, label, severity, neutralize, note) => traps.push({ id, label, severity, neutralize, note });

  // debugger trap (esp. inside a loop / interval)
  if (/\bdebugger\b/.test(code) || /constructor\s*\(\s*['"]debugger['"]/.test(code) || /atob\s*\(\s*['"]ZGVidWdnZXI/.test(code))
    add('debugger_trap', 'debugger statement trap', 'high', 'stub `debugger` (no-op) + neutralize Function("debugger")', 'anti-step-debug');
  if (/setInterval\s*\([^,]{1,40},\s*\d{1,4}\s*\)/.test(code) && /\bdebugger\b|toString/.test(code))
    add('interval_trap', 'setInterval self-defense loop', 'high', 'stub setInterval callback that references debugger/toString', 'periodic anti-tamper');
  // timing check
  if (/(Date\.now\s*\(\s*\)|performance\.now\s*\(\s*\))[\s\S]{0,60}(Date\.now|performance\.now)/.test(code))
    add('timing_check', 'timing delta anti-debug', 'medium', 'freeze Date.now()/performance.now() to constant', 'detects breakpoints via wall-clock delta');
  // source-integrity self-check
  if (/toString\s*\(\s*\)\s*[\s\S]{0,30}(search|test|replace|indexOf|match)|(RegExp|\/[^\n]{1,40}\/)[\s\S]{0,30}\.test\s*\(\s*[\s\S]{0,20}(function|arguments\.callee|\w+)\s*\)/.test(code))
    add('integrity_selfcheck', 'source-integrity (toString) self-check', 'high', 'make Function.prototype.toString return the pre-tamper source (or spoof)', 'corrupts logic if code reformatted');
  // devtools detection
  if (/window\.(outer|inner)(Width|Height)[\s\S]{0,40}(outer|inner)(Width|Height)|__REACT_DEVTOOLS|devtoolsFormatters/.test(code))
    add('devtools_detect', 'devtools open detection', 'medium', 'spoof window dimensions / devtools hooks', 'behavior changes when devtools open');
  // console tampering
  if (/console\s*\[\s*['"][^'"]+['"]\s*\]\s*=|console\.\w+\s*=\s*function/.test(code))
    add('console_tamper', 'console override', 'low', 'sandbox console (no-op or capture)', 'suppresses/monitors console');
  // environmental keying (decrypt only under condition) — value-gated decode
  if (/(location|navigator|document\.domain)[\s\S]{0,80}(atob|charCodeAt|fromCharCode|decrypt|xor|\^)/i.test(code))
    add('env_keying', 'environmental keying (env-gated decode)', 'high', 'provide expected env (hostname/date/UA) OR extract key statically', 'string decode gated on environment');
  // dynamic exec sinks (not a trap per se, but must be watched when running)
  if (/\bnew\s+Function\s*\(|\beval\s*\(|document\.write\s*\(/.test(code))
    add('dynamic_exec', 'dynamic code execution sink', 'info', 'hook eval/Function/document.write to capture generated code', 'runtime code generation');

  // AST: obfuscator.io call-controller wrapper — IDENT(this, function(){...}).
  // This is the REAL shape of selfDefending / debugProtection; the "debugger"
  // keyword and integrity regex live in the string array (concealed), so the
  // literal-keyword regexes above miss them. The wrapper shape is the invariant.
  if (ast) {
    traverse(ast, {
      CallExpression(p) {
        const a = p.node.arguments;
        if (t.isIdentifier(p.node.callee) && a.length >= 2 && t.isThisExpression(a[0]) && (t.isFunctionExpression(a[1]) || t.isArrowFunctionExpression(a[1]))) {
          const body = src(a[1]);
          // self-defending: integrity/regex/indexOf('\n') check on function source
          if (/indexOf|search|test|toString|RegExp|constructor/.test(body))
            add('selfdefend_wrapper', 'self-defending call-controller (this,fn)', 'high', 'stub the (this,function(){}) self-defense wrapper before eval', 'obfuscator.io selfDefending — corrupts on reformat');
          // debug-protection: builds a while(true)/debugger via constructor + interval
          if (/constructor|while|debugg|interval/i.test(body) || /setInterval/.test(code))
            add('debugprotect_wrapper', 'debug-protection call-controller loop', 'high', 'stub the debug-protection wrapper + setInterval trap', 'obfuscator.io debugProtection (concealed debugger)');
        }
      }
    });
  }

  const seen = new Set();
  const deduped = traps.filter(x => { if (seen.has(x.id)) return false; seen.add(x.id); return true; });
  const plan = deduped.filter(x => x.severity === 'high' || x.severity === 'medium').map(x => x.neutralize);
  return { traps: deduped, neutralizePlan: [...new Set(plan)] };
}

// ───────────────────────────────────────────────────────────────────────────
// 6. MULTI-LAYER / STACKING DETECTION  (decode → execute sink chains)
// ───────────────────────────────────────────────────────────────────────────
function detectLayers(code, ast) {
  const layers = [];
  const sinks = /\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"]|setInterval\s*\(\s*['"]|document\.write\s*\(/;
  const decoders = /\batob\s*\(|unescape\s*\(|decodeURIComponent\s*\(|String\.fromCharCode|\.charCodeAt|\\x[0-9a-f]{2}/i;

  // heuristic: a decode result flowing into an exec sink = at least one wrap layer
  if (ast) {
    traverse(ast, {
      CallExpression(p) {
        const c = p.node.callee;
        const isSink = (t.isIdentifier(c) && (c.name === 'eval' || c.name === 'Function')) ||
                       (t.isMemberExpression(c) && t.isIdentifier(c.property) && c.property.name === 'write');
        if (!isSink) return;
        const argSrc = src(p.node.arguments[0] || {});
        if (decoders.test(argSrc)) layers.push({ sink: t.isIdentifier(c) ? c.name : 'document.write', decodedArg: true });
      }
    });
  }
  const encoderCount = [/atob/, /unescape/, /fromCharCode/, /charCodeAt/, /\\x[0-9a-f]{2}/i, /\\u[0-9a-f]{4}/i].filter(re => re.test(code)).length;
  const hasSink = sinks.test(code);
  const stacked = layers.length > 0 || (encoderCount >= 2 && hasSink);
  return { stacked, wrapLayers: layers.length, distinctEncoders: encoderCount, execSink: hasSink, detail: layers.slice(0, 5) };
}

// ───────────────────────────────────────────────────────────────────────────
// 7. ENTROPY TRIAGE  (per research thresholds)
// ───────────────────────────────────────────────────────────────────────────
function shannon(sample) {
  if (!sample) return 0;
  const freq = {}; for (const ch of sample) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0; const n = sample.length;
  for (const k in freq) { const p = freq[k] / n; h -= p * Math.log2(p); }
  return h;
}
function entropyTriage(code) {
  // longest/among-longest string literals → the payload pool
  const strs = (code.match(/(["'])(?:\\.|(?!\1).)*\1/g) || []).map(s => s.slice(1, -1)).filter(s => s.length >= 16);
  strs.sort((a, b) => b.length - a.length);
  const pool = strs.slice(0, 200).join('');
  const poolH = Math.round(shannon(pool) * 100) / 100;
  // per-string flag: >64 chars & >4.5 bits/char (AquilaX)
  const flagged = strs.filter(s => s.length > 64 && shannon(s) > 4.5).length;
  // whole-source byte entropy
  const byteH = Math.round(shannon(code.slice(0, 200000)) * 100) / 100;
  let verdict = 'normal';
  if (byteH > 5.6 || poolH > 5.2 || flagged > 0) verdict = 'obfuscated-likely';
  if (poolH > 5.9 || byteH > 6.2) verdict = 'encoded/encrypted-likely';
  return { poolEntropy: poolH, byteEntropy: byteH, highEntropyStrings: flagged, verdict };
}

// ───────────────────────────────────────────────────────────────────────────
// 8. STRUCTURAL FEATURES + NOVELTY  ("obfuscated-but-unknown")
// ───────────────────────────────────────────────────────────────────────────
function structuralFeatures(code, ast) {
  let computedAccess = 0, dotAccess = 0, strLits = 0, fns = 0, maxArray = 0, hexIds = 0, totalIds = 0, depth = 0;
  const hexIdRe = /^_?0x[0-9a-f]+$|^[a-z]\d?_0x[0-9a-f]+$/i;
  if (ast) {
    const walk = (node, d) => { if (d > depth) depth = d; };
    traverse(ast, {
      MemberExpression(p) { if (p.node.computed) computedAccess++; else dotAccess++; },
      StringLiteral() { strLits++; },
      'FunctionDeclaration|FunctionExpression|ArrowFunctionExpression'() { fns++; },
      ArrayExpression(p) { if (p.node.elements.length > maxArray) maxArray = p.node.elements.length; },
      Identifier(p) { totalIds++; if (hexIdRe.test(p.node.name)) hexIds++; },
      enter(p) { walk(p.node, p.scope ? 0 : 0); }
    });
  }
  const totalAccess = computedAccess + dotAccess || 1;
  return {
    computedAccessRatio: Math.round((computedAccess / totalAccess) * 100) / 100,
    stringLiterals: strLits,
    functions: fns,
    largestArray: maxArray,
    hexIdentifierRatio: totalIds ? Math.round((hexIds / totalIds) * 100) / 100 : 0
  };
}

// ───────────────────────────────────────────────────────────────────────────
// MAIN
// ───────────────────────────────────────────────────────────────────────────
function advancedRecon(code) {
  const ast = parse(code);
  const encodings = detectEncodings(code);
  const bundler = detectBundler(code);
  const packer = detectPacker(code);
  const jscrambler = detectJScramblerFeatures(code, ast);
  const vm = detectVM(code, ast);
  const trapResult = detectTraps(code, ast);
  const layers = detectLayers(code, ast);
  const entropy = entropyTriage(code);
  const features = structuralFeatures(code, ast);
  const obfio = detectObfuscatorIO(code, ast, features);
  const jsconfuser = detectJSConfuser(code, ast, features);

  const familyEncoding = encodings.find(e => e.level === 'family' && e.confidence >= 0.9);
  const jscramblerScore = jscrambler.reduce((s, f) => s + f.confidence, 0);

  // structural "obfuscated-but-unknown" score (name-independent)
  let obfScore = 0;
  if (features.hexIdentifierRatio > 0.3) obfScore += 0.3;
  if (features.computedAccessRatio > 0.5) obfScore += 0.2;
  if (features.largestArray > 50) obfScore += 0.2;
  if (entropy.verdict !== 'normal') obfScore += 0.2;
  if (trapResult.traps.some(x => x.severity === 'high')) obfScore += 0.1;

  // ── family classification priority: structural families rank above sub-encodings ──
  // packer > bundler > VM > obfuscator.io > jscrambler > family-encoding > (novelty)
  let family = null, confidence = 0, route = 'obfuscator_static', strategy = 'static fold + fallback';
  if (packer) {
    family = packer.id; confidence = packer.confidence; route = 'packer'; strategy = 'unwrap decode→exec layers iteratively (replace eval, capture payload)';
  } else if (bundler) {
    family = bundler.id; confidence = bundler.confidence; route = 'webpack'; strategy = 'unbundle modules then per-module deobfuscate';
  } else if (obfio.detected) {
    family = 'obfuscator_io'; confidence = obfio.confidence; route = 'obfuscator_dynamic'; strategy = 'sandbox decode (100% coverage) + const-bindings + proxy resolve + strip';
  } else if (jsconfuser.detected) {
    family = 'js_confuser'; confidence = jsconfuser.confidence; route = 'jsconfuser';
    strategy = vm.detected
      ? 'unwrap Function-constructor program; VM-like CFF present → string recovery + honest partial on flattened logic'
      : 'unwrap Function-constructor program, resolve string-concealing; CFF/opaque-predicate parts = partial';
  } else if (vm.detected) {
    family = 'vm_virtualization'; confidence = vm.confidence; route = 'virtualized'; strategy = 'HONEST partial: string extraction via runtime trace; full logic needs opcode map + CFG reconstruction (devirt phase)';
  } else if (jscramblerScore >= 1.0) {
    family = 'jscrambler'; confidence = Math.min(0.85, jscramblerScore / 3); route = 'jscrambler'; strategy = 'string-concealing recovery; VM/CFF parts = partial';
  } else if (familyEncoding) {
    family = familyEncoding.id; confidence = familyEncoding.confidence; route = 'esoteric'; strategy = 'interpret encoder in isolated sandbox';
  } else if (encodings.some(e => ['base64_atob', 'fromcharcode', 'percent_encoding'].includes(e.id)) && layers.execSink) {
    family = 'layered_encoding'; confidence = 0.5; route = 'packer'; strategy = 'unwrap decode→exec layers iteratively';
  }

  const obfuscated = !!family || obfScore >= 0.5;
  const novelty = (!family && obfuscated) ? 'obfuscated-but-unknown' : (family ? 'classified' : 'clean-or-plain');

  // ── FALSE-POSITIVE CONTROL: JScrambler features that ALSO appear in other
  // families (string_concealing, self_defending — obfuscator.io/js-confuser use
  // heavy bracket-access + self-defense too) must NOT be reported as JScrambler
  // when a more specific family already claimed the file. Only JScrambler-SPECIFIC
  // markers (.f= namespace, [189638] domain-lock const) survive that filter.
  const JSCR_SPECIFIC = new Set(['jscrambler_ns', 'jscrambler_domainlock_const']);
  const claimedByOther = family && family !== 'jscrambler';
  const reportedJscr = claimedByOther ? jscrambler.filter(f => JSCR_SPECIFIC.has(f.id)) : jscrambler;
  const reportedJscrScore = reportedJscr.reduce((s, f) => s + f.confidence, 0);

  return {
    family, confidence: Math.round(confidence * 100) / 100, novelty, obfuscated,
    route, strategy,
    encodings,
    bundler,
    packer,
    obfuscatorIO: obfio,
    jsConfuser: jsconfuser,
    jscrambler: { features: reportedJscr, score: Math.round(reportedJscrScore * 100) / 100, likelyVM: vm.detected && reportedJscrScore > 0 },
    vm,
    traps: trapResult.traps,
    neutralizePlan: trapResult.neutralizePlan,
    layers,
    entropy,
    features,
    obfuscationScore: Math.round(obfScore * 100) / 100
  };
}

module.exports = {
  advancedRecon,
  detectEncodings, detectBundler, detectPacker, detectObfuscatorIO,
  detectJScramblerFeatures, detectVM, detectTraps, detectLayers,
  entropyTriage, structuralFeatures
};
