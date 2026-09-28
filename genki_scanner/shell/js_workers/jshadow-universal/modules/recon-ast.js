/**
 * 🔍 J-Shadow Recon — obfuscation fingerprint pass
 *
 * Profiles a file BEFORE decoding so the engine knows how to attack it:
 *   • regex signatures      — obfuscator family, encodings, anti-debug
 *   • AST-shape signatures   — string-array provider, rotation IIFE, decoders,
 *                              decoder proxies, packers (survives renaming)
 *   • decoder-body hashing   — normalized decoder shape -> stable family key
 *   • entropy analysis       — how encoded the string pool is
 *   • required-files scan     — external deps needed for a full dynamic run
 *
 * Output: { family, encodings, antiDebug, structure, requires, entropy,
 *           shapeHash, score, strategy, confidence }
 * The strategy tells the pipeline which tier to use (static / dynamic / ai).
 */

'use strict';

const crypto = require('crypto');

let babel, traverse, t;
try {
  babel = require('@babel/core');
  traverse = require('@babel/traverse').default;
  t = require('@babel/types');
} catch (e) { /* regex-only mode if babel absent */ }

// ── Regex signature database (family + encoding + anti-debug) ──
const SIGNATURES = {
  family: [
    { id: 'obfuscator_io', re: /_0x[0-9a-f]{4,6}\b|a\d+_0x[0-9a-f]+/i, w: 30, label: 'obfuscator.io' },
    { id: 'jscrambler', re: /\b\w+\.f\s*=\s*\(function|\[189638\]|jscrambler/i, w: 35, label: 'JScrambler' },
    { id: 'webpack', re: /__webpack_require__|__webpack_modules__|webpackJsonp/, w: 40, label: 'webpack bundle' },
    { id: 'packer_eval', re: /eval\(function\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/, w: 40, label: 'P.A.C.K.E.R' },
    { id: 'jsfuck', re: /\[\]\[[\[(!\+]+\]/, w: 45, label: 'JSFuck' },
    { id: 'aaencode', re: /ﾟωﾟ|ﾟДﾟ|ﾟΘﾟ/, w: 45, label: 'AAEncode' },
    { id: 'jjencode', re: /\$=~\[\];/, w: 45, label: 'JJEncode' },
    // Universal catch-all: any string-array + decoder pattern not matching above families
    { id: 'generic_string_array', re: /var\s+\w+\s*=\s*\[(?:\s*['"][^'"]*['"]\s*,){10,}/, w: 15, label: 'generic string-array obfuscation' }
  ],
  // VM / virtualization = a different problem class (interpreter loop over bytecode).
  // Not string-decodable by hooking a decoder — needs opcode mapping + CFG recovery.
  virtualization: [
    { id: 'cff_dispatcher', re: /switch\s*\(\s*\w+\[\s*\w+\+\+\s*\]\s*\)|while\s*\(\s*!!\[\]\s*\)\s*\{\s*switch/, w: 25, label: 'control-flow flattening' },
    { id: 'bytecode_array', re: /\[(?:\s*-?\d+\s*,){30,}/, w: 20, label: 'bytecode array' },
    { id: 'interpreter_loop', re: /for\s*\(;;\)|while\s*\(\s*(?:true|1)\s*\)\s*\{[\s\S]{0,80}switch/, w: 20, label: 'interpreter loop' },
    { id: 'stack_machine', re: /\.pop\(\)[\s\S]{0,40}\.push\(|\bsp\+\+|\bstack\[/, w: 12, label: 'stack machine ops' }
  ],
  encoding: [
    { id: 'base64', re: /["'][A-Za-z0-9+/]{16,}={0,2}["']/, w: 10, label: 'base64' },
    { id: 'base64_atob', re: /atob\s*\(/, w: 12, label: 'atob() decode' },
    { id: 'hex_escape', re: /\\x[0-9a-fA-F]{2}/, w: 8, label: 'hex escapes' },
    { id: 'unicode_escape', re: /\\u[0-9a-fA-F]{4}/, w: 8, label: 'unicode escapes' },
    { id: 'rc4', re: /charCodeAt\([^)]*\)\s*\^|%\s*256[\s\S]{0,40}charCodeAt/, w: 25, label: 'RC4 / XOR stream' },
    { id: 'hex_numbers', re: /\b0x[0-9a-fA-F]{2,}\b/, w: 5, label: 'hex numerics' },
    { id: 'fromcharcode', re: /String\.fromCharCode\s*\(/, w: 12, label: 'fromCharCode builder' },
    { id: 'eval_unescape', re: /eval\s*\(\s*unescape\s*\(/, w: 18, label: 'eval(unescape())' },
    { id: 'eval_generic', re: /eval\s*\(|new\s+Function\s*\(/, w: 10, label: 'eval/Function constructor' },
    { id: 'string_concat', re: /["'][^"']{1,6}["']\s*\+\s*["'][^"']{1,6}["']\s*\+\s*["']/, w: 8, label: 'string concatenation' },
    { id: 'array_lookup', re: /\w+\[\d+\]\s*[,;][\s\S]{0,40}\w+\[\d+\]/, w: 6, label: 'array index lookup' },
    { id: 'computed_prop', re: /\[\s*["'][a-zA-Z]+["']\s*\]/, w: 5, label: 'computed property access' }
  ],
  antiDebug: [
    { id: 'debugger_trap', re: /\bdebugger\b|constructor\(\s*["']debugger["']/, w: 15, label: 'debugger trap' },
    { id: 'setinterval_trap', re: /setInterval\s*\([^,]+,\s*\d{2,4}\s*\)/, w: 10, label: 'setInterval trap' },
    { id: 'tostring_selfcheck', re: /\.toString\(\)\)\s*\?|test\(\s*\w+\.toString/, w: 20, label: 'toString() self-check' },
    { id: 'console_hook', re: /console\[[^\]]+\]\s*=|\['log'\][\s\S]{0,60}bind/, w: 10, label: 'console hook' },
    { id: 'timing_check', re: /Date\.now\(\)[\s\S]{0,40}Date\.now\(\)|performance\.now/, w: 8, label: 'timing check' }
  ]
};

function regexScan(code, group) {
  const hits = [];
  for (const s of SIGNATURES[group]) if (s.re.test(code)) hits.push({ id: s.id, label: s.label, w: s.w });
  return hits;
}

// ── Shannon entropy of the string pool (0..8 bits/char) ──
function stringEntropy(code) {
  const strs = code.match(/["'][A-Za-z0-9+/=_\-]{8,}["']/g) || [];
  if (!strs.length) return 0;
  const sample = strs.slice(0, 400).join('').replace(/["']/g, '');
  if (!sample) return 0;
  const freq = {};
  for (const ch of sample) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0; const n = sample.length;
  for (const k in freq) { const p = freq[k] / n; h -= p * Math.log2(p); }
  return Math.round(h * 100) / 100;
}

// ── AST-shape detection: array provider, rotation, decoders, proxies ──
function astShapes(code) {
  const shape = { stringArray: false, arrayLen: 0, rotation: false, decoders: [], proxies: 0, packer: false, requires: [] };
  if (!babel) return shape;
  let ast;
  try { ast = babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } }); }
  catch (e) { return shape; }

  let arrayName = null;
  traverse(ast, {
    'FunctionDeclaration|VariableDeclarator'(p) {
      if (arrayName) return;
      let arr = null, name = null;
      if (p.isFunctionDeclaration() && p.node.id) {
        name = p.node.id.name; const b = p.node.body.body || [];
        const ret = b.find(s => t.isReturnStatement(s));
        if (ret && t.isArrayExpression(ret.argument)) arr = ret.argument;
        if (!arr) for (const s of b) if (t.isVariableDeclaration(s)) { const d = s.declarations.find(d => t.isArrayExpression(d.init)); if (d) { arr = d.init; break; } }
      } else if (p.isVariableDeclarator() && t.isIdentifier(p.node.id) && t.isArrayExpression(p.node.init)) { name = p.node.id.name; arr = p.node.init; }
      if (arr && arr.elements.length >= 10 && arr.elements.filter(e => e && t.isStringLiteral(e)).length >= arr.elements.length * 0.6) { arrayName = name; shape.stringArray = true; shape.arrayLen = arr.elements.length; }
    }
  });

  traverse(ast, {
    ExpressionStatement(p) {
      if (!arrayName) return;
      const s = (p.node.expression && p.node.expression.type === 'CallExpression') ? generateSafe(p.node) : '';
      if (s && s.includes(arrayName) && /push|shift/.test(s) && /parseInt|while|for/.test(s)) shape.rotation = true;
    },
    FunctionDeclaration(p) {
      const n = p.node.id && p.node.id.name; if (!n || n === arrayName) return;
      const s = generateSafe(p.node);
      if (s && s.includes(arrayName) && /charCodeAt|fromCharCode|decodeURIComponent|atob/.test(s)) shape.decoders.push(n);
    },
    ObjectExpression(p) {
      const props = p.node.properties;
      if (props.length >= 3 && props.every(pr => t.isObjectProperty(pr))) {
        const fnProps = props.filter(pr => (t.isFunctionExpression(pr.value) || t.isArrowFunctionExpression(pr.value)));
        if (fnProps.length >= 2 && /__webpack/.test(generateSafe(p.node) || '')) shape.packer = true;
      }
    },
    CallExpression(p) {
      const c = p.node.callee;
      if (t.isIdentifier(c, { name: 'require' }) && p.node.arguments.length === 1 && t.isStringLiteral(p.node.arguments[0])) {
        if (!shape.requires.includes(p.node.arguments[0].value)) shape.requires.push(p.node.arguments[0].value);
      }
    },
    'FunctionDeclaration|FunctionExpression'(p) {
      // proxy: function(a,b){ return DECODER(<expr>) }
      const fn = p.node; const body = fn.body && fn.body.body;
      if (body && body.length === 1 && t.isReturnStatement(body[0]) && t.isCallExpression(body[0].argument)) {
        const callee = body[0].argument.callee;
        if (t.isIdentifier(callee) && shape.decoders.includes(callee.name)) shape.proxies++;
      }
    }
  });
  return shape;
}

function generateSafe(node) {
  try { return require('@babel/generator').default(node, { compact: true }).code; } catch (e) { return ''; }
}

// ── Decoder-body hash: normalize a decoder's shape into a stable key ──
function decoderShapeHash(code, decoderNames) {
  if (!babel || !decoderNames.length) return null;
  let ast; try { ast = babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true } }); } catch (e) { return null; }
  let src = '';
  traverse(ast, { FunctionDeclaration(p) { const n = p.node.id && p.node.id.name; if (decoderNames.includes(n)) src += generateSafe(p.node); } });
  if (!src) return null;
  // normalize: drop identifiers + numbers + string contents -> keep structural tokens
  const norm = src
    .replace(/_0x[0-9a-fA-F]+/g, 'ID').replace(/\b[A-Za-z_$][\w$]*\b/g, 'ID')
    .replace(/0x[0-9a-fA-F]+|\b\d+\b/g, 'N').replace(/(["'])(?:\\.|(?!\1).)*\1/g, 'S')
    .replace(/\s+/g, '');
  return crypto.createHash('sha1').update(norm).digest('hex').slice(0, 16);
}

/**
 * Full recon. Returns a profile + recommended strategy.
 */
function recon(code) {
  const family = regexScan(code, 'family');
  const encoding = regexScan(code, 'encoding');
  const antiDebug = regexScan(code, 'antiDebug');
  const virtualization = regexScan(code, 'virtualization');
  const entropy = stringEntropy(code);
  const shape = astShapes(code);
  const shapeHash = decoderShapeHash(code, shape.decoders);

  // score
  let score = 0;
  [...family, ...encoding, ...antiDebug, ...virtualization].forEach(h => score += h.w);
  if (shape.stringArray) score += 15;
  if (shape.rotation) score += 15;
  if (shape.decoders.length) score += 10;
  score = Math.min(100, score);

  // strategy decision
  const hasRC4 = encoding.some(e => e.id === 'rc4');
  const hasSelfDefend = antiDebug.length > 0;
  const isVM = virtualization.length >= 2 || (family.some(f => f.id === 'jscrambler') && virtualization.length >= 1);
  const familyId = (family[0] && family[0].id) || (shape.stringArray ? 'obfuscator_io' : 'unknown');

  let strategy, confidence, reason;
  if (isVM) {
    // VM / virtualization is NOT string-decodable by hooking a decoder.
    strategy = 'virtualized'; confidence = 0.8;
    reason = `VM/virtualization (${virtualization.map(v => v.label).join(', ')}) — needs opcode mapping + CFG recovery, not decoder hooking`;
  } else if (family.some(f => f.id === 'jscrambler')) {
    strategy = 'jscrambler'; confidence = 0.75; reason = 'JScrambler string-protection (non-VM)';
  } else if (shape.packer || family.some(f => f.id === 'webpack')) {
    strategy = 'debundle'; confidence = 0.9; reason = 'webpack bundle detected';
  } else if (family.some(f => f.id === 'packer_eval')) {
    strategy = 'unpack_then_static'; confidence = 0.9; reason = 'eval-packer detected';
  } else if (shape.stringArray && (hasRC4 || hasSelfDefend || shape.rotation)) {
    strategy = 'dynamic'; confidence = 0.85;
    reason = `string-array + ${hasRC4 ? 'RC4 ' : ''}${shape.rotation ? 'rotation ' : ''}${hasSelfDefend ? 'anti-debug' : ''}`.trim();
  } else if (shape.stringArray) {
    strategy = 'static'; confidence = 0.8; reason = 'plain string-array, static suffices';
  } else if (encoding.length) {
    strategy = 'static'; confidence = 0.6; reason = 'simple encodings only';
  } else {
    strategy = 'static'; confidence = 0.3; reason = 'no strong obfuscation signal';
  }

  return {
    family: familyId,
    familyLabel: (family[0] && family[0].label) || (shape.stringArray ? 'obfuscator.io (shape)' : 'unknown'),
    encodings: encoding.map(e => e.id),
    antiDebug: antiDebug.map(a => a.id),
    virtualization: virtualization.map(v => v.id),
    isVM,
    structure: { stringArray: shape.stringArray, arrayLen: shape.arrayLen, rotation: shape.rotation, decoders: shape.decoders, proxies: shape.proxies, packer: shape.packer },
    requires: shape.requires,
    entropy,
    shapeHash,
    score,
    severity: score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : score >= 20 ? 'low' : 'minimal',
    strategy,
    confidence,
    reason
  };
}

module.exports = { recon, SIGNATURES };
