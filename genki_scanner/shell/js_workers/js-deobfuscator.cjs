#!/usr/bin/env node
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  GENKI-PROBER — js-deobfuscator.cjs v2.0                               ║
// ║  JS Deep Extraction: GZip decompress, Webpack split, XOR/entropy deobf ║
// ║  GENKI-TECH LABS | ANBU BLACK OPS SECURITY                             ║
// ╚══════════════════════════════════════════════════════════════════════════╝

'use strict';

const fs   = require('fs');
const path = require('path');
const zlib = require('zlib');
const { promisify } = require('util');

const gunzip   = promisify(zlib.gunzip);
const inflate  = promisify(zlib.inflate);
const brotli   = promisify(zlib.brotliDecompress);

// ── Constants ────────────────────────────────────────────────────────────────

// Shannon entropy threshold — above this = likely obfuscated
const ENTROPY_THRESHOLD = 4.5;

// Minimum file size to bother analyzing (bytes)
const MIN_SIZE = 100;

// Webpack chunk signature patterns
const WEBPACK_PATTERNS = [
  /\bwebpackJsonp\s*\(/,
  /\bwebpackChunk\w*\s*=\s*\(\s*self\[/,
  /\(__webpack_require__\)/,
  /\bwebpack_require\b/,
  /\/\*!\s+\d+\s+\*\//,                      // chunk ID comments
  /\bmodule\s*\.\s*exports\s*=\s*__webpack_require__/,
];

// Rollup/Vite bundle patterns
const ROLLUP_PATTERNS = [
  /\/\*\*\s+@license\s+.+\*\//,
  /\bexports\s*\[\s*['"]default['"]\s*\]/,
  /define\(\['require','exports'/,
];

// Known XOR key patterns (common obfuscators)
const XOR_PATTERNS = [
  /\.charCodeAt\(\w+\)\s*\^\s*\w+/,           // xor char-by-char
  /String\.fromCharCode\(.+\^/,
  /\[\s*\d+\s*,\s*\d+\s*,\s*\d+.*\]\.map\(.*charCodeAt/,
];

// Self-executing string decode patterns
const DECODE_PATTERNS = [
  /atob\s*\(/,                                  // base64
  /Buffer\.from\s*\(.*,\s*['"]base64['"]\s*\)/,
  /eval\s*\(\s*(?:atob|unescape|decodeURI)/,
  /\(function\(\w,\w\)\{.*\.split.*\.join/,     // JSFuck / obfuscator.io pattern
  /\bString\['fromCharCode'\]/,
];

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Shannon entropy of a string (higher = more randomness = likely obfuscated)
 */
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((acc, f) => {
    const p = f / len;
    return acc + p * Math.log2(p);
  }, 0);
}

/**
 * Detect if a buffer starts with GZip magic bytes (1f 8b)
 */
function isGzip(buf) {
  return buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b;
}

/**
 * Detect if content looks like a zlib stream (78 01 / 78 9c / 78 da)
 */
function isZlib(buf) {
  return buf.length >= 2 && buf[0] === 0x78 && (buf[1] === 0x01 || buf[1] === 0x9c || buf[1] === 0xda);
}

/**
 * Detect Brotli — no magic bytes, so detect by trying to decompress
 * We'll do this as a last resort only.
 */

/**
 * Basic JS prettifier (indent + newlines) — used as fallback when js-beautify not available
 */
function basicPrettify(code) {
  let out = '';
  let depth = 0;
  let inStr = null;
  let escape = false;
  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    // String tracking
    if (escape) { out += ch; escape = false; continue; }
    if (ch === '\\' && inStr) { out += ch; escape = true; continue; }
    if (ch === inStr) { out += ch; inStr = null; continue; }
    if (!inStr && (ch === '"' || ch === "'" || ch === '`')) { out += ch; inStr = ch; continue; }
    if (inStr) { out += ch; continue; }
    // Structure
    if (ch === '{' || ch === '[' || ch === '(') {
      out += ch + '\n' + '  '.repeat(++depth);
    } else if (ch === '}' || ch === ']' || ch === ')') {
      out += '\n' + '  '.repeat(--depth < 0 ? (depth = 0) : depth) + ch;
    } else if (ch === ';') {
      out += ch + '\n' + '  '.repeat(depth);
    } else if (ch === ',') {
      out += ch + '\n' + '  '.repeat(depth);
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * Try to use js-beautify if available, fallback to basicPrettify
 */
function prettify(code) {
  try {
    const jsBeautify = require('js-beautify');
    return jsBeautify.js(code, { indent_size: 2, space_in_empty_paren: true, max_preserve_newlines: 2 });
  } catch(e) {
    return basicPrettify(code);
  }
}

/**
 * Detect obfuscation type from source string
 */
function detectObfuscationType(src) {
  const flags = [];
  if (XOR_PATTERNS.some(rx => rx.test(src)))    flags.push('XOR');
  if (DECODE_PATTERNS.some(rx => rx.test(src))) flags.push('BASE64/EVAL');
  if (/\$\$\w{3,}/.test(src))                   flags.push('OBFUSCATOR.IO');
  if (/\b_0x[0-9a-f]{4,}\b/.test(src))          flags.push('HEX_VARS');
  if (/\[\s*['"]\\x/.test(src))                 flags.push('HEX_STRING_ARRAY');
  if (/JSFuck|\[\+\[\]\]|\[\!/.test(src))       flags.push('JSFUCK');
  if (/\beval\s*\(/.test(src))                   flags.push('EVAL');
  if (shannonEntropy(src.slice(0, 2000)) > ENTROPY_THRESHOLD) flags.push('HIGH_ENTROPY');
  return flags;
}

/**
 * Detect if this is a webpack bundle and extract module chunks
 */
function isWebpack(src) {
  return WEBPACK_PATTERNS.some(rx => rx.test(src));
}
function isRollup(src) {
  return ROLLUP_PATTERNS.some(rx => rx.test(src));
}

/**
 * Extract webpack modules from a bundle
 * Handles: webpack 4 (webpackJsonp), webpack 5 (self[chunkName])
 */
function extractWebpackModules(src) {
  const modules = [];
  
  // Webpack 5: modules defined as object/array in the chunk
  // Pattern: (self["webpackChunkapp"] = self["webpackChunkapp"] || []).push([[chunkId], { moduleId: function(...) {...} }])
  const chunkRx = /\.push\(\[\[[\d,]+\],\s*\{([\s\S]*?)\}\]\)/g;
  let m;
  while ((m = chunkRx.exec(src)) !== null) {
    const moduleBlock = m[1];
    // Extract individual modules: "moduleId": function(module, exports, __webpack_require__) { ... }
    const modRx = /["']?(\d+|[./\\a-zA-Z0-9_-]+)["']?\s*:\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\n\s*\})/g;
    let mm;
    while ((mm = modRx.exec(moduleBlock)) !== null) {
      modules.push({ id: mm[1], code: mm[2] });
    }
  }

  // Webpack 4: webpackJsonp([chunkIds], { "moduleId": function(...){} })
  const w4Rx = /webpackJsonp\(\s*\[[\d,\s]*\]\s*,\s*\{([\s\S]*?)\}\s*\)/g;
  while ((m = w4Rx.exec(src)) !== null) {
    const modRx = /["']?(\w+)["']?\s*:\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\n\s*\})/g;
    let mm;
    while ((mm = modRx.exec(m[1])) !== null) {
      modules.push({ id: mm[1], code: mm[2] });
    }
  }

  return modules;
}

/**
 * Try to decode a base64 eval payload
 * e.g. eval(atob("...")) or eval(Buffer.from("...","base64").toString())
 */
function tryDecodeBase64Evals(src) {
  const decoded = [];
  const atobRx = /(?:eval\s*\()?\s*atob\s*\(\s*['"`]([\w+/=]+)['"`]\s*\)/g;
  let m;
  while ((m = atobRx.exec(src)) !== null) {
    try {
      const b64 = m[1];
      const dec = Buffer.from(b64, 'base64').toString('utf8');
      decoded.push({ type: 'atob', offset: m.index, decoded: dec.substring(0, 2000) });
    } catch(e) {}
  }
  const bufRx = /Buffer\.from\s*\(\s*['"`]([\w+/=]+)['"`]\s*,\s*['"]base64['"]\s*\)/g;
  while ((m = bufRx.exec(src)) !== null) {
    try {
      const dec = Buffer.from(m[1], 'base64').toString('utf8');
      decoded.push({ type: 'Buffer.base64', offset: m.index, decoded: dec.substring(0, 2000) });
    } catch(e) {}
  }
  return decoded;
}

/**
 * Scan source for high-entropy string literals (potential encoded payloads)
 */
function findHighEntropyStrings(src, threshold = 5.0, minLen = 50) {
  const found = [];
  const strRx = /['"`]([\w+/=\\]{50,})['"`]/g;
  let m;
  while ((m = strRx.exec(src)) !== null) {
    const s = m[1];
    const ent = shannonEntropy(s);
    if (ent >= threshold) {
      found.push({ entropy: ent.toFixed(2), length: s.length, preview: s.substring(0, 80), offset: m.index });
    }
  }
  return found;
}

// ── Main Module Class ─────────────────────────────────────────────────────────

class JsDeobfuscator {
  constructor(logger, config) {
    this.logger  = logger;
    this.config  = config;
    this.outDir  = path.join(config.outputDir, 'js-deobf');
    this.findings = [];
    this._summary = { analyzed: 0, gzip: 0, zlib: 0, webpack: 0, rollup: 0, obfuscated: 0, base64Decoded: 0, modulesExtracted: 0, highEntropyStrings: 0, errors: 0 };
  }

  async run(jsFiles = [], inlineScripts = [], runtimeGlobals = {}) {
    if (!fs.existsSync(this.outDir)) fs.mkdirSync(this.outDir, { recursive: true });

    this.logger.log('JS-DEOBF', 'INFO', `Analyzing ${jsFiles.length} JS files + ${inlineScripts.length} inline scripts`);

    // Process downloaded JS files
    for (const filePath of jsFiles) {
      try {
        await this._processFile(filePath);
      } catch(e) {
        this.logger.log('JS-DEOBF', 'WARN', `Error processing ${filePath}: ${e.message}`);
        this._summary.errors++;
      }
    }

    // Process inline scripts
    for (let i = 0; i < inlineScripts.length; i++) {
      const script = inlineScripts[i];
      const src = typeof script === 'string' ? script : script?.content || '';
      const srcUrl = typeof script === 'string' ? `inline_${i}` : (script?.src || `inline_${i}`);
      if (!src || src.length < MIN_SIZE) continue;
      try {
        await this._analyzeSource(src, srcUrl, `inline_${i}.js`);
      } catch(e) {
        this.logger.log('JS-DEOBF', 'WARN', `Inline script ${i} error: ${e.message}`);
        this._summary.errors++;
      }
    }

    this.logger.log('JS-DEOBF', 'OK', 
      `Done — webpack:${this._summary.webpack} gzip:${this._summary.gzip} obfuscated:${this._summary.obfuscated} ` +
      `modules:${this._summary.modulesExtracted} highEntropy:${this._summary.highEntropyStrings}`
    );
  }

  async _processFile(filePath) {
    if (!fs.existsSync(filePath)) return;
    const stat = fs.statSync(filePath);
    if (stat.size < MIN_SIZE || stat.size > 20 * 1024 * 1024) return; // Skip tiny/huge files

    const raw = fs.readFileSync(filePath);
    const baseName = path.basename(filePath, path.extname(filePath));
    this._summary.analyzed++;

    let src = null;
    let decompressType = null;

    // ── Step 1: Detect + Decompress binary compression ────────────────────
    if (isGzip(raw)) {
      try {
        const decompressed = await gunzip(raw);
        src = decompressed.toString('utf8');
        decompressType = 'gzip';
        this._summary.gzip++;
        this.logger.log('JS-DEOBF', 'FIND', `GZip detected + decompressed: ${baseName} (${raw.length} → ${decompressed.length} bytes)`);
      } catch(e) {
        this.logger.log('JS-DEOBF', 'WARN', `GZip decompress failed for ${baseName}: ${e.message}`);
        return;
      }
    } else if (isZlib(raw)) {
      try {
        const decompressed = await inflate(raw);
        src = decompressed.toString('utf8');
        decompressType = 'zlib';
        this._summary.zlib++;
        this.logger.log('JS-DEOBF', 'FIND', `Zlib stream detected + inflated: ${baseName}`);
      } catch(e) {}
    }

    // Not binary compressed — treat as text JS
    if (!src) {
      src = raw.toString('utf8');
      // Check if it looks like text at all
      if (!/[a-zA-Z$_]/.test(src.slice(0, 100))) return;
    }

    await this._analyzeSource(src, filePath, baseName, decompressType);
  }

  async _analyzeSource(src, srcPath, baseName, decompressType = null) {
    const report = {
      source: srcPath,
      size: src.length,
      decompressType,
      obfuscationFlags: [],
      isWebpack: false,
      isRollup: false,
      webpackModules: [],
      base64Decoded: [],
      highEntropyStrings: [],
      prettifiedFile: null,
      modulesDir: null,
    };

    // ── Step 2: Detect obfuscation ────────────────────────────────────────
    report.obfuscationFlags = detectObfuscationType(src);
    if (report.obfuscationFlags.length) {
      this._summary.obfuscated++;
      this.logger.log('JS-DEOBF', 'FIND', `Obfuscation detected in ${baseName}: [${report.obfuscationFlags.join(', ')}]`);
    }

    // ── Step 3: Webpack / Rollup bundle detection + splitting ─────────────
    report.isWebpack = isWebpack(src);
    report.isRollup  = !report.isWebpack && isRollup(src);

    if (report.isWebpack) {
      this._summary.webpack++;
      this.logger.log('JS-DEOBF', 'INFO', `Webpack bundle detected: ${baseName}`);
      const modules = extractWebpackModules(src);
      if (modules.length) {
        const modDir = path.join(this.outDir, `${baseName}_webpack_modules`);
        if (!fs.existsSync(modDir)) fs.mkdirSync(modDir, { recursive: true });
        for (const mod of modules) {
          const modFile = path.join(modDir, `module_${String(mod.id).replace(/[^a-zA-Z0-9_-]/g,'_')}.js`);
          const prettified = prettify(mod.code);
          fs.writeFileSync(modFile, `// Webpack Module ID: ${mod.id}\n// Extracted by GENKI-PROBER v2.0\n\n${prettified}`);
          this._summary.modulesExtracted++;
        }
        report.webpackModules = modules.map(m => ({ id: m.id, size: m.code.length }));
        report.modulesDir = modDir;
        this.logger.log('JS-DEOBF', 'OK', `  → Extracted ${modules.length} webpack modules to ${path.basename(modDir)}/`);
      }
    }

    if (report.isRollup) {
      this._summary.rollup++;
      this.logger.log('JS-DEOBF', 'INFO', `Rollup/Vite bundle detected: ${baseName}`);
    }

    // ── Step 4: Base64/eval decode ────────────────────────────────────────
    if (report.obfuscationFlags.includes('BASE64/EVAL') || report.obfuscationFlags.includes('EVAL')) {
      const decoded = tryDecodeBase64Evals(src);
      if (decoded.length) {
        this._summary.base64Decoded += decoded.length;
        report.base64Decoded = decoded;
        this.logger.log('JS-DEOBF', 'FIND', `  → ${decoded.length} base64/eval payload(s) decoded in ${baseName}`);
      }
    }

    // ── Step 5: High-entropy string extraction ────────────────────────────
    const entropy = findHighEntropyStrings(src);
    if (entropy.length) {
      this._summary.highEntropyStrings += entropy.length;
      report.highEntropyStrings = entropy;
      if (entropy.length >= 3) {
        this.logger.log('JS-DEOBF', 'FIND', `  → ${entropy.length} high-entropy strings in ${baseName} (possible encoded payloads)`);
      }
    }

    // ── Step 6: Prettify + write output ──────────────────────────────────
    // Always prettify if: decompressed, obfuscated, webpack, or has obfuscation flags
    const shouldPrettify = decompressType || report.obfuscationFlags.length || report.isWebpack || report.isRollup;
    if (shouldPrettify) {
      const prettified = prettify(src);
      const outFile = path.join(this.outDir, `${baseName}.deobf.js`);
      const header = [
        `// ═══════════════════════════════════════════════════════════`,
        `// GENKI-PROBER v2.0 — Deobfuscated Output`,
        `// Source: ${srcPath}`,
        `// Size: ${src.length} bytes`,
        decompressType ? `// Decompressed: ${decompressType}` : '',
        report.obfuscationFlags.length ? `// Obfuscation: [${report.obfuscationFlags.join(', ')}]` : '',
        report.isWebpack ? `// Type: Webpack bundle (${report.webpackModules.length} modules extracted)` : '',
        report.isRollup  ? `// Type: Rollup/Vite bundle` : '',
        `// Analyzed: ${new Date().toISOString()}`,
        `// ═══════════════════════════════════════════════════════════`,
        '',
      ].filter(l => l !== null).join('\n');

      fs.writeFileSync(outFile, header + prettified);
      report.prettifiedFile = outFile;
      this.logger.log('JS-DEOBF', 'OK', `  → Prettified → ${path.basename(outFile)}`);
    }

    // ── Step 7: Write JSON analysis report for this file ─────────────────
    if (report.obfuscationFlags.length || report.isWebpack || report.base64Decoded.length || decompressType) {
      const reportFile = path.join(this.outDir, `${baseName}.analysis.json`);
      fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));

      // Push as finding if notable
      const severity = report.obfuscationFlags.includes('EVAL') || report.base64Decoded.length
        ? 'HIGH'
        : report.obfuscationFlags.length
          ? 'MEDIUM'
          : 'LOW';

      this.findings.push({
        type: 'js-deobf',
        severity,
        title: `JS Analysis: ${baseName}`,
        detail: {
          source: srcPath,
          decompressed: decompressType,
          obfuscation: report.obfuscationFlags,
          webpackModules: report.webpackModules.length,
          base64Payloads: report.base64Decoded.length,
          highEntropyStrings: report.highEntropyStrings.length,
        },
        reportFile,
      });
    }
  }

  summary() { return { ...this._summary, findings: this.findings.length }; }
  getFindings() { return this.findings; }
}

module.exports = JsDeobfuscator;
