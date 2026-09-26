#!/usr/bin/env node
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  GENKI-PROBER — script-harvester.cjs v2.0                              ║
// ║  CDP Debugger.scriptParsed — passive listener, catches EVERYTHING       ║
// ║  Eval'd code, blob: scripts, workers, inline, webpack chunks — all of it║
// ║  = Firefox DevTools Debugger > Sources panel, but automated + saved     ║
// ║  GENKI-TECH LABS | ANBU BLACK OPS SECURITY                             ║
// ╚══════════════════════════════════════════════════════════════════════════╝

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Script type classifier ────────────────────────────────────────────────────

function classifyScript(params) {
  const url = params.url || '';
  if (!url || url === 'debugger eval code')          return 'eval';
  if (url.startsWith('webpack-internal://'))          return 'webpack-internal';
  if (url.startsWith('webpack://'))                  return 'webpack-module';
  if (url.startsWith('blob:'))                       return 'blob';
  if (url.startsWith('data:'))                       return 'data-uri';
  if (/service.?worker|sw\.js$/i.test(url))          return 'service-worker';
  if (/\.worker\.|worker\.js$|workerize/i.test(url)) return 'web-worker';
  if (params.startLine > 0 && !url.includes('.js'))  return 'inline';
  if (/\.(min|bundle|chunk|vendor|runtime)\.js/.test(url)) return 'bundle';
  if (/node_modules|\/vendor\/|@\w+\//.test(url))    return 'vendor';
  if (url.endsWith('.mjs'))                          return 'esmodule';
  return 'script';
}

// ── Safe filename from script URL ─────────────────────────────────────────────

function safeFileName(url, type, index) {
  if (!url || url === 'debugger eval code') return `eval_${index}.js`;
  if (url.startsWith('blob:'))              return `blob_${index}.js`;
  if (url.startsWith('data:'))              return `data_uri_${index}.js`;
  if (url.startsWith('webpack://') || url.startsWith('webpack-internal://')) {
    const cleaned = url.replace(/^webpack(-internal)?:\/\/\/?/, '')
      .replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 80);
    return `webpack_${cleaned}_${index}.js`;
  }
  try {
    const u    = new URL(url);
    const base = u.pathname.replace(/\//g, '__').replace(/[^a-zA-Z0-9._-]/g, '_');
    return `${base}_${index}.js`.replace(/^_+/, '').substring(0, 100);
  } catch(e) {
    return `script_${index}.js`;
  }
}

// ── Build header comment block ────────────────────────────────────────────────

function buildHeader(record) {
  return [
    `// ════════════════════════════════════════════════════════════════`,
    `// GENKI-PROBER v2.0 — Script Harvest`,
    `// Type:      ${record.type}`,
    `// URL:       ${record.url || '(no url)'}`,
    `// ScriptID:  ${record.scriptId}`,
    `// Lines:     ${record.startLine}–${record.endLine}`,
    `// Size:      ${record.length} bytes`,
    `// Module:    ${record.isModule}`,
    record.hasSourceMap ? `// SourceMap: ${record.sourceMapURL}` : null,
    `// Context:   executionContextId=${record.executionContext}`,
    `// Captured:  ${new Date(record.ts).toISOString()}`,
    `// ════════════════════════════════════════════════════════════════`,
    '', '',
  ].filter(l => l !== null).join('\n');
}

// ── Main Class ────────────────────────────────────────────────────────────────

class ScriptHarvester {
  constructor(logger, config) {
    this.logger   = logger;
    this.config   = config;
    this.outDir   = path.join(config.outputDir, 'script-harvest');
    this.findings = [];

    this._scripts  = new Map();  // scriptId → record + source
    this._attached = new Set();  // CDP target IDs already instrumented
    this._index    = 0;
    this._enabled  = false;

    this._summary = {
      total: 0, saved: 0, errors: 0,
      byType: {},
      evalScripts: 0, blobScripts: 0, workerScripts: 0,
      inlineScripts: 0, webpackModules: 0, totalBytes: 0,
      sourceMaps: 0,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // attach(browser, page)
  //
  // Call IMMEDIATELY after page creation, BEFORE any navigation.
  // Sets up Debugger.scriptParsed on current page AND every new target.
  // ─────────────────────────────────────────────────────────────────────────────
  async attach(browser, page) {
    if (!fs.existsSync(this.outDir)) fs.mkdirSync(this.outDir, { recursive: true });

    await this._instrumentTarget(page);

    // Auto-instrument every new page/iframe/worker created during session
    browser.on('targetcreated', async (target) => {
      try {
        const tPage = await target.page();
        if (tPage) await this._instrumentTarget(tPage);
      } catch(e) {}
    });

    this._enabled = true;
    this.logger.log('SCRIPT-HARVESTER', 'OK',
      'CDP Debugger.scriptParsed active — capturing all scripts passively on all targets');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // _instrumentTarget(page) — attaches CDP + registers scriptParsed listener
  // ─────────────────────────────────────────────────────────────────────────────
  async _instrumentTarget(page) {
    let targetId;
    try { targetId = page.target()._targetId; } catch(e) { return; }
    if (this._attached.has(targetId)) return;
    this._attached.add(targetId);

    let cdp;
    try {
      cdp = await page.createCDPSession();
      await cdp.send('Debugger.enable', {});
      try { await cdp.send('Runtime.enable'); } catch(e) {}
    } catch(e) {
      this.logger.log('SCRIPT-HARVESTER', 'WARN',
        `CDP session failed for target ${targetId}: ${e.message}`);
      return;
    }

    // ── THE CORE EVENT ────────────────────────────────────────────────────────
    // Chrome fires this for EVERY script it parses, in execution order:
    //   • External <script src="..."> tags
    //   • Inline <script> blocks
    //   • eval() / new Function() / setTimeout(string) calls
    //   • blob: URL scripts (dynamically created scripts)
    //   • Dynamically injected <script> elements
    //   • Webpack runtime + ALL chunk modules
    //   • ES module imports (import())
    //   • Service Worker registrations
    //   • Web Workers
    //   • Worklets (Paint/Audio/Layout)
    cdp.on('Debugger.scriptParsed', async (params) => {
      const url = params.url || '';

      // Skip internal Chrome / Puppeteer internals
      if (
        url.startsWith('chrome-extension://') ||
        url.startsWith('devtools://') ||
        url.includes('__puppeteer_evaluation_script__') ||
        url.includes('__chromeDebugger') ||
        url === 'extensions::SafeBuiltins' ||
        url === 'extensions::schemaUtils'
      ) return;

      this._summary.total++;
      const idx = this._index++;

      try {
        // ── FETCH FULL SOURCE VIA CDP ─────────────────────────────────────────
        const { scriptSource } = await cdp.send('Debugger.getScriptSource', {
          scriptId: params.scriptId,
        });

        if (!scriptSource || scriptSource.trim().length < 10) return;

        const type     = classifyScript(params);
        const fileName = safeFileName(url, type, idx);

        // Subdirectory per type — keeps output organised
        const typeDir = path.join(this.outDir, type);
        if (!fs.existsSync(typeDir)) fs.mkdirSync(typeDir, { recursive: true });
        const filePath = path.join(typeDir, fileName);

        const record = {
          index:            idx,
          scriptId:         params.scriptId,
          url,
          type,
          fileName,
          filePath,
          startLine:        params.startLine  || 0,
          endLine:          params.endLine    || 0,
          length:           scriptSource.length,
          hasSourceMap:     !!params.sourceMapURL,
          sourceMapURL:     params.sourceMapURL || null,
          executionContext: params.executionContextId,
          hash:             params.hash || null,
          isModule:         params.isModule || false,
          ts:               Date.now(),
        };

        // Store full record + source in memory (outliner will use this)
        this._scripts.set(params.scriptId, { ...record, source: scriptSource });

        // Write to disk
        fs.writeFileSync(filePath, buildHeader(record) + scriptSource);

        // ── Update stats ──────────────────────────────────────────────────────
        this._summary.saved++;
        this._summary.totalBytes += scriptSource.length;
        this._summary.byType[type] = (this._summary.byType[type] || 0) + 1;

        if (type === 'eval')                                        this._summary.evalScripts++;
        if (type === 'blob')                                        this._summary.blobScripts++;
        if (type === 'web-worker' || type === 'service-worker')     this._summary.workerScripts++;
        if (type === 'inline')                                      this._summary.inlineScripts++;
        if (type === 'webpack-module' || type === 'webpack-internal') this._summary.webpackModules++;
        if (record.hasSourceMap)                                    this._summary.sourceMaps++;

        // ── Log high-value script types ───────────────────────────────────────
        if (['eval', 'blob', 'service-worker', 'web-worker', 'data-uri'].includes(type)) {
          this.logger.log('SCRIPT-HARVESTER', 'FIND',
            `[${type.toUpperCase()}] ${url.substring(0, 70) || '(no url)'} — ${scriptSource.length}B`);
        }

        // ── Push as finding for notable types ─────────────────────────────────
        if (['eval', 'blob', 'service-worker', 'web-worker', 'data-uri'].includes(type)) {
          this.findings.push({
            type: 'script-harvest', severity: type === 'eval' ? 'MEDIUM' : 'INFO',
            title:  `Captured ${type} script`,
            detail: { url, scriptId: record.scriptId, size: record.length, file: filePath },
          });
        }

      } catch(e) {
        // Debugger.getScriptSource fails for destroyed/GC'd scripts — expected, skip silently
        this._summary.errors++;
      }
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Public accessors — used by JsOutliner, JsDeobfuscator, SecurityScanner
  // ─────────────────────────────────────────────────────────────────────────────

  /** All captured scripts as array of { ...record, source } */
  getAllScripts() {
    return Array.from(this._scripts.values());
  }

  /** File paths only — drop-in for modules that expect file arrays */
  getSavedFilePaths() {
    return Array.from(this._scripts.values()).map(s => s.filePath);
  }

  /** Filter by type */
  getScriptsByType(type) {
    return Array.from(this._scripts.values()).filter(s => s.type === type);
  }

  /** Scripts with source maps — for SourceExtractor cross-ref */
  getSourceMappedScripts() {
    return Array.from(this._scripts.values()).filter(s => s.hasSourceMap);
  }

  /** Write JSON index of all captured scripts (no source — just metadata) */
  writeIndex() {
    const indexPath = path.join(this.outDir, '_index.json');
    const index     = Array.from(this._scripts.values()).map(({ source, ...rec }) => rec);
    fs.writeFileSync(indexPath, JSON.stringify(index, null, 2));
    this.logger.log('SCRIPT-HARVESTER', 'OK',
      `Index written → script-harvest/_index.json (${index.length} scripts)`);
    return indexPath;
  }

  /** Finalize after crawl completes */
  async finalize() {
    this.writeIndex();
    const kb = (this._summary.totalBytes / 1024).toFixed(1);
    this.logger.log('SCRIPT-HARVESTER', 'OK',
      `Harvest complete: ${this._summary.saved} scripts (${kb} KB) | ` +
      `eval:${this._summary.evalScripts} blob:${this._summary.blobScripts} ` +
      `worker:${this._summary.workerScripts} webpack:${this._summary.webpackModules} ` +
      `inline:${this._summary.inlineScripts} sourceMaps:${this._summary.sourceMaps}`
    );
  }

  summary()     { return { ...this._summary, scripts: this._scripts.size }; }
  getFindings() { return this.findings; }
  async run()   { return; }  // orchestrator uses attach() directly, not run()
  getSavedFilePaths() {
    const files = [];
    this._scripts.forEach(s => { if (s.savedPath) files.push(s.savedPath); });
    return files;
  }
}

module.exports = ScriptHarvester;
