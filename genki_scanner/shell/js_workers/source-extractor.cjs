// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  GENKI-PROBER MODULE: SOURCE-EXTRACTOR                                 ║
// ║  Extract ALL source code from browser via CDP — including webpack://    ║
// ║  Source maps, inline scripts, workers, dynamic modules                  ║
// ║  GENKI-TECH LABS | ANBU BLACK OPS SECURITY                             ║
// ╚══════════════════════════════════════════════════════════════════════════╝

const fs = require('fs');
const path = require('path');

class SourceExtractor {
  constructor(logger, config) {
    this.logger = logger;
    this.config = config || {};
    this.outputDir = path.join(config.outputDir || '.', 'source-extract');
    this.stats = {
      totalScripts: 0,
      extractedScripts: 0,
      failedScripts: 0,
      totalBytes: 0,
      sources: { page: 0, webpack: 0, sourcemap: 0, inline: 0, worker: 0, extension: 0, eval: 0, other: 0 },
      resourceTree: { frames: 0, resources: 0 },
    };
    this.scriptIndex = [];    // metadata for all discovered scripts
    this.extractedPaths = []; // paths of saved files
  }

  // ── MAIN ENTRY POINT ──
  async run(page, browser, urls) {
    this.logger.log('SRC-EXTRACT', 'INFO', 'Starting full source code extraction via CDP...');
    
    // Create output directories
    const dirs = ['scripts', 'webpack', 'sourcemaps', 'inline', 'workers', 'resources', 'frames'];
    dirs.forEach(d => {
      const p = path.join(this.outputDir, d);
      if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
    });

    // Phase 1: Extract from current page via Debugger domain
    await this._extractViaDebugger(page);
    
    // Phase 2: Extract resource tree (all frames, all resources)
    await this._extractResourceTree(page);
    
    // Phase 3: If we have more URLs, extract from those too
    if (urls && urls.length > 1) {
      for (const url of urls.slice(1, Math.min(urls.length, 20))) { // cap at 20
        try {
          await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 });
          await this._extractViaDebugger(page);
          await this._extractResourceTree(page);
        } catch (e) {
          this.logger.log('SRC-EXTRACT', 'WARN', `Failed to extract from ${url}: ${e.message}`);
        }
      }
    }

    // Phase 4: Save index
    this._saveIndex();
    
    this.logger.log('SRC-EXTRACT', 'OK', 
      `Extraction complete: ${this.stats.extractedScripts}/${this.stats.totalScripts} scripts | ` +
      `${(this.stats.totalBytes / 1024).toFixed(1)}KB | ` +
      `page=${this.stats.sources.page} webpack=${this.stats.sources.webpack} inline=${this.stats.sources.inline} ` +
      `sourcemap=${this.stats.sources.sourcemap} worker=${this.stats.sources.worker}`
    );
  }

  // ══════════════════════════════════════════════════════════════════
  // PHASE 1: CDP Debugger — captures ALL scripts including webpack://
  // ══════════════════════════════════════════════════════════════════
  async _extractViaDebugger(page) {
    const cdp = await page.createCDPSession();
    const scripts = [];

    try {
      // Collect all script metadata first
      cdp.on('Debugger.scriptParsed', (params) => {
        scripts.push(params);
      });

      // Enable Debugger — this triggers scriptParsed for EVERY loaded script
      await cdp.send('Debugger.enable', { maxScriptsCacheSize: 100000000 }); // 100MB cache
      
      // Small delay to collect all async-parsed scripts
      await new Promise(r => setTimeout(r, 2000));

      this.logger.log('SRC-EXTRACT', 'INFO', `Debugger found ${scripts.length} scripts on this page`);

      // Now extract source for each script
      for (const script of scripts) {
        this.stats.totalScripts++;
        
        try {
          const { scriptSource, bytecode } = await cdp.send('Debugger.getScriptSource', {
            scriptId: script.scriptId
          });

          if (!scriptSource && !bytecode) {
            this.stats.failedScripts++;
            continue;
          }

          const source = scriptSource || '[WASM/Bytecode]';
          const category = this._categorizeScript(script);
          const filename = this._buildFilename(script, category);
          
          // Save the source
          const savePath = path.join(this.outputDir, category, filename);
          const saveDir = path.dirname(savePath);
          if (!fs.existsSync(saveDir)) fs.mkdirSync(saveDir, { recursive: true });
          
          fs.writeFileSync(savePath, source, 'utf8');
          
          this.stats.extractedScripts++;
          this.stats.totalBytes += source.length;
          this.stats.sources[category] = (this.stats.sources[category] || 0) + 1;
          this.extractedPaths.push(savePath);

          // Build index entry
          this.scriptIndex.push({
            scriptId: script.scriptId,
            url: script.url || '(inline/eval)',
            category,
            savedAs: path.relative(this.outputDir, savePath),
            size: source.length,
            hash: script.hash,
            startLine: script.startLine,
            startColumn: script.startColumn,
            endLine: script.endLine,
            endColumn: script.endColumn,
            executionContextId: script.executionContextId,
            sourceMapURL: script.sourceMapURL || null,
            hasSourceURL: !!script.hasSourceURL,
            isModule: !!script.isModule,
            stackTrace: script.stackTrace ? true : false,
          });

          // Also fetch source map if available
          if (script.sourceMapURL) {
            await this._fetchSourceMap(cdp, page, script);
          }

        } catch (e) {
          this.stats.failedScripts++;
          if (!e.message.includes('No script')) {
            this.logger.log('SRC-EXTRACT', 'WARN', `Failed to get source for ${script.url || script.scriptId}: ${e.message}`);
          }
        }
      }

      await cdp.send('Debugger.disable');
    } catch (e) {
      this.logger.log('SRC-EXTRACT', 'ERROR', `Debugger extraction error: ${e.message}`);
    } finally {
      await cdp.detach().catch(() => {});
    }
  }

  // ══════════════════════════════════════════════════════════════════
  // PHASE 2: Resource Tree — mirrors the Sources > Page panel
  // ══════════════════════════════════════════════════════════════════
  async _extractResourceTree(page) {
    const cdp = await page.createCDPSession();
    
    try {
      await cdp.send('Page.enable');
      const { frameTree } = await cdp.send('Page.getResourceTree');
      
      await this._processFrame(cdp, frameTree, 'resources');
      
    } catch (e) {
      this.logger.log('SRC-EXTRACT', 'WARN', `Resource tree extraction error: ${e.message}`);
    } finally {
      await cdp.detach().catch(() => {});
    }
  }

  async _processFrame(cdp, frameTree, baseDir) {
    const frame = frameTree.frame;
    this.stats.resourceTree.frames++;
    
    const frameDir = path.join(this.outputDir, baseDir);
    if (!fs.existsSync(frameDir)) fs.mkdirSync(frameDir, { recursive: true });

    // Process resources in this frame
    if (frameTree.resources) {
      for (const resource of frameTree.resources) {
        this.stats.resourceTree.resources++;
        
        // Skip data: URLs and blob: URLs (too large/meaningless)
        if (resource.url.startsWith('data:') || resource.url.startsWith('blob:')) continue;
        
        // Focus on useful resource types
        const types = ['Script', 'Stylesheet', 'Document', 'XHR', 'Fetch', 'Other'];
        if (!types.includes(resource.type)) continue;

        try {
          const { content, base64Encoded } = await cdp.send('Page.getResourceContent', {
            frameId: frame.id,
            url: resource.url
          });

          if (!content) continue;

          const filename = this._urlToFilename(resource.url, resource.type);
          const savePath = path.join(frameDir, filename);
          const saveDir = path.dirname(savePath);
          if (!fs.existsSync(saveDir)) fs.mkdirSync(saveDir, { recursive: true });

          if (base64Encoded) {
            fs.writeFileSync(savePath, Buffer.from(content, 'base64'));
          } else {
            fs.writeFileSync(savePath, content, 'utf8');
          }

          this.logger.log('SRC-EXTRACT', 'OK', `Resource: ${resource.type} → ${filename} (${(content.length/1024).toFixed(1)}KB)`);

        } catch (e) {
          // Silently skip failed resources (common for CORS-blocked items)
        }
      }
    }

    // Process child frames recursively
    if (frameTree.childFrames) {
      for (const child of frameTree.childFrames) {
        const childDir = path.join(baseDir, `frame_${this._sanitize(child.frame.url).substring(0, 50)}`);
        await this._processFrame(cdp, child, childDir);
      }
    }
  }

  // ══════════════════════════════════════════════════════════════════
  // SOURCE MAP FETCHER — resolve and download .map files
  // ══════════════════════════════════════════════════════════════════
  async _fetchSourceMap(cdp, page, script) {
    try {
      let mapUrl = script.sourceMapURL;
      
      // Resolve relative URLs
      if (mapUrl && !mapUrl.startsWith('http') && !mapUrl.startsWith('data:')) {
        if (script.url) {
          try { mapUrl = new URL(mapUrl, script.url).href; } catch(e) { return; }
        } else return;
      }
      
      // Skip data: URLs (inline source maps — already in the script)
      if (mapUrl.startsWith('data:')) {
        // Extract inline source map
        const match = mapUrl.match(/^data:[^,]+,(.+)$/);
        if (match) {
          try {
            const decoded = Buffer.from(match[1], 'base64').toString('utf8');
            const filename = this._sanitize(script.url || `inline_${script.scriptId}`) + '.map';
            const savePath = path.join(this.outputDir, 'sourcemaps', filename);
            fs.writeFileSync(savePath, decoded, 'utf8');
            this.stats.sources.sourcemap++;
            this.logger.log('SRC-EXTRACT', 'OK', `Inline source map: ${filename}`);
            
            // Parse and extract individual source files from the map
            await this._extractFromSourceMap(decoded, savePath);
          } catch(e) {}
        }
        return;
      }

      // Fetch remote source map
      try {
        const response = await page.evaluate(async (url) => {
          try {
            const r = await fetch(url, { credentials: 'include' });
            if (!r.ok) return null;
            return await r.text();
          } catch(e) { return null; }
        }, mapUrl);

        if (response) {
          const filename = this._sanitize(mapUrl) + '.map';
          const savePath = path.join(this.outputDir, 'sourcemaps', filename);
          fs.writeFileSync(savePath, response, 'utf8');
          this.stats.sources.sourcemap++;
          this.logger.log('SRC-EXTRACT', 'OK', `Source map: ${filename} (${(response.length/1024).toFixed(1)}KB)`);
          
          // Extract individual files from source map
          await this._extractFromSourceMap(response, savePath);
        }
      } catch(e) {}

    } catch (e) {
      // Non-critical — skip
    }
  }

  // Extract original source files from a source map JSON
  async _extractFromSourceMap(mapContent, mapPath) {
    try {
      const map = JSON.parse(mapContent);
      if (!map.sources || !map.sourcesContent) return;
      
      const mapDir = path.join(path.dirname(mapPath), 'mapped-sources');
      if (!fs.existsSync(mapDir)) fs.mkdirSync(mapDir, { recursive: true });

      let extracted = 0;
      for (let i = 0; i < map.sources.length; i++) {
        if (!map.sourcesContent[i]) continue;
        
        const sourcePath = map.sources[i]
          .replace(/^webpack:\/\/\/?/, '')
          .replace(/^\.\//,'')
          .replace(/\.\.\//g, '_parent_/');
        
        const savePath = path.join(mapDir, this._sanitize(sourcePath));
        const saveDir = path.dirname(savePath);
        if (!fs.existsSync(saveDir)) fs.mkdirSync(saveDir, { recursive: true });
        
        fs.writeFileSync(savePath, map.sourcesContent[i], 'utf8');
        extracted++;
      }
      
      if (extracted > 0) {
        this.logger.log('SRC-EXTRACT', 'OK', `Source map → extracted ${extracted} original source files`);
      }
    } catch(e) {}
  }

  // ══════════════════════════════════════════════════════════════════
  // HELPERS
  // ══════════════════════════════════════════════════════════════════
  
  _categorizeScript(script) {
    const url = script.url || '';
    
    // Chrome extensions
    if (url.startsWith('chrome-extension://') || url.startsWith('moz-extension://'))
      return 'extension';
    
    // Webpack internal modules
    if (url.startsWith('webpack://') || url.startsWith('webpack-internal://'))
      return 'webpack';
    
    // Web workers / service workers
    if (url.includes('worker') && (url.endsWith('.js') || url.endsWith('.mjs')))
      return 'worker';
    
    // Eval / dynamic
    if (!url || url === '' || script.isLiveEdit || (script.stackTrace && !url))
      return 'eval';
    
    // Inline scripts (URL matches the page itself, not a .js file)
    if (url && !url.endsWith('.js') && !url.endsWith('.mjs') && !url.endsWith('.ts') && 
        !url.includes('.js?') && !url.includes('.mjs?') &&
        script.startLine > 0)
      return 'inline';
    
    // Regular page scripts
    return 'scripts';
  }

  _buildFilename(script, category) {
    const url = script.url || '';
    
    if (!url || category === 'eval' || category === 'inline') {
      return `${category}_${script.scriptId}_line${script.startLine || 0}.js`;
    }
    
    // For webpack:// URLs, preserve the internal path structure
    if (category === 'webpack') {
      const wpPath = url
        .replace(/^webpack:\/\/\/?/, '')
        .replace(/^webpack-internal:\/\/\/?/, '')
        .replace(/\.\.\//g, '_parent_/')
        .replace(/\?.*$/, '');
      return this._sanitize(wpPath);
    }

    // For normal URLs, extract meaningful filename
    try {
      const parsed = new URL(url);
      let filepath = parsed.pathname;
      // Remove leading slash and limit depth
      filepath = filepath.replace(/^\//, '');
      return this._sanitize(filepath) || `script_${script.scriptId}.js`;
    } catch(e) {
      return `script_${script.scriptId}.js`;
    }
  }

  _urlToFilename(url, type) {
    try {
      const parsed = new URL(url);
      let filepath = parsed.pathname.replace(/^\//, '') || 'index';
      
      // Add extension based on type if missing
      const ext = path.extname(filepath);
      if (!ext) {
        switch(type) {
          case 'Script': filepath += '.js'; break;
          case 'Stylesheet': filepath += '.css'; break;
          case 'Document': filepath += '.html'; break;
          default: filepath += '.txt';
        }
      }
      
      // Include hostname for cross-origin resources
      const hostname = parsed.hostname.replace(/\./g, '_');
      return path.join(hostname, this._sanitize(filepath));
    } catch(e) {
      return `resource_${Date.now()}.txt`;
    }
  }

  _sanitize(str) {
    return str
      .replace(/[<>:"|?*\x00-\x1f]/g, '_')  // Illegal chars
      .replace(/\/{2,}/g, '/')                 // Double slashes
      .replace(/\.{2,}/g, '.')                 // Double dots
      .substring(0, 200);                       // Length limit
  }

  _saveIndex() {
    const indexPath = path.join(this.outputDir, 'source-index.json');
    const index = {
      meta: {
        tool: 'GENKI-PROBER Source Extractor',
        date: new Date().toISOString(),
        target: this.config.targetUrl,
      },
      stats: this.stats,
      scripts: this.scriptIndex,
    };
    fs.writeFileSync(indexPath, JSON.stringify(index, null, 2));
    this.logger.log('SRC-EXTRACT', 'OK', `Index saved: ${indexPath}`);
  }

  // ── Module interface ──
  summary() {
    return { ...this.stats, extractedPaths: this.extractedPaths.length };
  }

  getFindings() {
    const findings = [];
    
    // Flag exposed source maps
    for (const script of this.scriptIndex) {
      if (script.sourceMapURL) {
        findings.push({
          module: 'source-extractor',
          type: 'info-disclosure',
          severity: 'INFO',
          title: 'Source Map Exposed',
          description: `Source map available for: ${script.url || script.scriptId}`,
          url: script.sourceMapURL,
          evidence: `SourceMapURL: ${script.sourceMapURL}`,
        });
      }
    }

    // Flag webpack:// sources (internal code exposed)
    if (this.stats.sources.webpack > 0) {
      findings.push({
        module: 'source-extractor',
        type: 'info-disclosure',
        severity: 'LOW',
        title: 'Webpack Internal Source Code Exposed',
        description: `${this.stats.sources.webpack} webpack:// internal modules exposed via Debugger protocol`,
        evidence: `webpack modules found in browser Sources panel`,
      });
    }

    return findings;
  }
}

module.exports = SourceExtractor;
