
    // ── Deep browser extraction (XJutsu mode) ──

// GENKI-PROBER MODULE: CRAWLER — Deep crawl, endpoint discovery, JS/asset downloader
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');

class Crawler {
  constructor(logger, config) {
    this.logger = logger;
    this.config = config;
    this.visited = new Set();
    this.queued = new Set();
    this.allUrls = new Set();       // Every URL discovered
    this.apiEndpoints = new Set();   // /api/* endpoints
    this.jsUrls = new Set();         // All JS file URLs
    this.cssUrls = new Set();
    this.assetUrls = new Set();
    this.forms = [];
    this.downloadedJs = [];          // Local paths of downloaded JS
    this.downloadedAssets = [];
    this.scriptContents = new Map(); // url -> content (for inline scripts)
    this.responseHeaders = new Map();
    this.errors = [];
    this.interceptedRequests = [];
    this.sourceMaps = new Set();
  }

  isInScope(url) {
    try {
      const hostname = new URL(url).hostname;
      return this.config.scope.some(s => hostname === s || hostname.endsWith('.' + s));
    } catch (e) { return false; }
  }

  normalizeUrl(url) {
    try {
      const u = new URL(url);
      u.hash = '';
      // Remove common tracking params
      ['utm_source','utm_medium','utm_campaign','utm_term','utm_content','fbclid','gclid','_ga'].forEach(p => u.searchParams.delete(p));
      return u.href;
    } catch (e) { return null; }
  }

  classifyUrl(url) {
    const lower = url.toLowerCase();
    if (/\.js(\?|$)/i.test(lower)) return 'js';
    if (/\.css(\?|$)/i.test(lower)) return 'css';
    if (/\.json(\?|$)/i.test(lower)) return 'json';
    if (/\.xml(\?|$)/i.test(lower)) return 'xml';
    if (/\.map(\?|$)/i.test(lower)) return 'sourcemap';
    if (/\.(png|jpg|jpeg|gif|svg|ico|webp|avif|woff2?|ttf|eot|mp[34]|wav|ogg|pdf)(\?|$)/i.test(lower)) return 'static';
    if (lower.includes('/api/') || lower.includes('/graphql') || lower.match(/\/v\d+\//)) return 'api';
    return 'page';
  }

  async run(page, browser) {
    this.logger.log('CRAWLER', 'INFO', `Starting crawl: ${this.config.targetUrl} (depth: ${this.config.maxDepth}, max: ${this.config.maxPages})`);
    
    // Set up network interception for asset discovery
    await this._setupInterception(page);
    
    // Seed the queue
    this.queued.add(this.config.targetUrl);
    
    // BFS crawl
    let depth = 0;
    while (depth < this.config.maxDepth && this.visited.size < this.config.maxPages) {
      const batch = [...this.queued].filter(u => !this.visited.has(u)).slice(0, this.config.maxPages - this.visited.size);
      if (batch.length === 0) break;
      
      this.logger.log('CRAWLER', 'INFO', `Depth ${depth}: ${batch.length} URLs to visit (${this.visited.size} visited)`);
      this.queued.clear();
      
      for (const url of batch) {
        if (this.visited.size >= this.config.maxPages) break;
        await this._visitPage(page, url, depth);
        if (this.config.crawlDelay > 0) await this._sleep(this.config.crawlDelay);
      }
      depth++;
    }
    
    // ── Interactive Crawl Phase ── forms, clicks, SPA routes, scroll
    if (this.config.interactiveCrawl !== false) {
      await this._interactiveCrawlPhase(page);
    }

    // ── Deep Browser Extraction (XJutsu mode) ── discover MORE before downloading
    await this._deepExtractFromBrowser(page);
    await this._extractCdpSources(page);
    await this._scanLoadedResourcesForEndpoints(page);

    // Download discovered JS files
    if (this.config.downloadJs && this.jsUrls.size > 0) {
      this.logger.log('CRAWLER', 'INFO', `Downloading ${this.jsUrls.size} JS files...`);
      await this._downloadAll([...this.jsUrls], 'js');
    }
    
    // Download other assets
    if (this.config.downloadAssets) {
      const otherAssets = [...this.cssUrls, ...this.sourceMaps];
      if (otherAssets.length > 0) {
        this.logger.log('CRAWLER', 'INFO', `Downloading ${otherAssets.length} other assets...`);
        await this._downloadAll([...this.cssUrls], 'css');
        await this._downloadAll([...this.sourceMaps], 'other');
      }
    }
    
    // Save all discovered data
    this._saveDiscoveryData();
    
    this.logger.log('CRAWLER', 'OK', `Crawl complete: ${this.visited.size} pages, ${this.jsUrls.size} JS, ${this.apiEndpoints.size} API endpoints, ${this.forms.length} forms`);
  }

  async _setupInterception(page) {

    // ── XJutsu-style: Intercept XHR/fetch RESPONSE BODIES in-browser ──
    await page.evaluateOnNewDocument(() => {
      window.__GENKI_XHR_RESPONSES = [];
      window.__GENKI_FETCH_RESPONSES = [];

      // Hook XHR to capture response bodies
      const _xhrOpen = XMLHttpRequest.prototype.open;
      const _xhrSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(method, url) {
        this.__genki_method = method;
        this.__genki_url = url;
        return _xhrOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function(body) {
        this.addEventListener('load', function() {
          try {
            if (this.responseText && this.responseText.length < 500000) {
              window.__GENKI_XHR_RESPONSES.push({
                method: this.__genki_method, url: this.__genki_url,
                status: this.status, postData: body ? String(body).substring(0, 2000) : null,
                contentType: this.getResponseHeader('content-type') || '',
                responseBody: this.responseText.substring(0, 50000),
                time: Date.now()
              });
            }
          } catch(e) {}
        });
        return _xhrSend.apply(this, arguments);
      };

      // Hook fetch to capture response bodies
      const _fetch = window.fetch;
      window.fetch = function(input, init) {
        const url = typeof input === 'string' ? input : input.url;
        const method = init?.method || 'GET';
        return _fetch.apply(this, arguments).then(function(resp) {
          const clone = resp.clone();
          clone.text().then(function(body) {
            if (body.length < 500000) {
              window.__GENKI_FETCH_RESPONSES.push({
                method: method, url: url, status: resp.status,
                contentType: resp.headers.get('content-type') || '',
                responseBody: body.substring(0, 50000), time: Date.now()
              });
            }
          }).catch(function() {});
          return resp;
        });
      };
    });

    // Listen to all network requests to discover hidden endpoints
    page.on('request', req => {
      const url = req.url();
      this.allUrls.add(url);
      const type = this.classifyUrl(url);
      if (type === 'js') this.jsUrls.add(url);
      if (type === 'css') this.cssUrls.add(url);
      if (type === 'api') this.apiEndpoints.add(`${req.method()} ${url}`);
      if (type === 'sourcemap') this.sourceMaps.add(url);
      
      // Track XHR/fetch requests specifically
      if (req.resourceType() === 'xhr' || req.resourceType() === 'fetch') {
        this.interceptedRequests.push({
          method: req.method(),
          url: url,
          postData: req.postData()?.substring(0, 2000),
          headers: req.headers(),
          resourceType: req.resourceType()
        });
        this.apiEndpoints.add(`${req.method()} ${url}`);
      }
    });
    
    // Capture response headers for security analysis
    page.on('response', async resp => {
      const url = resp.url();
      if (!this.responseHeaders.has(url)) {
        this.responseHeaders.set(url, resp.headers());
      }
      // Detect source maps from headers
      const smHeader = resp.headers()['sourcemap'] || resp.headers()['x-sourcemap'];
      if (smHeader) {
        try {
          const smUrl = new URL(smHeader, url).href;
          this.sourceMaps.add(smUrl);
          this.logger.log('CRAWLER', 'FINDING', `Source map header: ${smUrl}`);
        } catch(e) {}
      }
    });
  }

  async _visitPage(page, url, depth) {
    this.visited.add(url);
    
    try {
      const resp = await page.goto(url, { waitUntil: 'networkidle2', timeout: this.config.timeout });
      if (!resp) return;
      
      const status = resp.status();
      this.logger.log('CRAWLER', status >= 400 ? 'WARN' : 'INFO', `[${status}] ${url.substring(0, 120)}`);
      
      // Extract links, forms, scripts, and endpoints from the page
      const extracted = await page.evaluate(() => {
        const data = { links: [], scripts: [], forms: [], inlineScripts: [], endpoints: [], comments: [] };
        
        // All <a> hrefs
        document.querySelectorAll('a[href]').forEach(a => {
          try { data.links.push(new URL(a.href, location.href).href); } catch(e) {}
        });
        // Link tags (stylesheets, preload, etc.)
        document.querySelectorAll('link[href]').forEach(l => {
          try { data.links.push(new URL(l.href, location.href).href); } catch(e) {}
        });
        // Iframes
        document.querySelectorAll('iframe[src]').forEach(f => {
          try { data.links.push(new URL(f.src, location.href).href); } catch(e) {}
        });
        
        // Script tags with src
        document.querySelectorAll('script[src]').forEach(s => {
          try { data.scripts.push(new URL(s.src, location.href).href); } catch(e) {}
        });
        
        // Inline scripts (for analysis)
        document.querySelectorAll('script:not([src])').forEach(s => {
          if (s.textContent.trim().length > 10) {
            data.inlineScripts.push(s.textContent.substring(0, 50000));
          }
        });
        
        // Forms
        document.querySelectorAll('form').forEach(f => {
          const inputs = Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
            name: i.name || i.id, type: i.type, value: i.value?.substring(0, 100)
          }));
          data.forms.push({ action: f.action, method: f.method || 'GET', id: f.id, inputs });
        });
        
        // Extract API endpoints from page source
        const html = document.documentElement.outerHTML;
        // Extract API endpoints from page source (simple approach)
        const apiPatterns = [];
        ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/internal/'].forEach(function(pattern) {
          var idx = 0;
          while ((idx = html.indexOf(pattern, idx)) !== -1) {
            // Find the quoted string containing this pattern
            var start = html.lastIndexOf('"', idx);
            if (start === -1) start = html.lastIndexOf("'", idx);
            if (start === -1) { idx += pattern.length; continue; }
            var end = html.indexOf('"', idx + 1);
            if (end === -1) end = html.indexOf("'", idx + 1);
            if (end !== -1 && end - start < 300) {
              var path = html.substring(start + 1, end).trim();
              if (path.startsWith('/') && !path.includes(' ')) apiPatterns.push(path);
            }
            idx += pattern.length;
          }
        });
        apiPatterns.forEach(function(p) {
          try { data.endpoints.push(new URL(p, location.href).href); } catch(e) { data.endpoints.push(p); }
        });

        
        // Extract URLs from inline scripts
        data.inlineScripts.forEach(script => {
          const urlMatches = script.match(/["'](https?:\/\/[^"'\s]{5,200})["']/g);
          if (urlMatches) {
            urlMatches.forEach(m => {
              const cleaned = m.replace(/^["']|["']$/g, '');
              data.endpoints.push(cleaned);
            });
          }
          // Source map comments
          const smMatch = script.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
          if (smMatch) {
            try { data.endpoints.push(new URL(smMatch[1], location.href).href); } catch(e) {}
          }
        });
        
        // HTML comments (often contain debug info, hidden endpoints)
        const commentIterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT);
        let node;
        while (node = commentIterator.nextNode()) {
          const text = node.textContent.trim();
          if (text.length > 5 && text.length < 5000) data.comments.push(text);
        }
        
        return data;
      });
      
      // Process extracted links
      extracted.links.forEach(link => {
        const norm = this.normalizeUrl(link);
        if (norm && this.isInScope(norm) && !this.visited.has(norm) && this.classifyUrl(norm) === 'page') {
          this.queued.add(norm);
        }
        if (norm) this.allUrls.add(norm);
      });
      
      // Process scripts
      extracted.scripts.forEach(s => { this.jsUrls.add(s); this.allUrls.add(s); });
      
      // Process endpoints
      extracted.endpoints.forEach(ep => {
        this.allUrls.add(ep);
        if (/api|graphql|internal/i.test(ep)) this.apiEndpoints.add(`GET ${ep}`);
        if (/\.map(\?|$)/i.test(ep)) this.sourceMaps.add(ep);
        if (/\.js(\?|$)/i.test(ep)) this.jsUrls.add(ep);
      });
      
      // Store forms
      extracted.forms.forEach(f => this.forms.push({ ...f, foundOn: url }));
      
      // Store inline scripts for security analysis
      extracted.inlineScripts.forEach((s, i) => {
        this.scriptContents.set(`inline:${url}#${i}`, s);
      });
      
      // Log HTML comments (potential info disclosure)
      if (extracted.comments.length > 0) {
        this.logger.log('CRAWLER', 'FINDING', `${extracted.comments.length} HTML comments on ${url.substring(0, 80)}`);
        extracted.comments.forEach(c => {
          if (/todo|fixme|hack|password|secret|key|token|api|debug|admin|internal/i.test(c)) {
            this.logger.log('CRAWLER', 'FIND', `[LOW] Interesting HTML comment | ${c.substring(0, 300)}`);
          }
        });
      }
      
      // Check for source maps in loaded scripts via comment
      extracted.inlineScripts.forEach(script => {
        const smMatch = script.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
        if (smMatch) {
          try {
            const smUrl = new URL(smMatch[1], url).href;
            this.sourceMaps.add(smUrl);
            this.logger.log('CRAWLER', 'FINDING', `Source map in inline: ${smUrl}`);
          } catch(e) {}
        }
      });
      
    } catch (e) {
      this.errors.push({ url, error: e.message });
      this.logger.log('CRAWLER', 'WARN', `Error on ${url.substring(0, 100)}: ${e.message.substring(0, 100)}`);
    }
  }

  async _downloadAll(urls, type) {
    const subdir = path.join(this.config.outputDir, 'downloads', type);
    if (!fs.existsSync(subdir)) fs.mkdirSync(subdir, { recursive: true });
    
    let downloaded = 0;
    const concurrency = 5;
    const chunks = [];
    for (let i = 0; i < urls.length; i += concurrency) chunks.push(urls.slice(i, i + concurrency));
    
    for (const chunk of chunks) {
      await Promise.all(chunk.map(async url => {
        try {
          const content = await this._fetch(url);
          if (!content) return;
          
          // Generate safe filename
          const hash = crypto.createHash('md5').update(url).digest('hex').substring(0, 8);
          let basename;
          try { basename = path.basename(new URL(url).pathname) || 'index'; } catch(e) { basename = 'file'; }
          if (basename.length > 80) basename = basename.substring(0, 80);
          const filename = `${hash}_${basename}`;
          const filepath = path.join(subdir, filename);
          
          fs.writeFileSync(filepath, content);
          downloaded++;
          
          if (type === 'js') this.downloadedJs.push({ url, path: filepath, size: content.length });
          else this.downloadedAssets.push({ url, path: filepath, size: content.length });
          
          // Check for source maps in JS content
          if (type === 'js') {
            const smMatch = content.toString().match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
            if (smMatch) {
              try {
                const smUrl = new URL(smMatch[1], url).href;
                this.sourceMaps.add(smUrl);
                this.logger.log('CRAWLER', 'FINDING', `Source map ref in JS: ${smUrl}`);
              } catch(e) {}
            }
          }
        } catch (e) {
          this.errors.push({ url, error: e.message });
        }
      }));
    }
    
    this.logger.log('CRAWLER', 'OK', `Downloaded ${downloaded}/${urls.length} ${type} files to ${subdir}`);
  }

  _fetch(url) {
    return new Promise((resolve, reject) => {
      const mod = url.startsWith('https') ? https : http;
      const req = mod.get(url, { timeout: 15000, headers: { 'User-Agent': this.config.userAgent } }, resp => {
        // Follow redirects
        if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
          this._fetch(new URL(resp.headers.location, url).href).then(resolve).catch(reject);
          return;
        }
        if (resp.statusCode !== 200) { resolve(null); return; }
        const chunks = [];
        resp.on('data', c => chunks.push(c));
        resp.on('end', () => resolve(Buffer.concat(chunks)));
        resp.on('error', reject);
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    });
  }

  _saveDiscoveryData() {
    const dir = this.config.outputDir;
    
    // All URLs
    fs.writeFileSync(path.join(dir, 'all-urls.txt'), [...this.allUrls].sort().join('\n'));
    // API endpoints
    fs.writeFileSync(path.join(dir, 'api-endpoints.txt'), [...this.apiEndpoints].sort().join('\n'));
    // JS URLs
    fs.writeFileSync(path.join(dir, 'js-urls.txt'), [...this.jsUrls].sort().join('\n'));
    // Source maps
    if (this.sourceMaps.size > 0) fs.writeFileSync(path.join(dir, 'source-maps.txt'), [...this.sourceMaps].sort().join('\n'));
    // Forms
    if (this.forms.length > 0) fs.writeFileSync(path.join(dir, 'forms.json'), JSON.stringify(this.forms, null, 2));
    // Intercepted XHR/Fetch requests
    if (this.interceptedRequests.length > 0) fs.writeFileSync(path.join(dir, 'xhr-requests.json'), JSON.stringify(this.interceptedRequests, null, 2));
    // Response headers
    const hdrObj = {};
    this.responseHeaders.forEach((v, k) => { hdrObj[k] = v; });
    fs.writeFileSync(path.join(dir, 'response-headers.json'), JSON.stringify(hdrObj, null, 2));
    
    this.logger.log('CRAWLER', 'INFO', `Saved: ${this.allUrls.size} URLs, ${this.apiEndpoints.size} API endpoints, ${this.jsUrls.size} JS, ${this.sourceMaps.size} source maps, ${this.forms.length} forms`);
  }

  getVisitedUrls() { return [...this.visited]; }
  getDownloadedJs() { return this.downloadedJs; }
  getScriptUrls() { return [...this.jsUrls]; }
  getInlineScripts() { return this.scriptContents; }
  getApiEndpoints() { return [...this.apiEndpoints]; }
  getResponseHeaders() { const obj = {}; this.responseHeaders.forEach((v,k) => { obj[k] = v; }); return obj; }

  summary() {
    return {
      urlsCrawled: this.visited.size,
      totalUrlsFound: this.allUrls.size,
      jsFilesFound: this.jsUrls.size,
      apiEndpoints: this.apiEndpoints.size,
      formsFound: this.forms.length,
      sourceMapsFound: this.sourceMaps.size,
      assetsDownloaded: this.downloadedJs.length + this.downloadedAssets.length,
      errors: this.errors.length,
    };
  }


  // ═══════════════════════════════════════════════════════════════
  //  DEEP BROWSER EXTRACTION (XJutsu-style)
  //  Extracts everything the browser already loaded with auth cookies
  //  Performance API + endpoint scan + response bodies + page HTML
  // ═══════════════════════════════════════════════════════════════
  async _deepExtractFromBrowser(page) {
    this.logger.log('CRAWLER', 'INFO', 'Deep browser extraction (XJutsu mode)...');

    const deepData = await page.evaluate(() => {
      const result = {
        perfResources: [], xhrResponses: [], fetchResponses: [],
        filteredLinks: [], pageHtml: '', sourceScripts: [],
        endpoints: new Set()
      };

      // 1. Performance API — ALL resources the browser loaded
      try {
        performance.getEntriesByType('resource').forEach(function(r) {
          result.perfResources.push({
            name: r.name, type: r.initiatorType, duration: Math.round(r.duration),
            size: r.transferSize || 0, decoded: r.decodedBodySize || 0
          });
        });
      } catch(e) {}

      // 2. Harvest XHR/fetch response bodies (from our hooks)
      result.xhrResponses = (window.__GENKI_XHR_RESPONSES || []).slice(0, 200);
      result.fetchResponses = (window.__GENKI_FETCH_RESPONSES || []).slice(0, 200);

      // 3. Link collection with LOGOUT FILTERING (XJutsu-style)
      var logoutPatterns = /logout|signout|logoff|signoff|sign-off|log-off|sign-out|log-out|adminlogout/i;
      var allLinks = [];
      document.querySelectorAll('a[href]').forEach(function(a) {
        try {
          var href = new URL(a.href, location.href).href;
          if (!logoutPatterns.test(href)) allLinks.push(href);
        } catch(e) {}
      });
      result.filteredLinks = allLinks;

      // 4. Page HTML (full DOM for offline analysis)
      try { result.pageHtml = document.documentElement.outerHTML.substring(0, 2000000); } catch(e) {}

      // 5. Extract ALL script sources (including dynamically loaded)
      document.querySelectorAll('script').forEach(function(s) {
        if (s.src) result.sourceScripts.push(s.src);
        if (s.textContent && s.textContent.length > 20) {
          // Extract endpoints from inline scripts
          var pathMatches = s.textContent.match(/['"](\/[^'"\s]{2,200})['"]\s*/g);
          if (pathMatches) {
            pathMatches.forEach(function(m) {
              var cleaned = m.replace(/^['"]|['"]s*$/g, '');
              if (cleaned.length > 1 && cleaned.length < 200 && !/[^ -~]/.test(cleaned)) {
                try { result.endpoints.add(new URL(cleaned, location.href).href); } catch(e) { result.endpoints.add(cleaned); }
              }
            });
          }
        }
      });

      // 6. Extract endpoints from ALL loaded resources (bookmarklet approach)
      // Fetch each JS/JSON resource and scan for paths
      result.endpoints = [...result.endpoints];
      return result;
    });

    // Process performance resources — discover JS/API not caught by request interceptor
    let newJs = 0, newApi = 0;
    for (const r of deepData.perfResources) {
      this.allUrls.add(r.name);
      if (/\.js(\?|$)/i.test(r.name) && !this.jsUrls.has(r.name)) {
        this.jsUrls.add(r.name); newJs++;
      }
      if (/api|graphql|internal/i.test(r.name)) {
        this.apiEndpoints.add('GET ' + r.name); newApi++;
      }
      if (/\.map(\?|$)/i.test(r.name)) this.sourceMaps.add(r.name);
    }

    // Process XHR/fetch response bodies — extract endpoints from JSON responses
    const allResponses = [...deepData.xhrResponses, ...deepData.fetchResponses];
    for (const r of allResponses) {
      this.allUrls.add(r.url);
      if (r.contentType && r.contentType.includes('json') && r.responseBody) {
        // Extract URLs from JSON responses
        const urlMatches = r.responseBody.match(/https?:\/\/[^"'\s]{5,300}/g);
        if (urlMatches) urlMatches.forEach(u => { this.allUrls.add(u); this.apiEndpoints.add('GET ' + u); });
        // Extract path patterns
        const pathMatches = r.responseBody.match(/"(\/[a-zA-Z0-9_\/-]{3,100})"/g);
        if (pathMatches) pathMatches.forEach(p => {
          const cleaned = p.replace(/"/g, '');
          try { this.apiEndpoints.add('GET ' + new URL(cleaned, this.config.targetUrl).href); } catch(e) {}
        });
      }
    }

    // Process filtered links (logout-safe)
    deepData.filteredLinks.forEach(link => {
      const norm = this.normalizeUrl(link);
      if (norm && this.isInScope(norm) && !this.visited.has(norm)) this.queued.add(norm);
      if (norm) this.allUrls.add(norm);
    });

    // Process extracted endpoints
    deepData.endpoints.forEach(ep => { this.allUrls.add(ep); });

    // Save response bodies for analysis
    const respDir = require('path').join(this.config.outputDir, 'response-bodies');
    if (!require('fs').existsSync(respDir)) require('fs').mkdirSync(respDir, { recursive: true });
    if (allResponses.length > 0) {
      require('fs').writeFileSync(require('path').join(respDir, 'xhr-fetch-responses.json'),
        JSON.stringify(allResponses, null, 2));
    }

    // Save page HTML
    if (deepData.pageHtml) {
      require('fs').writeFileSync(require('path').join(this.config.outputDir, 'page-dom.html'), deepData.pageHtml);
    }

    // Save performance resources list
    if (deepData.perfResources.length > 0) {
      require('fs').writeFileSync(require('path').join(this.config.outputDir, 'performance-resources.json'),
        JSON.stringify(deepData.perfResources, null, 2));
    }

    this.logger.log('CRAWLER', 'OK',
      'Deep extract: ' + deepData.perfResources.length + ' perf resources, ' +
      allResponses.length + ' XHR/fetch bodies, ' +
      deepData.filteredLinks.length + ' links (logout filtered), ' +
      newJs + ' new JS, ' + newApi + ' new API endpoints');
  }

  // ═══════════════════════════════════════════════════════════════
  //  CDP SOURCE TREE — extract from DevTools Sources panel
  //  Gets ALL scripts the debugger knows about (including eval'd)
  // ═══════════════════════════════════════════════════════════════
  async _extractCdpSources(page) {
    try {
      const cdp = await page.createCDPSession();
      await cdp.send('Debugger.enable');
      const { result } = await cdp.send('Debugger.searchInContent', { scriptId: '0', query: '' }).catch(() => ({ result: [] }));

      // Get all script sources the debugger knows about
      const { scriptParsed } = await new Promise((resolve) => {
        const scripts = [];
        const handler = (params) => scripts.push(params);
        cdp.on('Debugger.scriptParsed', handler);
        // Give it a moment to collect scripts
        setTimeout(() => {
          cdp.off('Debugger.scriptParsed', handler);
          resolve({ scriptParsed: scripts });
        }, 2000);
        // Trigger script collection
        cdp.send('Runtime.evaluate', { expression: '1+1' }).catch(() => {});
      });

      // Already collected during enable, query all known scripts
      const scripts = [];
      // Use Page.getResourceTree for complete resource listing
      try {
        const { frameTree } = await cdp.send('Page.getResourceTree');
        const extractResources = (frame) => {
          if (frame.resources) {
            frame.resources.forEach(r => {
              scripts.push({ url: r.url, type: r.type, mimeType: r.mimeType });
              this.allUrls.add(r.url);
              if (r.type === 'Script' || /\.js(\?|$)/i.test(r.url)) this.jsUrls.add(r.url);
            });
          }
          if (frame.childFrames) frame.childFrames.forEach(cf => extractResources(cf.frame || cf));
        };
        extractResources(frameTree.frame || frameTree);
        this.logger.log('CRAWLER', 'OK', 'CDP Source Tree: ' + scripts.length + ' resources from DevTools');
      } catch(e) {
        this.logger.log('CRAWLER', 'WARN', 'CDP getResourceTree: ' + e.message.substring(0, 60));
      }

      await cdp.send('Debugger.disable').catch(() => {});
      await cdp.detach().catch(() => {});
    } catch(e) {
      this.logger.log('CRAWLER', 'WARN', 'CDP source extraction: ' + e.message.substring(0, 80));
    }
  }

  // ═══════════════════════════════════════════════════════════════
  //  ENDPOINT SCANNER — scan loaded resource contents for paths
  //  (The bookmarklet approach: fetch each loaded resource and grep)
  // ═══════════════════════════════════════════════════════════════
  async _scanLoadedResourcesForEndpoints(page) {
    this.logger.log('CRAWLER', 'INFO', 'Scanning loaded resources for hidden endpoints...');

    const endpoints = await page.evaluate(async () => {
      const found = new Set();
      const scanned = new Set();

      function isValidPath(p) {
        return (p.startsWith('/') || p.startsWith('./') || p.startsWith('../')) &&
               !p.includes(' ') && p.length > 1 && p.length > 1 && p.length < 200;
      }

      function extractPaths(content) {
        var paths = [];
        var matches = content.match(/['"](\/[^'"\s]{2,200})['"]\s*/g);
        if (matches) {
          matches.forEach(function(m) {
            var cleaned = m.replace(/^['"]|['"]s*$/g, '');
            if (isValidPath(cleaned)) paths.push(cleaned);
          });
        }
        return paths;
      }

      // Scan all JS/JSON resources via performance API
      var resources = performance.getEntriesByType('resource')
        .filter(function(r) { return /script|fetch|xmlhttp|other/.test(r.initiatorType); })
        .map(function(r) { return r.name; });

      // Also add all script srcs
      document.querySelectorAll('script[src]').forEach(function(s) { resources.push(s.src); });

      // Dedupe
      resources = [...new Set(resources)];

      // Fetch and scan each (with cookies!)
      for (var i = 0; i < resources.length && i < 50; i++) {
        var url = resources[i];
        if (scanned.has(url)) continue;
        scanned.add(url);
        try {
          var resp = await fetch(url, { credentials: 'include' });
          if (resp.ok) {
            var text = await resp.text();
            if (text.length < 2000000) {
              var paths = extractPaths(text);
              paths.forEach(function(p) { found.add(p); });
            }
          }
        } catch(e) {}
      }

      return { paths: [...found], scannedCount: scanned.size };
    });

    // Process discovered endpoints
    let newEndpoints = 0;
    for (const p of endpoints.paths) {
      try {
        const fullUrl = new URL(p, this.config.targetUrl).href;
        if (!this.allUrls.has(fullUrl)) { this.allUrls.add(fullUrl); newEndpoints++; }
        if (p.includes('/api/') || p.includes('/graphql') || p.includes('/internal/')) this.apiEndpoints.add('GET ' + fullUrl);
      } catch(e) { this.allUrls.add(p); }
    }

    this.logger.log('CRAWLER', 'OK',
      'Endpoint scan: ' + endpoints.paths.length + ' paths from ' + endpoints.scannedCount + ' resources (' + newEndpoints + ' new)');
  }


  // ══════════════════════════════════════════════════════════════════════════════
  // ██ INTERACTIVE CRAWL PHASE — Forms, Clicks, SPA Routes, Scroll, Events
  // ══════════════════════════════════════════════════════════════════════════════

  async _interactiveCrawlPhase(page) {
    this.logger.log('CRAWLER', 'INFO', '═══ INTERACTIVE CRAWL PHASE ═══');
    this.formSubmissions = [];
    this.clickDiscoveries = [];
    this.spaRoutes = new Set();

    // Visit each page we already crawled and interact with it
    const pagesToInteract = [...this.visited].slice(0, Math.min(this.visited.size, 30));
    for (const url of pagesToInteract) {
      try {
        await page.goto(url, { waitUntil: 'networkidle2', timeout: this.config.timeout || 30000 });
        await this._sleep(500);

        // Phase 1: Forms
        if (this.config.fillForms !== false) await this._interactWithForms(page, url);
        // Phase 2: Click discovery
        if (this.config.clickDiscovery !== false) await this._clickDiscovery(page, url);
        // Phase 4: Scroll + lazy load
        if (this.config.lazyLoadTrigger !== false) await this._triggerLazyContent(page, url);
        // Phase 5: Event sweep
        await this._fireEvents(page, url);

      } catch (e) {
        this.logger.log('CRAWLER', 'WARN', `Interactive error on ${url.substring(0, 80)}: ${e.message.substring(0, 80)}`);
      }
    }

    // Phase 3: SPA route discovery (once, uses JS bundle analysis)
    if (this.config.spaDiscovery !== false) await this._discoverSpaRoutes(page);

    this.logger.log('CRAWLER', 'OK',
      `Interactive phase done: ${this.formSubmissions.length} forms submitted, ` +
      `${this.clickDiscoveries.length} click discoveries, ${this.spaRoutes.size} SPA routes`);
  }

  // ── Phase 1: Smart Form Auto-Fill + Submit ──────────────────────────────────
  async _interactWithForms(page, url) {
    const maxForms = this.config.maxFormsPerPage || 10;
    const taintPrefix = this.config.taintPrefix || 'GNKTNT';
    let taintId = Date.now();

    try {
      const formCount = await page.evaluate((max, tPrefix, tId) => {
        const forms = Array.from(document.querySelectorAll('form')).slice(0, max);
        const results = [];

        for (const form of forms) {
          const formInfo = { action: form.action, method: form.method, fields: [], submitted: false };
          const inputs = form.querySelectorAll('input, textarea, select');

          for (const input of inputs) {
            const name = input.name || input.id || '';
            const type = (input.type || input.tagName).toLowerCase();
            const nameLower = name.toLowerCase();

            // Skip hidden CSRF tokens — preserve their values
            if (type === 'hidden') { formInfo.fields.push({ name, type, value: input.value, preserved: true }); continue; }
            // Skip submit/button
            if (type === 'submit' || type === 'button' || type === 'image') continue;

            // Generate taint-aware test value
            let testVal = tPrefix + (++tId);
            if (nameLower.includes('email') || type === 'email') testVal = `${tPrefix}${tId}@genki-probe.com`;
            else if (nameLower.includes('url') || nameLower.includes('website') || type === 'url') testVal = `https://${tPrefix}${tId}.genki-probe.com`;
            else if (nameLower.includes('search') || nameLower === 'q' || nameLower === 'query') testVal = tPrefix + tId;
            else if (nameLower.includes('pass') || type === 'password') testVal = `${tPrefix}${tId}Pass!`;
            else if (nameLower.includes('phone') || type === 'tel') testVal = '5551234' + tId;
            else if (type === 'number') testVal = String(tId);
            else if (type === 'checkbox' || type === 'radio') { input.checked = true; formInfo.fields.push({ name, type, value: 'checked' }); continue; }
            else if (input.tagName === 'SELECT') {
              const opts = input.querySelectorAll('option');
              if (opts.length > 1) input.selectedIndex = 1;
              formInfo.fields.push({ name, type: 'select', value: input.value }); continue;
            }
            else if (type === 'file') { formInfo.fields.push({ name, type, value: 'skipped' }); continue; }

            // Set value and fire events
            try {
              const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set
                || Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value')?.set;
              if (nativeInputValueSetter) nativeInputValueSetter.call(input, testVal);
              else input.value = testVal;
              input.dispatchEvent(new Event('input', { bubbles: true }));
              input.dispatchEvent(new Event('change', { bubbles: true }));
              input.dispatchEvent(new Event('blur', { bubbles: true }));
            } catch(e) { input.value = testVal; }
            formInfo.fields.push({ name, type, value: testVal });
          }

          // Try submitting
          try {
            const submitBtn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
            if (submitBtn) submitBtn.click();
            else form.submit();
            formInfo.submitted = true;
          } catch(e) { formInfo.error = e.message; }

          results.push(formInfo);
        }
        return results;
      }, maxForms, taintPrefix, taintId);

      if (formCount && formCount.length > 0) {
        // Wait for form submissions to trigger XHR/navigations
        await this._sleep(2000);
        await page.waitForNetworkIdle({ timeout: 5000 }).catch(() => {});

        // Capture new URLs discovered from form submissions
        const newUrls = await page.evaluate(() => {
          const urls = new Set();
          // Check XHR responses for new endpoints
          (window.__GENKI_XHR_RESPONSES || []).forEach(r => urls.add(r.url));
          (window.__GENKI_FETCH_RESPONSES || []).forEach(r => urls.add(r.url));
          // Check if we navigated
          urls.add(location.href);
          return [...urls];
        });

        newUrls.forEach(u => {
          if (u && this.isInScope(u)) {
            this.allUrls.add(u);
            if (/api|graphql|internal/i.test(u)) this.apiEndpoints.add(`POST ${u}`);
            if (!this.visited.has(u) && this.classifyUrl(u) === 'page') this.queued.add(u);
          }
        });

        formCount.forEach(f => this.formSubmissions.push({ ...f, foundOn: url }));
        this.logger.log('CRAWLER', 'OK', `[FORMS] ${formCount.length} forms filled+submitted on ${url.substring(0, 80)} (${newUrls.length} new URLs)`);

        // Navigate back if form submission changed the page
        try { await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 }); } catch(e) {}
      }
    } catch (e) {
      this.logger.log('CRAWLER', 'WARN', `Form interaction error: ${e.message.substring(0, 100)}`);
    }
  }

  // ── Phase 2: Click-Through Discovery ────────────────────────────────────────
  async _clickDiscovery(page, url) {
    const maxClicks = this.config.maxClicksPerPage || 20;

    try {
      // Dangerous action keywords to avoid clicking
      const dangerWords = ['logout', 'signout', 'sign-out', 'log-out', 'delete', 'remove', 'destroy',
        'deactivate', 'unsubscribe', 'close-account', 'cancel-subscription'];

      const clickables = await page.evaluate((max, danger) => {
        const selectors = [
          'button:not([type="submit"])',
          '[role="button"]',
          '[role="tab"]',
          '[role="menuitem"]',
          'a[href="#"]',
          'a[href="javascript:void(0)"]',
          'a[href="javascript:;"]',
          '[onclick]',
          '[ng-click]',
          '[v-on\\:click]',
          '[@click]',
          '[data-toggle]',
          '[data-bs-toggle]',
          '.accordion-header',
          '.tab-link',
          '.nav-link',
          '.dropdown-toggle',
          'details > summary',
        ];

        const elements = [];
        const seen = new Set();

        for (const sel of selectors) {
          try {
            document.querySelectorAll(sel).forEach(el => {
              const text = (el.textContent || '').trim().toLowerCase().substring(0, 50);
              const id = el.id || el.className?.toString().substring(0, 30) || text;
              // Skip dangerous actions
              if (danger.some(d => text.includes(d) || (el.href || '').toLowerCase().includes(d))) return;
              // Skip already processed
              if (seen.has(id)) return;
              seen.add(id);
              // Skip invisible
              const rect = el.getBoundingClientRect();
              if (rect.width === 0 || rect.height === 0) return;

              elements.push({
                selector: el.id ? `#${el.id}` : (el.dataset.testid ? `[data-testid="${el.dataset.testid}"]` : null),
                text: text.substring(0, 30),
                tag: el.tagName,
                x: rect.x + rect.width / 2,
                y: rect.y + rect.height / 2
              });
            });
          } catch(e) {}
        }
        return elements.slice(0, max);
      }, maxClicks, dangerWords);

      if (clickables.length === 0) return;

      let discovered = 0;
      const beforeUrls = new Set(this.allUrls);

      for (const el of clickables) {
        try {
          const beforeCount = await page.evaluate(() => document.querySelectorAll('a[href], form, [role="dialog"], .modal').length);
          const beforeUrl = page.url();

          // Click the element
          await page.mouse.click(el.x, el.y);
          await this._sleep(800);

          // Check what changed
          const afterUrl = page.url();
          const changes = await page.evaluate((prevCount) => {
            const newCount = document.querySelectorAll('a[href], form, [role="dialog"], .modal').length;
            const newLinks = [];
            // Check for newly visible modals/dialogs
            const dialogs = document.querySelectorAll('[role="dialog"]:not([aria-hidden="true"]), .modal.show, .modal:not(.hidden), dialog[open]');
            dialogs.forEach(d => {
              d.querySelectorAll('a[href]').forEach(a => { try { newLinks.push(new URL(a.href, location.href).href); } catch(e) {} });
              d.querySelectorAll('form').forEach(f => {
                newLinks.push('FORM:' + (f.action || location.href) + ':' + (f.method || 'GET'));
              });
            });
            // Also grab any new links on page
            document.querySelectorAll('a[href]').forEach(a => { try { newLinks.push(new URL(a.href, location.href).href); } catch(e) {} });
            return { domDelta: newCount - prevCount, newLinks, hasDialog: dialogs.length > 0 };
          }, beforeCount);

          // Process discoveries
          changes.newLinks.forEach(link => {
            if (link.startsWith('FORM:')) {
              // New form found in modal/dynamic content
              const [, action, method] = link.split(':');
              this.forms.push({ action, method, foundOn: url, source: 'click_discovery' });
            } else if (this.isInScope(link) && !this.allUrls.has(link)) {
              this.allUrls.add(link);
              if (this.classifyUrl(link) === 'page' && !this.visited.has(link)) this.queued.add(link);
              discovered++;
            }
          });

          // URL changed — new page/route discovered
          if (afterUrl !== beforeUrl && afterUrl !== url) {
            if (this.isInScope(afterUrl) && !this.visited.has(afterUrl)) {
              this.queued.add(afterUrl);
              this.allUrls.add(afterUrl);
              discovered++;
            }
            // Navigate back
            await page.goto(url, { waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
          }

          // Close any modals
          if (changes.hasDialog) {
            await page.evaluate(() => {
              document.querySelectorAll('[role="dialog"] button[aria-label*="close"], .modal .close, .modal [data-dismiss="modal"], dialog button').forEach(b => b.click());
            });
            await this._sleep(300);
          }

        } catch (e) { /* Click failed, continue */ }
      }

      if (discovered > 0 || clickables.length > 0) {
        this.clickDiscoveries.push({ url, clicked: clickables.length, discovered });
        this.logger.log('CRAWLER', 'OK', `[CLICKS] ${clickables.length} elements clicked on ${url.substring(0, 80)} (${discovered} new discoveries)`);
      }
    } catch (e) {
      this.logger.log('CRAWLER', 'WARN', `Click discovery error: ${e.message.substring(0, 100)}`);
    }
  }

  // ── Phase 3: SPA Route Discovery ────────────────────────────────────────────
  async _discoverSpaRoutes(page) {
    this.logger.log('CRAWLER', 'INFO', '[SPA] Discovering framework routes...');
    try {
      await page.goto(this.config.targetUrl, { waitUntil: 'networkidle2', timeout: this.config.timeout || 30000 });

      const routes = await page.evaluate(() => {
        const found = new Set();

        // Next.js __NEXT_DATA__
        try {
          const nd = document.querySelector('#__NEXT_DATA__');
          if (nd) {
            const data = JSON.parse(nd.textContent);
            // Build manifest routes
            if (data.buildManifest?.sortedPages) data.buildManifest.sortedPages.forEach(p => found.add(p));
            // Page props
            if (data.page) found.add(data.page);
            // Also search for routes in the serialized data
            const json = nd.textContent;
            const routeMatches = json.match(/"\/[a-zA-Z0-9/_[\]-]+"/g);
            if (routeMatches) routeMatches.forEach(m => {
              const r = m.replace(/"/g, '');
              if (r.length > 1 && r.length < 100 && !r.includes('.')) found.add(r);
            });
          }
        } catch(e) {}

        // Next.js page manifest from script tags
        try {
          document.querySelectorAll('script').forEach(s => {
            const text = s.textContent || '';
            // Match _buildManifest.js patterns
            const pages = text.match(/static\/[a-zA-Z0-9/_-]+\.js/g);
            if (pages) pages.forEach(p => found.add('/_next/' + p));
            // Match sortedPages patterns
            const sorted = text.match(/sortedPages['":\s]*\[(.*?)\]/);
            if (sorted) {
              const paths = sorted[1].match(/"\/[^"]+"/g);
              if (paths) paths.forEach(p => found.add(p.replace(/"/g, '')));
            }
          });
        } catch(e) {}

        // Nuxt.js __NUXT__
        try {
          if (window.__NUXT__?.routeMap) {
            Object.values(window.__NUXT__.routeMap).forEach(r => { if (r.path) found.add(r.path); });
          }
        } catch(e) {}

        // React Router / Reach Router — search for route paths in scripts
        try {
          document.querySelectorAll('script[src]').forEach(() => {}); // trigger load
          // Check window for router state
          if (window.__REACT_ROUTER_HISTORY__) found.add(window.__REACT_ROUTER_HISTORY__.location.pathname);
        } catch(e) {}

        // Generic: search all scripts for path-like strings /word/word
        try {
          document.querySelectorAll('script:not([src])').forEach(s => {
            const text = s.textContent;
            const pathMatches = text.match(/["']\/(?:app|dashboard|settings|profile|account|admin|api|auth|login|register|users?|items?|products?|orders?|checkout|cart|search|browse|explore|discover|collection|categories|help|support|about|contact|blog|news|docs?|faq|pricing|terms|privacy|notifications?|messages?|inbox)[\/a-zA-Z0-9_-]*["']/g);
            if (pathMatches) pathMatches.forEach(m => {
              const r = m.replace(/["']/g, '');
              if (r.length > 1 && r.length < 80) found.add(r);
            });
          });
        } catch(e) {}

        return [...found];
      });

      let newRoutes = 0;
      for (const route of routes) {
        try {
          const fullUrl = new URL(route, this.config.targetUrl).href;
          if (this.isInScope(fullUrl) && !this.visited.has(fullUrl) && !this.allUrls.has(fullUrl)) {
            this.queued.add(fullUrl);
            this.allUrls.add(fullUrl);
            this.spaRoutes.add(route);
            newRoutes++;
          }
        } catch(e) {}
      }

      this.logger.log('CRAWLER', 'OK', `[SPA] Found ${routes.length} routes (${newRoutes} new): ${routes.slice(0, 5).join(', ')}${routes.length > 5 ? '...' : ''}`);
    } catch (e) {
      this.logger.log('CRAWLER', 'WARN', `SPA route discovery error: ${e.message.substring(0, 100)}`);
    }
  }

  // ── Phase 4: Scroll + Lazy Load Trigger ─────────────────────────────────────
  async _triggerLazyContent(page, url) {
    try {
      const beforeLinks = await page.evaluate(() => document.querySelectorAll('a[href]').length);

      // Scroll to bottom in increments
      const scrollResult = await page.evaluate(async () => {
        let newElements = 0;
        const scrollHeight = () => document.documentElement.scrollHeight;
        let prevHeight = scrollHeight();

        for (let i = 0; i < 10; i++) {
          window.scrollBy(0, window.innerHeight);
          await new Promise(r => setTimeout(r, 500));

          // Click "Load More" / "Show More" buttons
          const loadMore = document.querySelector(
            'button[class*="load-more"], button[class*="show-more"], ' +
            'a[class*="load-more"], a[class*="show-more"], ' +
            '[data-testid*="load-more"], [data-testid*="show-more"], ' +
            'button:not([disabled])');
          // Only click if text matches
          if (loadMore) {
            const text = (loadMore.textContent || '').toLowerCase();
            if (text.includes('load more') || text.includes('show more') || text.includes('see more') || text.includes('view more')) {
              loadMore.click();
              await new Promise(r => setTimeout(r, 1000));
            }
          }

          const newHeight = scrollHeight();
          if (newHeight > prevHeight) { newElements++; prevHeight = newHeight; }
          if (newHeight === prevHeight && i > 2) break; // No new content
        }

        // Scroll back to top
        window.scrollTo(0, 0);
        return { scrollSteps: newElements };
      });

      // Extract any new links that appeared
      const afterLinks = await page.evaluate(() => {
        const links = [];
        document.querySelectorAll('a[href]').forEach(a => {
          try { links.push(new URL(a.href, location.href).href); } catch(e) {}
        });
        return links;
      });

      let newFromScroll = 0;
      afterLinks.forEach(link => {
        if (this.isInScope(link) && !this.allUrls.has(link)) {
          this.allUrls.add(link);
          if (this.classifyUrl(link) === 'page' && !this.visited.has(link)) this.queued.add(link);
          newFromScroll++;
        }
      });

      if (newFromScroll > 0) {
        this.logger.log('CRAWLER', 'OK', `[SCROLL] ${newFromScroll} new URLs from lazy-load on ${url.substring(0, 80)}`);
      }
    } catch(e) {}
  }

  // ── Phase 5: Event Trigger Sweep ────────────────────────────────────────────
  async _fireEvents(page, url) {
    try {
      const triggered = await page.evaluate(() => {
        let count = 0;
        // Fire mouseover on elements with hover handlers
        document.querySelectorAll('[onmouseover], [onmouseenter], .dropdown, .tooltip-trigger, [data-tooltip]').forEach(el => {
          try {
            el.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
            el.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
            count++;
          } catch(e) {}
        });

        // Fire focus on inputs (some apps load suggestions/content on focus)
        document.querySelectorAll('input[type="text"], input[type="search"], input:not([type]), textarea').forEach(el => {
          try {
            el.dispatchEvent(new FocusEvent('focus', { bubbles: true }));
            el.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
            count++;
          } catch(e) {}
        });

        // Fire change on all selects
        document.querySelectorAll('select').forEach(el => {
          try {
            if (el.options.length > 1) { el.selectedIndex = 1; }
            el.dispatchEvent(new Event('change', { bubbles: true }));
            count++;
          } catch(e) {}
        });

        // Open all <details> elements
        document.querySelectorAll('details:not([open])').forEach(el => {
          try { el.open = true; count++; } catch(e) {}
        });

        return count;
      });

      // Wait for any triggered content
      if (triggered > 0) {
        await this._sleep(500);
        // Extract any new content
        const newLinks = await page.evaluate(() => {
          const links = [];
          document.querySelectorAll('a[href]').forEach(a => { try { links.push(new URL(a.href, location.href).href); } catch(e) {} });
          return links;
        });
        newLinks.forEach(link => {
          if (this.isInScope(link) && !this.allUrls.has(link)) { this.allUrls.add(link); this.queued.add(link); }
        });
      }
    } catch(e) {}
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}
module.exports = Crawler;
