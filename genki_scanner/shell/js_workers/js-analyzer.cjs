// GENKI-PROBER MODULE: JS STATIC ANALYZER
// Deep-scans downloaded JS bundles for endpoints, params, fields, routes, secrets
// Designed for SPAs where traditional crawling finds nothing
const fs = require('fs');
const path = require('path');

class JsAnalyzer {
  constructor(logger, config) {
    this.logger = logger;
    this.config = config;
    this.endpoints = new Set();
    this.params = new Set();
    this.routes = new Set();
    this.secrets = [];
    this.sockets = new Set();
    this.graphql = [];
    this.methods = [];       // {method, path} pairs
    this.fields = new Set();
    this.configs = [];
    this.findings = [];
    this.internalUrls = new Set();
    this.externalUrls = new Set();
  }

  async run(jsFiles, inlineScripts) {
    this.logger.log('JS-ANALYZER', 'INFO', `Analyzing ${jsFiles.length} JS files + ${inlineScripts?.size || 0} inline scripts...`);
    
    // Analyze downloaded JS files
    for (const jsFile of jsFiles) {
      try {
        const content = fs.readFileSync(jsFile.path, 'utf8');
        const filename = path.basename(jsFile.path);
        // Skip vendor/pendo/analytics bundles for endpoint extraction (too noisy)
        const isVendor = /vendor|pendo|analytics|sentry|gtag/i.test(filename);
        this._analyzeContent(content, jsFile.url, isVendor);
      } catch (e) {
        this.logger.log('JS-ANALYZER', 'WARN', `Error reading ${jsFile.path}: ${e.message.substring(0, 80)}`);
      }
    }
    
    // Analyze inline scripts
    if (inlineScripts) {
      for (const [key, content] of inlineScripts) {
        this._analyzeContent(content, key, false);
      }
    }
    
    // Save results
    this._saveResults();
    
    const stats = this.summary();
    this.logger.log('JS-ANALYZER', 'OK', 
      `Found: ${stats.endpoints} endpoints, ${stats.params} params, ${stats.routes} routes, ` +
      `${stats.secrets} secrets, ${stats.sockets} websockets, ${stats.methods} method+path pairs`);
  }

  _analyzeContent(content, source, isVendor) {
    // ═══════════════════════════════════════════════════
    // 1. API ENDPOINTS — /api/*, /v1/*, /rest/*, /graphql
    // ═══════════════════════════════════════════════════
    const apiPatterns = [
      // String literals: "/api/something"
      /["'`](\/api\/[^"'`\s\)]{2,200})["'`]/g,
      /["'`](\/v[0-9]+\/[^"'`\s\)]{2,200})["'`]/g,
      /["'`](\/rest\/[^"'`\s\)]{2,200})["'`]/g,
      /["'`](\/internal\/[^"'`\s\)]{2,200})["'`]/g,
      /["'`](\/graphql[^"'`\s\)]*)["'`]/g,
      /["'`](\/app\/api\/[^"'`\s\)]{2,200})["'`]/g,
      /["'`](\/app\/auth\/[^"'`\s\)]{2,100})["'`]/g,
      /["'`](\/app\/nav\/[^"'`\s\)]{2,100})["'`]/g,
      /["'`](\/app\/socket[^"'`\s\)]{2,100})["'`]/g,
      // Template literals: `/api/${var}/something`
      /`(\/api\/[^`]{2,200})`/g,
      /`(\/v[0-9]+\/[^`]{2,200})`/g,
      /`(\/app\/api\/[^`]{2,200})`/g,
    ];
    
    if (!isVendor) {
      for (const pattern of apiPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const ep = match[1];
          // Normalize template vars: ${var} -> {id}
          const normalized = ep
            .replace(/\$\{[^}]+\}/g, '{id}')
            .replace(/\?.*$/, '');  // Remove query strings for dedup
          this.endpoints.add(normalized);
          // Also keep the raw one with query params
          if (ep !== normalized) this.endpoints.add(ep.replace(/\$\{[^}]+\}/g, '{id}'));
        }
      }
    }

    // ═══════════════════════════════════════════════════
    // 2. HTTP METHOD + PATH PAIRS
    // ═══════════════════════════════════════════════════
    const methodPatterns = [
      // axios/fetch style: .get("/api/..."), .post("/api/...")
      /\.(get|post|put|patch|delete|GET|POST|PUT|PATCH|DELETE)\s*\(\s*["'`](\/[^"'`\s]{3,200})["'`]/g,
      // method: "POST", url: "/api/..."
      /method\s*:\s*["'](GET|POST|PUT|PATCH|DELETE)["'].*?(?:url|path|endpoint)\s*:\s*["'`](\/[^"'`\s]{3,200})["'`]/gs,
      // fetch("/api/...", { method: "POST" })
      /fetch\s*\(\s*["'`](\/[^"'`\s]{3,200})["'`]\s*,\s*\{[^}]*method\s*:\s*["'](GET|POST|PUT|PATCH|DELETE)["']/gs,
    ];
    
    if (!isVendor) {
      for (const pattern of methodPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          // Different capture groups for different patterns
          if (match[1].startsWith('/')) {
            this.methods.push({ method: match[2]?.toUpperCase() || 'GET', path: match[1].replace(/\$\{[^}]+\}/g, '{id}') });
          } else {
            this.methods.push({ method: match[1].toUpperCase(), path: match[2].replace(/\$\{[^}]+\}/g, '{id}') });
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════
    // 3. ROUTE DEFINITIONS (SPA routes)
    // ═══════════════════════════════════════════════════
    const routePatterns = [
      /(?:path|route|to)\s*[:=]\s*["'`](\/[^"'`\s]{2,100})["'`]/g,
      /Route\s+(?:exact\s+)?path=["'](\/[^"'\s]{2,100})["']/g,
      /navigate\s*\(\s*["'`](\/[^"'`\s]{2,100})["'`]/g,
      /history\.push\s*\(\s*["'`](\/[^"'`\s]{2,100})["'`]/g,
      /window\.location\s*=\s*["'`](\/[^"'`\s]{2,100})["'`]/g,
      /redirect\s*[:=]\s*["'`](\/[^"'`\s]{2,100})["'`]/g,
    ];
    
    for (const pattern of routePatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        this.routes.add(match[1].replace(/\$\{[^}]+\}/g, '{id}'));
      }
    }

    // ═══════════════════════════════════════════════════
    // 4. PARAMETERS & FIELD NAMES
    // ═══════════════════════════════════════════════════
    const paramPatterns = [
      // Query params: ?param=, &param=
      /[?&]([a-zA-Z_][a-zA-Z0-9_]{1,50})=/g,
      // Object keys that look like API params
      /(?:params|query|body|data|payload|fields|input)\s*[:=]\s*\{([^}]{5,500})\}/g,
      // FormData.append("field", ...)
      /(?:FormData|formData|form_data).*?append\s*\(\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,50})["']/g,
      // name="field" or name: "field" (form inputs)
      /name\s*[:=]\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,50})["']/g,
    ];
    
    if (!isVendor) {
      for (const pattern of paramPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          if (match[1].length < 50 && !/^(function|return|const|let|var|class|import|export|true|false|null|undefined|this|new|if|else|for|while|switch|case|break|continue|default|try|catch|throw|typeof|instanceof|void|delete|in|of)$/.test(match[1])) {
            this.params.add(match[1]);
          }
          // For object pattern, extract individual keys
          if (pattern.source.includes('params|query')) {
            const keys = match[1]?.match(/([a-zA-Z_][a-zA-Z0-9_]{2,40})\s*:/g);
            if (keys) keys.forEach(k => this.params.add(k.replace(':', '').trim()));
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════
    // 5. INPUT FIELD NAMES (UI forms)
    // ═══════════════════════════════════════════════════
    const fieldPatterns = [
      /(?:field|input|column|attribute|property)\s*[:=]\s*["']([a-zA-Z_][a-zA-Z0-9_.]{1,60})["']/g,
      /placeholder\s*[:=]\s*["']([^"']{2,60})["']/g,
      /label\s*[:=]\s*["']([^"']{2,60})["']/g,
    ];
    
    if (!isVendor) {
      for (const pattern of fieldPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          this.fields.add(match[1]);
        }
      }
    }

    // ═══════════════════════════════════════════════════
    // 6. WEBSOCKET ENDPOINTS
    // ═══════════════════════════════════════════════════
    const wsPatterns = [
      /["'`](wss?:\/\/[^"'`\s]{5,200})["'`]/g,
      /WebSocket\s*\(\s*["'`]([^"'`\s]{5,200})["'`]/g,
      /["'`](\/socket[^"'`\s]{2,100})["'`]/g,
      /["'`](\/ws[^"'`\s]{2,100})["'`]/g,
      /["'`](\/sockets\/[^"'`\s]{2,100})["'`]/g,
    ];
    
    for (const pattern of wsPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        this.sockets.add(match[1]);
      }
    }

    // ═══════════════════════════════════════════════════
    // 7. GRAPHQL QUERIES/MUTATIONS
    // ═══════════════════════════════════════════════════
    const gqlPatterns = [
      /(?:query|mutation|subscription)\s+([A-Z][a-zA-Z]+)/g,
      /gql\s*`\s*(query|mutation|subscription)\s+([A-Z][a-zA-Z]+)/g,
    ];
    
    for (const pattern of gqlPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        this.graphql.push(match[0].substring(0, 200));
      }
    }

    // ═══════════════════════════════════════════════════
    // 8. SECRETS / HARDCODED KEYS — FULL SECRET MINER
    // ═══════════════════════════════════════════════════
    const secretPatterns = [
      // ── Cloud / Infra ─────────────────────────────────
      { rx: /sk-ant-api03-[\w-]{93}AA/g,                                                 type: 'Anthropic API Key',                     sev: 'critical' },
      { rx: /AKIA[0-9A-Z]{16}/g,                                                         type: 'AWS API Key',                           sev: 'critical' },
      { rx: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,      type: 'AWS Client ID',                         sev: 'critical' },
      { rx: /da2-[a-z0-9]{26}/g,                                                         type: 'AWS AppSync GraphQL Key',               sev: 'high'     },
      { rx: /mzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,type: 'AWS MWS ID',                            sev: 'high'     },
      // ── OpenAI / Anthropic ────────────────────────────
      { rx: /sk-[a-zA-Z0-9_-]{48}/g,                                                    type: 'OpenAI API Key',                        sev: 'critical' },
      // ── GitHub ────────────────────────────────────────
      { rx: /ghp_[0-9a-zA-Z]{36}/g,                                                     type: 'GitHub Personal Access Token',          sev: 'critical' },
      { rx: /gho_[0-9a-zA-Z]{36}/g,                                                     type: 'GitHub OAuth Access Token',             sev: 'critical' },
      { rx: /(ghu|ghs)_[0-9a-zA-Z]{36}/g,                                               type: 'GitHub App Token',                      sev: 'critical' },
      { rx: /ghr_[0-9a-zA-Z]{76}/g,                                                     type: 'GitHub App Refresh Token',              sev: 'critical' },
      // ── Slack ─────────────────────────────────────────
      { rx: /xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}/g,                 type: 'Slack Token',                           sev: 'critical' },
      { rx: /xox[baprs]-([0-9a-zA-Z]{10,48})/g,                                         type: 'Slack API Token',                       sev: 'high'     },
      { rx: /xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g,                               type: 'Slack OAuth Bot Token',                 sev: 'critical' },
      { rx: /xoxe\.xoxp-1-[0-9a-zA-Z]{166}/g,                                           type: 'Slack OAuth v2 Config Token',           sev: 'critical' },
      { rx: /xoxe-1-[0-9a-zA-Z]{147}/g,                                                 type: 'Slack OAuth v2 Refresh Token',          sev: 'critical' },
      { rx: /xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/g,                               type: 'Slack OAuth User Token',                sev: 'critical' },
      { rx: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{10}\/B[a-zA-Z0-9_]{10}\/[a-zA-Z0-9_]{24}/g, type: 'Slack Webhook', sev: 'critical' },
      { rx: /(?:r|s)k_live_[0-9a-zA-Z]{24}/g,                                           type: 'Slack Live API Key',                    sev: 'critical' },
      { rx: /(?:r|s)k_test_[0-9a-zA-Z]{24}/g,                                           type: 'Slack Test API Key',                    sev: 'medium'   },
      // ── Stripe ────────────────────────────────────────
      { rx: /sk_live_[0-9a-zA-Z]{24}/g,                                                  type: 'Stripe API Key',                        sev: 'critical' },
      { rx: /sk_test_[0-9a-zA-Z]{24}/g,                                                  type: 'Stripe Test Key',                       sev: 'medium'   },
      { rx: /rk_live_[0-9a-zA-Z]{24}/g,                                                  type: 'Stripe Restricted Key',                 sev: 'critical' },
      // ── Google ────────────────────────────────────────
      { rx: /AIza[0-9A-Za-z_-]{35}/g,                                                    type: 'Google API Key',                        sev: 'critical' },
      { rx: /ya29\.[0-9A-Za-z_-]+/g,                                                     type: 'Google OAuth Access Token',             sev: 'critical' },
      // ── Discord ───────────────────────────────────────
      { rx: /(?:N|M|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}/g,          type: 'Discord Bot Token',                     sev: 'critical' },
      { rx: /https?:\/\/(?:ptb\.|canary\.)?discord\.com\/api(?:\/v\d{1,2})?\/webhooks\/(\d{17,19})\/([\w-]{68})/gi, type: 'Discord Webhook URL', sev: 'critical' },
      // ── Facebook / Meta ───────────────────────────────
      { rx: /EAACEdEose0cBA[0-9A-Za-z]+/g,                                               type: 'Facebook Access Token',                 sev: 'critical' },
      { rx: /(?:facebook|fb)[_-]?(?:app[_-]?secret|client[_-]?secret|secret[_-]?key)\s*[:=]\s*['"][0-9a-f]{32}['"]/gi, type: 'Facebook OAuth', sev: 'critical' },
      // ── Twitter / X ───────────────────────────────────
      { rx: /[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}/g,              type: 'Twitter Access Token',                  sev: 'critical' },
      { rx: /(?:twitter|tw)[_-]?(?:consumer[_-]?secret|api[_-]?secret|oauth[_-]?secret|client[_-]?secret)\s*[:=]\s*['"][0-9a-zA-Z]{35,44}['"]/gi, type: 'Twitter OAuth', sev: 'high' },
      // ── SendGrid / Mailgun / MailChimp ────────────────
      { rx: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g,                                type: 'SendGrid API Key',                      sev: 'critical' },
      { rx: /key-[0-9a-zA-Z]{32}/g,                                                      type: 'Mailgun API Key',                       sev: 'critical' },
      { rx: /[0-9a-f]{32}-us[0-9]{1,2}/g,                                                type: 'MailChimp API Key',                     sev: 'critical' },
      // ── Shopify ───────────────────────────────────────
      { rx: /shpat_[a-fA-F0-9]{32}/g,                                                    type: 'Shopify Access Token',                  sev: 'critical' },
      { rx: /shpss_[a-fA-F0-9]{32}/g,                                                    type: 'Shopify App Shared Secret',             sev: 'critical' },
      { rx: /shpca_[a-fA-F0-9]{32}/g,                                                    type: 'Shopify Custom App Token',              sev: 'critical' },
      { rx: /shppa_[a-fA-F0-9]{32}/g,                                                    type: 'Shopify Private App Password',          sev: 'critical' },
      // ── Square ────────────────────────────────────────
      { rx: /sq0atp-[0-9A-Za-z_-]{22}/g,                                                 type: 'Square Access Token',                   sev: 'critical' },
      { rx: /sq0csp-[0-9A-Za-z_-]{43}/g,                                                 type: 'Square OAuth Secret',                   sev: 'critical' },
      // ── Heroku ────────────────────────────────────────
      { rx: /[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g, type: 'Heroku API Key', sev: 'critical' },
      // ── Twilio ────────────────────────────────────────
      { rx: /SK[0-9a-fA-F]{32}/g,                                                        type: 'Twilio API Key',                        sev: 'critical' },
      // ── Dynatrace ─────────────────────────────────────
      { rx: /dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}/gi,                    type: 'Dynatrace Token',                       sev: 'critical' },
      // ── Mapbox ────────────────────────────────────────
      { rx: /[sp]k\.eyJ1Ijoi[\w.-]+/g,                                                   type: 'Mapbox Key',                            sev: 'high'     },
      // ── npm / NuGet / PyPI ────────────────────────────
      { rx: /npm_[0-9a-zA-Z]{36}/g,                                                      type: 'npm Access Token',                      sev: 'critical' },
      { rx: /oy2[a-z0-9]{43}/g,                                                          type: 'NuGet API Key',                         sev: 'high'     },
      { rx: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000}/g,                              type: 'PyPI API Token',                        sev: 'critical' },
      // ── Picatic ───────────────────────────────────────
      { rx: /sk_live_[0-9a-z]{32}/g,                                                     type: 'Picatic API Key',                       sev: 'critical' },
      // ── Instagram ────────────────────────────────────
      { rx: /[0-9a-fA-F]{7}\.[0-9a-fA-F]{32}/g,                                         type: 'Instagram OAuth',                       sev: 'high'     },
      // ── Private Keys / Certs ──────────────────────────
      { rx: /-----BEGIN RSA PRIVATE KEY-----/g,                                           type: 'SSH RSA Private Key',                   sev: 'critical' },
      { rx: /-----BEGIN EC PRIVATE KEY-----/g,                                            type: 'SSH EC Private Key',                    sev: 'critical' },
      { rx: /-----BEGIN DSA PRIVATE KEY-----/g,                                           type: 'SSH DSA Private Key',                   sev: 'critical' },
      { rx: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,                                    type: 'PGP Private Key',                       sev: 'critical' },
      { rx: /-----BEGIN OPENSSH PRIVATE KEY-----/g,                                      type: 'OpenSSH Private Key',                   sev: 'critical' },
      // ── JWT ───────────────────────────────────────────
      { rx: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,      type: 'JWT Token',                             sev: 'high'     },
      // ── Encryption Keys / Secrets in code ────────────
      { rx: /(?:encryption[_-]?key|aes[_-]?key|cipher[_-]?key|crypto[_-]?key)\s*[:=]\s*["']([^"']{16,})['"]/gi, type: 'Encryption Key', sev: 'critical' },
      { rx: /(?:private[_-]?key|secret[_-]?key|signing[_-]?key|signing[_-]?secret)\s*[:=]\s*["']([^"']{16,})['"]/gi, type: 'Signing Key', sev: 'critical' },
      { rx: /(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?key)\s*[:=]\s*["']([^"']{16,100})['"]/gi, type: 'Generic API Key', sev: 'high' },
      { rx: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,100})['"]/gi,                 type: 'Hardcoded Password',                    sev: 'high'     },
      { rx: /(?:auth[_-]?token|bearer[_-]?token|access[_-]?token|session[_-]?token)\s*[:=]\s*["']([a-zA-Z0-9+/_.=-]{20,500})['"]/gi, type: 'Auth Token', sev: 'high' },
      // ── Database connection strings ───────────────────
      { rx: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mssql):\/\/[^\s"'`]{10,}/gi, type: 'Database Connection String', sev: 'critical' },
      { rx: /(?:DB_PASSWORD|DATABASE_URL|DB_HOST|REDIS_URL|MONGO_URI)\s*[:=]\s*["']([^"']{4,})['"]/gi, type: 'DB Credential', sev: 'critical' },
      // ── Generic high-entropy secret detection ─────────
      { rx: /["']([A-Za-z0-9+/]{40,}={0,2})["']/g,                                      type: 'Base64 Secret (possible)',              sev: 'low'      },
    ];

    for (const { rx, type, sev = 'high' } of secretPatterns) {
      let match;
      // Reset lastIndex for global regexes
      rx.lastIndex = 0;
      while ((match = rx.exec(content)) !== null) {
        const val = (match[1] || match[0]).substring(0, 200);
        // Skip common false positives
        if (!val || val.length < 8) continue;
        if (/^(true|false|null|undefined|function|return|module|exports|require|window|document|console|process|prototype|constructor)$/i.test(val)) continue;
        if (/^[0-9]+$/.test(val)) continue; // pure numbers
        // Skip CSS/Tailwind classes, npm package scopes, HTML attributes
        if (/^[@:]|^[\w-]+:[\w-]+\s|pl-\d|w-\[|grow\s|flex\s|overflow|text-|font-|bg-|border-|rounded-|shadow-|hover:/i.test(val)) continue;
        // Skip common non-secret string patterns (social share URLs, meta tags, enum values)
        if (/^https?:\/\/(?:x|twitter|facebook|t)\.com\//i.test(val)) continue;
        if (/^(?:Twitter|Facebook|Discord|Instagram|LinkedIn|GitHub|website|email)$/i.test(val)) continue;
        // Skip contract/blockchain identifiers (Erc, Seaport, etc)
        if (/^(?:Erc|Seaport|SeaDrop|Wyvern|Conduit)/i.test(val)) continue;
        // For base64, check entropy to reduce noise
        if (type === 'Base64 Secret (possible)' && this._entropy(val) < 4.0) continue;
        // Decode JWT if found — expose header + payload
        let decoded = null;
        if (type === 'JWT Token') {
          try {
            const [h, p] = val.split('.');
            decoded = {
              header:  JSON.parse(Buffer.from(h, 'base64url').toString()),
              payload: JSON.parse(Buffer.from(p, 'base64url').toString()),
            };
          } catch(e) { /* malformed, still record it */ }
        }
        // Deduplicate
        const key = `${type}:${val.substring(0, 50)}`;
        if (this._secretsSeen) {
          if (this._secretsSeen.has(key)) continue;
          this._secretsSeen.add(key);
        } else {
          this._secretsSeen = new Set([key]);
        }
        this.secrets.push({
          type, sev, value: val,
          source: path.basename(source),
          decoded,
          context: content.substring(Math.max(0, match.index - 60), match.index + val.length + 60).replace(/\n/g, ' ').substring(0, 300),
        });
      }
    }

    // ═══════════════════════════════════════════════════
    // 9. FULL URLS (internal + external)
    // ═══════════════════════════════════════════════════
    const urlMatch = content.match(/["'`](https?:\/\/[^"'`\s]{10,300})["'`]/g);
    if (urlMatch) {
      urlMatch.forEach(m => {
        const url = m.replace(/^["'`]|["'`]$/g, '');
        try {
          const hostname = new URL(url).hostname;
          if (this.config.scope.some(s => hostname === s || hostname.endsWith('.' + s))) {
            this.internalUrls.add(url);
          } else {
            this.externalUrls.add(url);
          }
        } catch(e) {}
      });
    }

    // ═══════════════════════════════════════════════════
    // 10. CONFIG OBJECTS
    // ═══════════════════════════════════════════════════
    if (!isVendor) {
      const configPatterns = [
        /(?:config|CONFIG|settings|SETTINGS|options|OPTIONS|env|ENV)\s*[:=]\s*(\{[^}]{10,500}\})/g,
        /(?:baseUrl|baseURL|BASE_URL|apiUrl|API_URL|apiBase)\s*[:=]\s*["'`]([^"'`\s]{5,200})["'`]/g,
      ];
      for (const pattern of configPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          this.configs.push({ pattern: pattern.source.substring(0, 50), value: match[1]?.substring(0, 300), source: path.basename(source) });
        }
      }
    }

    // ═══════════════════════════════════════════════════
    // 11. PROTOTYPE POLLUTION STATIC ANALYSIS
    //     Sources → merge functions → gadgets → sinks
    // ═══════════════════════════════════════════════════
    if (!isVendor) {
      const ppPatterns = [
        // PP Sources: unsafe JSON.parse of external data
        { rx: /JSON\.parse\s*\(\s*(?:req\.|request\.|ctx\.|body\b|input\b|data\b|params\b|query\b|e\.data\b|event\.data\b|message\.data\b|localStorage|sessionStorage|location\.|window\.name)/g,
          name: 'json_parse_untrusted', sev: 'high', desc: 'JSON.parse() on untrusted input — PP source if merged' },
        // Unsafe parsers
        { rx: /(?:JSON5|YAML|yaml|toml)\.(?:parse|load)\s*\(/g,
          name: 'unsafe_parser', sev: 'medium', desc: 'JSON5/YAML parse — may allow __proto__ key' },
        { rx: /(?:qs|querystring)\.parse\s*\(/g,
          name: 'qs_parse', sev: 'medium', desc: 'qs.parse() — bracket notation ?a[__proto__][x]=1 PP vector' },
        { rx: /(?:flatted|destr|node-serialize)\.parse\s*\(/g,
          name: 'unsafe_deserializer', sev: 'high', desc: 'Unsafe deserializer — PP / RCE vectors' },
        // Lodash merge sinks
        { rx: /(?:_|lodash)\s*\.\s*(?:merge|defaultsDeep|mergeWith|assignIn|defaults)\s*\(/g,
          name: 'lodash_merge', sev: 'high', desc: 'Lodash merge/defaultsDeep — PP sink CVE-2020-8203' },
        // jQuery deep extend
        { rx: /\$\s*\.\s*extend\s*\(\s*true/g,
          name: 'jquery_extend_deep', sev: 'high', desc: 'jQuery $.extend(true,...) deep merge — PP sink CVE-2019-11358' },
        // deepmerge packages
        { rx: /(?:deepmerge|deep-merge|merge-deep|deepMerge)\s*\(/g,
          name: 'deepmerge_pkg', sev: 'high', desc: 'deepmerge package — PP sink' },
        // Custom deep merge functions
        { rx: /(?:mergeWith|mergeDeep|deepExtend|deepAssign|recursiveMerge|deepDefaults)\s*\(/g,
          name: 'custom_deep_merge', sev: 'high', desc: 'Custom deep merge — potential PP sink' },
        // Object.assign with controlled source
        { rx: /Object\s*\.\s*assign\s*\(\s*(?:this|self|\{\}|target|obj|options|config|settings)\s*,/g,
          name: 'object_assign_controlled', sev: 'medium', desc: 'Object.assign with potentially controlled source' },
        // for..in without hasOwnProperty
        { rx: /for\s*\(\s*(?:let|var|const)\s+\w+\s+in\s+\w+\s*\)/g,
          name: 'forin_no_hasown', sev: 'medium', desc: 'for..in — check if hasOwnProperty guard exists' },
        // constructor.prototype bracket notation
        { rx: /\[["']constructor["']\]\s*\[["']prototype["']\]/g,
          name: 'constructor_prototype_bracket', sev: 'high', desc: 'obj["constructor"]["prototype"] — alternative PP path' },
        // a[b][c]=val pattern
        { rx: /\w+\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\]\s*=[^=]/g,
          name: 'bracket_bracket_assign', sev: 'medium', desc: 'a[b][c]=val — PP if b/c user-controlled' },
        // SSR props flowing into merge
        { rx: /getServerSideProps[\s\S]{0,500}?(?:merge|assign|extend|defaultsDeep)\s*\(/g,
          name: 'ssrprops_merge', sev: 'critical', desc: 'getServerSideProps data flows into merge — SSPP vector' },
        { rx: /pageProps[\s\S]{0,200}?(?:merge|assign|extend|defaultsDeep)\s*\(/g,
          name: 'pageprops_merge', sev: 'high', desc: 'pageProps merged — PP via crafted query param' },
        { rx: /getInitialProps[\s\S]{0,400}?(?:merge|assign|extend)\s*\(/g,
          name: 'getinitialprops_merge', sev: 'high', desc: 'getInitialProps data merged — SSR PP vector' },
        // Direct __proto__ assignment
        { rx: /__proto__\s*[:=]/g,
          name: 'direct_proto_assign', sev: 'high', desc: 'Direct __proto__ assignment' },
        { rx: /Object\s*\.\s*setPrototypeOf\s*\(/g,
          name: 'set_prototype_of', sev: 'medium', desc: 'Object.setPrototypeOf() — prototype chain manipulation' },
        // req.body / req.query merged
        { rx: /(?:req|ctx)\s*\.\s*body[\s\S]{0,200}?(?:merge|assign|extend|defaultsDeep)\s*\(/g,
          name: 'reqbody_merge', sev: 'critical', desc: 'req.body merged — PP via POST body __proto__' },
        { rx: /(?:req|ctx)\s*\.\s*(?:query|params)[\s\S]{0,200}?(?:merge|assign|extend)\s*\(/g,
          name: 'reqquery_merge', sev: 'high', desc: 'req.query merged — PP via URL bracket notation' },
        // Handlebars compile with options
        { rx: /(?:Handlebars|hbs)\.compile\s*\([^)]*(?:options|opts|data)/g,
          name: 'handlebars_compile_opts', sev: 'high', desc: 'Handlebars.compile with options — PP via __defineGetter__' },
        // yaml.load unsafe
        { rx: /yaml\.(?:load|safeLoad)\s*\(/g,
          name: 'yaml_load', sev: 'high', desc: 'yaml.load() — JS object injection (js-yaml <4.0)' },
      ];

      for (const { rx, name, sev, desc } of ppPatterns) {
        rx.lastIndex = 0;
        let match;
        while ((match = rx.exec(content)) !== null) {
          const snippet = match[0].substring(0, 150).replace(/\s+/g, ' ');
          const ctx    = content.substring(Math.max(0, match.index - 40), match.index + match[0].length + 40)
                                .replace(/\n/g, ' ').substring(0, 250);
          const lineNo = content.substring(0, match.index).split('\n').length;
          this.findings.push({ type: 'pp_static', severity: sev, name, desc, snippet, context: ctx, source: path.basename(source), line: lineNo });
        }
      }
    }
  }

  _entropy(str) {
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    const len = str.length;
    return Object.values(freq).reduce((e, f) => {
      const p = f / len;
      return e - p * Math.log2(p);
    }, 0);
  }

  _saveResults() {
    const dir = this.config.outputDir;
    const jsDir = path.join(dir, 'js-analysis');
    if (!fs.existsSync(jsDir)) fs.mkdirSync(jsDir, { recursive: true });
    
    // All API endpoints (the goldmine)
    const endpoints = [...this.endpoints].sort();
    fs.writeFileSync(path.join(jsDir, 'api-endpoints-from-js.txt'), endpoints.join('\n'));
    
    // Method+Path pairs
    const methodPaths = [...new Set(this.methods.map(m => `${m.method} ${m.path}`))].sort();
    fs.writeFileSync(path.join(jsDir, 'method-paths.txt'), methodPaths.join('\n'));
    
    // Routes
    fs.writeFileSync(path.join(jsDir, 'spa-routes.txt'), [...this.routes].sort().join('\n'));
    
    // Parameters
    fs.writeFileSync(path.join(jsDir, 'parameters.txt'), [...this.params].sort().join('\n'));
    
    // Fields
    fs.writeFileSync(path.join(jsDir, 'fields.txt'), [...this.fields].sort().join('\n'));
    
    // WebSocket endpoints
    if (this.sockets.size) fs.writeFileSync(path.join(jsDir, 'websocket-endpoints.txt'), [...this.sockets].sort().join('\n'));
    
    // GraphQL
    if (this.graphql.length) fs.writeFileSync(path.join(jsDir, 'graphql-operations.txt'), [...new Set(this.graphql)].join('\n'));
    
    // Secrets
    if (this.secrets.length) fs.writeFileSync(path.join(jsDir, 'secrets.json'), JSON.stringify(this.secrets, null, 2));
    
    // Internal URLs
    fs.writeFileSync(path.join(jsDir, 'internal-urls.txt'), [...this.internalUrls].sort().join('\n'));
    
    // External URLs (3rd party services — interesting for SSRF, etc.)
    fs.writeFileSync(path.join(jsDir, 'external-urls.txt'), [...this.externalUrls].sort().join('\n'));
    
    // Configs
    if (this.configs.length) fs.writeFileSync(path.join(jsDir, 'configs.json'), JSON.stringify(this.configs, null, 2));
    
    // Full summary JSON
    fs.writeFileSync(path.join(jsDir, 'analysis-summary.json'), JSON.stringify({
      endpoints: endpoints.length,
      methods: methodPaths.length,
      routes: [...this.routes].length,
      params: [...this.params].length,
      fields: [...this.fields].length,
      sockets: [...this.sockets].length,
      graphql: this.graphql.length,
      secrets: this.secrets.length,
      internalUrls: this.internalUrls.size,
      externalUrls: this.externalUrls.size,
    }, null, 2));
    
    // Log secrets as findings
    this.secrets.forEach(s => {
      const jwtInfo = s.decoded ? ` [alg:${s.decoded.header?.alg||'?'} sub:${s.decoded.payload?.sub||s.decoded.payload?.email||'?'}]` : '';
      const sev = (s.sev || 'high').toUpperCase();
      this.logger.log('JS-ANALYZER', 'FIND', `🔑 [${sev}] ${s.type}: ${s.value.substring(0, 50)}${jwtInfo} | In: ${s.source}`);
      this.findings.push({ type: 'hardcoded_secret', severity: s.sev || 'high', ...s });
    });
  }

  summary() {
    return {
      endpoints: this.endpoints.size,
      params: this.params.size,
      routes: this.routes.size,
      secrets: this.secrets.length,
      sockets: this.sockets.size,
      methods: new Set(this.methods.map(m => `${m.method} ${m.path}`)).size,
      fields: this.fields.size,
      graphql: this.graphql.length,
      internalUrls: this.internalUrls.size,
      externalUrls: this.externalUrls.size,
    };
  }

  getFindings() { return this.findings; }
  getEndpoints() { return [...this.endpoints]; }
  getParams() { return [...this.params]; }
}
module.exports = JsAnalyzer;
