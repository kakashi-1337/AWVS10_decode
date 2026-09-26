/**
 * 🧠 J-SHADOW AI/ML PATTERN ENGINE v1.0
 * =====================================
 * Advanced pattern detection with machine learning capabilities
 * 
 * Features:
 * ✅ Pattern Database (patterns.json) - Learnable pattern storage
 * ✅ AI Function Renaming (OpenAI GPT-4o-mini or local)
 * ✅ ML-like Pattern Classification
 * ✅ Sourcemap Detection (headers, inline, base64, hidden)
 * ✅ Fingerprint-based Obfuscator Identification
 * ✅ Pattern Learning from successful deobfuscations
 * 
 * @author Kakashi x Claude Tandem
 * @version 1.0.0
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============================================================================
// SECTION 1: PATTERN DATABASE
// ============================================================================

class PatternDatabase {
    constructor(dbPath = './patterns.json') {
        this.dbPath = dbPath;
        this.db = this._loadOrCreate();
        this.dirty = false;
    }

    /**
     * Load existing database or create new one
     */
    _loadOrCreate() {
        try {
            if (fs.existsSync(this.dbPath)) {
                const data = fs.readFileSync(this.dbPath, 'utf8');
                return JSON.parse(data);
            }
        } catch (e) {
            console.warn(`[PatternDB] Could not load ${this.dbPath}, creating new`);
        }

        return this._createEmpty();
    }

    _createEmpty() {
        return {
            version: '1.0.0',
            lastUpdated: new Date().toISOString(),
            totalPatterns: 0,
            totalDetections: 0,
            
            // Known patterns organized by category
            patterns: {
                obfuscators: {
                    'obfuscator.io': {
                        signatures: [
                            { pattern: '_0x[a-f0-9]{4,}', weight: 0.8, type: 'regex' },
                            { pattern: 'var _0x\\w+=\\[', weight: 0.9, type: 'regex' },
                            { pattern: "\\['push'\\]\\(\\w+\\['shift'\\]", weight: 0.95, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        successRate: 0,
                        handler: 'obfuscator_io'
                    },
                    'jscrambler': {
                        signatures: [
                            { pattern: '\\)\\s*[~:`\\)|\\xAA]', weight: 0.9, type: 'regex' },
                            { pattern: 'charAt\\s*\\(\\s*\\w+\\s*\\^', weight: 0.85, type: 'regex' },
                            { pattern: 'fromCharCode\\s*\\(\\s*\\w+\\s*\\^', weight: 0.85, type: 'regex' }
                        ],
                        knownKeys: ['YN3ZHE', '28K&IL', '4PJ#3('],
                        knownDelimiters: ['~', ':', '`', ')', '|', '\xAA'],
                        confidence: 0,
                        detectionCount: 0,
                        successRate: 0,
                        handler: 'jscrambler'
                    },
                    'javascript-obfuscator': {
                        signatures: [
                            { pattern: '_0x[a-f0-9]{4}\\(', weight: 0.8, type: 'regex' },
                            { pattern: 'rotateStringArray', weight: 0.95, type: 'literal' },
                            { pattern: 'stringArrayThreshold', weight: 0.95, type: 'literal' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'obfuscator_io'
                    },
                    'defendjs': {
                        signatures: [
                            { pattern: '_defendjs_', weight: 0.99, type: 'literal' },
                            { pattern: 'defendjs', weight: 0.95, type: 'literal' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'defendjs'
                    },
                    'uglifyjs': {
                        signatures: [
                            { pattern: '!function\\(', weight: 0.5, type: 'regex' },
                            { pattern: 'void 0', weight: 0.4, type: 'literal' },
                            { pattern: '\\w=\\w\\|\\|\\{\\}', weight: 0.6, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'beautify'
                    },
                    'terser': {
                        signatures: [
                            { pattern: '=>\\{', weight: 0.3, type: 'regex' },
                            { pattern: '\\w\\?\\w:void 0', weight: 0.6, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'beautify'
                    },
                    'closure-compiler': {
                        signatures: [
                            { pattern: '\\$jscomp', weight: 0.95, type: 'literal' },
                            { pattern: 'goog\\.', weight: 0.9, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'beautify'
                    }
                },
                
                bundlers: {
                    'webpack': {
                        signatures: [
                            { pattern: '__webpack_require__', weight: 0.99, type: 'literal' },
                            { pattern: 'webpackJsonp', weight: 0.95, type: 'literal' },
                            { pattern: '__webpack_modules__', weight: 0.99, type: 'literal' },
                            { pattern: 'installedModules', weight: 0.7, type: 'literal' }
                        ],
                        versions: {
                            'webpack5': ['__webpack_module_cache__', '__webpack_exports__'],
                            'webpack4': ['webpackJsonpCallback', 'installedChunks'],
                            'webpack3': ['webpackJsonp', 'modules']
                        },
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'webpack'
                    },
                    'rollup': {
                        signatures: [
                            { pattern: "\\(function\\s*\\(\\s*exports\\s*,", weight: 0.8, type: 'regex' },
                            { pattern: "Object\\.defineProperty\\(exports", weight: 0.7, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'rollup'
                    },
                    'parcel': {
                        signatures: [
                            { pattern: 'parcelRequire', weight: 0.99, type: 'literal' },
                            { pattern: '__parcel__', weight: 0.95, type: 'literal' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'parcel'
                    },
                    'browserify': {
                        signatures: [
                            { pattern: 'require=function.*_prelude', weight: 0.9, type: 'regex' },
                            { pattern: "require\\(\\d+\\)", weight: 0.7, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'browserify'
                    },
                    'esbuild': {
                        signatures: [
                            { pattern: '__esm\\(', weight: 0.9, type: 'regex' },
                            { pattern: '__commonJS\\(', weight: 0.9, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'esbuild'
                    },
                    'vite': {
                        signatures: [
                            { pattern: '__vite__', weight: 0.95, type: 'literal' },
                            { pattern: 'import\\.meta\\.hot', weight: 0.8, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'vite'
                    }
                },

                encodings: {
                    'jsfuck': {
                        signatures: [
                            { pattern: '^[\\[\\]\\(\\)!+\\s]{50,}$', weight: 0.99, type: 'regex', multiline: true },
                            { pattern: '\\[\\]\\[\\[\\]\\]', weight: 0.9, type: 'regex' },
                            { pattern: '\\(!\\!\\[\\]\\+\\[\\]\\)', weight: 0.95, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'esoteric'
                    },
                    'jjencode': {
                        signatures: [
                            { pattern: '\\$=~\\[\\];', weight: 0.99, type: 'regex' },
                            { pattern: '\\$\\.\\$\\(\\$\\.\\$', weight: 0.95, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'esoteric'
                    },
                    'aaencode': {
                        signatures: [
                            { pattern: 'ﾟωﾟ', weight: 0.99, type: 'literal' },
                            { pattern: 'ﾟΘﾟ', weight: 0.95, type: 'literal' },
                            { pattern: 'ﾟДﾟ', weight: 0.95, type: 'literal' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'esoteric'
                    },
                    'base64': {
                        signatures: [
                            { pattern: 'atob\\s*\\(', weight: 0.7, type: 'regex' },
                            { pattern: 'btoa\\s*\\(', weight: 0.5, type: 'regex' },
                            { pattern: "Buffer\\.from\\([^,]+,\\s*['\"]base64['\"]\\)", weight: 0.8, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'string'
                    },
                    'hex': {
                        signatures: [
                            { pattern: '\\\\x[0-9a-fA-F]{2}', weight: 0.6, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'string'
                    },
                    'unicode': {
                        signatures: [
                            { pattern: '\\\\u[0-9a-fA-F]{4}', weight: 0.5, type: 'regex' },
                            { pattern: '\\\\u\\{[0-9a-fA-F]+\\}', weight: 0.6, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'string'
                    },
                    'xor': {
                        signatures: [
                            { pattern: 'charCodeAt\\([^)]*\\)\\s*\\^', weight: 0.8, type: 'regex' },
                            { pattern: 'String\\.fromCharCode\\([^)]*\\^', weight: 0.85, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'crypto'
                    },
                    'rc4': {
                        signatures: [
                            { pattern: 'rc4', weight: 0.9, type: 'literal', caseSensitive: false },
                            { pattern: '%\\s*256', weight: 0.6, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'crypto'
                    }
                },

                sourcemaps: {
                    'inline-comment': {
                        signatures: [
                            { pattern: '//[#@]\\s*sourceMappingURL=', weight: 0.99, type: 'regex' },
                            { pattern: '/\\*[#@]\\s*sourceMappingURL=', weight: 0.99, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0
                    },
                    'inline-base64': {
                        signatures: [
                            { pattern: 'sourceMappingURL=data:application/json;base64,', weight: 0.99, type: 'literal' },
                            { pattern: 'sourceMappingURL=data:[^;]+;base64,', weight: 0.95, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0
                    },
                    'external-file': {
                        signatures: [
                            { pattern: 'sourceMappingURL=[^\\s]+\\.map', weight: 0.95, type: 'regex' },
                            { pattern: '\\.js\\.map', weight: 0.7, type: 'literal' }
                        ],
                        confidence: 0,
                        detectionCount: 0
                    },
                    'hidden-chunk': {
                        signatures: [
                            { pattern: '"sources"\\s*:\\s*\\[', weight: 0.7, type: 'regex' },
                            { pattern: '"mappings"\\s*:\\s*"', weight: 0.8, type: 'regex' },
                            { pattern: '"sourcesContent"\\s*:', weight: 0.9, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0
                    },
                    'webpack-devtool': {
                        signatures: [
                            { pattern: 'webpack:///src/', weight: 0.9, type: 'literal' },
                            { pattern: 'webpack:///', weight: 0.7, type: 'literal' },
                            { pattern: 'sourceURL=webpack', weight: 0.85, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0
                    }
                },

                anti_debug: {
                    'debugger-trap': {
                        signatures: [
                            { pattern: '\\bdebugger\\b', weight: 0.99, type: 'regex' },
                            { pattern: 'setInterval.*debugger', weight: 0.95, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'anti_debug'
                    },
                    'timing-check': {
                        signatures: [
                            { pattern: 'performance\\.now\\(', weight: 0.7, type: 'regex' },
                            { pattern: 'Date\\.now\\(', weight: 0.5, type: 'regex' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'anti_debug'
                    },
                    'devtools-detect': {
                        signatures: [
                            { pattern: 'outerWidth.*innerWidth', weight: 0.8, type: 'regex' },
                            { pattern: '__REACT_DEVTOOLS', weight: 0.9, type: 'literal' },
                            { pattern: 'Firebug', weight: 0.85, type: 'literal' }
                        ],
                        confidence: 0,
                        detectionCount: 0,
                        handler: 'anti_debug'
                    }
                },

                custom: {}
            },

            // Code fingerprints for quick identification
            fingerprints: {},

            // Learned patterns from successful deobfuscations
            learned: [],

            // Statistics
            statistics: {
                successfulDeobfuscations: 0,
                failedDeobfuscations: 0,
                patternsLearned: 0
            }
        };
    }

    /**
     * Save database to file
     */
    save() {
        this.db.lastUpdated = new Date().toISOString();
        fs.writeFileSync(this.dbPath, JSON.stringify(this.db, null, 2));
        this.dirty = false;
    }

    /**
     * Add a new pattern
     */
    addPattern(category, name, signature, weight = 0.5, type = 'regex') {
        if (!this.db.patterns[category]) {
            this.db.patterns[category] = {};
        }
        if (!this.db.patterns[category][name]) {
            this.db.patterns[category][name] = {
                signatures: [],
                confidence: 0,
                detectionCount: 0
            };
        }

        this.db.patterns[category][name].signatures.push({
            pattern: signature,
            weight,
            type,
            addedAt: new Date().toISOString(),
            learned: true
        });

        this.db.totalPatterns++;
        this.dirty = true;
        return true;
    }

    /**
     * Learn from successful deobfuscation
     */
    learn(code, obfuscatorName, success, extractedPatterns = []) {
        const fingerprint = this._generateFingerprint(code);
        
        // Store fingerprint
        if (!this.db.fingerprints[fingerprint]) {
            this.db.fingerprints[fingerprint] = {
                obfuscator: obfuscatorName,
                firstSeen: new Date().toISOString(),
                successCount: 0,
                failCount: 0
            };
        }

        if (success) {
            this.db.fingerprints[fingerprint].successCount++;
            this.db.statistics.successfulDeobfuscations++;

            // Learn new patterns
            for (const pattern of extractedPatterns) {
                if (!this._patternExists(pattern)) {
                    this.db.learned.push({
                        pattern,
                        obfuscator: obfuscatorName,
                        learnedAt: new Date().toISOString(),
                        confidence: 0.5
                    });
                    this.db.statistics.patternsLearned++;
                }
            }
        } else {
            this.db.fingerprints[fingerprint].failCount++;
            this.db.statistics.failedDeobfuscations++;
        }

        this.dirty = true;
    }

    /**
     * Generate code fingerprint
     */
    _generateFingerprint(code) {
        // Create a structural fingerprint (ignoring variable names)
        const normalized = code
            .replace(/\s+/g, ' ')                    // Normalize whitespace
            .replace(/_0x[a-f0-9]+/gi, '_VAR_')      // Normalize obfuscated vars
            .replace(/['"][^'"]{1,50}['"]/g, '_STR_') // Normalize short strings
            .slice(0, 1000);                          // First 1000 chars
        
        return crypto.createHash('md5').update(normalized).digest('hex').slice(0, 16);
    }

    /**
     * Check if pattern already exists
     */
    _patternExists(pattern) {
        for (const category of Object.values(this.db.patterns)) {
            for (const entry of Object.values(category)) {
                if (entry.signatures?.some(s => s.pattern === pattern)) {
                    return true;
                }
            }
        }
        return this.db.learned.some(l => l.pattern === pattern);
    }

    /**
     * Get all patterns for detection
     */
    getAllPatterns() {
        const all = [];
        
        for (const [category, entries] of Object.entries(this.db.patterns)) {
            for (const [name, data] of Object.entries(entries)) {
                for (const sig of data.signatures || []) {
                    all.push({
                        category,
                        name,
                        ...sig,
                        handler: data.handler
                    });
                }
            }
        }

        // Include learned patterns
        for (const learned of this.db.learned) {
            all.push({
                category: 'learned',
                name: learned.obfuscator,
                pattern: learned.pattern,
                weight: learned.confidence,
                type: 'regex',
                learned: true
            });
        }

        return all;
    }

    /**
     * Get statistics
     */
    getStats() {
        return {
            ...this.db.statistics,
            totalPatterns: this.db.totalPatterns,
            totalFingerprints: Object.keys(this.db.fingerprints).length,
            learnedPatterns: this.db.learned.length
        };
    }

    /**
     * Update pattern confidence based on results
     */
    updateConfidence(category, name, success) {
        if (this.db.patterns[category]?.[name]) {
            const entry = this.db.patterns[category][name];
            entry.detectionCount++;
            
            // Update confidence using exponential moving average
            const alpha = 0.1;
            const result = success ? 1 : 0;
            entry.confidence = entry.confidence * (1 - alpha) + result * alpha;
            
            this.dirty = true;
        }
    }

    /**
     * Export database for sharing
     */
    export() {
        return JSON.stringify(this.db, null, 2);
    }

    /**
     * Import patterns from another database
     */
    import(jsonData) {
        try {
            const imported = JSON.parse(jsonData);
            
            // Merge patterns
            for (const [category, entries] of Object.entries(imported.patterns || {})) {
                if (!this.db.patterns[category]) {
                    this.db.patterns[category] = {};
                }
                for (const [name, data] of Object.entries(entries)) {
                    if (!this.db.patterns[category][name]) {
                        this.db.patterns[category][name] = data;
                        this.db.totalPatterns += (data.signatures?.length || 0);
                    }
                }
            }

            // Merge learned
            for (const learned of imported.learned || []) {
                if (!this._patternExists(learned.pattern)) {
                    this.db.learned.push(learned);
                }
            }

            this.dirty = true;
            return true;
        } catch (e) {
            return false;
        }
    }
}

// ============================================================================
// SECTION 2: SOURCEMAP DETECTOR
// ============================================================================

class SourcemapDetector {
    constructor() {
        this.patterns = {
            // Inline comment patterns
            inlineComment: [
                /\/\/[#@]\s*sourceMappingURL=([^\s\n]+)/g,
                /\/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*\//g
            ],
            
            // Inline base64 pattern
            inlineBase64: /sourceMappingURL=data:([^;]+);base64,([A-Za-z0-9+/=]+)/g,
            
            // External file reference
            externalFile: /sourceMappingURL=([^\s"']+\.map)/g,
            
            // Hidden sourcemap JSON in code
            hiddenJson: {
                sources: /"sources"\s*:\s*\[([^\]]+)\]/g,
                mappings: /"mappings"\s*:\s*"([^"]+)"/g,
                sourcesContent: /"sourcesContent"\s*:\s*\[/g,
                file: /"file"\s*:\s*"([^"]+)"/g
            },
            
            // Webpack specific
            webpack: {
                devtool: /\/\/\s*sourceURL=webpack:\/\/\/([^\n]+)/g,
                sourceRoot: /webpack:\/\/\//g
            },
            
            // HTTP header patterns (for reference)
            headers: [
                'SourceMap',
                'X-SourceMap'
            ]
        };
    }

    /**
     * Detect all sourcemaps in code
     */
    detect(code, options = {}) {
        const results = {
            found: false,
            locations: [],
            types: new Set(),
            extractedMaps: [],
            originalSources: []
        };

        // Check inline comments
        this._detectInlineComments(code, results);

        // Check inline base64
        this._detectInlineBase64(code, results);

        // Check external file references
        this._detectExternalFiles(code, results);

        // Check for hidden sourcemap JSON
        this._detectHiddenJson(code, results);

        // Check webpack patterns
        this._detectWebpackPatterns(code, results);

        results.found = results.locations.length > 0;
        results.types = Array.from(results.types);

        return results;
    }

    _detectInlineComments(code, results) {
        for (const pattern of this.patterns.inlineComment) {
            let match;
            const regex = new RegExp(pattern.source, pattern.flags);
            
            while ((match = regex.exec(code)) !== null) {
                results.locations.push({
                    type: 'inline-comment',
                    position: match.index,
                    url: match[1],
                    raw: match[0]
                });
                results.types.add('inline-comment');
            }
        }
    }

    _detectInlineBase64(code, results) {
        let match;
        const regex = new RegExp(this.patterns.inlineBase64.source, this.patterns.inlineBase64.flags);
        
        while ((match = regex.exec(code)) !== null) {
            const mimeType = match[1];
            const base64Data = match[2];
            
            try {
                const decoded = Buffer.from(base64Data, 'base64').toString('utf8');
                const sourcemap = JSON.parse(decoded);
                
                results.locations.push({
                    type: 'inline-base64',
                    position: match.index,
                    mimeType,
                    decoded: true
                });
                
                results.extractedMaps.push(sourcemap);
                
                if (sourcemap.sources) {
                    results.originalSources.push(...sourcemap.sources);
                }
                
                results.types.add('inline-base64');
            } catch (e) {
                results.locations.push({
                    type: 'inline-base64',
                    position: match.index,
                    mimeType,
                    decoded: false,
                    error: e.message
                });
            }
        }
    }

    _detectExternalFiles(code, results) {
        let match;
        const regex = new RegExp(this.patterns.externalFile.source, this.patterns.externalFile.flags);
        
        while ((match = regex.exec(code)) !== null) {
            const url = match[1];
            
            // Skip data URLs (handled separately)
            if (url.startsWith('data:')) continue;
            
            results.locations.push({
                type: 'external-file',
                position: match.index,
                url,
                raw: match[0]
            });
            results.types.add('external-file');
        }
    }

    _detectHiddenJson(code, results) {
        const indicators = {
            hasSources: false,
            hasMappings: false,
            hasSourcesContent: false,
            positions: []
        };

        // Check for sourcemap JSON structure
        for (const [key, pattern] of Object.entries(this.patterns.hiddenJson)) {
            let match;
            const regex = new RegExp(pattern.source, pattern.flags);
            
            while ((match = regex.exec(code)) !== null) {
                indicators[`has${key.charAt(0).toUpperCase() + key.slice(1)}`] = true;
                indicators.positions.push({
                    key,
                    position: match.index,
                    value: match[1]
                });
            }
        }

        // If we have multiple indicators, likely a hidden sourcemap
        const indicatorCount = [indicators.hasSources, indicators.hasMappings, indicators.hasSourcesContent]
            .filter(Boolean).length;

        if (indicatorCount >= 2) {
            results.locations.push({
                type: 'hidden-json',
                indicators,
                confidence: indicatorCount / 3
            });
            results.types.add('hidden-json');

            // Try to extract source filenames
            for (const pos of indicators.positions) {
                if (pos.key === 'sources' && pos.value) {
                    const sources = pos.value.match(/"([^"]+)"/g);
                    if (sources) {
                        results.originalSources.push(
                            ...sources.map(s => s.replace(/"/g, ''))
                        );
                    }
                }
            }
        }
    }

    _detectWebpackPatterns(code, results) {
        // Webpack sourceURL comments
        let match;
        const devtoolRegex = new RegExp(this.patterns.webpack.devtool.source, this.patterns.webpack.devtool.flags);
        
        while ((match = devtoolRegex.exec(code)) !== null) {
            results.locations.push({
                type: 'webpack-devtool',
                position: match.index,
                path: match[1]
            });
            results.types.add('webpack-devtool');
            results.originalSources.push(match[1]);
        }

        // General webpack source root
        if (this.patterns.webpack.sourceRoot.test(code)) {
            results.types.add('webpack-source');
        }
    }

    /**
     * Extract sourcemap from base64 inline
     */
    extractInlineSourcemap(code) {
        const match = this.patterns.inlineBase64.exec(code);
        if (match) {
            try {
                const decoded = Buffer.from(match[2], 'base64').toString('utf8');
                return JSON.parse(decoded);
            } catch (e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Remove sourcemap references from code
     */
    removeSourcemapRefs(code) {
        let result = code;
        
        // Remove inline comments
        for (const pattern of this.patterns.inlineComment) {
            result = result.replace(pattern, '');
        }
        
        // Remove base64 inline
        result = result.replace(this.patterns.inlineBase64, '');
        
        return result;
    }
}

// ============================================================================
// SECTION 3: AI ENGINE (OpenAI + Local)
// ============================================================================

class AIEngine {
    constructor(options = {}) {
        this.options = {
            provider: options.provider || 'local',  // 'openai' or 'local'
            apiKey: options.apiKey || process.env.OPENAI_API_KEY,
            model: options.model || 'gpt-4o-mini',
            baseUrl: options.baseUrl || 'https://api.openai.com/v1',
            maxTokens: options.maxTokens || 1000,
            temperature: options.temperature || 0.3,
            ...options
        };

        // Local pattern-based naming rules
        this.namingPatterns = {
            network: {
                patterns: [/fetch|xhr|ajax|request|http|url|api|endpoint/i, /\.send\(|\.open\(/],
                names: ['fetchData', 'sendRequest', 'callAPI', 'httpRequest', 'loadResource']
            },
            crypto: {
                patterns: [/encrypt|decrypt|hash|md5|sha|aes|rsa|hmac|cipher/i, /crypto\./],
                names: ['encrypt', 'decrypt', 'hashData', 'signData', 'verifySignature']
            },
            dom: {
                patterns: [/document\.|getElementById|querySelector|innerHTML|className|appendChild/],
                names: ['updateDOM', 'renderElement', 'createElement', 'modifyElement', 'queryElement']
            },
            storage: {
                patterns: [/localStorage|sessionStorage|indexedDB|cookie/i],
                names: ['saveData', 'loadData', 'storeValue', 'cacheData', 'persistData']
            },
            validation: {
                patterns: [/valid|check|verify|test|match|assert/i],
                names: ['validateInput', 'checkValue', 'verifyData', 'testCondition', 'assertValid']
            },
            encoding: {
                patterns: [/encode|decode|base64|atob|btoa|escape|unescape|serialize/i],
                names: ['encodeData', 'decodeData', 'serializeData', 'parseData', 'transformData']
            },
            array: {
                patterns: [/\.map\(|\.filter\(|\.reduce\(|\.forEach\(|\.find\(|\.some\(|\.every\(/],
                names: ['processArray', 'filterItems', 'transformList', 'collectData', 'aggregateValues']
            },
            string: {
                patterns: [/\.split\(|\.join\(|\.replace\(|\.substring\(|\.slice\(|\.trim\(/],
                names: ['formatString', 'parseText', 'extractValue', 'buildString', 'cleanText']
            },
            math: {
                patterns: [/Math\.|random|floor|ceil|round|abs|sqrt|pow/i],
                names: ['calculate', 'computeValue', 'generateRandom', 'roundNumber', 'mathOperation']
            },
            handler: {
                patterns: [/onClick|onSubmit|addEventListener|handler|callback|trigger/i],
                names: ['handleEvent', 'onAction', 'processEvent', 'triggerAction', 'eventCallback']
            },
            init: {
                patterns: [/init|setup|configure|bootstrap|start|begin/i],
                names: ['initialize', 'setup', 'configure', 'bootstrap', 'startApp']
            },
            async: {
                patterns: [/async|await|promise|then|catch|finally/i],
                names: ['asyncOperation', 'awaitResult', 'handlePromise', 'fetchAsync', 'loadAsync']
            },
            error: {
                patterns: [/error|exception|throw|catch|try|fail/i],
                names: ['handleError', 'catchException', 'throwError', 'errorHandler', 'onError']
            },
            loop: {
                patterns: [/for\s*\(|while\s*\(|\.forEach|iterate|loop/i],
                names: ['iterateItems', 'loopThrough', 'processEach', 'traverseData', 'walkCollection']
            },
            conditional: {
                patterns: [/if\s*\(|switch\s*\(|\?.*:/],
                names: ['checkCondition', 'evaluateCase', 'branchLogic', 'selectOption', 'decideAction']
            }
        };

        this.usedNames = new Set();
        this.counter = {};
    }

    /**
     * Generate a name for a function based on its code
     */
    async generateFunctionName(code, context = {}) {
        if (this.options.provider === 'openai' && this.options.apiKey) {
            return this._generateWithOpenAI(code, context);
        }
        return this._generateLocal(code, context);
    }

    /**
     * Local pattern-based name generation
     */
    _generateLocal(code, context = {}) {
        // Analyze code to find best category
        let bestCategory = null;
        let bestScore = 0;

        for (const [category, config] of Object.entries(this.namingPatterns)) {
            let score = 0;
            for (const pattern of config.patterns) {
                if (pattern.test(code)) {
                    score += 1;
                }
            }
            if (score > bestScore) {
                bestScore = score;
                bestCategory = category;
            }
        }

        // Generate unique name
        if (bestCategory) {
            const names = this.namingPatterns[bestCategory].names;
            return this._uniqueName(names[0], bestCategory);
        }

        // Default fallback
        return this._uniqueName('fn', 'default');
    }

    /**
     * Generate unique name
     */
    _uniqueName(baseName, category) {
        if (!this.counter[category]) {
            this.counter[category] = 0;
        }

        let name = baseName;
        while (this.usedNames.has(name)) {
            this.counter[category]++;
            name = `${baseName}${this.counter[category]}`;
        }

        this.usedNames.add(name);
        return name;
    }

    /**
     * Generate name using OpenAI API
     */
    async _generateWithOpenAI(code, context = {}) {
        try {
            const prompt = this._buildPrompt(code, context);
            
            const response = await fetch(`${this.options.baseUrl}/chat/completions`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.options.apiKey}`
                },
                body: JSON.stringify({
                    model: this.options.model,
                    messages: [
                        {
                            role: 'system',
                            content: `You are a code analysis expert. Your task is to suggest a meaningful, descriptive function name based on the code's purpose. 
                            
Rules:
- Use camelCase
- Be concise but descriptive (max 25 chars)
- Use common programming conventions
- Return ONLY the function name, nothing else`
                        },
                        {
                            role: 'user',
                            content: prompt
                        }
                    ],
                    max_tokens: 50,
                    temperature: this.options.temperature
                })
            });

            if (!response.ok) {
                console.warn('[AI] OpenAI API error, falling back to local');
                return this._generateLocal(code, context);
            }

            const data = await response.json();
            const name = data.choices?.[0]?.message?.content?.trim();

            if (name && /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(name)) {
                if (this.usedNames.has(name)) {
                    return this._uniqueName(name, 'ai');
                }
                this.usedNames.add(name);
                return name;
            }

            return this._generateLocal(code, context);
        } catch (e) {
            console.warn('[AI] Error calling OpenAI:', e.message);
            return this._generateLocal(code, context);
        }
    }

    _buildPrompt(code, context) {
        let prompt = `Analyze this JavaScript function and suggest a descriptive name:\n\n`;
        
        if (context.originalName) {
            prompt += `Original obfuscated name: ${context.originalName}\n`;
        }
        if (context.params) {
            prompt += `Parameters: ${context.params.join(', ')}\n`;
        }
        
        prompt += `\nCode:\n${code.slice(0, 500)}\n\n`;
        prompt += `Suggest a single function name (camelCase, max 25 chars):`;
        
        return prompt;
    }

    /**
     * Batch rename multiple functions
     */
    async batchRename(functions) {
        const results = new Map();

        for (const func of functions) {
            if (this._shouldRename(func.name)) {
                const newName = await this.generateFunctionName(func.body, {
                    originalName: func.name,
                    params: func.params
                });
                results.set(func.name, newName);
            }
        }

        return results;
    }

    _shouldRename(name) {
        // Rename obfuscated-looking names
        if (/^_0x[a-f0-9]+$/i.test(name)) return true;
        if (/^[a-z]$/.test(name)) return true;
        if (/^__\w+$/.test(name)) return true;
        if (/^[_$]{2,}/.test(name)) return true;
        if (/^[a-zA-Z]{1,2}\d+$/.test(name)) return true;
        return false;
    }

    /**
     * Analyze code and suggest deobfuscation strategy
     */
    async analyzeCode(code) {
        if (this.options.provider === 'openai' && this.options.apiKey) {
            return this._analyzeWithOpenAI(code);
        }
        return this._analyzeLocal(code);
    }

    _analyzeLocal(code) {
        const analysis = {
            techniques: [],
            complexity: 'low',
            suggestedApproach: [],
            estimatedDifficulty: 1
        };

        // Detect techniques
        if (/_0x[a-f0-9]+/i.test(code)) {
            analysis.techniques.push('variable-obfuscation');
        }
        if (/\['[a-zA-Z]+'\]/g.test(code)) {
            analysis.techniques.push('bracket-notation');
        }
        if (/atob\(|btoa\(/g.test(code)) {
            analysis.techniques.push('base64-encoding');
        }
        if (/\\x[0-9a-f]{2}/gi.test(code)) {
            analysis.techniques.push('hex-encoding');
        }
        if (/eval\(|Function\(/g.test(code)) {
            analysis.techniques.push('dynamic-execution');
        }
        if (/while\s*\(\s*!?!?\s*[01]\s*\)\s*\{\s*switch/g.test(code)) {
            analysis.techniques.push('control-flow-flattening');
        }

        // Estimate complexity
        const score = analysis.techniques.length;
        if (score >= 5) {
            analysis.complexity = 'critical';
            analysis.estimatedDifficulty = 5;
        } else if (score >= 3) {
            analysis.complexity = 'high';
            analysis.estimatedDifficulty = 4;
        } else if (score >= 2) {
            analysis.complexity = 'medium';
            analysis.estimatedDifficulty = 3;
        } else {
            analysis.complexity = 'low';
            analysis.estimatedDifficulty = 2;
        }

        // Suggest approach
        if (analysis.techniques.includes('control-flow-flattening')) {
            analysis.suggestedApproach.push('Apply control flow deobfuscation first');
        }
        if (analysis.techniques.includes('dynamic-execution')) {
            analysis.suggestedApproach.push('Use sandboxed evaluation for eval/Function');
        }
        if (analysis.techniques.includes('base64-encoding')) {
            analysis.suggestedApproach.push('Decode base64 strings');
        }

        return analysis;
    }

    async _analyzeWithOpenAI(code) {
        // Use local for now to avoid rate limits
        // Can be extended to use OpenAI for complex analysis
        return this._analyzeLocal(code);
    }

    /**
     * Reset used names (for new file)
     */
    reset() {
        this.usedNames.clear();
        this.counter = {};
    }
}

// ============================================================================
// SECTION 4: ML-LIKE PATTERN CLASSIFIER
// ============================================================================

class PatternClassifier {
    constructor(patternDb) {
        this.db = patternDb;
        this.cache = new Map();
    }

    /**
     * Classify code and return confidence scores for each obfuscator
     */
    classify(code) {
        const cacheKey = this._hashCode(code.slice(0, 1000));
        if (this.cache.has(cacheKey)) {
            return this.cache.get(cacheKey);
        }

        const results = {
            obfuscators: {},
            bundlers: {},
            encodings: {},
            sourcemaps: {},
            anti_debug: {},
            topMatch: null,
            confidence: 0
        };

        const patterns = this.db.getAllPatterns();

        for (const pattern of patterns) {
            try {
                const regex = pattern.type === 'literal' 
                    ? new RegExp(this._escapeRegex(pattern.pattern), pattern.caseSensitive === false ? 'gi' : 'g')
                    : new RegExp(pattern.pattern, 'g');

                const matches = code.match(regex);
                if (matches) {
                    const category = pattern.category;
                    const name = pattern.name;
                    
                    if (!results[category]) results[category] = {};
                    if (!results[category][name]) {
                        results[category][name] = {
                            score: 0,
                            matchCount: 0,
                            patterns: [],
                            handler: pattern.handler
                        };
                    }

                    results[category][name].score += pattern.weight * matches.length;
                    results[category][name].matchCount += matches.length;
                    results[category][name].patterns.push(pattern.pattern);
                }
            } catch (e) {
                // Invalid regex, skip
            }
        }

        // Normalize scores and find top match
        let topScore = 0;
        let topMatch = null;

        for (const [category, entries] of Object.entries(results)) {
            if (typeof entries !== 'object' || category === 'topMatch' || category === 'confidence') continue;
            
            for (const [name, data] of Object.entries(entries)) {
                // Normalize score to 0-1 range
                data.confidence = Math.min(1, data.score / 10);
                
                if (data.score > topScore) {
                    topScore = data.score;
                    topMatch = { category, name, ...data };
                }
            }
        }

        results.topMatch = topMatch;
        results.confidence = topMatch ? topMatch.confidence : 0;

        this.cache.set(cacheKey, results);
        return results;
    }

    /**
     * Get recommended deobfuscation stages
     */
    getRecommendedStages(classification) {
        const stages = new Set();
        const handlers = new Set();

        for (const [category, entries] of Object.entries(classification)) {
            if (typeof entries !== 'object' || category === 'topMatch' || category === 'confidence') continue;
            
            for (const [name, data] of Object.entries(entries)) {
                if (data.confidence > 0.3 && data.handler) {
                    handlers.add(data.handler);
                }
            }
        }

        // Map handlers to stages
        const handlerStageMap = {
            'obfuscator_io': ['decodeStringArray', 'inlineStrings', 'simplifyExpressions'],
            'jscrambler': ['decodeJScrambler', 'decryptXOR'],
            'webpack': ['unpackWebpack'],
            'rollup': ['unpackRollup'],
            'parcel': ['unpackParcel'],
            'browserify': ['unpackBrowserify'],
            'esoteric': ['decodeEsoteric'],
            'string': ['decodeStrings', 'decodeHex', 'decodeUnicode'],
            'crypto': ['decryptXOR', 'decryptRC4'],
            'anti_debug': ['removeAntiDebug'],
            'beautify': ['beautify']
        };

        for (const handler of handlers) {
            const stagesForHandler = handlerStageMap[handler] || [];
            stagesForHandler.forEach(s => stages.add(s));
        }

        // Always add beautify
        stages.add('beautify');

        return Array.from(stages);
    }

    _hashCode(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(16);
    }

    _escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
}

// ============================================================================
// SECTION 5: INTEGRATED AI/ML ENGINE
// ============================================================================

class JShadowAI {
    constructor(options = {}) {
        this.options = {
            dbPath: options.dbPath || './patterns.json',
            openaiKey: options.openaiKey || process.env.OPENAI_API_KEY,
            useOpenAI: options.useOpenAI || false,
            model: options.model || 'gpt-4o-mini',
            verbose: options.verbose || false,
            ...options
        };

        // Initialize components
        this.patternDb = new PatternDatabase(this.options.dbPath);
        this.sourcemapDetector = new SourcemapDetector();
        this.aiEngine = new AIEngine({
            provider: this.options.useOpenAI ? 'openai' : 'local',
            apiKey: this.options.openaiKey,
            model: this.options.model
        });
        this.classifier = new PatternClassifier(this.patternDb);
    }

    log(msg) {
        if (this.options.verbose) {
            console.log(`[AI] ${msg}`);
        }
    }

    /**
     * Full analysis of code
     */
    async analyze(code) {
        this.log('Starting AI analysis...');
        
        const startTime = Date.now();
        const results = {
            classification: null,
            sourcemaps: null,
            aiAnalysis: null,
            recommendedStages: [],
            fingerprint: null
        };

        // 1. Classify using pattern database
        this.log('Running pattern classification...');
        results.classification = this.classifier.classify(code);

        // 2. Detect sourcemaps
        this.log('Detecting sourcemaps...');
        results.sourcemaps = this.sourcemapDetector.detect(code);

        // 3. AI analysis
        this.log('Running AI analysis...');
        results.aiAnalysis = await this.aiEngine.analyzeCode(code);

        // 4. Get recommended stages
        results.recommendedStages = this.classifier.getRecommendedStages(results.classification);

        // 5. Generate fingerprint
        results.fingerprint = this._generateFingerprint(code);

        results.analysisTime = Date.now() - startTime;
        
        this.log(`Analysis complete in ${results.analysisTime}ms`);
        return results;
    }

    /**
     * Rename functions using AI
     */
    async renameFunctions(functions) {
        this.log(`Renaming ${functions.length} functions...`);
        return this.aiEngine.batchRename(functions);
    }

    /**
     * Learn from deobfuscation result
     */
    learn(originalCode, deobfuscatedCode, success) {
        const classification = this.classifier.classify(originalCode);
        const obfuscatorName = classification.topMatch?.name || 'unknown';
        
        // Extract new patterns from successful deobfuscation
        const newPatterns = [];
        if (success && deobfuscatedCode) {
            // Find patterns that appear in original but not in deobfuscated
            const origPatterns = this._extractPatterns(originalCode);
            const deobPatterns = this._extractPatterns(deobfuscatedCode);
            
            for (const p of origPatterns) {
                if (!deobPatterns.has(p) && p.length > 10) {
                    newPatterns.push(p);
                }
            }
        }

        this.patternDb.learn(originalCode, obfuscatorName, success, newPatterns);
        
        if (success) {
            this.log(`Learned ${newPatterns.length} new patterns from successful deobfuscation`);
        }
    }

    /**
     * Save pattern database
     */
    save() {
        this.patternDb.save();
        this.log('Pattern database saved');
    }

    /**
     * Get statistics
     */
    getStats() {
        return this.patternDb.getStats();
    }

    /**
     * Add custom pattern
     */
    addPattern(category, name, pattern, weight = 0.5) {
        return this.patternDb.addPattern(category, name, pattern, weight);
    }

    /**
     * Export database
     */
    exportDatabase() {
        return this.patternDb.export();
    }

    /**
     * Import database
     */
    importDatabase(jsonData) {
        return this.patternDb.import(jsonData);
    }

    _generateFingerprint(code) {
        const normalized = code
            .replace(/\s+/g, ' ')
            .replace(/_0x[a-f0-9]+/gi, '_VAR_')
            .replace(/['"][^'"]{1,50}['"]/g, '_STR_')
            .slice(0, 1000);
        
        return crypto.createHash('md5').update(normalized).digest('hex').slice(0, 16);
    }

    _extractPatterns(code) {
        const patterns = new Set();
        
        // Extract potential patterns
        const regexes = [
            /_0x[a-f0-9]+/gi,
            /\[['"][a-zA-Z]+['"]\]/g,
            /\\x[0-9a-f]{2}/gi,
            /\\u[0-9a-f]{4}/gi
        ];

        for (const regex of regexes) {
            const matches = code.match(regex);
            if (matches) {
                matches.forEach(m => patterns.add(m));
            }
        }

        return patterns;
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
    // Main integrated engine
    JShadowAI,
    
    // Individual components
    PatternDatabase,
    SourcemapDetector,
    AIEngine,
    PatternClassifier,
    
    // Factory function
    createAI: (options = {}) => new JShadowAI(options)
};

// CLI usage example
if (require.main === module) {
    const fs = require('fs');
    
    async function demo() {
        console.log('🧠 J-Shadow AI/ML Pattern Engine Demo\n');
        
        const ai = new JShadowAI({ verbose: true });
        
        // Example obfuscated code
        const testCode = `
            var _0x1234 = ['log', 'Hello'];
            console[_0x1234[0]](_0x1234[1]);
            eval(atob("Y29uc29sZS5sb2coJ3Rlc3QnKQ=="));
            //# sourceMappingURL=app.js.map
        `;
        
        console.log('Analyzing test code...\n');
        const analysis = await ai.analyze(testCode);
        
        console.log('=== CLASSIFICATION ===');
        console.log('Top Match:', analysis.classification.topMatch?.name || 'None');
        console.log('Confidence:', (analysis.classification.confidence * 100).toFixed(1) + '%');
        
        console.log('\n=== SOURCEMAPS ===');
        console.log('Found:', analysis.sourcemaps.found);
        if (analysis.sourcemaps.found) {
            console.log('Types:', analysis.sourcemaps.types.join(', '));
        }
        
        console.log('\n=== RECOMMENDED STAGES ===');
        console.log(analysis.recommendedStages.join(' → '));
        
        console.log('\n=== STATISTICS ===');
        console.log(ai.getStats());
    }
    
    demo().catch(console.error);
}
