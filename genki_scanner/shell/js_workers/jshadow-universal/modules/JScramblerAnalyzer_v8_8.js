/**
 * J-SHADOW V8 ULTIMATE - FULLY DYNAMIC JSCRAMBLER ANALYZER
 * Now handles advanced anti-debugging and domain lock variants!
 * @version 8.8.0 ULTIMATE
 */

const { JSDOM } = require('jsdom');
const fs = require('fs');

class JScramblerDynamic {
    constructor(options = {}) {
        this.options = {
            timeout: options.timeout || 5000,
            verbose: options.verbose !== false,
            maxIndex: options.maxIndex || 80,
            ...options
        };
        this.reset();
    }

    reset() {
        this.namespace = null;
        this.decoderFunctions = [];
        this.decoderMappings = {};
        this.dataStructures = {};
        this.propertyNames = new Set();
        this.extractedStrings = [];
        this.errors = [];
    }

    log(msg) {
        if (this.options.verbose) console.log(msg);
    }

    async analyze(code) {
        this.reset();
        
        this.log('\n╔══════════════════════════════════════════════════════════════╗');
        this.log('║   🔥 J-SHADOW V8.8 ULTIMATE - FULLY DYNAMIC 🔥               ║');
        this.log('║   Handles anti-debug + domain lock variants!                 ║');
        this.log('╚══════════════════════════════════════════════════════════════╝\n');
        this.log(`📊 Input: ${code.length} bytes\n`);

        // Detect variant type
        const variantType = this._detectVariant(code);
        this.log(`[✓] Variant: ${variantType}`);

        this._detectNamespace(code);
        if (!this.namespace) {
            this.log('❌ Could not detect namespace');
            return { success: false, error: 'No namespace detected' };
        }
        this.log(`[✓] Namespace: ${this.namespace}`);

        // Try static extraction first for anti-debug variants
        if (variantType === 'ANTI_DEBUG' || variantType === 'DOMAIN_LOCK') {
            this.log('\n━━━ PHASE 1: Static String Extraction ━━━\n');
            this._staticExtraction(code);
        }

        this.log('\n━━━ PHASE 2: Dynamic Discovery ━━━\n');
        await this._executeAndDiscover(code, variantType);

        this.log('\n━━━ PHASE 3: Data Analysis ━━━\n');
        this._analyzeData();

        return this._buildResult(variantType);
    }

    _detectVariant(code) {
        // Check for anti-debug eval chains
        if (code.includes('eval(') && code.includes('D1RXhaS')) {
            return 'ANTI_DEBUG';
        }
        // Check for domain lock patterns
        if (code.includes('[189638]') || code.includes('globalThis')) {
            return 'DOMAIN_LOCK';
        }
        // Check for standard string decoder
        if (code.match(/\.f\s*=\s*\(function/)) {
            return 'STRING_DECODER';
        }
        return 'UNKNOWN';
    }

    _staticExtraction(code) {
        // Extract encoded strings from the code statically
        const stringMatches = code.match(/%[0-9A-Fa-f]{2}[^"'`]*/g) || [];
        const decodedStrings = [];
        
        for (const match of stringMatches.slice(0, 50)) {
            try {
                const decoded = decodeURIComponent(match);
                if (decoded.length > 3 && decoded.length < 200) {
                    decodedStrings.push(decoded);
                }
            } catch (e) {}
        }
        
        // Extract base64 strings
        const b64Matches = code.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || [];
        for (const match of b64Matches.slice(0, 20)) {
            try {
                const decoded = Buffer.from(match, 'base64').toString();
                if (decoded.length > 3 && /^[\x20-\x7E]+$/.test(decoded)) {
                    decodedStrings.push(decoded);
                }
            } catch (e) {}
        }

        // Extract hex-encoded strings
        const hexMatches = code.match(/\\x[0-9a-fA-F]{2}/g) || [];
        if (hexMatches.length > 0) {
            let hexStr = '';
            for (const h of hexMatches) {
                hexStr += String.fromCharCode(parseInt(h.slice(2), 16));
            }
            if (hexStr.length > 3) {
                decodedStrings.push(hexStr.slice(0, 200));
            }
        }

        this.extractedStrings = [...new Set(decodedStrings)];
        this.log(`[✓] Extracted ${this.extractedStrings.length} strings statically`);
        
        if (this.extractedStrings.length > 0) {
            this.log(`    Sample: "${this.extractedStrings[0].slice(0, 60)}..."`);
        }
    }

    _detectNamespace(code) {
        const patterns = [
            /([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\[189638\]/,  // Domain lock pattern
            /([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\.f\s*=\s*\(function/,
            /([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\.(P0|S5|P5|Q8)\s*[=(]/,
            /function\s+([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\s*\(\s*\)\s*\{\s*\}/,
        ];

        for (const p of patterns) {
            const m = code.match(p);
            if (m) { this.namespace = m[1]; return; }
        }

        // Fallback: frequency analysis
        const idCounts = {};
        const matches = code.matchAll(/([a-zA-Z_$][a-zA-Z0-9_$]{3,7})\./g);
        for (const m of matches) {
            idCounts[m[1]] = (idCounts[m[1]] || 0) + 1;
        }
        
        let maxCount = 0;
        for (const [id, count] of Object.entries(idCounts)) {
            if (count > maxCount && count > 50) {
                maxCount = count;
                this.namespace = id;
            }
        }
    }

    async _executeAndDiscover(code, variantType) {
        try {
            this.log('[1] Creating JSDOM sandbox with full browser stubs...');
            
            const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
                url: 'https://example.com',
                runScripts: 'dangerously',
                pretendToBeVisual: true,
            });

            const window = dom.window;
            
            // === COMPREHENSIVE BROWSER STUBS ===
            const browserStubs = `
                (function() {
                    // Storage stubs
                    var createStorage = function() {
                        var store = {};
                        return {
                            getItem: function(k) { return store[k] || null; },
                            setItem: function(k, v) { store[k] = String(v); },
                            removeItem: function(k) { delete store[k]; },
                            clear: function() { store = {}; },
                            get length() { return Object.keys(store).length; },
                            key: function(i) { return Object.keys(store)[i] || null; }
                        };
                    };
                    try { if (!window.localStorage) window.localStorage = createStorage(); } catch(e) {}
                    try { if (!window.sessionStorage) window.sessionStorage = createStorage(); } catch(e) {}
                    
                    // Crypto stubs
                    try {
                        if (!window.crypto) {
                            window.crypto = {
                                getRandomValues: function(arr) {
                                    for (var i = 0; i < arr.length; i++) {
                                        arr[i] = Math.floor(Math.random() * 256);
                                    }
                                    return arr;
                                }
                            };
                        }
                    } catch(e) {}
                    
                    // Performance stubs
                    try {
                        if (!window.performance) {
                            window.performance = {
                                now: function() { return Date.now(); },
                                timing: { navigationStart: Date.now() }
                            };
                        }
                    } catch(e) {}
                    
                    // Console stubs to prevent errors
                    window.console = window.console || {};
                    window.console.log = window.console.log || function(){};
                    window.console.warn = window.console.warn || function(){};
                    window.console.error = window.console.error || function(){};
                    window.console.debug = window.console.debug || function(){};
                    
                    // Prevent anti-debug detection
                    window.T4mf0 = {};
                    
                    // globalThis stub
                    if (typeof globalThis === 'undefined') {
                        window.globalThis = window;
                    }
                })();
            `;

            const ns = this.namespace;
            const maxIdx = this.options.maxIndex;

            window.__CAPTURE__ = {
                decoders: {},
                decoderFuncs: [],
                structures: {},
                errors: [],
                methods: [],
            };

            // For anti-debug variants, we wrap everything in try-catch
            const discoveryCode = `
(function() {
    var checkCount = 0;
    var maxChecks = 600;
    
    var interval = setInterval(function() {
        checkCount++;
        if (checkCount > maxChecks) {
            clearInterval(interval);
            return;
        }
        
        try {
            var ns = (typeof ${ns} !== 'undefined') ? ${ns} : null;
            if (!ns) return;
            
            // Capture all methods on namespace
            for (var prop in ns) {
                if (typeof ns[prop] === 'function') {
                    window.__CAPTURE__.methods.push(prop);
                }
            }
            
            // Look for short function names (likely decoders)
            var foundDecoders = [];
            for (var prop in ns) {
                if (typeof ns[prop] === 'function' && !prop.startsWith('__') && prop.length <= 3) {
                    try {
                        var testResult = ns[prop](0);
                        if (typeof testResult === 'string' && testResult.length < 100) {
                            var isDecoder = true;
                            var results = [testResult];
                            
                            for (var i = 1; i <= 5; i++) {
                                try {
                                    var r = ns[prop](i);
                                    if (typeof r !== 'string') {
                                        isDecoder = false;
                                        break;
                                    }
                                    results.push(r);
                                } catch(e) {}
                            }
                            
                            if (isDecoder && results.length >= 2) {
                                foundDecoders.push(prop);
                                window.__CAPTURE__.decoderFuncs.push(prop);
                            }
                        }
                    } catch(e) {}
                }
            }
            
            if (foundDecoders.length === 0 && checkCount < maxChecks) return;
            clearInterval(interval);
            
            // Hook decoders
            foundDecoders.forEach(function(funcName) {
                if (ns['__hooked_' + funcName]) return;
                ns['__hooked_' + funcName] = true;
                
                try {
                    var orig = ns[funcName];
                    ns[funcName] = function(idx) {
                        try {
                            var result = orig.apply(this, arguments);
                            window.__CAPTURE__.decoders[funcName + '(' + idx + ')'] = result;
                            return result;
                        } catch(e) { throw e; }
                    };
                    
                    for (var i = 0; i <= ${maxIdx}; i++) {
                        try { ns[funcName](i); } catch(e) {}
                    }
                } catch(e) {}
            });
            
            // Scan for data structures
            setTimeout(function() {
                for (var key in window) {
                    if (key.startsWith('__') || key === 'window' || key === 'document') continue;
                    try {
                        var val = window[key];
                        if (val && typeof val === 'object' && !Array.isArray(val) && val.constructor === Object) {
                            var keys = Object.keys(val);
                            if (keys.length > 0 && keys.length < 200) {
                                var hasNestedNumeric = false;
                                for (var k of keys.slice(0, 10)) {
                                    if (typeof val[k] === 'object' && val[k] !== null) {
                                        for (var p in val[k]) {
                                            if (typeof val[k][p] === 'number') {
                                                hasNestedNumeric = true;
                                                break;
                                            }
                                        }
                                    }
                                    if (hasNestedNumeric) break;
                                }
                                
                                if (hasNestedNumeric) {
                                    try { window.__CAPTURE__.structures[key] = JSON.parse(JSON.stringify(val)); } catch(e) {}
                                }
                            }
                        }
                    } catch(e) {}
                }
            }, 1500);
            
        } catch(e) {
            window.__CAPTURE__.errors.push(e.message);
        }
    }, 10);
})();
`;

            this.log('[2] Injecting stubs and code...');
            
            // Inject stubs first
            const stubScript = window.document.createElement('script');
            stubScript.textContent = browserStubs;
            window.document.body.appendChild(stubScript);

            // Suppress errors during execution
            const originalError = console.error;
            const capturedErrors = [];
            console.error = (...args) => {
                const msg = args.join(' ');
                if (!msg.includes('TypeError') && !msg.includes('ReferenceError')) {
                    capturedErrors.push(msg);
                }
            };
            
            // Inject the obfuscated code wrapped in try-catch
            const wrappedCode = `
                try {
                    ${code}
                } catch(e) {
                    window.__CAPTURE__.errors.push('Main code error: ' + e.message);
                }
            `;
            
            const mainScript = window.document.createElement('script');
            mainScript.textContent = wrappedCode + '\n' + discoveryCode;
            window.document.body.appendChild(mainScript);

            await new Promise(resolve => setTimeout(resolve, this.options.timeout));

            console.error = originalError;

            this.decoderFunctions = window.__CAPTURE__?.decoderFuncs || [];
            this.decoderMappings = window.__CAPTURE__?.decoders || {};
            this.dataStructures = window.__CAPTURE__?.structures || {};
            this.errors = window.__CAPTURE__?.errors || [];
            
            const methods = window.__CAPTURE__?.methods || [];

            this.log(`[3] Discovery results:`);
            this.log(`    - Namespace methods: ${methods.length}`);
            this.log(`    - Decoder functions: ${this.decoderFunctions.length} [${this.decoderFunctions.join(', ')}]`);
            this.log(`    - Decoder mappings: ${Object.keys(this.decoderMappings).length}`);
            this.log(`    - Data structures: ${Object.keys(this.dataStructures).length}`);
            
            if (this.errors.length > 0) {
                this.log(`    - Errors captured: ${this.errors.length}`);
                this.log(`    - Sample: ${this.errors[0]?.slice(0, 80)}...`);
            }

            dom.window.close();

        } catch (e) {
            this.log(`[!] Runtime Error: ${e.message}`);
            this.errors.push(e.message);
        }
    }

    _analyzeData() {
        const valueRanges = {};

        for (const [structName, struct] of Object.entries(this.dataStructures)) {
            this.log(`\n📦 ${structName}: ${Object.keys(struct).length} objects`);
            
            for (const [objName, obj] of Object.entries(struct)) {
                if (typeof obj !== 'object' || obj === null) continue;
                for (const [prop, val] of Object.entries(obj)) {
                    this.propertyNames.add(prop);
                    if (typeof val === 'number') {
                        if (!valueRanges[prop]) valueRanges[prop] = { min: Infinity, max: -Infinity };
                        valueRanges[prop].min = Math.min(valueRanges[prop].min, val);
                        valueRanges[prop].max = Math.max(valueRanges[prop].max, val);
                    }
                }
            }
        }

        if (Object.keys(valueRanges).length > 0) {
            this.log(`\n📋 Property Ranges:`);
            for (const [prop, range] of Object.entries(valueRanges)) {
                this.log(`    ${prop}: ${range.min} - ${range.max}`);
            }
        }
    }

    _buildResult(variantType) {
        const cleanCode = this._generateOutput(variantType);
        
        return {
            success: this.extractedStrings.length > 0 || 
                     Object.keys(this.dataStructures).length > 0 || 
                     Object.keys(this.decoderMappings).length > 0,
            variant: variantType,
            namespace: this.namespace,
            decoderFunctions: this.decoderFunctions,
            decoderMappings: this.decoderMappings,
            dataStructures: this.dataStructures,
            extractedStrings: this.extractedStrings,
            errors: this.errors,
            deobfuscatedCode: cleanCode,
            stats: {
                decoderFunctions: this.decoderFunctions.length,
                decoderMappings: Object.keys(this.decoderMappings).length,
                structures: Object.keys(this.dataStructures).length,
                extractedStrings: this.extractedStrings.length,
                errors: this.errors.length
            }
        };
    }

    _generateOutput(variantType) {
        let output = `/**\n * DEOBFUSCATED BY J-SHADOW V8.8 ULTIMATE\n * Variant: ${variantType}\n * Namespace: ${this.namespace}\n */\n\n`;

        // Output extracted strings
        if (this.extractedStrings.length > 0) {
            output += '// === EXTRACTED STRINGS ===\n';
            output += 'var EXTRACTED_STRINGS = [\n';
            for (const str of this.extractedStrings.slice(0, 100)) {
                const escaped = str.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
                output += `  "${escaped}",\n`;
            }
            output += '];\n\n';
        }

        // Output decoder mappings
        if (Object.keys(this.decoderMappings).length > 0) {
            output += '// === DECODER MAPPINGS ===\n';
            output += 'var DECODED = {\n';
            for (const [call, result] of Object.entries(this.decoderMappings)) {
                const escaped = String(result).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
                output += `  "${call}": "${escaped}",\n`;
            }
            output += '};\n\n';
        }

        // Output data structures
        if (Object.keys(this.dataStructures).length > 0) {
            output += '// === DATA STRUCTURES ===\n';
            for (const [structName, struct] of Object.entries(this.dataStructures)) {
                output += `var ${structName} = {\n`;
                for (const [objName, obj] of Object.entries(struct)) {
                    if (typeof obj !== 'object' || obj === null) continue;
                    const props = Object.entries(obj)
                        .map(([p, v]) => typeof v === 'number' ? `${p}: ${v}` : `${p}: "${v}"`)
                        .join(', ');
                    output += `  "${objName}": { ${props} },\n`;
                }
                output += '};\n\n';
            }
        }

        // Output errors if any
        if (this.errors.length > 0) {
            output += '// === EXECUTION NOTES ===\n';
            output += '// The following errors occurred during analysis:\n';
            for (const err of this.errors.slice(0, 5)) {
                output += `// - ${err.slice(0, 100)}\n`;
            }
            output += '\n';
        }

        if (output.trim() === `/**\n * DEOBFUSCATED BY J-SHADOW V8.8 ULTIMATE\n * Variant: ${variantType}\n * Namespace: ${this.namespace}\n */`) {
            output += '// No data extracted - this variant uses anti-debug that crashed in JSDOM\n';
            output += '// Recommendation: Try browser-based extraction or manual analysis\n';
        }

        return output;
    }
}

module.exports = { JScramblerDynamic };

if (require.main === module) {
    const args = process.argv.slice(2);
    const inputFile = args.find(a => !a.startsWith('-'));
    const quiet = args.includes('-q');
    let timeout = 5000;
    const tIdx = args.indexOf('-t');
    if (tIdx !== -1) timeout = parseInt(args[tIdx + 1]) || 5000;
    let outputFile = null;
    const oIdx = args.indexOf('-o');
    if (oIdx !== -1) outputFile = args[oIdx + 1];

    if (!inputFile || !fs.existsSync(inputFile)) {
        console.log('Usage: node JScramblerDynamic.js <input.js> [-o out.js] [-t 8000]');
        process.exit(1);
    }

    const code = fs.readFileSync(inputFile, 'utf8');
    new JScramblerDynamic({ verbose: !quiet, timeout }).analyze(code).then(result => {
        console.log('\n═══════════════════════════════════════════════════════════════');
        console.log('🎯 DEOBFUSCATED OUTPUT:');
        console.log('═══════════════════════════════════════════════════════════════\n');
        console.log(result.deobfuscatedCode);
        console.log('═══════════════════════════════════════════════════════════════');
        console.log(`📊 Stats: ${result.stats.decoderFunctions} decoders, ${result.stats.decoderMappings} mappings, ${result.stats.extractedStrings} strings extracted`);
        console.log(`🔍 Variant: ${result.variant}`);
        if (result.errors.length > 0) {
            console.log(`⚠️  Errors: ${result.errors.length} (code uses anti-debug)`);
        }
        if (outputFile) { fs.writeFileSync(outputFile, result.deobfuscatedCode); console.log(`\n✅ Saved: ${outputFile}`); }
    });
}
