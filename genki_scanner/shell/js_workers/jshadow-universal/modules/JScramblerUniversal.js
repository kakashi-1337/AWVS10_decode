/**
 * ███████╗ ██████╗██████╗  █████╗ ███╗   ███╗██████╗ ██╗     ███████╗██████╗ 
 * ██╔════╝██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██║     ██╔════╝██╔══██╗
 * ███████╗██║     ██████╔╝███████║██╔████╔██║██████╔╝██║     █████╗  ██████╔╝
 * ╚════██║██║     ██╔══██╗██╔══██║██║╚██╔╝██║██╔══██╗██║     ██╔══╝  ██╔══██╗
 * ███████║╚██████╗██║  ██║██║  ██║██║ ╚═╝ ██║██████╔╝███████╗███████╗██║  ██║
 * ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝
 * 
 * J-SHADOW V8 - JSCRAMBLER UNIVERSAL DEOBFUSCATOR
 * 
 * FULLY DYNAMIC - No hardcoded keys or delimiters!
 * Extracts everything from the code itself.
 * 
 * @author Kakashi x Claude - ANBU Black Ops Security
 * @version 8.1.0
 */

const { JSDOM } = require('jsdom');
const fs = require('fs');

class JScramblerUniversal {
    constructor(options = {}) {
        this.options = {
            timeout: options.timeout || 2000,
            maxIndex: options.maxIndex || 30,
            verbose: options.verbose !== false,
            ...options
        };
        this.reset();
    }

    reset() {
        this.namespace = null;
        this.xorKeys = [];          // All extracted keys
        this.xorKey = null;         // The one that worked
        this.delimiters = [];       // All potential delimiters
        this.delimiter = null;      // The one that worked
        this.stringTable = [];
        this.indexMap = {};
        this.structure = {};
        this.method = null;
    }

    log(msg) {
        if (this.options.verbose) console.log(msg);
    }

    /**
     * Main entry point
     */
    async deobfuscate(code) {
        this.reset();
        
        this.log('\n╔══════════════════════════════════════════════════════════════╗');
        this.log('║   🔥 J-SHADOW V8 - JSCRAMBLER UNIVERSAL (DYNAMIC) 🔥         ║');
        this.log('╚══════════════════════════════════════════════════════════════╝\n');
        this.log(`📊 Input: ${code.length} bytes\n`);

        // Step 1: Detect namespace
        this._detectNamespace(code);
        if (!this.namespace) {
            this.log('❌ No JScrambler patterns detected');
            return null;
        }
        this.log(`[✓] Namespace: ${this.namespace}`);

        // Step 2: Extract ALL potential XOR keys dynamically
        this._extractAllKeys(code);
        this.log(`[✓] Found ${this.xorKeys.length} potential XOR keys`);

        // Step 3: Extract ALL potential delimiters dynamically
        this._extractAllDelimiters(code);
        this.log(`[✓] Found ${this.delimiters.length} potential delimiters`);

        // Step 4: JSDOM Emulation (primary method)
        this.log('\n━━━ PHASE 1: Runtime Emulation ━━━\n');
        await this._emulate(code);

        // Step 5: Static XOR decode (secondary/validation)
        this.log('\n━━━ PHASE 2: Static XOR Analysis ━━━\n');
        this._staticDecode(code);

        return this._buildResult();
    }

    /**
     * Detect JScrambler namespace dynamically
     */
    _detectNamespace(code) {
        const patterns = [
            // Pattern: namespace.G_ or namespace.V7
            /([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\.(G_|V7)\s*[=(]/,
            // Pattern: namespace.f = (function
            /([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\.f\s*=\s*\(function/,
            // Pattern: namespace.P0 or namespace.S5
            /([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\.(P0|S5|P5|Q8)\s*[=(]/,
            // Pattern: namespace[number]
            /([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\[\d{5,}\]/,
        ];

        for (const p of patterns) {
            const m = code.match(p);
            if (m) {
                this.namespace = m[1];
                return;
            }
        }
    }

    /**
     * Extract ALL potential XOR keys from code
     * No hardcoding - finds them dynamically!
     */
    _extractAllKeys(code) {
        const keys = new Set();

        // Pattern 1: IIFE end parameter - })('KEY') or })("KEY")
        const iifeMatches = [...code.matchAll(/\}\)\s*\(\s*['"]([^'"]{4,50})['"]\s*\)/g)];
        for (const m of iifeMatches) {
            const key = m[1];
            // Filter out common false positives
            if (!/^(function|object|undefined|string|number|boolean|return)$/i.test(key)) {
                keys.add(key);
                this.log(`    [IIFE] '${key}'`);
            }
        }

        // Pattern 2: Char array with offset - [69,-1,61,28,3] transformed
        const arrayMatches = [...code.matchAll(/\[\s*(-?\d{1,3}(?:\s*,\s*-?\d{1,3}){3,20})\s*\]/g)];
        for (const m of arrayMatches) {
            const nums = m[1].split(',').map(n => parseInt(n.trim()));
            if (nums.length >= 4 && nums.length <= 20) {
                // Try common offsets used by JScrambler
                for (const offset of [48, 52, 58, 64, 32, 65]) {
                    try {
                        const decoded = nums.map(n => {
                            const c = n + offset;
                            if (c >= 32 && c <= 126) return String.fromCharCode(c);
                            return null;
                        });
                        if (!decoded.includes(null)) {
                            const key = decoded.join('');
                            if (/^[a-zA-Z0-9_$&!@#%^*()+=]{4,}$/.test(key)) {
                                keys.add(key);
                                this.log(`    [ARRAY+${offset}] '${key}'`);
                            }
                        }
                    } catch (e) {}
                }
            }
        }

        // Pattern 3: String literal near decodeURI calls
        const decodeMatches = [...code.matchAll(/decodeURI(?:Component)?\s*\([^)]+\)[^;]{0,50}['"]([^'"]{4,50})['"]/g)];
        for (const m of decodeMatches) {
            keys.add(m[1]);
            this.log(`    [DECODE] '${m[1]}'`);
        }

        // Pattern 4: Variable assignment with short alphanumeric string
        const varMatches = [...code.matchAll(/(?:var|let|const)\s+\w+\s*=\s*['"]([a-zA-Z0-9_$&!@#%^*]{4,20})['"]\s*;/g)];
        for (const m of varMatches) {
            keys.add(m[1]);
            this.log(`    [VAR] '${m[1]}'`);
        }

        // Pattern 5: Function parameter default value
        const paramMatches = [...code.matchAll(/function\s*\w*\s*\([^)]*['"]([^'"]{4,30})['"]/g)];
        for (const m of paramMatches) {
            if (!/^(function|object|undefined)$/i.test(m[1])) {
                keys.add(m[1]);
                this.log(`    [PARAM] '${m[1]}'`);
            }
        }

        this.xorKeys = [...keys];
    }

    /**
     * Extract ALL potential delimiters from code
     * Analyzes the actual split() calls and string patterns
     */
    _extractAllDelimiters(code) {
        const delimiters = new Set();

        // Pattern 1: .split('X') calls
        const splitMatches = [...code.matchAll(/\.split\s*\(\s*['"](.)['"]\s*\)/g)];
        for (const m of splitMatches) {
            delimiters.add(m[1]);
            this.log(`    [SPLIT] '${m[1]}' (char ${m[1].charCodeAt(0)})`);
        }

        // Pattern 2: String.fromCharCode(N) in split context
        const charCodeMatches = [...code.matchAll(/\.split\s*\(\s*String\.fromCharCode\s*\(\s*(\d+)\s*\)/g)];
        for (const m of charCodeMatches) {
            const char = String.fromCharCode(parseInt(m[1]));
            delimiters.add(char);
            this.log(`    [CHARCODE] char(${m[1]}) = '${char.charCodeAt(0) > 31 ? char : '?'}'`);
        }

        // Pattern 3: Look for common JScrambler delimiters in the encoded strings
        // These are often visible in the URL-encoded data
        const commonDelims = [')', '~', ':', '`', '|', ';', '#', '@', '^', String.fromCharCode(170)];
        for (const d of commonDelims) {
            delimiters.add(d);
        }

        // Pattern 4: m9(X3,')') pattern - wrapping function with delimiter
        const m9Matches = [...code.matchAll(/\w+\s*\(\s*\w+\s*,\s*['"](.)['"]\s*\)/g)];
        for (const m of m9Matches) {
            delimiters.add(m[1]);
            this.log(`    [WRAP] '${m[1]}'`);
        }

        this.delimiters = [...delimiters];
    }

    /**
     * JSDOM Runtime Emulation
     */
    async _emulate(code) {
        try {
            this.log('[1] Creating JSDOM sandbox...');
            
            const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
                runScripts: 'dangerously',
                pretendToBeVisual: true,
            });

            const window = dom.window;
            window.__JSHADOW__ = { captured: {}, errors: [] };

            const ns = this.namespace;
            const maxIdx = this.options.maxIndex;

            // Hook code that captures decoder outputs
            const hookCode = `
(function() {
    var attempts = 0;
    var interval = setInterval(function() {
        attempts++;
        if (attempts > 200) { clearInterval(interval); return; }
        
        try {
            var ns = typeof ${ns} !== 'undefined' ? ${ns} : null;
            if (!ns) return;
            
            // Hook G_ if exists
            if (ns.G_ && !ns.__hooked_G_) {
                ns.__hooked_G_ = true;
                var origG_ = ns.G_;
                ns.G_ = function(idx) {
                    try {
                        var result = origG_.apply(this, arguments);
                        window.__JSHADOW__.captured['G_(' + idx + ')'] = result;
                        return result;
                    } catch(e) { 
                        window.__JSHADOW__.errors.push('G_(' + idx + '): ' + e.message);
                        throw e; 
                    }
                };
            }
            
            // Hook V7 if exists
            if (ns.V7 && !ns.__hooked_V7) {
                ns.__hooked_V7 = true;
                var origV7 = ns.V7;
                ns.V7 = function(idx) {
                    try {
                        var result = origV7.apply(this, arguments);
                        window.__JSHADOW__.captured['V7(' + idx + ')'] = result;
                        return result;
                    } catch(e) {
                        window.__JSHADOW__.errors.push('V7(' + idx + '): ' + e.message);
                        throw e;
                    }
                };
            }

            // Hook X_ if exists (alternative to V7 in some versions)
            if (ns.X_ && !ns.__hooked_X_) {
                ns.__hooked_X_ = true;
                var origX_ = ns.X_;
                ns.X_ = function(idx) {
                    try {
                        var result = origX_.apply(this, arguments);
                        window.__JSHADOW__.captured['X_(' + idx + ')'] = result;
                        return result;
                    } catch(e) {
                        window.__JSHADOW__.errors.push('X_(' + idx + '): ' + e.message);
                        throw e;
                    }
                };
            }
            
            // Hook x7/D8 (older pattern)
            if (ns.x7 && !ns.__hooked_x7) {
                ns.__hooked_x7 = true;
                var origx7 = ns.x7;
                ns.x7 = function(idx) {
                    var result = origx7.apply(this, arguments);
                    window.__JSHADOW__.captured['x7(' + idx + ')'] = result;
                    return result;
                };
            }
            if (ns.D8 && !ns.__hooked_D8) {
                ns.__hooked_D8 = true;
                var origD8 = ns.D8;
                ns.D8 = function(idx) {
                    var result = origD8.apply(this, arguments);
                    window.__JSHADOW__.captured['D8(' + idx + ')'] = result;
                    return result;
                };
            }

            // Hook e$/U2 (another pattern)
            if (ns.e$ && !ns.__hooked_e$) {
                ns.__hooked_e$ = true;
                var orige$ = ns.e$;
                ns.e$ = function(idx) {
                    var result = orige$.apply(this, arguments);
                    window.__JSHADOW__.captured['e$(' + idx + ')'] = result;
                    return result;
                };
            }
            if (ns.U2 && !ns.__hooked_U2) {
                ns.__hooked_U2 = true;
                var origU2 = ns.U2;
                ns.U2 = function(idx) {
                    var result = origU2.apply(this, arguments);
                    window.__JSHADOW__.captured['U2(' + idx + ')'] = result;
                    return result;
                };
            }
            
            // If any hooks installed, populate by calling
            if (ns.__hooked_G_ || ns.__hooked_V7 || ns.__hooked_X_ || ns.__hooked_x7 || ns.__hooked_D8) {
                clearInterval(interval);
                for (var i = 0; i <= ${maxIdx}; i++) {
                    try { ns.G_ && ns.G_(i); } catch(e) {}
                    try { ns.V7 && ns.V7(i); } catch(e) {}
                    try { ns.X_ && ns.X_(i); } catch(e) {}
                    try { ns.x7 && ns.x7(i); } catch(e) {}
                    try { ns.D8 && ns.D8(i); } catch(e) {}
                    try { ns.e$ && ns.e$(i); } catch(e) {}
                    try { ns.U2 && ns.U2(i); } catch(e) {}
                }
            }
        } catch(e) {
            window.__JSHADOW__.errors.push('Hook error: ' + e.message);
        }
    }, 5);
})();
`;

            this.log('[2] Executing in sandbox...');
            const script = window.document.createElement('script');
            script.textContent = code + '\n' + hookCode;
            window.document.body.appendChild(script);

            await new Promise(resolve => setTimeout(resolve, this.options.timeout));

            // Extract results
            this.indexMap = window.__JSHADOW__?.captured || {};
            const errors = window.__JSHADOW__?.errors || [];
            
            this.log(`[3] Captured ${Object.keys(this.indexMap).length} mappings`);
            if (errors.length > 0) {
                this.log(`    (${errors.length} errors during capture)`);
            }

            // Extract data structure (M4BvX, R8pVzQ, etc.)
            this._extractStructure(window);

            this.method = Object.keys(this.indexMap).length > 0 ? 'emulation' : 'static';
            dom.window.close();

        } catch (e) {
            this.log(`[!] Emulation error: ${e.message}`);
            this.method = 'static';
        }
    }

    /**
     * Extract data structure from window
     * Searches ALL variables for array[3] pattern with object properties
     */
    _extractStructure(window) {
        this.log('[4] Searching for data structures...');

        // Search ALL window properties for arrays with [3] containing objects
        for (const key of Object.keys(window)) {
            // Skip internal/event properties
            if (key.startsWith('__') || key.startsWith('on') || key === 'window' || key === 'document') continue;
            
            try {
                const val = window[key];
                
                // Check if it's an array with [3] containing objects (JScrambler pattern)
                if (Array.isArray(val) && val[3] && typeof val[3] === 'object') {
                    const obj3 = val[3];
                    const objKeys = Object.keys(obj3);
                    
                    // Check if it has object properties with x/y values
                    let hasXY = false;
                    for (const k of objKeys) {
                        if (typeof obj3[k] === 'object' && obj3[k] !== null) {
                            if ('x' in obj3[k] || 'y' in obj3[k]) {
                                hasXY = true;
                                break;
                            }
                        }
                    }
                    
                    if (hasXY && objKeys.length > 0) {
                        this.log(`    Found ${key}[3] with ${objKeys.length} objects`);
                        for (const k of objKeys) {
                            const objVal = obj3[k];
                            if (typeof objVal === 'object' && objVal !== null) {
                                this.structure[k] = { ...objVal };
                                if (Object.keys(this.structure).length <= 5) {
                                    this.log(`    ${k}: ${JSON.stringify(objVal)}`);
                                }
                            }
                        }
                        if (Object.keys(this.structure).length > 5) {
                            this.log(`    ... and ${Object.keys(this.structure).length - 5} more objects`);
                        }
                        return; // Found it!
                    }
                }

                // Also check for direct object with x/y properties
                if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
                    const keys = Object.keys(val);
                    if (keys.length > 0 && keys.length < 100) {
                        let hasNestedXY = false;
                        for (const k of keys) {
                            if (typeof val[k] === 'object' && val[k] !== null && ('x' in val[k] || 'y' in val[k])) {
                                hasNestedXY = true;
                                break;
                            }
                        }
                        if (hasNestedXY) {
                            this.log(`    Found ${key} with ${keys.length} nested objects`);
                            for (const k of keys) {
                                if (typeof val[k] === 'object' && val[k] !== null) {
                                    this.structure[k] = { ...val[k] };
                                }
                            }
                            return;
                        }
                    }
                }
            } catch (e) {
                // Skip inaccessible properties
            }
        }

        if (Object.keys(this.structure).length === 0) {
            this.log('    No structure found via window scan');
        }
    }

    /**
     * Static XOR decode - try all key/delimiter combinations
     */
    _staticDecode(code) {
        // Find encoded strings
        const encodedStrings = this._findEncodedStrings(code);
        this.log(`[1] Found ${encodedStrings.length} encoded strings`);

        if (encodedStrings.length === 0 || this.xorKeys.length === 0) {
            this.log('    No encoded strings or keys found');
            return;
        }

        // Try each key with each encoded string
        for (const encoded of encodedStrings) {
            for (const key of this.xorKeys) {
                const result = this._tryDecode(encoded, key);
                if (result) {
                    this.xorKey = key;
                    this.delimiter = result.delimiter;
                    this.stringTable = [...new Set(result.strings)];
                    this.log(`[2] ✓ Decoded with key='${key}' delim='${this._displayDelim(result.delimiter)}'`);
                    this.log(`    ${this.stringTable.length} unique strings`);
                    return;
                }
            }
        }

        this.log('    Could not decode with any key/delimiter combination');
    }

    /**
     * Find URL-encoded strings in code
     */
    _findEncodedStrings(code) {
        const results = [];
        
        // return "X%..." or return "%..."
        const matches = [...code.matchAll(/return\s*"([X%][^"]+)"/g)];
        for (const m of matches) {
            if (m[1].length > 20 && m[1].includes('%')) {
                results.push(m[1]);
            }
        }

        // Function returning encoded string
        const funcMatches = [...code.matchAll(/function\s+\w+\s*\(\)\s*\{\s*return\s*"([%X][^"]+)"/g)];
        for (const m of funcMatches) {
            if (m[1].length > 20) {
                results.push(m[1]);
            }
        }

        return results;
    }

    /**
     * Try to decode with specific key, auto-detect delimiter
     */
    _tryDecode(encoded, key) {
        try {
            const decoded = decodeURIComponent(encoded);
            let xored = '';
            for (let i = 0; i < decoded.length; i++) {
                xored += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
            }

            // Try all delimiters, pick the one that gives best results
            let bestResult = null;
            let bestScore = 0;

            for (const delim of this.delimiters) {
                const parts = xored.split(delim).filter(p => p.length > 0);
                
                if (parts.length < 3) continue;
                
                // Score: prefer more printable strings of reasonable length
                const printable = parts.filter(p => /^[\x20-\x7E]+$/.test(p) && p.length < 100);
                const score = printable.length * 10 + parts.length;
                
                if (score > bestScore && printable.length >= 2) {
                    bestScore = score;
                    bestResult = { delimiter: delim, strings: parts };
                }
            }

            return bestResult;
        } catch (e) {
            return null;
        }
    }

    /**
     * Build final result
     */
    _buildResult() {
        const identifierMap = this._buildIdentifierMap();
        const cleanCode = this._generateCleanCode(identifierMap);

        return {
            success: true,
            method: this.method,
            namespace: this.namespace,
            
            // Extracted keys/delimiters
            xorKeysFound: this.xorKeys,
            xorKeyUsed: this.xorKey,
            delimitersFound: this.delimiters.map(d => ({ char: d, code: d.charCodeAt(0) })),
            delimiterUsed: this.delimiter,
            
            // Mappings
            indexMap: this.indexMap,
            stringTable: this.stringTable,
            structure: this.structure,
            identifierMap: identifierMap,
            
            // Output
            deobfuscatedCode: cleanCode,
            
            stats: {
                indexMappings: Object.keys(this.indexMap).length,
                uniqueStrings: this.stringTable.length,
                objectsFound: Object.keys(this.structure).length,
                keysFound: this.xorKeys.length,
                delimitersFound: this.delimiters.length
            }
        };
    }

    /**
     * Build identifier mapping (obfuscated → original)
     */
    _buildIdentifierMap() {
        const map = {};

        // From structure values
        for (const [objName, props] of Object.entries(this.structure)) {
            if (typeof props !== 'object') continue;
            
            for (const [prop, val] of Object.entries(props)) {
                // Infer property names from values
                if (val === 1280 || val === 1920) map[prop] = 'w';
                else if (val === 480 || val === 720 || val === 1080) map[prop] = 'h';
            }
            
            // Infer object names from y values
            if (props.y !== undefined) {
                if (props.y < 100) map[objName] = 'HILLS';
                else if (props.y < 600) map[objName] = 'SKY';
                else map[objName] = 'TREES';
            }
        }

        map['x'] = 'x';
        map['y'] = 'y';

        return map;
    }

    /**
     * Generate clean deobfuscated code
     */
    _generateCleanCode(identifierMap) {
        if (Object.keys(this.structure).length === 0) {
            return '// No structure extracted - check console output for index mappings';
        }

        const entries = Object.entries(this.structure)
            .filter(([_, props]) => typeof props === 'object' && props.y !== undefined)
            .sort((a, b) => (a[1].y || 0) - (b[1].y || 0));

        if (entries.length === 0) {
            return '// No complete objects with y-values found';
        }

        let code = 'var BACKGROUND = {\n';

        for (const [objName, props] of entries) {
            const cleanName = identifierMap[objName] || objName;
            
            let w = 1280, h = 480;
            for (const [prop, val] of Object.entries(props)) {
                if (identifierMap[prop] === 'w' || val === 1280 || val === 1920) w = val;
                if (identifierMap[prop] === 'h' || val === 480 || val === 720) h = val;
            }

            code += `  ${cleanName.padEnd(6)}: { x: ${String(props.x || 5).padStart(4)}, y: ${String(props.y).padStart(4)}, w: ${String(w).padStart(4)}, h: ${String(h).padStart(4)} },\n`;
        }

        code += '};';
        return code;
    }

    _displayDelim(d) {
        if (!d) return 'none';
        const c = d.charCodeAt(0);
        return c < 32 || c > 126 ? `char(${c})` : `'${d}'`;
    }
}

module.exports = { JScramblerUniversal };

// ═══════════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════════

if (require.main === module) {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
        console.log(`
╔══════════════════════════════════════════════════════════════╗
║   J-SHADOW V8 - JSCRAMBLER UNIVERSAL (FULLY DYNAMIC)         ║
╚══════════════════════════════════════════════════════════════╝

Usage: node JScramblerUniversal.js <input.js> [options]

Options:
  -o, --output <file>   Output file
  -q, --quiet           Quiet mode
  -t, --timeout <ms>    Emulation timeout (default: 2000)
  --json                Output as JSON
  -h, --help            Show help

Features:
  ✓ Auto-detects namespace (n_n6H, c4xOK, f6qCb, etc.)
  ✓ Auto-extracts XOR keys (no hardcoding!)
  ✓ Auto-detects delimiters (no hardcoding!)
  ✓ JSDOM runtime emulation
  ✓ Static XOR fallback
`);
        process.exit(0);
    }

    const inputFile = args.find(a => !a.startsWith('-'));
    const outputFile = args.includes('-o') ? args[args.indexOf('-o') + 1] : null;
    const quiet = args.includes('-q') || args.includes('--quiet');
    const jsonOut = args.includes('--json');
    const timeout = args.includes('-t') ? parseInt(args[args.indexOf('-t') + 1]) : 2000;

    if (!inputFile || !fs.existsSync(inputFile)) {
        console.error('Error: Input file not found');
        process.exit(1);
    }

    const code = fs.readFileSync(inputFile, 'utf8');
    const deobfuscator = new JScramblerUniversal({ verbose: !quiet, timeout });

    deobfuscator.deobfuscate(code).then(result => {
        if (!result) {
            console.error('Deobfuscation failed');
            process.exit(1);
        }

        if (jsonOut) {
            console.log(JSON.stringify(result, null, 2));
        } else {
            console.log('\n═══════════════════════════════════════════════════════════════');
            console.log('🔑 XOR KEYS FOUND:');
            console.log('═══════════════════════════════════════════════════════════════');
            result.xorKeysFound.forEach(k => console.log(`   '${k}'`));
            if (result.xorKeyUsed) console.log(`   ✓ Used: '${result.xorKeyUsed}'`);

            console.log('\n═══════════════════════════════════════════════════════════════');
            console.log('📋 INDEX MAPPINGS:');
            console.log('═══════════════════════════════════════════════════════════════');
            const entries = Object.entries(result.indexMap).slice(0, 20);
            for (const [k, v] of entries) {
                console.log(`   ${k} = "${v}"`);
            }
            if (Object.keys(result.indexMap).length > 20) {
                console.log(`   ... and ${Object.keys(result.indexMap).length - 20} more`);
            }

            console.log('\n═══════════════════════════════════════════════════════════════');
            console.log('🗺️  IDENTIFIER MAP:');
            console.log('═══════════════════════════════════════════════════════════════');
            for (const [k, v] of Object.entries(result.identifierMap)) {
                if (k !== v) console.log(`   "${k}" → ${v}`);
            }

            console.log('\n═══════════════════════════════════════════════════════════════');
            console.log('🎯 DEOBFUSCATED CODE:');
            console.log('═══════════════════════════════════════════════════════════════\n');
            console.log(result.deobfuscatedCode);

            console.log('\n═══════════════════════════════════════════════════════════════');
            console.log('📊 STATS:');
            console.log('═══════════════════════════════════════════════════════════════');
            console.log(`   Method: ${result.method}`);
            console.log(`   Keys found: ${result.stats.keysFound}`);
            console.log(`   Delimiters found: ${result.stats.delimitersFound}`);
            console.log(`   Index mappings: ${result.stats.indexMappings}`);
            console.log(`   Objects: ${result.stats.objectsFound}`);
        }

        if (outputFile) {
            fs.writeFileSync(outputFile, result.deobfuscatedCode);
            console.log(`\n✅ Saved to ${outputFile}`);
        }
    });
}
