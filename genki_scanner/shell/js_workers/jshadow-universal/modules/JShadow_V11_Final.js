/**
 * J-SHADOW V11 ULTIMATE - COMPREHENSIVE JSCRAMBLER DEOBFUSCATOR
 * Handles ALL JScrambler variants: .f=, [189638], anti-debug
 * @version 11.1.0 FINAL
 */

const { JSDOM } = require('jsdom');
const fs = require('fs');

class JScramblerV11 {
    constructor(options = {}) {
        this.options = {
            timeout: options.timeout || 12000,
            verbose: options.verbose !== false,
            ...options
        };
    }

    log(msg) {
        if (this.options.verbose) console.log(msg);
    }

    async deobfuscate(code) {
        this.log('\n╔══════════════════════════════════════════════════════════════╗');
        this.log('║   🔥 J-SHADOW V11.1 ULTIMATE - ALL VARIANTS 🔥               ║');
        this.log('╚══════════════════════════════════════════════════════════════╝\n');
        this.log(`📊 Input: ${code.length} bytes\n`);

        // Detect namespace - handle multiple patterns
        const namespace = this._detectNamespace(code);
        if (!namespace) return { success: false, error: 'No namespace detected' };
        this.log(`[✓] Namespace: ${namespace}`);

        // Detect variant type
        const variant = this._detectVariant(code, namespace);
        this.log(`[✓] Variant: ${variant}`);

        // Extract constants
        this.log('\n━━━ PHASE 1: Extract Constants ━━━\n');
        const constants = this._extractConstants(code);
        this.log(`[✓] Found ${Object.keys(constants).length} constants`);

        // Extract decoder strings
        this.log('\n━━━ PHASE 2: Extract Decoder Strings ━━━\n');
        const decoderStrings = await this._extractDecoderStrings(code, namespace);
        this.log(`[✓] Extracted ${Object.keys(decoderStrings).length} decoder strings`);

        // Transform code
        this.log('\n━━━ PHASE 3: Transform Code ━━━\n');
        let output = code;
        let decoderReplacements = 0;
        let constantReplacements = 0;

        // Replace decoder calls
        for (const [call, value] of Object.entries(decoderStrings)) {
            const match = call.match(/^([a-zA-Z_$][a-zA-Z0-9_$]*)\((\d+)\)$/);
            if (!match) continue;
            const [, fn, idx] = match;
            
            // Multiple patterns for decoder calls
            const patterns = [
                new RegExp(`${namespace}\\.${fn}\\(${idx}\\)`, 'g'),
                new RegExp(`${namespace}\\["${fn}"\\]\\(${idx}\\)`, 'g'),
            ];
            
            for (const pattern of patterns) {
                const before = output;
                output = output.replace(pattern, `"${this._escape(value)}"`);
                if (output !== before) decoderReplacements++;
            }
        }
        this.log(`[✓] Replaced ${decoderReplacements} decoder calls`);

        // Replace constants
        for (const [key, value] of Object.entries(constants)) {
            const regex = new RegExp(key.replace(/\[/g, '\\[').replace(/\]/g, '\\]').replace(/\$/g, '\\$'), 'g');
            const before = output;
            if (typeof value === 'number') {
                output = output.replace(regex, String(value));
            } else if (typeof value === 'string' && value.length < 50) {
                output = output.replace(regex, `"${this._escape(value)}"`);
            }
            if (output !== before) constantReplacements++;
        }
        this.log(`[✓] Replaced ${constantReplacements} constants`);

        // Generate output
        this.log('\n━━━ PHASE 4: Generate Output ━━━\n');
        const finalOutput = this._generateOutput(output, namespace, variant, decoderStrings, constants);

        return {
            success: true,
            code: finalOutput,
            stats: {
                original: code.length,
                output: finalOutput.length,
                variant,
                decoderStrings: Object.keys(decoderStrings).length,
                constants: Object.keys(constants).length,
                decoderReplacements,
                constantReplacements
            }
        };
    }

    _detectNamespace(code) {
        // Pattern 1: namespace[189638] (domain lock variant)
        let match = code.match(/([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\[189638\]/);
        if (match) return match[1];

        // Pattern 2: namespace.f = (function (string decoder variant)
        match = code.match(/([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\.f\s*=\s*\(function/);
        if (match) return match[1];

        // Pattern 3: function namespace() {} at start
        match = code.match(/^([a-zA-Z_$][a-zA-Z0-9_$]{2,8})\.f\s*=/m);
        if (match) return match[1];

        // Fallback: frequency analysis
        const counts = {};
        const matches = code.matchAll(/([a-zA-Z_$][a-zA-Z0-9_$]{3,8})\./g);
        for (const m of matches) {
            counts[m[1]] = (counts[m[1]] || 0) + 1;
        }
        let max = 0, ns = null;
        for (const [name, count] of Object.entries(counts)) {
            if (count > max && count > 30) { max = count; ns = name; }
        }
        return ns;
    }

    _detectVariant(code, namespace) {
        if (code.includes('[189638]')) return 'DOMAIN_LOCK';
        if (code.includes('D1RXhaS') || code.includes('eval(')) return 'ANTI_DEBUG';
        if (code.includes('.f=(function') || code.includes('.f = (function')) return 'STRING_DECODER';
        return 'UNKNOWN';
    }

    _extractConstants(code) {
        const constants = {};
        
        // Number constants: var[idx]=number
        const numPattern = /([a-zA-Z_$][a-zA-Z0-9_$]{1,5})\[(\d+)\]\s*=\s*(\d+)\s*[;,}]/g;
        let match;
        while ((match = numPattern.exec(code)) !== null) {
            constants[`${match[1]}[${match[2]}]`] = parseInt(match[3]);
        }

        // Short string constants
        const strPattern = /([a-zA-Z_$][a-zA-Z0-9_$]{1,5})\[(\d+)\]\s*=\s*"([^"]{1,30})"\s*[;,]/g;
        while ((match = strPattern.exec(code)) !== null) {
            constants[`${match[1]}[${match[2]}]`] = match[3];
        }

        return constants;
    }

    async _extractDecoderStrings(code, namespace) {
        const strings = {};
        
        try {
            const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
                url: 'https://example.com',
                runScripts: 'dangerously',
                pretendToBeVisual: true,
            });
            const window = dom.window;

            // Browser stubs
            window.eval(`
                (function() {
                    var store = {};
                    window.localStorage = window.sessionStorage = {
                        getItem: function(k) { return store[k] || null; },
                        setItem: function(k, v) { store[k] = v; },
                        removeItem: function(k) { delete store[k]; },
                        clear: function() { store = {}; },
                        get length() { return Object.keys(store).length; },
                        key: function(i) { return Object.keys(store)[i]; }
                    };
                    window.crypto = { getRandomValues: function(a) { for(var i=0;i<a.length;i++) a[i]=Math.floor(Math.random()*256); return a; } };
                    window.performance = { now: Date.now.bind(Date), timing: { navigationStart: Date.now() } };
                    window.globalThis = window;
                    window.T4mf0 = {};
                })();
            `);

            window.__STRINGS__ = {};

            // Inject code
            try {
                window.eval(code);
            } catch (e) {
                // Ignore execution errors
            }

            // Extract decoder strings
            const captureCode = `
                (function() {
                    var ns = window['${namespace}'];
                    if (!ns) return;
                    
                    for (var prop in ns) {
                        if (typeof ns[prop] === 'function' && prop.length <= 4) {
                            try {
                                var test = ns[prop](0);
                                if (typeof test === 'string' && test.length < 500) {
                                    for (var i = 0; i < 500; i++) {
                                        try {
                                            var r = ns[prop](i);
                                            if (typeof r === 'string') {
                                                window.__STRINGS__[prop + '(' + i + ')'] = r;
                                            }
                                        } catch(e) { break; }
                                    }
                                }
                            } catch(e) {}
                        }
                    }
                })();
            `;

            // Try multiple times with delays
            for (let attempt = 0; attempt < 5; attempt++) {
                await new Promise(r => setTimeout(r, 500));
                try {
                    window.eval(captureCode);
                    if (Object.keys(window.__STRINGS__).length > 0) break;
                } catch (e) {}
            }

            Object.assign(strings, window.__STRINGS__ || {});
            dom.window.close();
        } catch (e) {
            this.log(`[!] Error: ${e.message}`);
        }

        return strings;
    }

    _escape(str) {
        return String(str).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '');
    }

    _generateOutput(code, namespace, variant, decoderStrings, constants) {
        const totalStrings = Object.keys(decoderStrings).length;
        const totalConstants = Object.keys(constants).length;

        let output = `/**
 * ══════════════════════════════════════════════════════════════════
 *  J-SHADOW V11.1 ULTIMATE - DEOBFUSCATED OUTPUT
 * ══════════════════════════════════════════════════════════════════
 *  Namespace: ${namespace}
 *  Variant: ${variant}
 *  Decoder strings: ${totalStrings}
 *  Constants: ${totalConstants}
 * ══════════════════════════════════════════════════════════════════
 */

`;

        // Categorize strings
        const categories = { DOM: [], EVENTS: [], CSS: [], CANVAS: [], MATH: [], GAME: [], IDENTIFIERS: [], STRINGS: [] };
        const domWords = ['createElement','appendChild','getElementById','querySelector','innerHTML','style','document','getAttribute','setAttribute','textContent','className'];
        const eventWords = ['addEventListener','click','keydown','keyup','load','error','mousedown','mouseup','touchstart','blur','focus'];
        const cssWords = ['width','height','color','background','margin','padding','position','top','left','display','opacity','transform','border','font'];
        const canvasWords = ['canvas','getContext','fillStyle','strokeStyle','fillRect','beginPath','closePath','moveTo','lineTo','arc','fill','stroke','drawImage'];
        const mathWords = ['floor','ceil','round','random','max','min','pow','sqrt','PI','sin','cos','abs'];
        const gameWords = ['speed','score','player','enemy','level','game','sprite','collision','update','render','frame','animation'];

        for (const [call, value] of Object.entries(decoderStrings)) {
            const v = value.toLowerCase();
            if (domWords.some(w => v.includes(w.toLowerCase()))) categories.DOM.push({call, value});
            else if (eventWords.some(w => v.includes(w.toLowerCase()))) categories.EVENTS.push({call, value});
            else if (cssWords.some(w => v === w.toLowerCase())) categories.CSS.push({call, value});
            else if (canvasWords.some(w => v.includes(w.toLowerCase()))) categories.CANVAS.push({call, value});
            else if (mathWords.some(w => v === w.toLowerCase())) categories.MATH.push({call, value});
            else if (gameWords.some(w => v.includes(w.toLowerCase()))) categories.GAME.push({call, value});
            else if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(value)) categories.IDENTIFIERS.push({call, value});
            else categories.STRINGS.push({call, value});
        }

        output += '// ══════════════════════════════════════════════════════════════════\n';
        output += '// DECODED STRINGS BY CATEGORY\n';
        output += '// ══════════════════════════════════════════════════════════════════\n\n';

        for (const [cat, items] of Object.entries(categories)) {
            if (items.length === 0) continue;
            output += `// ─── ${cat} (${items.length}) ───\n`;
            for (const {call, value} of items.slice(0, 80)) {
                output += `//   ${namespace}.${call} = "${this._escape(value)}"\n`;
            }
            if (items.length > 80) output += `//   ... and ${items.length - 80} more\n`;
            output += '\n';
        }

        // Complete lookup table as JS object
        output += '\n// ══════════════════════════════════════════════════════════════════\n';
        output += '// COMPLETE STRING LOOKUP TABLE\n';
        output += '// ══════════════════════════════════════════════════════════════════\n\n';
        output += 'var DECODED_STRINGS = {\n';
        for (const [call, value] of Object.entries(decoderStrings)) {
            output += `  "${call}": "${this._escape(value)}",\n`;
        }
        output += '};\n\n';

        output += '// ══════════════════════════════════════════════════════════════════\n';
        output += '// TRANSFORMED CODE (constants replaced)\n';
        output += '// ══════════════════════════════════════════════════════════════════\n\n';
        output += code;

        return output;
    }
}

module.exports = { JScramblerV11 };

if (require.main === module) {
    const args = process.argv.slice(2);
    const input = args.find(a => !a.startsWith('-'));
    const oIdx = args.indexOf('-o');
    const output = oIdx !== -1 ? args[oIdx + 1] : null;
    const tIdx = args.indexOf('-t');
    const timeout = tIdx !== -1 ? parseInt(args[tIdx + 1]) : 12000;

    if (!input) {
        console.log('J-SHADOW V11.1 ULTIMATE - JScrambler Deobfuscator');
        console.log('Usage: node JScramblerV11_Final.js <input.js> [-o output.js] [-t timeout]');
        process.exit(1);
    }

    new JScramblerV11({ timeout })
        .deobfuscate(fs.readFileSync(input, 'utf8'))
        .then(r => {
            if (r.success) {
                if (output) {
                    fs.writeFileSync(output, r.code);
                    console.log(`\n✅ Saved: ${output}`);
                    console.log(`   Variant: ${r.stats.variant}`);
                    console.log(`   Strings: ${r.stats.decoderStrings}`);
                    console.log(`   Constants: ${r.stats.constants}`);
                    console.log(`   Replacements: ${r.stats.decoderReplacements + r.stats.constantReplacements}`);
                } else {
                    console.log(r.code.slice(0, 5000));
                }
            }
        });
}
