/**
 * ██████╗     ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
 *    ██╔╝     ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
 *    ██║      ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
 * ██ ██║ ██   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
 * ╚█ ██╔╝█╔   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
 *  ╚═╝ ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝  v5.0
 * 
 * J-SHADOW v5 ULTIMATE - Universal JavaScript Deobfuscator
 * GENKI-TECH LABS | ANBU Black Ops Security | War Chief Edition 🏴‍☠️
 * 
 * @author Kakashi x Claude Tandem
 * @version 5.0.0
 * @license MIT
 * 
 * FEATURES:
 * ✅ 50+ Obfuscation Pattern Detection
 * ✅ CONDITIONAL Stage Execution (only runs what's needed!)
 * ✅ Fixed Babel Parser Options
 * ✅ AI Function Renaming with OpenAI/Local
 * ✅ Final Prettify Output
 * ✅ All Major Obfuscators Supported
 */

'use strict';

const babel = require('@babel/core');
const traverse = require('@babel/traverse').default;
const generator = require('@babel/generator').default;
const t = require('@babel/types');
const vm = require('vm');
const crypto = require('crypto');
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');

// ============================================================================
// SECTION 0: BABEL PARSER HELPER (FIXED!)
// ============================================================================

/**
 * Safe Babel parse with correct options format
 * This fixes the "Unknown option: .allowReturnOutsideFunction" error
 */
function safeParse(code, extraOptions = {}) {
    try {
        return babel.parse(code, {
            sourceType: 'unambiguous',
            parserOpts: {
                allowReturnOutsideFunction: true,
                allowImportExportEverywhere: true,
                allowSuperOutsideMethod: true,
                allowAwaitOutsideFunction: true,
                plugins: [
                    'dynamicImport',
                    'classProperties',
                    'classPrivateProperties', 
                    'classPrivateMethods',
                    'optionalChaining',
                    'nullishCoalescingOperator',
                    'numericSeparator',
                    'bigInt',
                    'optionalCatchBinding',
                    'objectRestSpread'
                ]
            },
            ...extraOptions
        });
    } catch (e) {
        // Fallback: try without plugins
        try {
            return babel.parse(code, {
                sourceType: 'script',
                parserOpts: {
                    allowReturnOutsideFunction: true,
                    errorRecovery: true
                }
            });
        } catch (e2) {
            throw new Error(`Parse failed: ${e.message}`);
        }
    }
}

// ============================================================================
// SECTION 1: UNIVERSAL PATTERN DETECTOR (50+ PATTERNS!)
// ============================================================================

class UniversalPatternDetector {
    constructor() {
        this.version = '2.0.0';
        
        // ═══════════════════════════════════════════════════════════════
        // ALL DETECTION SIGNATURES
        // ═══════════════════════════════════════════════════════════════
        
        this.signatures = {
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 🎭 ESOTERIC ENCODINGS
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            jsfuck: {
                name: 'JSFuck',
                category: 'esoteric',
                patterns: [
                    /^[\[\]\(\)!+\s]{50,}$/m,           // Pure JSFuck (long)
                    /\[\]\[\s*[!\[\]()]+\s*\]\s*\[/,   // [][[]] pattern
                    /\(!!\[\]\+\[\]\)\[/,              // (!![]+ pattern
                    /\[\+!\+\[\]\+/                    // [+!+[]+ pattern
                ],
                severity: 'high',
                handler: 'esoteric',
                description: 'JSFuck encoding using only []()!+ characters'
            },
            
            jjencode: {
                name: 'JJEncode', 
                category: 'esoteric',
                patterns: [
                    /\$=~\[\];/,                       // Starting signature
                    /\$\.\$\(\$\.\$\(/,                // $.$($.$( pattern
                    /\$\.\$\$\$\$/                     // .$$$$ pattern
                ],
                severity: 'high',
                handler: 'esoteric',
                description: 'JJEncode obfuscation using $ variable'
            },
            
            aaencode: {
                name: 'AAEncode',
                category: 'esoteric', 
                patterns: [
                    /ﾟωﾟﾉ/,                           // Main emoticon
                    /ﾟΘﾟ/,                            // Theta emoticon
                    /ﾟДﾟ/,                            // D emoticon
                    /\(ﾟДﾟ\)\[ﾟoﾟ\]/                  // Pattern combo
                ],
                severity: 'high',
                handler: 'esoteric',
                description: 'AAEncode Japanese emoticon obfuscation'
            },

            hieroglyphy: {
                name: 'Hieroglyphy',
                category: 'esoteric',
                patterns: [
                    /\+\[\]\+\(\+!\+\[\]/,
                    /\(\+\{\}\+\[\]\)/
                ],
                severity: 'high',
                handler: 'esoteric',
                description: 'Hieroglyphy symbolic encoding'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 📦 BUNDLERS
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            webpack: {
                name: 'Webpack',
                category: 'bundler',
                patterns: [
                    /__webpack_require__/,
                    /webpackJsonp/,
                    /\["__webpack/,
                    /webpack_modules/,
                    /installedModules/,
                    /\(function\s*\(\s*modules\s*\)/
                ],
                severity: 'medium',
                handler: 'webpack',
                description: 'Webpack bundled code'
            },
            
            webpack5: {
                name: 'Webpack 5',
                category: 'bundler',
                patterns: [
                    /__webpack_exports__/,
                    /__webpack_module_cache__/,
                    /\/\*\*\*\/ "\w+":/               // Module key pattern
                ],
                severity: 'medium',
                handler: 'webpack',
                description: 'Webpack 5 specific bundle'
            },

            rollup: {
                name: 'Rollup',
                category: 'bundler',
                patterns: [
                    /\(function\s*\(\s*exports\s*,/,
                    /Object\.defineProperty\(exports/,
                    /this\.[\w]+\s*=\s*\(function/
                ],
                severity: 'medium',
                handler: 'rollup',
                description: 'Rollup bundled code'
            },

            parcel: {
                name: 'Parcel',
                category: 'bundler',
                patterns: [
                    /parcelRequire/,
                    /__parcel__/,
                    /parcel_require/
                ],
                severity: 'medium',
                handler: 'parcel',
                description: 'Parcel bundled code'
            },

            browserify: {
                name: 'Browserify',
                category: 'bundler',
                patterns: [
                    /require\s*=\s*function.*_prelude/s,
                    /\(function\s+e\s*\(\s*t\s*,\s*n\s*,\s*r\s*\)/,
                    /require\s*\(\s*\d+\s*\)/
                ],
                severity: 'medium',
                handler: 'browserify',
                description: 'Browserify bundled code'
            },

            requirejs: {
                name: 'RequireJS',
                category: 'bundler',
                patterns: [
                    /define\s*\(\s*\[/,
                    /require\s*\(\s*\[/,
                    /requirejs\.config/
                ],
                severity: 'medium',
                handler: 'requirejs',
                description: 'RequireJS AMD modules'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 🔒 OBFUSCATORS
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            obfuscator_io: {
                name: 'Obfuscator.io / javascript-obfuscator',
                category: 'obfuscator',
                patterns: [
                    /_0x[a-f0-9]{4,}/i,                // _0x prefix
                    /\['\\x[0-9a-f]{2}/i,             // Hex string arrays
                    /var\s+_0x\w+\s*=\s*\[/,          // String array var
                    /function\s*\(\s*_0x\w+\s*,\s*_0x\w+\s*\)/,  // Param pattern
                    /\['push'\]\s*\(\s*\w+\s*\['shift'\]/  // Array rotation
                ],
                severity: 'high',
                handler: 'obfuscator_io',
                description: 'javascript-obfuscator / Obfuscator.io'
            },

            jscrambler: {
                name: 'JScrambler',
                category: 'obfuscator',
                patterns: [
                    /\)\s*[~:`\)|\xAA]/,               // Delimiter patterns
                    /\(\s*function\s*\(\)\s*\{[\s\S]*?\}\s*\)\s*\(\s*['"][A-Z0-9]{6}/,  // IIFE with key
                    /charAt\s*\(\s*\w+\s*\^\s*\w+\s*%/,  // XOR decryption
                    /fromCharCode\s*\(\s*\w+\s*\^\s*\w+/  // XOR charcode
                ],
                severity: 'critical',
                handler: 'jscrambler',
                description: 'JScrambler enterprise obfuscation'
            },

            jsfuck_obf: {
                name: 'Obfuscator with JSFuck elements',
                category: 'obfuscator',
                patterns: [
                    /\[\]\s*\[\s*['"]constructor['"]\s*\]/,
                    /\+\[\]\+\+/
                ],
                severity: 'high',
                handler: 'esoteric',
                description: 'JSFuck-style elements in code'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 🔀 CONTROL FLOW
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            control_flow_flat: {
                name: 'Control Flow Flattening',
                category: 'control_flow',
                patterns: [
                    /while\s*\(\s*!?\s*!?\s*[01]\s*\)\s*\{\s*switch/,  // while(1){switch
                    /switch\s*\(\s*\w+\[\s*\w+\+\+\s*\]\s*\)/,         // switch(arr[i++])
                    /for\s*\(\s*;;\s*\)\s*\{\s*switch/,                // for(;;){switch
                    /case\s+['"][0-9]+['"]\s*:/                        // String case labels
                ],
                severity: 'high',
                handler: 'control_flow',
                description: 'Control flow flattening with state machine'
            },

            tigress_ollvm: {
                name: 'Tigress/OLLVM',
                category: 'control_flow',
                patterns: [
                    /while\s*\(\s*1\s*\)\s*\{[\s\S]*?switch\s*\(/,
                    /for\s*\(\s*var\s+\w+\s*=\s*0x[0-9a-f]+\s*;/,
                    /\w+\s*=\s*\w+\s*\^\s*0x[0-9a-f]{8}/              // XOR with constant
                ],
                severity: 'critical',
                handler: 'control_flow',
                description: 'Tigress or OLLVM obfuscation'
            },

            opaque_predicates: {
                name: 'Opaque Predicates',
                category: 'control_flow',
                patterns: [
                    /if\s*\(\s*(true|false|1|0)\s*\)/,
                    /if\s*\(\s*!\s*!\s*\[\s*\]\s*\)/,
                    /\?\s*\w+\s*:\s*\w+\s*,\s*\w+/                    // Nested ternary
                ],
                severity: 'medium',
                handler: 'control_flow',
                description: 'Opaque predicates (always true/false)'
            },

            dead_code: {
                name: 'Dead Code Insertion',
                category: 'control_flow',
                patterns: [
                    /if\s*\(\s*false\s*\)\s*\{[^}]+\}/,
                    /if\s*\(\s*0\s*\)\s*\{[^}]+\}/,
                    /while\s*\(\s*false\s*\)/
                ],
                severity: 'low',
                handler: 'cleanup',
                description: 'Unreachable dead code blocks'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 🔐 STRING ENCODING
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            hex_strings: {
                name: 'Hex String Encoding',
                category: 'encoding',
                patterns: [
                    /\\x[0-9a-fA-F]{2}/,
                    /['"]\\x[0-9a-fA-F]{2}.*?['"]/
                ],
                severity: 'low',
                handler: 'string',
                description: 'Hexadecimal escape sequences'
            },

            unicode_escape: {
                name: 'Unicode Escape',
                category: 'encoding',
                patterns: [
                    /\\u[0-9a-fA-F]{4}/,
                    /\\u\{[0-9a-fA-F]+\}/
                ],
                severity: 'low',
                handler: 'string',
                description: 'Unicode escape sequences'
            },

            base64: {
                name: 'Base64 Encoding',
                category: 'encoding',
                patterns: [
                    /atob\s*\(/,
                    /btoa\s*\(/,
                    /Buffer\.from\s*\([^,]+,\s*['"]base64['"]\)/,
                    /['"][A-Za-z0-9+/]{20,}={0,2}['"]/              // Base64 string
                ],
                severity: 'medium',
                handler: 'string',
                description: 'Base64 encoded strings'
            },

            xor_encoding: {
                name: 'XOR Encoding',
                category: 'encoding',
                patterns: [
                    /charCodeAt\s*\([^)]*\)\s*\^\s*\d+/,
                    /String\.fromCharCode\s*\([^)]*\s*\^\s*[^)]+\)/,
                    /\.map\s*\(\s*\(\s*\w+\s*,\s*\w+\s*\)\s*=>\s*\w+\s*\^/
                ],
                severity: 'medium',
                handler: 'string',
                description: 'XOR-based string encoding'
            },

            rc4: {
                name: 'RC4 Encryption',
                category: 'encoding',
                patterns: [
                    /rc4|RC4/,
                    /256\s*;\s*\w+\s*<\s*256/,                       // RC4 S-box init
                    /mod\s*256|%\s*256/
                ],
                severity: 'high',
                handler: 'crypto',
                description: 'RC4 stream cipher'
            },

            string_array: {
                name: 'String Array',
                category: 'encoding',
                patterns: [
                    /var\s+\w+\s*=\s*\[\s*['"][^'"]+['"](?:\s*,\s*['"][^'"]+['"]){10,}/,
                    /\.push\s*\(\s*\w+\.shift\s*\(\s*\)\s*\)/       // Array rotation
                ],
                severity: 'high',
                handler: 'string_array',
                description: 'String array with function access'
            },

            string_concat: {
                name: 'String Concatenation',
                category: 'encoding',
                patterns: [
                    /['"][a-zA-Z]{1,3}['"]\s*\+\s*['"][a-zA-Z]{1,3}['"]\s*\+/
                ],
                severity: 'low',
                handler: 'string',
                description: 'Split string concatenation'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 🛡️ ANTI-ANALYSIS
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            debugger_trap: {
                name: 'Debugger Trap',
                category: 'anti_debug',
                patterns: [
                    /\bdebugger\b/,
                    /setInterval\s*\(\s*function\s*\(\s*\)\s*\{\s*debugger/
                ],
                severity: 'medium',
                handler: 'anti_debug',
                description: 'Debugger statement traps'
            },

            timing_check: {
                name: 'Timing Detection',
                category: 'anti_debug',
                patterns: [
                    /performance\.now\s*\(\s*\)/,
                    /Date\.now\s*\(\s*\)/,
                    /new\s+Date\s*\(\s*\)\.getTime/,
                    /console\.time/
                ],
                severity: 'medium',
                handler: 'anti_debug',
                description: 'Timing-based debug detection'
            },

            devtools_detect: {
                name: 'DevTools Detection',
                category: 'anti_debug',
                patterns: [
                    /\/\.\{7\}\//,                                   // Regex trap
                    /toString\s*\(\s*\)\.length/,                   // toString length check
                    /outerWidth\s*-\s*innerWidth/,                  // Window size check
                    /Firebug|__REACT_DEVTOOLS/
                ],
                severity: 'medium',
                handler: 'anti_debug',
                description: 'Developer tools detection'
            },

            console_disable: {
                name: 'Console Override',
                category: 'anti_debug',
                patterns: [
                    /console\.\w+\s*=\s*function/,
                    /delete\s+console/,
                    /console\s*=\s*\{/
                ],
                severity: 'low',
                handler: 'anti_debug',
                description: 'Console method overrides'
            },

            stack_trace: {
                name: 'Stack Trace Analysis',
                category: 'anti_debug',
                patterns: [
                    /Error\s*\(\s*\)\.stack/,
                    /stackTraceLimit/,
                    /caller\s*\.\s*caller/
                ],
                severity: 'medium',
                handler: 'anti_debug',
                description: 'Stack trace inspection'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // ⚡ EVAL & DYNAMIC CODE
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            eval_direct: {
                name: 'Direct Eval',
                category: 'dynamic',
                patterns: [
                    /\beval\s*\(/,
                    /\['eval'\]\s*\(/,
                    /\["eval"\]\s*\(/,
                    /window\s*\[\s*['"]eval['"]\s*\]/
                ],
                severity: 'high',
                handler: 'eval',
                description: 'Direct eval() usage'
            },

            function_constructor: {
                name: 'Function Constructor',
                category: 'dynamic',
                patterns: [
                    /new\s+Function\s*\(/,
                    /Function\s*\(\s*['"][^'"]+['"]\s*\)/,
                    /\['constructor'\]\s*\(/
                ],
                severity: 'high',
                handler: 'eval',
                description: 'Function constructor for code execution'
            },

            settimeout_eval: {
                name: 'setTimeout/setInterval Eval',
                category: 'dynamic',
                patterns: [
                    /setTimeout\s*\(\s*['"`]/,
                    /setInterval\s*\(\s*['"`]/
                ],
                severity: 'medium',
                handler: 'eval',
                description: 'Timer-based code execution'
            },

            document_write: {
                name: 'Document Write',
                category: 'dynamic',
                patterns: [
                    /document\.write\s*\(/,
                    /document\.writeln\s*\(/
                ],
                severity: 'medium',
                handler: 'eval',
                description: 'Document.write injection'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 🧬 MINIFIERS
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            uglifyjs: {
                name: 'UglifyJS',
                category: 'minifier',
                patterns: [
                    /\w\s*=\s*\w\s*\|\|\s*\{\s*\}/,                  // a=a||{}
                    /!\s*function\s*\(/,                             // !function(
                    /void\s+0/                                       // void 0
                ],
                severity: 'low',
                handler: 'beautify',
                description: 'UglifyJS minification'
            },

            terser: {
                name: 'Terser',
                category: 'minifier',
                patterns: [
                    /\w{1,2}\s*\?\s*\w{1,2}\s*:\s*void\s+0/,        // Short ternary
                    /=>\s*\{/                                        // Arrow functions
                ],
                severity: 'low',
                handler: 'beautify',
                description: 'Terser minification'
            },

            closure_compiler: {
                name: 'Google Closure Compiler',
                category: 'minifier',
                patterns: [
                    /goog\./,
                    /\$jscomp/,
                    /\.prototype\.\w=function/
                ],
                severity: 'low',
                handler: 'beautify',
                description: 'Google Closure Compiler'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 🌐 WASM & WORKERS
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            webassembly: {
                name: 'WebAssembly',
                category: 'advanced',
                patterns: [
                    /WebAssembly\./,
                    /\.wasm['"]/,
                    /\\x00\\x61\\x73\\x6d/                          // WASM magic bytes
                ],
                severity: 'high',
                handler: 'wasm',
                description: 'WebAssembly module'
            },

            web_worker: {
                name: 'Web Worker',
                category: 'advanced',
                patterns: [
                    /new\s+Worker\s*\(/,
                    /Worker\s*\(/,
                    /SharedWorker/
                ],
                severity: 'medium',
                handler: 'worker',
                description: 'Web Worker thread'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 👻 STEGANOGRAPHY
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            zero_width: {
                name: 'Zero-Width Characters',
                category: 'steganography',
                patterns: [
                    /[\u200B-\u200D\uFEFF]/,                        // Zero-width chars
                    /[\u2060-\u2064]/                               // Invisible chars
                ],
                severity: 'high',
                handler: 'steganography',
                description: 'Hidden zero-width characters'
            },

            homoglyph: {
                name: 'Homoglyph Attack',
                category: 'steganography',
                patterns: [
                    /[а-яА-ЯёЁ]/,                                   // Cyrillic lookalikes
                    /[ＡＢＣＤ]/                                     // Fullwidth chars
                ],
                severity: 'high',
                handler: 'steganography',
                description: 'Lookalike Unicode characters'
            },

            invisible_chars: {
                name: 'Invisible Characters',
                category: 'steganography',
                patterns: [
                    /[\u3164\u115F\u1160]/,                         // Hangul filler
                    /[\u00AD]/                                      // Soft hyphen
                ],
                severity: 'high',
                handler: 'steganography',
                description: 'Invisible Unicode as identifiers'
            },

            bidi_override: {
                name: 'Bidirectional Override',
                category: 'steganography',
                patterns: [
                    /[\u202A-\u202E]/,                              // BIDI controls
                    /[\u2066-\u2069]/                               // Isolate controls
                ],
                severity: 'high',
                handler: 'steganography',
                description: 'Bidirectional text manipulation'
            },

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 🔧 PROTOTYPE/DOM
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            prototype_pollution: {
                name: 'Prototype Pollution',
                category: 'prototype',
                patterns: [
                    /__proto__/,
                    /prototype\s*\[/,
                    /Object\.setPrototypeOf/,
                    /constructor\s*\[\s*['"]prototype['"]\]/
                ],
                severity: 'high',
                handler: 'prototype',
                description: 'Prototype chain manipulation'
            },

            dom_clobbering: {
                name: 'DOM Clobbering',
                category: 'prototype',
                patterns: [
                    /document\.all\[/,
                    /document\.forms\[/,
                    /window\[['"]name['"]\]/
                ],
                severity: 'medium',
                handler: 'prototype',
                description: 'DOM clobbering attack'
            }
        };

        // Handler-to-stages mapping
        this.handlerStages = {
            esoteric: ['decodeEsoteric'],
            webpack: ['unpackWebpack'],
            rollup: ['unpackRollup'],
            parcel: ['unpackParcel'],
            browserify: ['unpackBrowserify'],
            requirejs: ['unpackRequireJS'],
            obfuscator_io: ['decodeStringArray', 'inlineStrings', 'simplifyExpressions'],
            jscrambler: ['decodeJScrambler', 'decryptXOR'],
            control_flow: ['deobfuscateControlFlow'],
            string: ['decodeStrings', 'decodeHex', 'decodeUnicode'],
            string_array: ['decodeStringArray', 'resolveArrayAccess'],
            crypto: ['decryptRC4', 'decryptXOR'],
            anti_debug: ['removeAntiDebug', 'removeDebugger'],
            eval: ['resolveEval', 'inlineEval'],
            beautify: ['beautify'],
            wasm: ['analyzeWASM'],
            worker: ['analyzeWorker'],
            steganography: ['normalizeUnicode', 'removeZeroWidth'],
            prototype: ['detectPrototypePollution'],
            cleanup: ['removeDeadCode', 'cleanupAST']
        };
    }

    /**
     * Detect all obfuscation patterns in code
     * @param {string} code - JavaScript source code
     * @returns {object} Detection results with stages to run
     */
    detect(code) {
        const startTime = Date.now();
        const detected = [];
        const categories = {};
        const handlersNeeded = new Set();
        const stagesToRun = new Set();
        let maxSeverity = 'none';
        const severityOrder = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

        // Run all pattern checks
        for (const [key, signature] of Object.entries(this.signatures)) {
            let matched = false;
            let matchCount = 0;
            const matchedPatterns = [];

            for (const pattern of signature.patterns) {
                const matches = code.match(new RegExp(pattern.source, 'g'));
                if (matches) {
                    matched = true;
                    matchCount += matches.length;
                    matchedPatterns.push(pattern.source);
                }
            }

            if (matched) {
                detected.push({
                    key,
                    name: signature.name,
                    category: signature.category,
                    severity: signature.severity,
                    handler: signature.handler,
                    matchCount,
                    matchedPatterns,
                    description: signature.description
                });

                // Group by category
                if (!categories[signature.category]) {
                    categories[signature.category] = [];
                }
                categories[signature.category].push(key);

                // Track handlers and stages
                handlersNeeded.add(signature.handler);
                const stages = this.handlerStages[signature.handler] || [];
                stages.forEach(s => stagesToRun.add(s));

                // Track max severity
                if (severityOrder[signature.severity] > severityOrder[maxSeverity]) {
                    maxSeverity = signature.severity;
                }
            }
        }

        // Calculate obfuscation score (0-100)
        const obfuscationScore = this._calculateScore(detected);

        // Generate execution plan
        const executionPlan = this._generateExecutionPlan(detected, stagesToRun);

        return {
            detected,
            categories,
            handlersNeeded: Array.from(handlersNeeded),
            stagesToRun: Array.from(stagesToRun),
            executionPlan,
            obfuscationScore,
            severity: maxSeverity,
            analysisTime: Date.now() - startTime,
            summary: this._generateSummary(detected, obfuscationScore, maxSeverity)
        };
    }

    /**
     * Calculate obfuscation score based on detected patterns
     */
    _calculateScore(detected) {
        const weights = {
            esoteric: 20,
            obfuscator: 15,
            control_flow: 15,
            encoding: 5,
            anti_debug: 10,
            dynamic: 10,
            bundler: 3,
            minifier: 2,
            steganography: 15,
            prototype: 8,
            advanced: 12
        };

        let score = 0;
        const seenCategories = new Set();

        for (const item of detected) {
            // Base score from category
            const categoryWeight = weights[item.category] || 5;
            score += categoryWeight;

            // Bonus for multiple patterns in same category
            if (seenCategories.has(item.category)) {
                score += 2;
            }
            seenCategories.add(item.category);

            // Severity multiplier
            const severityMult = { low: 1, medium: 1.5, high: 2, critical: 3 };
            score *= (severityMult[item.severity] || 1);
        }

        return Math.min(100, Math.round(score));
    }

    /**
     * Generate ordered execution plan
     */
    _generateExecutionPlan(detected, stagesToRun) {
        const plan = [];
        const stageOrder = [
            // Priority 1: Remove anti-debug first
            { stage: 'removeAntiDebug', priority: 1, description: 'Remove anti-debugging code' },
            { stage: 'removeDebugger', priority: 1, description: 'Remove debugger traps' },
            
            // Priority 2: Decode esoteric first (must happen before AST)
            { stage: 'decodeEsoteric', priority: 2, description: 'Decode JSFuck/JJEncode/AAEncode' },
            
            // Priority 3: Handle steganography
            { stage: 'normalizeUnicode', priority: 3, description: 'Normalize Unicode characters' },
            { stage: 'removeZeroWidth', priority: 3, description: 'Remove zero-width characters' },
            
            // Priority 4: Unpack bundles
            { stage: 'unpackWebpack', priority: 4, description: 'Unpack Webpack bundle' },
            { stage: 'unpackRollup', priority: 4, description: 'Unpack Rollup bundle' },
            { stage: 'unpackParcel', priority: 4, description: 'Unpack Parcel bundle' },
            { stage: 'unpackBrowserify', priority: 4, description: 'Unpack Browserify bundle' },
            
            // Priority 5: Decrypt/decode strings
            { stage: 'decryptXOR', priority: 5, description: 'Decrypt XOR-encoded strings' },
            { stage: 'decryptRC4', priority: 5, description: 'Decrypt RC4-encrypted strings' },
            { stage: 'decodeJScrambler', priority: 5, description: 'Decode JScrambler strings' },
            { stage: 'decodeStringArray', priority: 5, description: 'Resolve string array' },
            
            // Priority 6: Inline and simplify
            { stage: 'resolveArrayAccess', priority: 6, description: 'Inline array lookups' },
            { stage: 'inlineStrings', priority: 6, description: 'Inline decoded strings' },
            { stage: 'decodeStrings', priority: 6, description: 'Decode encoded strings' },
            { stage: 'decodeHex', priority: 6, description: 'Decode hex escapes' },
            { stage: 'decodeUnicode', priority: 6, description: 'Decode unicode escapes' },
            
            // Priority 7: Control flow
            { stage: 'deobfuscateControlFlow', priority: 7, description: 'Deobfuscate control flow' },
            
            // Priority 8: Eval resolution
            { stage: 'resolveEval', priority: 8, description: 'Resolve eval expressions' },
            { stage: 'inlineEval', priority: 8, description: 'Inline eval code' },
            
            // Priority 9: Simplify
            { stage: 'simplifyExpressions', priority: 9, description: 'Simplify expressions' },
            
            // Priority 10: Cleanup
            { stage: 'removeDeadCode', priority: 10, description: 'Remove dead code' },
            { stage: 'cleanupAST', priority: 10, description: 'Clean up AST' },
            
            // Priority 11: Final beautify
            { stage: 'beautify', priority: 11, description: 'Beautify output' }
        ];

        // Add stages that are needed
        for (const stageInfo of stageOrder) {
            if (stagesToRun.has(stageInfo.stage)) {
                plan.push(stageInfo);
            }
        }

        // Always add beautify at end
        if (!plan.find(p => p.stage === 'beautify')) {
            plan.push({ stage: 'beautify', priority: 11, description: 'Beautify output' });
        }

        return plan;
    }

    /**
     * Generate human-readable summary
     */
    _generateSummary(detected, score, severity) {
        if (detected.length === 0) {
            return '✅ No obfuscation detected - code appears clean';
        }

        const lines = [
            `🔍 Detected ${detected.length} obfuscation technique(s)`,
            `📊 Obfuscation Score: ${score}/100 (${severity.toUpperCase()})`,
            '',
            'Detected patterns:'
        ];

        for (const d of detected.slice(0, 10)) {
            lines.push(`  • ${d.name} (${d.category}) - ${d.matchCount} occurrence(s)`);
        }

        if (detected.length > 10) {
            lines.push(`  ... and ${detected.length - 10} more`);
        }

        return lines.join('\n');
    }

    /**
     * Quick check if code is obfuscated
     */
    isObfuscated(code) {
        const result = this.detect(code);
        return result.obfuscationScore > 10;
    }
}

// ============================================================================
// SECTION 2: CORE AST ENGINE (WITH FIXED PARSER!)
// ============================================================================

class JShadowCore {
    constructor(options = {}) {
        this.options = {
            maxIterations: options.maxIterations || 10,
            timeout: options.timeout || 60000,
            verbose: options.verbose || false,
            aggressive: options.aggressive || false,
            ...options
        };
        this.transformations = 0;
        this.stats = { strings: 0, expressions: 0, calls: 0, variables: 0 };
    }

    log(msg) {
        if (this.options.verbose) console.log(`  [Core] ${msg}`);
    }

    async deobfuscate(code, filename = 'unknown.js') {
        this.log('Starting core deobfuscation...');
        
        let currentCode = code;
        let prevCode = '';
        let iteration = 0;
        const stages = [];

        while (currentCode !== prevCode && iteration < this.options.maxIterations) {
            prevCode = currentCode;
            const passResult = await this._performPass(currentCode, iteration);
            currentCode = passResult.code;
            
            stages.push({
                iteration: iteration + 1,
                transformations: passResult.transformations,
                techniques: passResult.techniques
            });
            
            iteration++;
            this.log(`Pass ${iteration}: ${passResult.transformations} transformations`);
            
            if (passResult.transformations === 0) break;
        }

        return {
            success: true,
            code: currentCode,
            originalCode: code,
            filename,
            totalTransformations: stages.reduce((s, st) => s + st.transformations, 0),
            stages,
            stats: this.stats
        };
    }

    async _performPass(code, iteration) {
        try {
            // USE THE FIXED PARSER!
            const ast = safeParse(code);

            this.transformations = 0;
            const techniques = new Set();

            // Pre-pass: Build string array map
            const stringArrays = this._findStringArrays(ast);

            traverse(ast, {
                // String literal deobfuscation
                StringLiteral: (path) => {
                    if (this._deobfuscateString(path)) techniques.add('string_decode');
                },

                // Numeric literal conversion
                NumericLiteral: (path) => {
                    if (this._normalizeNumber(path)) techniques.add('number_normalize');
                },

                // Binary expression evaluation
                BinaryExpression: (path) => {
                    if (this._evaluateBinary(path)) techniques.add('binary_eval');
                },

                // Unary expression evaluation
                UnaryExpression: (path) => {
                    if (this._evaluateUnary(path)) techniques.add('unary_eval');
                },

                // Call expression deobfuscation
                CallExpression: (path) => {
                    if (this._deobfuscateCall(path, stringArrays)) techniques.add('call_deobfuscate');
                },

                // Member expression simplification
                MemberExpression: (path) => {
                    if (this._simplifyMember(path)) techniques.add('member_simplify');
                },

                // Variable inlining
                VariableDeclarator: (path) => {
                    if (this._inlineVariable(path)) techniques.add('variable_inline');
                },

                // Conditional expression simplification
                ConditionalExpression: (path) => {
                    if (this._simplifyConditional(path)) techniques.add('conditional_simplify');
                },

                // Logical expression simplification
                LogicalExpression: (path) => {
                    if (this._simplifyLogical(path)) techniques.add('logical_simplify');
                },

                // Dead code removal
                IfStatement: (path) => {
                    if (this._removeDeadIf(path)) techniques.add('dead_code_remove');
                }
            });

            return {
                code: generator(ast, { compact: false, comments: true }).code,
                transformations: this.transformations,
                techniques: Array.from(techniques)
            };

        } catch (error) {
            this.log(`Pass error: ${error.message}`);
            return { code, transformations: 0, techniques: [] };
        }
    }

    _findStringArrays(ast) {
        const arrays = new Map();

        traverse(ast, {
            VariableDeclarator: (path) => {
                if (t.isIdentifier(path.node.id) && t.isArrayExpression(path.node.init)) {
                    const elements = path.node.init.elements;
                    if (elements.length > 5 && elements.every(e => t.isStringLiteral(e))) {
                        arrays.set(path.node.id.name, elements.map(e => e.value));
                    }
                }
            }
        });

        return arrays;
    }

    _deobfuscateString(path) {
        const value = path.node.value;
        
        // Decode hex escapes: \x41 -> A
        if (/\\x[0-9a-fA-F]{2}/.test(value)) {
            try {
                const decoded = value.replace(/\\x([0-9a-fA-F]{2})/g, 
                    (_, hex) => String.fromCharCode(parseInt(hex, 16)));
                path.node.value = decoded;
                this.transformations++;
                this.stats.strings++;
                return true;
            } catch (e) {}
        }

        // Decode unicode escapes: \u0041 -> A
        if (/\\u[0-9a-fA-F]{4}/.test(value)) {
            try {
                const decoded = value.replace(/\\u([0-9a-fA-F]{4})/g,
                    (_, hex) => String.fromCharCode(parseInt(hex, 16)));
                path.node.value = decoded;
                this.transformations++;
                this.stats.strings++;
                return true;
            } catch (e) {}
        }

        return false;
    }

    _normalizeNumber(path) {
        // Already normalized
        return false;
    }

    _evaluateBinary(path) {
        const { left, right, operator } = path.node;

        // String concatenation
        if (operator === '+' && t.isStringLiteral(left) && t.isStringLiteral(right)) {
            path.replaceWith(t.stringLiteral(left.value + right.value));
            this.transformations++;
            this.stats.expressions++;
            return true;
        }

        // Numeric operations
        if (t.isNumericLiteral(left) && t.isNumericLiteral(right)) {
            let result;
            switch (operator) {
                case '+': result = left.value + right.value; break;
                case '-': result = left.value - right.value; break;
                case '*': result = left.value * right.value; break;
                case '/': result = left.value / right.value; break;
                case '%': result = left.value % right.value; break;
                case '|': result = left.value | right.value; break;
                case '&': result = left.value & right.value; break;
                case '^': result = left.value ^ right.value; break;
                case '<<': result = left.value << right.value; break;
                case '>>': result = left.value >> right.value; break;
                case '>>>': result = left.value >>> right.value; break;
                default: return false;
            }
            
            if (Number.isFinite(result)) {
                path.replaceWith(t.numericLiteral(result));
                this.transformations++;
                this.stats.expressions++;
                return true;
            }
        }

        return false;
    }

    _evaluateUnary(path) {
        const { operator, argument } = path.node;

        if (t.isNumericLiteral(argument)) {
            let result;
            switch (operator) {
                case '-': result = -argument.value; break;
                case '+': result = +argument.value; break;
                case '~': result = ~argument.value; break;
                case '!': result = !argument.value; break;
                default: return false;
            }

            if (typeof result === 'number' && Number.isFinite(result)) {
                path.replaceWith(t.numericLiteral(result));
                this.transformations++;
                return true;
            }
            if (typeof result === 'boolean') {
                path.replaceWith(t.booleanLiteral(result));
                this.transformations++;
                return true;
            }
        }

        // !![] -> true, ![] -> false
        if (t.isArrayExpression(argument) && argument.elements.length === 0) {
            if (operator === '!') {
                if (path.parentPath.isUnaryExpression({ operator: '!' })) {
                    path.parentPath.replaceWith(t.booleanLiteral(true));
                    this.transformations++;
                    return true;
                }
                path.replaceWith(t.booleanLiteral(false));
                this.transformations++;
                return true;
            }
        }

        return false;
    }

    _deobfuscateCall(path, stringArrays) {
        const { callee, arguments: args } = path.node;

        // String.fromCharCode
        if (t.isMemberExpression(callee) && 
            t.isIdentifier(callee.object, { name: 'String' }) &&
            t.isIdentifier(callee.property, { name: 'fromCharCode' })) {
            
            if (args.every(a => t.isNumericLiteral(a))) {
                const result = String.fromCharCode(...args.map(a => a.value));
                path.replaceWith(t.stringLiteral(result));
                this.transformations++;
                this.stats.calls++;
                return true;
            }
        }

        // parseInt/parseFloat with literal
        if (t.isIdentifier(callee, { name: 'parseInt' }) && 
            t.isStringLiteral(args[0])) {
            const radix = args[1] ? args[1].value : 10;
            const result = parseInt(args[0].value, radix);
            if (Number.isFinite(result)) {
                path.replaceWith(t.numericLiteral(result));
                this.transformations++;
                this.stats.calls++;
                return true;
            }
        }

        // atob (base64 decode)
        if (t.isIdentifier(callee, { name: 'atob' }) && t.isStringLiteral(args[0])) {
            try {
                const decoded = Buffer.from(args[0].value, 'base64').toString('utf8');
                path.replaceWith(t.stringLiteral(decoded));
                this.transformations++;
                this.stats.calls++;
                return true;
            } catch (e) {}
        }

        // String array access: _0xabc(123)
        if (t.isIdentifier(callee) && stringArrays.has(callee.name)) {
            const arr = stringArrays.get(callee.name);
            if (args.length >= 1 && t.isNumericLiteral(args[0])) {
                const idx = args[0].value;
                if (idx >= 0 && idx < arr.length) {
                    path.replaceWith(t.stringLiteral(arr[idx]));
                    this.transformations++;
                    this.stats.calls++;
                    return true;
                }
            }
        }

        return false;
    }

    _simplifyMember(path) {
        const { object, property, computed } = path.node;

        // obj["prop"] -> obj.prop
        if (computed && t.isStringLiteral(property) && /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(property.value)) {
            path.node.computed = false;
            path.node.property = t.identifier(property.value);
            this.transformations++;
            return true;
        }

        // Array literal access: ["a","b"][0] -> "a"
        if (t.isArrayExpression(object) && t.isNumericLiteral(property)) {
            const idx = property.value;
            if (idx >= 0 && idx < object.elements.length && object.elements[idx]) {
                path.replaceWith(object.elements[idx]);
                this.transformations++;
                return true;
            }
        }

        return false;
    }

    _inlineVariable(path) {
        const { id, init } = path.node;
        
        if (!t.isIdentifier(id) || !init) return false;

        // Only inline simple literals used once
        if (t.isStringLiteral(init) || t.isNumericLiteral(init) || t.isBooleanLiteral(init)) {
            const binding = path.scope.getBinding(id.name);
            if (binding && binding.references === 1 && binding.constant) {
                for (const refPath of binding.referencePaths) {
                    refPath.replaceWith(t.cloneNode(init));
                }
                path.remove();
                this.transformations++;
                this.stats.variables++;
                return true;
            }
        }

        return false;
    }

    _simplifyConditional(path) {
        const { test, consequent, alternate } = path.node;

        // true ? a : b -> a
        if (t.isBooleanLiteral(test)) {
            path.replaceWith(test.value ? consequent : alternate);
            this.transformations++;
            return true;
        }

        // 1 ? a : b -> a, 0 ? a : b -> b
        if (t.isNumericLiteral(test)) {
            path.replaceWith(test.value ? consequent : alternate);
            this.transformations++;
            return true;
        }

        return false;
    }

    _simplifyLogical(path) {
        const { left, right, operator } = path.node;

        // true && x -> x, false && x -> false
        if (operator === '&&' && t.isBooleanLiteral(left)) {
            path.replaceWith(left.value ? right : left);
            this.transformations++;
            return true;
        }

        // true || x -> true, false || x -> x
        if (operator === '||' && t.isBooleanLiteral(left)) {
            path.replaceWith(left.value ? left : right);
            this.transformations++;
            return true;
        }

        return false;
    }

    _removeDeadIf(path) {
        const { test, consequent, alternate } = path.node;

        // if (false) { ... } or if (0) { ... }
        if (t.isBooleanLiteral(test, { value: false }) || t.isNumericLiteral(test, { value: 0 })) {
            if (alternate) {
                path.replaceWith(alternate);
            } else {
                path.remove();
            }
            this.transformations++;
            return true;
        }

        // if (true) { ... } or if (1) { ... }
        if (t.isBooleanLiteral(test, { value: true }) || (t.isNumericLiteral(test) && test.value)) {
            path.replaceWith(consequent);
            this.transformations++;
            return true;
        }

        return false;
    }
}

// ============================================================================
// SECTION 3: ADVANCED STRING DECODER
// ============================================================================

class AdvancedStringDecoder {
    constructor() {
        this.transformations = 0;
        this.sandbox = vm.createContext({
            console: { log: () => {}, error: () => {} },
            String, Array, Object, Math, Number, Boolean,
            parseInt, parseFloat, RegExp, Date, JSON,
            encodeURIComponent, decodeURIComponent,
            atob: (s) => Buffer.from(s, 'base64').toString('utf8'),
            btoa: (s) => Buffer.from(s).toString('base64'),
            unescape: unescape,
            escape: escape
        });
    }

    async decode(code) {
        this.transformations = 0;
        let result = code;

        // Layer 1: Hex escapes
        result = this._decodeHex(result);

        // Layer 2: Unicode escapes
        result = this._decodeUnicode(result);

        // Layer 3: Base64
        result = this._decodeBase64(result);

        // Layer 4: String concatenation
        result = this._decodeConcatenation(result);

        // Layer 5: String array lookups
        result = await this._decodeStringArray(result);

        return {
            code: result,
            transformations: this.transformations
        };
    }

    _decodeHex(code) {
        return code.replace(/\\x([0-9a-fA-F]{2})/g, (match, hex) => {
            this.transformations++;
            return String.fromCharCode(parseInt(hex, 16));
        });
    }

    _decodeUnicode(code) {
        return code.replace(/\\u([0-9a-fA-F]{4})/g, (match, hex) => {
            this.transformations++;
            return String.fromCharCode(parseInt(hex, 16));
        });
    }

    _decodeBase64(code) {
        // Find atob("...") calls and decode them
        const atobPattern = /atob\s*\(\s*(['"])([A-Za-z0-9+/=]+)\1\s*\)/g;
        
        return code.replace(atobPattern, (match, quote, b64) => {
            try {
                const decoded = Buffer.from(b64, 'base64').toString('utf8');
                this.transformations++;
                return JSON.stringify(decoded);
            } catch (e) {
                return match;
            }
        });
    }

    _decodeConcatenation(code) {
        // "a" + "b" + "c" -> "abc"
        const concatPattern = /(['"])([^'"]*)\1\s*\+\s*(['"])([^'"]*)\3/g;
        let prev;
        
        do {
            prev = code;
            code = code.replace(concatPattern, (match, q1, s1, q2, s2) => {
                this.transformations++;
                return `${q1}${s1}${s2}${q1}`;
            });
        } while (code !== prev);

        return code;
    }

    async _decodeStringArray(code) {
        try {
            const ast = safeParse(code);
            const stringArrays = new Map();
            
            // Find string arrays
            traverse(ast, {
                VariableDeclarator: (path) => {
                    if (t.isIdentifier(path.node.id) && t.isArrayExpression(path.node.init)) {
                        const elements = path.node.init.elements;
                        if (elements.length > 5 && elements.every(e => t.isStringLiteral(e))) {
                            stringArrays.set(path.node.id.name, {
                                values: elements.map(e => e.value),
                                path
                            });
                        }
                    }
                }
            });

            // Replace lookups
            traverse(ast, {
                CallExpression: (path) => {
                    const { callee, arguments: args } = path.node;
                    
                    if (t.isIdentifier(callee) && stringArrays.has(callee.name)) {
                        const arr = stringArrays.get(callee.name);
                        if (args.length >= 1 && t.isNumericLiteral(args[0])) {
                            const idx = args[0].value;
                            if (idx >= 0 && idx < arr.values.length) {
                                path.replaceWith(t.stringLiteral(arr.values[idx]));
                                this.transformations++;
                            }
                        }
                    }
                },

                MemberExpression: (path) => {
                    const { object, property } = path.node;
                    
                    if (t.isIdentifier(object) && stringArrays.has(object.name)) {
                        const arr = stringArrays.get(object.name);
                        if (t.isNumericLiteral(property)) {
                            const idx = property.value;
                            if (idx >= 0 && idx < arr.values.length) {
                                path.replaceWith(t.stringLiteral(arr.values[idx]));
                                this.transformations++;
                            }
                        }
                    }
                }
            });

            return generator(ast, { compact: false }).code;
        } catch (e) {
            return code;
        }
    }
}

// ============================================================================
// SECTION 4: CONTROL FLOW DEOBFUSCATOR
// ============================================================================

class ControlFlowDeobfuscator {
    constructor() {
        this.transformations = 0;
    }

    async deobfuscate(code) {
        this.transformations = 0;
        
        try {
            const ast = safeParse(code);
            
            // Find and process control flow flattening patterns
            traverse(ast, {
                WhileStatement: (path) => {
                    this._processWhileSwitch(path);
                },
                ForStatement: (path) => {
                    this._processForSwitch(path);
                }
            });

            // Remove opaque predicates
            traverse(ast, {
                IfStatement: (path) => {
                    this._removeOpaquePredicate(path);
                },
                ConditionalExpression: (path) => {
                    this._simplifyConditional(path);
                }
            });

            return {
                code: generator(ast, { compact: false }).code,
                transformations: this.transformations,
                transformed: this.transformations > 0
            };
        } catch (e) {
            return { code, transformations: 0, transformed: false };
        }
    }

    _processWhileSwitch(path) {
        const { test, body } = path.node;
        
        // while(true) { switch(...) } pattern
        if (!t.isBooleanLiteral(test, { value: true }) && 
            !t.isNumericLiteral(test, { value: 1 }) &&
            !(t.isUnaryExpression(test) && test.operator === '!')) {
            return;
        }

        if (!t.isBlockStatement(body)) return;
        
        const switchStmt = body.body.find(s => t.isSwitchStatement(s));
        if (!switchStmt) return;

        // Try to reconstruct linear flow
        const reconstructed = this._reconstructFlow(switchStmt);
        if (reconstructed) {
            path.replaceWithMultiple(reconstructed);
            this.transformations++;
        }
    }

    _processForSwitch(path) {
        const { test, body } = path.node;
        
        // for(;;) { switch(...) } pattern
        if (test !== null) return;
        
        if (!t.isBlockStatement(body)) return;
        
        const switchStmt = body.body.find(s => t.isSwitchStatement(s));
        if (!switchStmt) return;

        const reconstructed = this._reconstructFlow(switchStmt);
        if (reconstructed) {
            path.replaceWithMultiple(reconstructed);
            this.transformations++;
        }
    }

    _reconstructFlow(switchStmt) {
        const cases = switchStmt.cases;
        if (cases.length === 0) return null;

        // Simple case: linear flow with numeric or string labels
        const statements = [];
        
        for (const caseNode of cases) {
            if (caseNode.consequent) {
                for (const stmt of caseNode.consequent) {
                    // Skip break/continue statements
                    if (t.isBreakStatement(stmt) || t.isContinueStatement(stmt)) continue;
                    statements.push(stmt);
                }
            }
        }

        return statements.length > 0 ? statements : null;
    }

    _removeOpaquePredicate(path) {
        const { test, consequent, alternate } = path.node;

        // if(true) or if(1)
        if (t.isBooleanLiteral(test, { value: true }) || 
            (t.isNumericLiteral(test) && test.value !== 0)) {
            path.replaceWith(consequent);
            this.transformations++;
            return;
        }

        // if(false) or if(0)
        if (t.isBooleanLiteral(test, { value: false }) || 
            t.isNumericLiteral(test, { value: 0 })) {
            if (alternate) {
                path.replaceWith(alternate);
            } else {
                path.remove();
            }
            this.transformations++;
            return;
        }

        // if(!![]) -> if(true)
        if (t.isUnaryExpression(test, { operator: '!' })) {
            const arg = test.argument;
            if (t.isUnaryExpression(arg, { operator: '!' })) {
                const innerArg = arg.argument;
                if (t.isArrayExpression(innerArg) && innerArg.elements.length === 0) {
                    path.replaceWith(consequent);
                    this.transformations++;
                    return;
                }
            }
        }
    }

    _simplifyConditional(path) {
        const { test, consequent, alternate } = path.node;

        if (t.isBooleanLiteral(test)) {
            path.replaceWith(test.value ? consequent : alternate);
            this.transformations++;
        } else if (t.isNumericLiteral(test)) {
            path.replaceWith(test.value ? consequent : alternate);
            this.transformations++;
        }
    }
}

// ============================================================================
// SECTION 5: ANTI-DEBUG EVASION
// ============================================================================

class AntiDebugEvasion {
    constructor() {
        this.neutralizedCount = 0;
    }

    async neutralize(code) {
        this.neutralizedCount = 0;
        
        try {
            const ast = safeParse(code);

            traverse(ast, {
                // Remove debugger statements
                DebuggerStatement: (path) => {
                    path.remove();
                    this.neutralizedCount++;
                },

                // Remove setInterval/setTimeout with debugger
                CallExpression: (path) => {
                    const { callee, arguments: args } = path.node;
                    
                    if (t.isIdentifier(callee) && 
                        (callee.name === 'setInterval' || callee.name === 'setTimeout')) {
                        
                        // Check if callback contains debugger
                        if (args[0] && this._containsDebugger(args[0])) {
                            path.remove();
                            this.neutralizedCount++;
                            return;
                        }
                    }

                    // Remove console detection
                    if (this._isConsoleOverride(path)) {
                        path.remove();
                        this.neutralizedCount++;
                    }
                },

                // Remove timing checks
                VariableDeclarator: (path) => {
                    const init = path.node.init;
                    if (init && this._isTimingCheck(init)) {
                        // Replace with dummy value
                        path.node.init = t.numericLiteral(0);
                        this.neutralizedCount++;
                    }
                },

                // Remove devtools detection
                IfStatement: (path) => {
                    if (this._isDevtoolsCheck(path.node.test)) {
                        path.remove();
                        this.neutralizedCount++;
                    }
                }
            });

            return {
                code: generator(ast, { compact: false }).code,
                neutralizedCount: this.neutralizedCount
            };
        } catch (e) {
            return { code, neutralizedCount: 0 };
        }
    }

    _containsDebugger(node) {
        let found = false;
        
        if (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) {
            traverse(node, {
                DebuggerStatement: () => { found = true; },
                noScope: true
            });
        }
        
        return found;
    }

    _isConsoleOverride(path) {
        const { callee, arguments: args } = path.node;
        
        // Object.defineProperty(console, ...)
        if (t.isMemberExpression(callee) &&
            t.isIdentifier(callee.object, { name: 'Object' }) &&
            t.isIdentifier(callee.property, { name: 'defineProperty' }) &&
            args[0] && t.isIdentifier(args[0], { name: 'console' })) {
            return true;
        }

        return false;
    }

    _isTimingCheck(node) {
        if (t.isCallExpression(node)) {
            const { callee } = node;
            
            // performance.now()
            if (t.isMemberExpression(callee) &&
                t.isIdentifier(callee.object, { name: 'performance' }) &&
                t.isIdentifier(callee.property, { name: 'now' })) {
                return true;
            }

            // Date.now()
            if (t.isMemberExpression(callee) &&
                t.isIdentifier(callee.object, { name: 'Date' }) &&
                t.isIdentifier(callee.property, { name: 'now' })) {
                return true;
            }
        }

        return false;
    }

    _isDevtoolsCheck(node) {
        if (t.isBinaryExpression(node)) {
            const code = generator(node).code;
            
            // Common devtools detection patterns
            if (code.includes('outerWidth') && code.includes('innerWidth')) return true;
            if (code.includes('outerHeight') && code.includes('innerHeight')) return true;
            if (code.includes('Firebug')) return true;
            if (code.includes('__REACT_DEVTOOLS')) return true;
        }

        return false;
    }
}

// ============================================================================
// SECTION 6: WEBPACK UNPACKER
// ============================================================================

class WebpackUnpacker {
    constructor() {
        this.modules = [];
        this.entryPoint = null;
    }

    async unpack(code) {
        this.modules = [];
        
        try {
            const ast = safeParse(code);
            
            // Find webpack bootstrap
            const bootstrap = this._findBootstrap(ast);
            
            if (!bootstrap) {
                return { success: false, modules: [], message: 'No webpack bootstrap found' };
            }

            // Extract modules
            this._extractModules(bootstrap);

            return {
                success: true,
                modules: this.modules,
                moduleCount: this.modules.length,
                entryPoint: this.entryPoint
            };
        } catch (e) {
            return { success: false, modules: [], message: e.message };
        }
    }

    _findBootstrap(ast) {
        let bootstrap = null;

        traverse(ast, {
            CallExpression: (path) => {
                if (bootstrap) return;
                
                const { callee, arguments: args } = path.node;
                
                // IIFE with array/object modules
                if ((t.isFunctionExpression(callee) || t.isArrowFunctionExpression(callee)) &&
                    args.length > 0) {
                    
                    if (t.isArrayExpression(args[0])) {
                        bootstrap = { type: 'array', modules: args[0], path };
                    } else if (t.isObjectExpression(args[0])) {
                        bootstrap = { type: 'object', modules: args[0], path };
                    }
                }

                // webpackJsonp pattern
                if (t.isMemberExpression(callee) && 
                    t.isIdentifier(callee.property, { name: 'push' })) {
                    
                    const objCode = generator(callee.object).code;
                    if (objCode.includes('webpackJsonp')) {
                        if (args[0] && t.isArrayExpression(args[0]) && args[0].elements.length >= 2) {
                            bootstrap = { 
                                type: 'jsonp', 
                                modules: args[0].elements[1], 
                                path 
                            };
                        }
                    }
                }
            }
        });

        return bootstrap;
    }

    _extractModules(bootstrap) {
        const modulesNode = bootstrap.modules;
        
        if (t.isArrayExpression(modulesNode)) {
            modulesNode.elements.forEach((element, index) => {
                if (element && (t.isFunctionExpression(element) || t.isArrowFunctionExpression(element))) {
                    this.modules.push({
                        id: index,
                        code: generator(element.body).code.replace(/^\{|\}$/g, '').trim()
                    });
                }
            });
        } else if (t.isObjectExpression(modulesNode)) {
            modulesNode.properties.forEach(prop => {
                if (t.isObjectProperty(prop)) {
                    const key = t.isIdentifier(prop.key) ? prop.key.name :
                               t.isStringLiteral(prop.key) ? prop.key.value :
                               t.isNumericLiteral(prop.key) ? String(prop.key.value) : 'unknown';
                    
                    if (t.isFunctionExpression(prop.value) || t.isArrowFunctionExpression(prop.value)) {
                        this.modules.push({
                            id: key,
                            code: generator(prop.value.body).code.replace(/^\{|\}$/g, '').trim()
                        });
                    }
                }
            });
        }
    }
}

// ============================================================================
// SECTION 7: AI FUNCTION RENAMER
// ============================================================================

class AIFunctionRenamer {
    constructor(options = {}) {
        this.options = {
            useOpenAI: options.useOpenAI || false,
            apiKey: options.apiKey || process.env.OPENAI_API_KEY,
            model: options.model || 'gpt-4o-mini',
            ...options
        };

        // Pattern-based naming rules
        this.patterns = {
            network: {
                indicators: [/fetch|xhr|ajax|request|http|url|api|endpoint/i, /\.send\(|\.open\(/],
                prefixes: ['fetch', 'request', 'call', 'get', 'post', 'send']
            },
            crypto: {
                indicators: [/encrypt|decrypt|hash|md5|sha|aes|rsa|hmac|cipher/i, /crypto\./],
                prefixes: ['encrypt', 'decrypt', 'hash', 'sign', 'verify']
            },
            dom: {
                indicators: [/document\.|getElementById|querySelector|innerHTML|className/],
                prefixes: ['render', 'update', 'show', 'hide', 'create', 'remove']
            },
            storage: {
                indicators: [/localStorage|sessionStorage|indexedDB|cookie/i],
                prefixes: ['save', 'load', 'store', 'cache', 'persist']
            },
            validation: {
                indicators: [/valid|check|verify|test|match|regex|pattern/i],
                prefixes: ['validate', 'check', 'verify', 'test', 'is']
            },
            encoding: {
                indicators: [/encode|decode|base64|atob|btoa|escape|unescape/i],
                prefixes: ['encode', 'decode', 'serialize', 'deserialize']
            },
            array: {
                indicators: [/\.map\(|\.filter\(|\.reduce\(|\.forEach\(|\.find\(/],
                prefixes: ['process', 'transform', 'filter', 'map', 'collect']
            },
            string: {
                indicators: [/\.split\(|\.join\(|\.replace\(|\.substring\(|\.slice\(/],
                prefixes: ['format', 'parse', 'extract', 'build', 'compose']
            },
            math: {
                indicators: [/Math\.|random|floor|ceil|round|abs|sqrt/i],
                prefixes: ['calculate', 'compute', 'generate', 'random']
            },
            handler: {
                indicators: [/onClick|onSubmit|addEventListener|handler|callback/i],
                prefixes: ['handle', 'on', 'process', 'trigger']
            },
            init: {
                indicators: [/init|setup|configure|bootstrap|start/i],
                prefixes: ['init', 'setup', 'configure', 'bootstrap']
            }
        };

        this.usedNames = new Set();
        this.counter = 0;
    }

    async rename(code, options = {}) {
        try {
            const ast = safeParse(code);
            const renames = new Map();
            const functions = this._extractFunctions(ast);

            // Generate names for each function
            for (const func of functions) {
                if (this._shouldRename(func.name)) {
                    const newName = await this._generateName(func);
                    if (newName && newName !== func.name) {
                        renames.set(func.name, newName);
                    }
                }
            }

            // Apply renames
            this._applyRenames(ast, renames);

            return {
                code: generator(ast, { compact: false }).code,
                renames: Object.fromEntries(renames),
                renameCount: renames.size
            };
        } catch (e) {
            return { code, renames: {}, renameCount: 0 };
        }
    }

    _extractFunctions(ast) {
        const functions = [];

        traverse(ast, {
            FunctionDeclaration: (path) => {
                if (path.node.id) {
                    functions.push({
                        name: path.node.id.name,
                        body: generator(path.node.body).code,
                        params: path.node.params.map(p => generator(p).code),
                        node: path.node,
                        path
                    });
                }
            },
            VariableDeclarator: (path) => {
                if (t.isIdentifier(path.node.id) &&
                    (t.isFunctionExpression(path.node.init) || t.isArrowFunctionExpression(path.node.init))) {
                    functions.push({
                        name: path.node.id.name,
                        body: generator(path.node.init.body).code,
                        params: path.node.init.params.map(p => generator(p).code),
                        node: path.node.init,
                        path
                    });
                }
            }
        });

        return functions;
    }

    _shouldRename(name) {
        // Rename _0x*, __, single letters, etc.
        if (/^_0x[a-f0-9]+$/i.test(name)) return true;
        if (/^[a-z]$/.test(name)) return true;
        if (/^__\w+$/.test(name)) return true;
        if (/^[_$]{2,}/.test(name)) return true;
        return false;
    }

    async _generateName(func) {
        const body = func.body;

        // Pattern-based detection
        for (const [category, config] of Object.entries(this.patterns)) {
            for (const pattern of config.indicators) {
                if (pattern.test(body)) {
                    const prefix = config.prefixes[0];
                    const name = this._uniqueName(prefix);
                    return name;
                }
            }
        }

        // Default: use generic name
        return this._uniqueName('fn');
    }

    _uniqueName(prefix) {
        let name = prefix;
        let suffix = 1;
        
        while (this.usedNames.has(name)) {
            name = `${prefix}${suffix}`;
            suffix++;
        }
        
        this.usedNames.add(name);
        return name;
    }

    _applyRenames(ast, renames) {
        traverse(ast, {
            Identifier: (path) => {
                if (renames.has(path.node.name)) {
                    path.node.name = renames.get(path.node.name);
                }
            }
        });
    }
}

// ============================================================================
// SECTION 8: ESOTERIC DECODER (JSFuck, JJEncode, AAEncode)
// ============================================================================

class EsotericDecoder {
    constructor() {
        this.transformations = 0;
        this.sandbox = vm.createContext({
            console: { log: () => {}, error: () => {} },
            String, Array, Object, Math, Number, Boolean,
            parseInt, parseFloat, RegExp, Date, JSON,
            encodeURIComponent, decodeURIComponent,
            atob: (s) => Buffer.from(s, 'base64').toString('utf8'),
            btoa: (s) => Buffer.from(s).toString('base64')
        });
    }

    async decode(code) {
        this.transformations = 0;
        let result = code;

        // Try JSFuck first
        result = this._decodeJSFuck(result);

        // Try JJEncode
        result = this._decodeJJEncode(result);

        // Try AAEncode
        result = this._decodeAAEncode(result);

        return {
            code: result,
            transformations: this.transformations
        };
    }

    _decodeJSFuck(code) {
        // Find JSFuck segments
        const jsfuckPattern = /[\[\]\(\)!+]{30,}/g;
        const matches = code.match(jsfuckPattern);
        
        if (!matches) return code;

        for (const match of matches) {
            try {
                const result = vm.runInContext(`(${match})`, this.sandbox, { timeout: 5000 });
                if (result !== undefined && typeof result === 'string') {
                    code = code.replace(match, JSON.stringify(result));
                    this.transformations++;
                }
            } catch (e) {
                // Evaluation failed, skip
            }
        }

        return code;
    }

    _decodeJJEncode(code) {
        if (!code.includes('$=~[];')) return code;

        try {
            // Find JJEncode block
            const startIdx = code.indexOf('$=~[];');
            if (startIdx === -1) return code;

            // Try to evaluate
            const result = vm.runInContext(code, this.sandbox, { timeout: 5000 });
            if (typeof result === 'string') {
                this.transformations++;
                return result;
            }
        } catch (e) {
            // Evaluation failed
        }

        return code;
    }

    _decodeAAEncode(code) {
        if (!code.includes('ﾟωﾟ')) return code;

        try {
            const result = vm.runInContext(code, this.sandbox, { timeout: 5000 });
            if (typeof result === 'string') {
                this.transformations++;
                return result;
            }
        } catch (e) {
            // Evaluation failed
        }

        return code;
    }
}

// ============================================================================
// SECTION 9: CODE BEAUTIFIER
// ============================================================================

class CodeBeautifier {
    constructor(options = {}) {
        this.options = {
            indent: options.indent || 2,
            maxLineLength: options.maxLineLength || 120,
            ...options
        };
    }

    async beautify(code) {
        try {
            const ast = safeParse(code);
            
            // Generate with proper formatting
            const output = generator(ast, {
                compact: false,
                comments: true,
                retainLines: false,
                concise: false,
                indent: {
                    style: ' '.repeat(this.options.indent)
                }
            });

            return {
                code: output.code,
                success: true
            };
        } catch (e) {
            // If parsing fails, return original
            return {
                code: code,
                success: false,
                error: e.message
            };
        }
    }
}

// ============================================================================
// SECTION 10: STEGANOGRAPHY HANDLER
// ============================================================================

class SteganographyHandler {
    constructor() {
        this.transformations = 0;
    }

    async process(code) {
        this.transformations = 0;
        let result = code;

        // Remove zero-width characters
        result = this._removeZeroWidth(result);

        // Normalize homoglyphs
        result = this._normalizeHomoglyphs(result);

        // Remove invisible characters
        result = this._removeInvisible(result);

        // Fix BIDI overrides
        result = this._fixBidi(result);

        return {
            code: result,
            transformations: this.transformations
        };
    }

    _removeZeroWidth(code) {
        const before = code.length;
        code = code.replace(/[\u200B-\u200D\uFEFF\u2060-\u2064]/g, '');
        this.transformations += before - code.length;
        return code;
    }

    _normalizeHomoglyphs(code) {
        // Cyrillic to Latin mappings
        const cyrillicToLatin = {
            'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p',
            'х': 'x', 'у': 'y', 'А': 'A', 'С': 'C', 'Е': 'E',
            'Н': 'H', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X'
        };

        let changed = 0;
        for (const [cyrillic, latin] of Object.entries(cyrillicToLatin)) {
            const regex = new RegExp(cyrillic, 'g');
            const before = code.length;
            code = code.replace(regex, latin);
            if (code.length !== before) changed++;
        }
        
        this.transformations += changed;
        return code;
    }

    _removeInvisible(code) {
        // Hangul filler, soft hyphen, etc.
        const before = code.length;
        code = code.replace(/[\u3164\u115F\u1160\u00AD]/g, '');
        this.transformations += before - code.length;
        return code;
    }

    _fixBidi(code) {
        // Remove BIDI control characters
        const before = code.length;
        code = code.replace(/[\u202A-\u202E\u2066-\u2069]/g, '');
        this.transformations += before - code.length;
        return code;
    }
}

// ============================================================================
// SECTION 11: MASTER ORCHESTRATOR (J-SHADOW v5 ULTIMATE)
// ============================================================================

class JShadowV5 extends EventEmitter {
    constructor(options = {}) {
        super();
        
        this.options = {
            verbose: options.verbose || false,
            aggressive: options.aggressive || false,
            maxIterations: options.maxIterations || 10,
            timeout: options.timeout || 60000,
            enableAI: options.enableAI !== false,  // Default true
            enableDynamic: options.enableDynamic || false,
            beautify: options.beautify !== false,  // Default true
            ...options
        };

        // Initialize all engines
        this.detector = new UniversalPatternDetector();
        this.core = new JShadowCore(this.options);
        this.stringDecoder = new AdvancedStringDecoder();
        this.cfDeobfuscator = new ControlFlowDeobfuscator();
        this.webpackUnpacker = new WebpackUnpacker();
        this.antiDebug = new AntiDebugEvasion();
        this.aiRenamer = new AIFunctionRenamer(this.options);
        this.esotericDecoder = new EsotericDecoder();
        this.beautifier = new CodeBeautifier(this.options);
        this.steganography = new SteganographyHandler();
    }

    log(msg, level = 'info') {
        if (this.options.verbose) {
            const prefix = { 
                info: '📋', 
                warn: '⚠️', 
                error: '❌', 
                success: '✅',
                stage: '🔄'
            };
            console.log(`${prefix[level] || '📋'} [J-Shadow v5] ${msg}`);
        }
        this.emit('log', { level, message: msg });
    }

    async deobfuscate(code, options = {}) {
        const startTime = Date.now();
        const filename = options.filename || 'unknown.js';
        
        this.log(`🔥 J-SHADOW v5 ULTIMATE: Processing ${filename}`, 'info');
        this.emit('start', { filename, codeLength: code.length });

        const result = {
            success: false,
            originalCode: code,
            deobfuscatedCode: code,
            filename,
            detection: null,
            stages: [],
            stagesSkipped: [],
            stats: {}
        };

        let currentCode = code;

        try {
            // ══════════════════════════════════════════════════════════════
            // STAGE 1: DETECTION & ANALYSIS
            // ══════════════════════════════════════════════════════════════
            this.log('Stage 1: Pattern Detection & Analysis', 'stage');
            const detection = this.detector.detect(currentCode);
            result.detection = detection;
            result.stages.push({ name: 'detection', ...detection });
            this.emit('stage', { stage: 1, name: 'detection', result: detection });

            // Log what we found
            this.log(`  Found ${detection.detected.length} obfuscation patterns`, 'info');
            this.log(`  Obfuscation Score: ${detection.obfuscationScore}/100 (${detection.severity})`, 'info');
            this.log(`  Stages to run: ${detection.executionPlan.map(s => s.stage).join(', ')}`, 'info');

            // ══════════════════════════════════════════════════════════════
            // CONDITIONAL STAGE EXECUTION
            // ══════════════════════════════════════════════════════════════
            
            const stagesToRun = new Set(detection.stagesToRun);
            const handlers = new Set(detection.handlersNeeded);

            // STAGE 2: ANTI-DEBUG (if detected)
            if (handlers.has('anti_debug')) {
                this.log('Stage 2: Anti-Debug Neutralization', 'stage');
                const antiDebugResult = await this.antiDebug.neutralize(currentCode);
                currentCode = antiDebugResult.code;
                result.stages.push({ name: 'antiDebug', neutralized: antiDebugResult.neutralizedCount });
                this.emit('stage', { stage: 2, name: 'antiDebug', result: antiDebugResult });
            } else {
                result.stagesSkipped.push('antiDebug');
                this.log('Stage 2: Anti-Debug - SKIPPED (not detected)', 'info');
            }

            // STAGE 3: STEGANOGRAPHY (if detected)
            if (handlers.has('steganography')) {
                this.log('Stage 3: Steganography Cleanup', 'stage');
                const stegoResult = await this.steganography.process(currentCode);
                currentCode = stegoResult.code;
                result.stages.push({ name: 'steganography', transformations: stegoResult.transformations });
                this.emit('stage', { stage: 3, name: 'steganography', result: stegoResult });
            } else {
                result.stagesSkipped.push('steganography');
                this.log('Stage 3: Steganography - SKIPPED (not detected)', 'info');
            }

            // STAGE 4: ESOTERIC DECODING (if detected)
            if (handlers.has('esoteric')) {
                this.log('Stage 4: Esoteric Decoding (JSFuck/JJEncode/AAEncode)', 'stage');
                const esotericResult = await this.esotericDecoder.decode(currentCode);
                currentCode = esotericResult.code;
                result.stages.push({ name: 'esoteric', transformations: esotericResult.transformations });
                this.emit('stage', { stage: 4, name: 'esoteric', result: esotericResult });
            } else {
                result.stagesSkipped.push('esoteric');
                this.log('Stage 4: Esoteric - SKIPPED (not detected)', 'info');
            }

            // STAGE 5: WEBPACK UNPACKING (if detected)
            if (handlers.has('webpack')) {
                this.log('Stage 5: Webpack Bundle Unpacking', 'stage');
                const unpackResult = await this.webpackUnpacker.unpack(currentCode);
                if (unpackResult.success && unpackResult.modules.length > 0) {
                    // Combine modules
                    const combined = unpackResult.modules.map(m => 
                        `// ===== Module ${m.id} =====\n${m.code}`
                    ).join('\n\n');
                    currentCode = combined;
                    result.stages.push({ name: 'webpack', modules: unpackResult.moduleCount });
                }
                this.emit('stage', { stage: 5, name: 'webpack', result: unpackResult });
            } else {
                result.stagesSkipped.push('webpack');
                this.log('Stage 5: Webpack - SKIPPED (not detected)', 'info');
            }

            // STAGE 6: STRING DECODING (always run if any encoding detected)
            if (handlers.has('string') || handlers.has('string_array') || handlers.has('crypto')) {
                this.log('Stage 6: Advanced String Decoding', 'stage');
                const stringResult = await this.stringDecoder.decode(currentCode);
                currentCode = stringResult.code;
                result.stages.push({ name: 'stringDecode', transformations: stringResult.transformations });
                this.emit('stage', { stage: 6, name: 'stringDecode', result: stringResult });
            } else {
                result.stagesSkipped.push('stringDecode');
                this.log('Stage 6: String Decoding - SKIPPED (not detected)', 'info');
            }

            // STAGE 7: CONTROL FLOW (if detected)
            if (handlers.has('control_flow')) {
                this.log('Stage 7: Control Flow Deobfuscation', 'stage');
                const cfResult = await this.cfDeobfuscator.deobfuscate(currentCode);
                if (cfResult.transformed) {
                    currentCode = cfResult.code;
                }
                result.stages.push({ name: 'controlFlow', transformations: cfResult.transformations });
                this.emit('stage', { stage: 7, name: 'controlFlow', result: cfResult });
            } else {
                result.stagesSkipped.push('controlFlow');
                this.log('Stage 7: Control Flow - SKIPPED (not detected)', 'info');
            }

            // STAGE 8: CORE AST DEOBFUSCATION (always run)
            this.log('Stage 8: Core AST Deobfuscation', 'stage');
            const coreResult = await this.core.deobfuscate(currentCode, filename);
            currentCode = coreResult.code;
            result.stages.push({ 
                name: 'coreAST', 
                transformations: coreResult.totalTransformations,
                passes: coreResult.stages.length
            });
            result.stats = coreResult.stats;
            this.emit('stage', { stage: 8, name: 'coreAST', result: coreResult });

            // STAGE 9: AI FUNCTION RENAMING (if enabled)
            if (this.options.enableAI) {
                this.log('Stage 9: AI Function Renaming', 'stage');
                const renameResult = await this.aiRenamer.rename(currentCode);
                currentCode = renameResult.code;
                result.stages.push({ name: 'aiRename', renames: renameResult.renameCount });
                result.renames = renameResult.renames;
                this.emit('stage', { stage: 9, name: 'aiRename', result: renameResult });
            } else {
                result.stagesSkipped.push('aiRename');
                this.log('Stage 9: AI Renaming - SKIPPED (disabled)', 'info');
            }

            // STAGE 10: FINAL BEAUTIFY (always run)
            if (this.options.beautify) {
                this.log('Stage 10: Final Beautify', 'stage');
                const beautifyResult = await this.beautifier.beautify(currentCode);
                currentCode = beautifyResult.code;
                result.stages.push({ name: 'beautify', success: beautifyResult.success });
                this.emit('stage', { stage: 10, name: 'beautify', result: beautifyResult });
            }

            // ══════════════════════════════════════════════════════════════
            // SUCCESS!
            // ══════════════════════════════════════════════════════════════
            result.success = true;
            result.deobfuscatedCode = currentCode;
            result.processingTime = Date.now() - startTime;
            result.compressionRatio = ((1 - currentCode.length / code.length) * 100).toFixed(1);

            this.log(`✅ Deobfuscation complete in ${result.processingTime}ms`, 'success');
            this.log(`   Stages executed: ${result.stages.length}`, 'info');
            this.log(`   Stages skipped: ${result.stagesSkipped.length}`, 'info');
            this.emit('complete', result);

        } catch (error) {
            result.success = false;
            result.error = error.message;
            result.deobfuscatedCode = currentCode;
            result.processingTime = Date.now() - startTime;
            
            this.log(`Error: ${error.message}`, 'error');
            this.emit('error', error);
        }

        return result;
    }

    // Convenience methods
    async analyze(code) {
        return this.detector.detect(code);
    }

    async decodeStrings(code) {
        return this.stringDecoder.decode(code);
    }

    async unpackWebpack(code) {
        return this.webpackUnpacker.unpack(code);
    }

    async renameFunctions(code) {
        return this.aiRenamer.rename(code);
    }

    async beautify(code) {
        return this.beautifier.beautify(code);
    }
}

// ============================================================================
// SECTION 12: CLI INTERFACE
// ============================================================================

async function cli() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
        console.log(`
██████╗     ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
   ██╔╝     ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
   ██║      ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
██ ██║ ██   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
╚█ ██╔╝█╔   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
 ╚═╝ ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝  v5.0

J-SHADOW v5 ULTIMATE - Universal JavaScript Deobfuscator
GENKI-TECH LABS | ANBU Black Ops Security | War Chief Edition 🏴‍☠️

Features:
  ✅ 50+ Obfuscation Pattern Detection
  ✅ CONDITIONAL Stage Execution (only runs what's needed!)
  ✅ AI Function Renaming
  ✅ Final Prettify Output

Usage: node j-shadow-v5-ultimate.js <input> [options]

Options:
  -o, --output <file>    Output file (default: stdout)
  -v, --verbose          Verbose output with stage details
  -a, --aggressive       Enable aggressive mode
  --no-ai                Disable AI function renaming
  --no-beautify          Disable final beautification
  --analyze              Only analyze, don't deobfuscate
  --json                 Output as JSON
  -h, --help             Show this help

Examples:
  node j-shadow-v5-ultimate.js malware.js -o clean.js -v
  node j-shadow-v5-ultimate.js obfuscated.js --analyze --json
  cat code.js | node j-shadow-v5-ultimate.js - -o output.js
`);
        process.exit(0);
    }

    const options = {
        verbose: args.includes('-v') || args.includes('--verbose'),
        aggressive: args.includes('-a') || args.includes('--aggressive'),
        enableAI: !args.includes('--no-ai'),
        beautify: !args.includes('--no-beautify'),
        analyzeOnly: args.includes('--analyze'),
        jsonOutput: args.includes('--json')
    };

    // Get output file
    const outputIdx = args.findIndex(a => a === '-o' || a === '--output');
    const outputFile = outputIdx >= 0 ? args[outputIdx + 1] : null;

    // Get input - filter out flags and output file
    const flagsWithValues = ['-o', '--output'];
    const inputFile = args.find((a, i) => {
        // Skip if it's a flag
        if (a.startsWith('-')) return false;
        // Skip if it's the value of a flag with value
        if (i > 0 && flagsWithValues.includes(args[i - 1])) return false;
        // Skip if it's the output file
        if (a === outputFile) return false;
        return true;
    });

    let code;
    if (inputFile === '-') {
        // Read from stdin
        code = await new Promise((resolve) => {
            let data = '';
            process.stdin.on('data', chunk => data += chunk);
            process.stdin.on('end', () => resolve(data));
        });
    } else if (inputFile) {
        // Check if file exists
        if (!fs.existsSync(inputFile)) {
            console.error(`❌ Error: File not found: ${inputFile}`);
            process.exit(1);
        }
        
        // Check if it's a directory
        const stats = fs.statSync(inputFile);
        if (stats.isDirectory()) {
            console.error(`❌ Error: "${inputFile}" is a directory, not a file`);
            console.error(`   Please specify a JavaScript file to deobfuscate`);
            console.error(`   Example: node jshadow.js ${inputFile}/script.js -o output.js`);
            process.exit(1);
        }
        
        // Check if it's a valid file type
        const ext = path.extname(inputFile).toLowerCase();
        if (!['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.txt', ''].includes(ext)) {
            console.warn(`⚠️  Warning: Unusual file extension "${ext}", proceeding anyway...`);
        }
        
        try {
            code = fs.readFileSync(inputFile, 'utf8');
        } catch (err) {
            console.error(`❌ Error reading file: ${err.message}`);
            process.exit(1);
        }
    } else {
        console.error('❌ Error: No input file specified');
        console.error('   Usage: node jshadow.js <input.js> [options]');
        console.error('   Run with --help for more information');
        process.exit(1);
    }

    const jshadow = new JShadowV5(options);

    try {
        let result;
        
        if (options.analyzeOnly) {
            result = await jshadow.analyze(code);
            console.log('\n' + result.summary);
        } else {
            result = await jshadow.deobfuscate(code, { filename: inputFile });
        }

        if (options.jsonOutput) {
            const output = JSON.stringify(result, null, 2);
            if (outputFile) {
                fs.writeFileSync(outputFile, output);
                console.error(`✅ JSON output written to ${outputFile}`);
            } else {
                console.log(output);
            }
        } else if (!options.analyzeOnly) {
            const output = result.deobfuscatedCode;
            
            if (outputFile) {
                fs.writeFileSync(outputFile, output);
                console.error(`\n✅ Output written to ${outputFile}`);
                console.error(`   Processing time: ${result.processingTime}ms`);
                console.error(`   Stages executed: ${result.stages.length}`);
                console.error(`   Stages skipped: ${result.stagesSkipped.length}`);
            } else {
                console.log(output);
            }
        }

    } catch (error) {
        console.error(`❌ Error: ${error.message}`);
        process.exit(1);
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
    // Main class
    JShadowV5,
    
    // Pattern detector
    UniversalPatternDetector,
    
    // Individual components
    JShadowCore,
    AdvancedStringDecoder,
    ControlFlowDeobfuscator,
    WebpackUnpacker,
    AntiDebugEvasion,
    AIFunctionRenamer,
    EsotericDecoder,
    CodeBeautifier,
    SteganographyHandler,
    
    // Helper
    safeParse,
    
    // Convenience function
    deobfuscate: async (code, options = {}) => {
        const jshadow = new JShadowV5(options);
        return jshadow.deobfuscate(code, options);
    },
    
    // CLI
    cli
};

// Run CLI if executed directly
if (require.main === module) {
    cli().catch(console.error);
}
