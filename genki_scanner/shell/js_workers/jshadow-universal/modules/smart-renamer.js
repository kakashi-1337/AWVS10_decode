/**
 * 🧠 SMART MINIFIED CODE RENAMER v1.0
 * ====================================
 * Renames minified/terser variable names to meaningful names
 * Uses semantic analysis to understand what each function does
 * 
 * @author Kakashi x Claude Tandem
 */

'use strict';

const babel = require('@babel/core');
const traverse = require('@babel/traverse').default;
const generator = require('@babel/generator').default;
const t = require('@babel/types');

/**
 * Safe Babel parse
 */
function safeParse(code) {
    return babel.parse(code, {
        sourceType: 'unambiguous',
        parserOpts: {
            errorRecovery: true,
            allowReturnOutsideFunction: true,
            allowAwaitOutsideFunction: true,
            allowSuperOutsideMethod: true,
            allowUndeclaredExports: true,
            allowImportExportEverywhere: true,
            plugins: [
                'jsx',
                'typescript',
                'dynamicImport',
                'classProperties',
                'optionalChaining',
                'nullishCoalescingOperator'
            ]
        }
    });
}

class SmartMinifiedRenamer {
    constructor(options = {}) {
        this.options = {
            verbose: options.verbose || false,
            useOpenAI: options.useOpenAI || false,
            openaiKey: options.openaiKey || process.env.OPENAI_API_KEY,
            ...options
        };

        this.usedNames = new Set();
        this.renames = new Map();
        this.stats = { analyzed: 0, renamed: 0 };

        // ═══════════════════════════════════════════════════════════════
        // SEMANTIC PATTERNS - What the code DOES determines the name
        // ═══════════════════════════════════════════════════════════════
        
        this.semanticPatterns = {
            // ─────────────────────────────────────────────────────────────
            // CONSTANT VALUES
            // ─────────────────────────────────────────────────────────────
            constants: [
                { pattern: /^\{\}$/, name: 'EMPTY_OBJECT', description: 'Empty object literal' },
                { pattern: /^\[\]$/, name: 'EMPTY_ARRAY', description: 'Empty array literal' },
                { pattern: /^\(\)\s*=>\s*\{\}$/, name: 'noop', description: 'No-operation function' },
                { pattern: /^\(\)\s*=>\s*!1$/, name: 'alwaysFalse', description: 'Always returns false' },
                { pattern: /^\(\)\s*=>\s*!0$/, name: 'alwaysTrue', description: 'Always returns true' },
                { pattern: /^\(\)\s*=>\s*false$/, name: 'alwaysFalse', description: 'Always returns false' },
                { pattern: /^\(\)\s*=>\s*true$/, name: 'alwaysTrue', description: 'Always returns true' },
                { pattern: /^\(\)\s*=>\s*null$/, name: 'alwaysNull', description: 'Always returns null' },
                { pattern: /^\(\)\s*=>\s*void 0$/, name: 'alwaysUndefined', description: 'Always returns undefined' },
            ],

            // ─────────────────────────────────────────────────────────────
            // TYPE CHECKING FUNCTIONS
            // ─────────────────────────────────────────────────────────────
            typeChecks: [
                { pattern: /typeof\s+\w+\s*===?\s*["']function["']/, name: 'isFunction' },
                { pattern: /typeof\s+\w+\s*===?\s*["']string["']/, name: 'isString' },
                { pattern: /typeof\s+\w+\s*===?\s*["']number["']/, name: 'isNumber' },
                { pattern: /typeof\s+\w+\s*===?\s*["']boolean["']/, name: 'isBoolean' },
                { pattern: /typeof\s+\w+\s*===?\s*["']object["']/, name: 'isObject' },
                { pattern: /typeof\s+\w+\s*===?\s*["']symbol["']/, name: 'isSymbol' },
                { pattern: /typeof\s+\w+\s*===?\s*["']undefined["']/, name: 'isUndefined' },
                { pattern: /typeof\s+\w+\s*===?\s*["']bigint["']/, name: 'isBigInt' },
                { pattern: /\[object Map\]/, name: 'isMap' },
                { pattern: /\[object Set\]/, name: 'isSet' },
                { pattern: /\[object Date\]/, name: 'isDate' },
                { pattern: /\[object RegExp\]/, name: 'isRegExp' },
                { pattern: /\[object Array\]/, name: 'isArray' },
                { pattern: /\[object Object\]/, name: 'isPlainObject' },
                { pattern: /\[object Promise\]/, name: 'isPromise' },
                { pattern: /\[object WeakMap\]/, name: 'isWeakMap' },
                { pattern: /\[object WeakSet\]/, name: 'isWeakSet' },
                { pattern: /Array\.isArray/, name: 'isArray' },
                { pattern: /instanceof\s+Array/, name: 'isArray' },
                { pattern: /instanceof\s+Map/, name: 'isMap' },
                { pattern: /instanceof\s+Set/, name: 'isSet' },
                { pattern: /instanceof\s+Promise/, name: 'isPromise' },
                { pattern: /instanceof\s+Error/, name: 'isError' },
                { pattern: /instanceof\s+Function/, name: 'isFunction' },
                { pattern: /===?\s*null/, name: 'isNull' },
                { pattern: /===?\s*undefined/, name: 'isUndefined' },
                { pattern: /!==?\s*null\s*&&.*!==?\s*undefined/, name: 'isDefined' },
            ],

            // ─────────────────────────────────────────────────────────────
            // OBJECT/ARRAY UTILITIES
            // ─────────────────────────────────────────────────────────────
            objectUtils: [
                { pattern: /Object\.assign/, name: 'assign', alias: 'extend' },
                { pattern: /Object\.keys/, name: 'getKeys' },
                { pattern: /Object\.values/, name: 'getValues' },
                { pattern: /Object\.entries/, name: 'getEntries' },
                { pattern: /Object\.freeze/, name: 'freeze' },
                { pattern: /Object\.seal/, name: 'seal' },
                { pattern: /Object\.create/, name: 'createObject' },
                { pattern: /Object\.defineProperty/, name: 'defineProp' },
                { pattern: /Object\.getOwnPropertyDescriptor/, name: 'getPropDescriptor' },
                { pattern: /Object\.prototype\.hasOwnProperty/, name: 'hasOwnProp' },
                { pattern: /Object\.prototype\.toString/, name: 'toString' },
                { pattern: /\.hasOwnProperty\.call|hasOwnProp.*\.call/, name: 'hasOwn' },
                { pattern: /JSON\.stringify/, name: 'stringify' },
                { pattern: /JSON\.parse/, name: 'parseJSON' },
            ],

            // ─────────────────────────────────────────────────────────────
            // ARRAY OPERATIONS
            // ─────────────────────────────────────────────────────────────
            arrayOps: [
                { pattern: /\.indexOf\(.*\).*\.splice\(/, name: 'removeFromArray' },
                { pattern: /\.push\(/, name: 'addToArray', context: 'singleOp' },
                { pattern: /\.pop\(/, name: 'removeLastItem', context: 'singleOp' },
                { pattern: /\.shift\(/, name: 'removeFirstItem', context: 'singleOp' },
                { pattern: /\.unshift\(/, name: 'prependToArray', context: 'singleOp' },
                { pattern: /\.slice\(/, name: 'sliceArray', context: 'singleOp' },
                { pattern: /\.splice\(/, name: 'spliceArray', context: 'singleOp' },
                { pattern: /\.concat\(/, name: 'concatArrays', context: 'singleOp' },
                { pattern: /\.flat\(/, name: 'flattenArray', context: 'singleOp' },
                { pattern: /\.flatMap\(/, name: 'flatMapArray', context: 'singleOp' },
                { pattern: /\.includes\(/, name: 'includes' },
                { pattern: /\.indexOf\(.*\)\s*[>!=]/, name: 'hasItem' },
                { pattern: /\.find\(/, name: 'findItem' },
                { pattern: /\.findIndex\(/, name: 'findIndex' },
                { pattern: /\.filter\(/, name: 'filterItems' },
                { pattern: /\.map\(/, name: 'mapItems' },
                { pattern: /\.reduce\(/, name: 'reduceItems' },
                { pattern: /\.forEach\(/, name: 'forEachItem' },
                { pattern: /\.some\(/, name: 'someMatch' },
                { pattern: /\.every\(/, name: 'everyMatch' },
                { pattern: /\.sort\(/, name: 'sortItems' },
                { pattern: /\.reverse\(/, name: 'reverseItems' },
                { pattern: /\.join\(/, name: 'joinItems' },
            ],

            // ─────────────────────────────────────────────────────────────
            // STRING OPERATIONS
            // ─────────────────────────────────────────────────────────────
            stringOps: [
                { pattern: /\.startsWith\(/, name: 'startsWith' },
                { pattern: /\.endsWith\(/, name: 'endsWith' },
                { pattern: /\.includes\(/, name: 'includes' },
                { pattern: /\.indexOf\(/, name: 'indexOf' },
                { pattern: /\.replace\(/, name: 'replace' },
                { pattern: /\.replaceAll\(/, name: 'replaceAll' },
                { pattern: /\.split\(/, name: 'split' },
                { pattern: /\.trim\(/, name: 'trim' },
                { pattern: /\.toLowerCase\(/, name: 'toLowerCase' },
                { pattern: /\.toUpperCase\(/, name: 'toUpperCase' },
                { pattern: /\.substring\(/, name: 'substring' },
                { pattern: /\.slice\(/, name: 'slice' },
                { pattern: /\.charAt\(/, name: 'charAt' },
                { pattern: /\.charCodeAt\(/, name: 'charCodeAt' },
                { pattern: /String\.fromCharCode/, name: 'fromCharCode' },
                { pattern: /\.padStart\(/, name: 'padStart' },
                { pattern: /\.padEnd\(/, name: 'padEnd' },
                { pattern: /\.match\(/, name: 'matchPattern' },
                { pattern: /\.test\(/, name: 'testPattern' },
            ],

            // ─────────────────────────────────────────────────────────────
            // EVENT/PROP DETECTION (Vue, React, etc.)
            // ─────────────────────────────────────────────────────────────
            eventDetection: [
                { pattern: /charCodeAt\(0\)\s*===?\s*111.*charCodeAt\(1\)\s*===?\s*110/, name: 'isOnEventProp', description: 'Checks for "on" prefix (event handler)' },
                { pattern: /startsWith\(["']on["']\)/, name: 'isEventHandler' },
                { pattern: /startsWith\(["']onUpdate:["']\)/, name: 'isUpdateEvent' },
                { pattern: /startsWith\(["']v-["']\)/, name: 'isVueDirective' },
                { pattern: /startsWith\(["']@["']\)/, name: 'isVueEventShorthand' },
                { pattern: /startsWith\(["']:["']\)/, name: 'isVueBindShorthand' },
                { pattern: /^on[A-Z]/, name: 'isEventHandler' },
            ],

            // ─────────────────────────────────────────────────────────────
            // DOM OPERATIONS
            // ─────────────────────────────────────────────────────────────
            domOps: [
                { pattern: /document\.createElement/, name: 'createElement' },
                { pattern: /document\.createTextNode/, name: 'createTextNode' },
                { pattern: /document\.createDocumentFragment/, name: 'createFragment' },
                { pattern: /document\.getElementById/, name: 'getById' },
                { pattern: /document\.querySelector/, name: 'querySelector' },
                { pattern: /document\.querySelectorAll/, name: 'querySelectorAll' },
                { pattern: /\.appendChild\(/, name: 'appendChild' },
                { pattern: /\.removeChild\(/, name: 'removeChild' },
                { pattern: /\.insertBefore\(/, name: 'insertBefore' },
                { pattern: /\.replaceChild\(/, name: 'replaceChild' },
                { pattern: /\.cloneNode\(/, name: 'cloneNode' },
                { pattern: /\.setAttribute\(/, name: 'setAttribute' },
                { pattern: /\.getAttribute\(/, name: 'getAttribute' },
                { pattern: /\.removeAttribute\(/, name: 'removeAttribute' },
                { pattern: /\.classList\.add\(/, name: 'addClass' },
                { pattern: /\.classList\.remove\(/, name: 'removeClass' },
                { pattern: /\.classList\.toggle\(/, name: 'toggleClass' },
                { pattern: /\.classList\.contains\(/, name: 'hasClass' },
                { pattern: /\.innerHTML/, name: 'setInnerHTML', context: 'assignment' },
                { pattern: /\.textContent/, name: 'setTextContent', context: 'assignment' },
                { pattern: /\.style\./, name: 'setStyle' },
            ],

            // ─────────────────────────────────────────────────────────────
            // ASYNC/PROMISE PATTERNS
            // ─────────────────────────────────────────────────────────────
            asyncPatterns: [
                { pattern: /new\s+Promise/, name: 'createPromise' },
                { pattern: /Promise\.resolve/, name: 'resolvePromise' },
                { pattern: /Promise\.reject/, name: 'rejectPromise' },
                { pattern: /Promise\.all/, name: 'promiseAll' },
                { pattern: /Promise\.race/, name: 'promiseRace' },
                { pattern: /Promise\.allSettled/, name: 'promiseAllSettled' },
                { pattern: /\.then\(/, name: 'thenHandler' },
                { pattern: /\.catch\(/, name: 'catchHandler' },
                { pattern: /\.finally\(/, name: 'finallyHandler' },
                { pattern: /async\s+/, name: 'asyncFn' },
                { pattern: /await\s+/, name: 'awaitResult' },
            ],

            // ─────────────────────────────────────────────────────────────
            // ERROR HANDLING
            // ─────────────────────────────────────────────────────────────
            errorHandling: [
                { pattern: /throw\s+new\s+Error/, name: 'throwError' },
                { pattern: /throw\s+new\s+TypeError/, name: 'throwTypeError' },
                { pattern: /throw\s+new\s+RangeError/, name: 'throwRangeError' },
                { pattern: /try\s*\{/, name: 'tryCatch' },
                { pattern: /console\.error/, name: 'logError' },
                { pattern: /console\.warn/, name: 'logWarning' },
            ],

            // ─────────────────────────────────────────────────────────────
            // COMMON UTILITIES
            // ─────────────────────────────────────────────────────────────
            utilities: [
                { pattern: /Math\.random/, name: 'random' },
                { pattern: /Math\.floor/, name: 'floor' },
                { pattern: /Math\.ceil/, name: 'ceil' },
                { pattern: /Math\.round/, name: 'round' },
                { pattern: /Math\.abs/, name: 'abs' },
                { pattern: /Math\.min/, name: 'min' },
                { pattern: /Math\.max/, name: 'max' },
                { pattern: /Date\.now/, name: 'now' },
                { pattern: /new\s+Date/, name: 'createDate' },
                { pattern: /setTimeout/, name: 'delay' },
                { pattern: /setInterval/, name: 'interval' },
                { pattern: /clearTimeout/, name: 'clearDelay' },
                { pattern: /clearInterval/, name: 'clearInterval' },
                { pattern: /requestAnimationFrame/, name: 'requestFrame' },
                { pattern: /cancelAnimationFrame/, name: 'cancelFrame' },
            ],

            // ─────────────────────────────────────────────────────────────
            // FRAMEWORK SPECIFIC (Vue, React, etc.)
            // ─────────────────────────────────────────────────────────────
            frameworks: [
                // Vue
                { pattern: /\$emit\(/, name: 'emit' },
                { pattern: /\$on\(/, name: 'onEvent' },
                { pattern: /\$off\(/, name: 'offEvent' },
                { pattern: /\$watch\(/, name: 'watch' },
                { pattern: /\$nextTick\(/, name: 'nextTick' },
                { pattern: /reactive\(/, name: 'reactive' },
                { pattern: /ref\(/, name: 'ref' },
                { pattern: /computed\(/, name: 'computed' },
                { pattern: /watchEffect\(/, name: 'watchEffect' },
                // React
                { pattern: /useState\(/, name: 'useState' },
                { pattern: /useEffect\(/, name: 'useEffect' },
                { pattern: /useCallback\(/, name: 'useCallback' },
                { pattern: /useMemo\(/, name: 'useMemo' },
                { pattern: /useRef\(/, name: 'useRef' },
                { pattern: /useContext\(/, name: 'useContext' },
                { pattern: /useReducer\(/, name: 'useReducer' },
            ],
        };

        // Names that should not be renamed
        this.reservedNames = new Set([
            // JavaScript globals
            'undefined', 'null', 'true', 'false', 'NaN', 'Infinity',
            'Object', 'Array', 'String', 'Number', 'Boolean', 'Function',
            'Symbol', 'BigInt', 'Math', 'Date', 'RegExp', 'Error',
            'Map', 'Set', 'WeakMap', 'WeakSet', 'Promise', 'Proxy', 'Reflect',
            'JSON', 'console', 'window', 'document', 'navigator', 'location',
            'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
            'requestAnimationFrame', 'cancelAnimationFrame',
            'fetch', 'XMLHttpRequest', 'WebSocket',
            'localStorage', 'sessionStorage', 'indexedDB',
            // Common framework names
            'React', 'Vue', 'Angular', 'Svelte', 'jQuery',
            'require', 'module', 'exports', 'import', 'export',
            '__dirname', '__filename', 'process', 'global', 'globalThis',
        ]);
    }

    log(msg) {
        if (this.options.verbose) {
            console.log(`[Renamer] ${msg}`);
        }
    }

    /**
     * Main rename function
     */
    async rename(code, options = {}) {
        this.renames.clear();
        this.usedNames.clear();
        this.stats = { analyzed: 0, renamed: 0 };

        try {
            const ast = safeParse(code);
            
            // Phase 1: Collect all declarations and analyze them
            const declarations = this._collectDeclarations(ast);
            this.log(`Found ${declarations.length} declarations to analyze`);

            // Phase 2: Analyze each declaration and generate names
            for (const decl of declarations) {
                this.stats.analyzed++;
                const newName = this._analyzeAndName(decl);
                
                if (newName && newName !== decl.name) {
                    this.renames.set(decl.name, newName);
                    this.stats.renamed++;
                    this.log(`  ${decl.name} → ${newName}`);
                }
            }

            // Phase 3: Apply renames
            this._applyRenames(ast);

            const output = generator(ast, {
                compact: false,
                comments: true,
                retainLines: false
            }).code;

            return {
                code: output,
                renames: Object.fromEntries(this.renames),
                stats: this.stats
            };

        } catch (error) {
            console.error('Rename error:', error.message);
            return { code, renames: {}, stats: this.stats, error: error.message };
        }
    }

    /**
     * Collect all variable/function declarations
     */
    _collectDeclarations(ast) {
        const declarations = [];

        traverse(ast, {
            VariableDeclarator: (path) => {
                if (t.isIdentifier(path.node.id)) {
                    const name = path.node.id.name;
                    const init = path.node.init;
                    
                    if (init && this._shouldRename(name)) {
                        declarations.push({
                            name,
                            type: 'variable',
                            init,
                            code: generator(init).code,
                            path
                        });
                    }
                }
            },

            FunctionDeclaration: (path) => {
                if (path.node.id && this._shouldRename(path.node.id.name)) {
                    declarations.push({
                        name: path.node.id.name,
                        type: 'function',
                        init: path.node,
                        code: generator(path.node.body).code,
                        path
                    });
                }
            }
        });

        return declarations;
    }

    /**
     * Check if name should be renamed
     */
    _shouldRename(name) {
        if (!name) return false;
        if (this.reservedNames.has(name)) return false;
        
        // Rename short names (1-2 chars) or obfuscated-looking names
        if (name.length <= 2) return true;
        if (/^_0x[a-f0-9]+$/i.test(name)) return true;
        if (/^[a-zA-Z][a-zA-Z0-9]?$/.test(name)) return true;  // Short like 'fe', 'Mt', 'Gr'
        if (/^[A-Z][a-z]$/.test(name)) return true;  // Like 'We', 'Lo'
        
        return false;
    }

    /**
     * Analyze declaration and generate meaningful name
     */
    _analyzeAndName(decl) {
        const code = decl.code;
        
        // Try each pattern category
        for (const [category, patterns] of Object.entries(this.semanticPatterns)) {
            for (const patternDef of patterns) {
                if (patternDef.pattern.test(code)) {
                    return this._uniqueName(patternDef.name);
                }
            }
        }

        // Fallback: analyze structure
        return this._analyzeStructure(decl);
    }

    /**
     * Analyze code structure for naming
     */
    _analyzeStructure(decl) {
        const code = decl.code;
        const init = decl.init;

        // Empty object
        if (t.isObjectExpression(init) && init.properties.length === 0) {
            return this._uniqueName('emptyObject');
        }

        // Empty array
        if (t.isArrayExpression(init) && init.elements.length === 0) {
            return this._uniqueName('emptyArray');
        }

        // Arrow function returning boolean
        if (t.isArrowFunctionExpression(init) || t.isFunctionExpression(init)) {
            const body = generator(init.body).code;
            
            // Returns false
            if (/^!1$|^false$/.test(body.trim())) {
                return this._uniqueName('alwaysFalse');
            }
            // Returns true
            if (/^!0$|^true$/.test(body.trim())) {
                return this._uniqueName('alwaysTrue');
            }
            // No-op
            if (/^\{\s*\}$/.test(body.trim())) {
                return this._uniqueName('noop');
            }

            // Generic function based on param count
            const paramCount = init.params?.length || 0;
            if (paramCount === 0) {
                return this._uniqueName('getter');
            } else if (paramCount === 1) {
                return this._uniqueName('transform');
            } else if (paramCount === 2) {
                return this._uniqueName('combine');
            }
        }

        // Reference to built-in
        if (t.isMemberExpression(init)) {
            const memberCode = generator(init).code;
            
            if (memberCode.includes('Object.assign')) return this._uniqueName('assign');
            if (memberCode.includes('Object.keys')) return this._uniqueName('keys');
            if (memberCode.includes('Array.isArray')) return this._uniqueName('isArray');
            if (memberCode.includes('hasOwnProperty')) return this._uniqueName('hasOwnProp');
        }

        // Default: use generic name
        return null;
    }

    /**
     * Generate unique name
     */
    _uniqueName(baseName) {
        let name = baseName;
        let counter = 1;

        while (this.usedNames.has(name) || this.reservedNames.has(name)) {
            name = `${baseName}${counter}`;
            counter++;
        }

        this.usedNames.add(name);
        return name;
    }

    /**
     * Apply renames to AST
     */
    _applyRenames(ast) {
        traverse(ast, {
            Identifier: (path) => {
                const oldName = path.node.name;
                const newName = this.renames.get(oldName);
                
                if (newName) {
                    path.node.name = newName;
                }
            }
        });
    }

    /**
     * Quick analysis without renaming
     */
    analyze(code) {
        const results = [];
        
        try {
            const ast = safeParse(code);
            const declarations = this._collectDeclarations(ast);

            for (const decl of declarations) {
                const suggestedName = this._analyzeAndName(decl);
                results.push({
                    original: decl.name,
                    suggested: suggestedName || '(keep original)',
                    type: decl.type,
                    preview: decl.code.slice(0, 60) + (decl.code.length > 60 ? '...' : '')
                });
            }
        } catch (e) {
            results.push({ error: e.message });
        }

        return results;
    }
}

// ============================================================================
// CLI
// ============================================================================

async function cli() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args.includes('--help')) {
        console.log(`
🧠 Smart Minified Code Renamer

Usage: node smart-renamer.js <input.js> [options]

Options:
  -o, --output <file>   Output file
  -v, --verbose         Show detailed renaming info
  --analyze             Only analyze, don't rename
  --help                Show this help

Examples:
  node smart-renamer.js minified.js -o readable.js -v
  node smart-renamer.js bundle.js --analyze
`);
        return;
    }

    const fs = require('fs');
    const path = require('path');

    const options = {
        verbose: args.includes('-v') || args.includes('--verbose'),
        analyzeOnly: args.includes('--analyze')
    };

    const outputIdx = args.findIndex(a => a === '-o' || a === '--output');
    const outputFile = outputIdx >= 0 ? args[outputIdx + 1] : null;
    const inputFile = args.find(a => !a.startsWith('-') && a !== outputFile);

    if (!inputFile || !fs.existsSync(inputFile)) {
        console.error('Error: Input file not found');
        process.exit(1);
    }

    const code = fs.readFileSync(inputFile, 'utf8');
    const renamer = new SmartMinifiedRenamer(options);

    if (options.analyzeOnly) {
        console.log('\n📊 Analysis Results:\n');
        const results = renamer.analyze(code);
        
        for (const r of results) {
            if (r.error) {
                console.log(`  ❌ Error: ${r.error}`);
            } else {
                const arrow = r.suggested !== '(keep original)' ? '→' : ' ';
                console.log(`  ${r.original.padEnd(15)} ${arrow} ${r.suggested.padEnd(20)} [${r.type}]`);
                console.log(`    ${r.preview}`);
            }
        }
        return;
    }

    console.log('🔄 Renaming minified variables...\n');
    const result = await renamer.rename(code);

    if (result.error) {
        console.error(`❌ Error: ${result.error}`);
        process.exit(1);
    }

    console.log(`✅ Renamed ${result.stats.renamed} of ${result.stats.analyzed} variables\n`);

    if (Object.keys(result.renames).length > 0) {
        console.log('📝 Renames applied:');
        for (const [old, newName] of Object.entries(result.renames)) {
            console.log(`   ${old} → ${newName}`);
        }
        console.log('');
    }

    if (outputFile) {
        fs.writeFileSync(outputFile, result.code);
        console.log(`💾 Output written to ${outputFile}`);
    } else {
        console.log('\n--- OUTPUT ---\n');
        console.log(result.code);
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
    SmartMinifiedRenamer,
    cli
};

if (require.main === module) {
    cli().catch(console.error);
}
