/**
 * 🔓 J-Shadow — Universal JavaScript Deobfuscator (standalone)
 *
 * © Genki-Tech Labs · MIT
 *
 * Capabilities:
 * - eval-packer unwrapping (P.A.C.K.E.R, eval("...") chains) via isolated VM
 * - String-array decoder lifting (obfuscator.io: runs the script's own decoder/key)
 * - Webpack bundle splitting into labelled, readable modules
 * - Scope-aware constant inlining (variable -> value propagation)
 * - String-array index resolution + Babel path.evaluate() constant folding
 * - Safe string decoding (hex / base64 / unicode / charCode) with round-trip guards
 * - atob / String.fromCharCode / decodeURIComponent / unescape evaluation
 * - Array .join/.reverse, member cleanup (obj["x"] -> obj.x, arr[i] -> elem)
 * - Dead-code & branch simplification, void 0 -> undefined
 * - Timeout + node-budget enforcement (safe on hostile input)
 *
 * ⚠️ Decoder lifting / eval-unpacking execute the target's own decode functions
 *    in a Node `vm` sandbox with a timeout. `vm` is NOT a hard security boundary —
 *    run untrusted samples in a disposable/isolated environment.
 */

'use strict';

const vm = require('vm');
const path = require('path');

class JShadowEngine {
    constructor(options = {}) {
        this.options = {
            maxIterations: options.maxIterations || 12,
            timeout: options.timeout || 15000,
            maxNodes: options.maxNodes || 5000000,
            verbose: options.verbose || false,
            ...options
        };

        this.babel = null;
        this.traverse = null;
        this.generator = null;
        this.t = null;

        this._initBabel();

        this.stats = { processed: 0, deobfuscated: 0, transforms: 0 };
    }

    _initBabel() {
        try {
            this.babel = require('@babel/core');
            this.traverse = require('@babel/traverse').default;
            this.generator = require('@babel/generator').default;
            this.t = require('@babel/types');
        } catch (e) {
            console.warn('⚠️ Babel not available, deobfuscation disabled');
        }
    }

    isReady() { return this.babel !== null; }

    /**
     * Main deobfuscation method. Runs passes until the output stabilises,
     * the iteration cap is hit, or the time budget is exceeded.
     */
    async process(code, options = {}) {
        this.stats.processed++;

        if (!this.isReady()) {
            return { code, original: code, transformations: 0, iterations: 0, wasObfuscated: false, error: 'Babel not available' };
        }

        let currentCode = code;
        let prevCode = '';
        let iteration = 0;
        let totalTransforms = 0;
        const maxIter = options.maxIterations || this.options.maxIterations;
        const deadline = Date.now() + (options.timeout || this.options.timeout);

        // ── Pre-pass 1: unwrap eval-packers (P.A.C.K.E.R, eval("...") chains) ──
        let unpacked = false;
        try {
            const up = this._unpackEval(currentCode, deadline);
            if (up && up.count > 0) { currentCode = up.code; totalTransforms += up.count; unpacked = true; }
        } catch (e) {
            if (this.options.verbose) console.warn('  ⚠️ Unpack skipped:', e.message);
        }

        // ── Pre-pass 2: lift & execute the file's own string-array decoder ──
        // This is what cracks obfuscator.io / enterprise-grade: we locate the
        // decoder function + encoded string array + rotation routine, run them
        // in an isolated VM using THEIR embedded key/seed, then replace every
        // decoder call with the real decoded string.
        let decoderInfo = null;
        let liveDecoders = null, baseDecoderNames = [];
        try {
            const lift = this._liftStringArrayDecoder(currentCode, deadline);
            if (lift) {
                liveDecoders = lift.live || null;
                baseDecoderNames = lift.baseNames || [];
            }
            if (lift && lift.count > 0) {
                currentCode = lift.code;
                totalTransforms += lift.count;
                decoderInfo = lift.info;
                if (this.options.verbose) console.log(`  🔑 Decoder lifted: ${lift.count} call(s) decoded`);
            } else if (lift && lift.info) {
                decoderInfo = lift.info; // detected but nothing decoded directly
            }
        } catch (e) {
            if (this.options.verbose) console.warn('  ⚠️ Decoder lift skipped:', e.message);
        }

        while (currentCode !== prevCode && iteration < maxIter) {
            if (Date.now() > deadline) {
                if (this.options.verbose) console.warn('  ⏱️ J-Shadow timeout — returning partial result');
                break;
            }
            prevCode = currentCode;
            try {
                const result = this._performPass(currentCode, deadline, liveDecoders, baseDecoderNames);
                currentCode = result.code;
                totalTransforms += result.transforms;
                if (result.decoderInfo) decoderInfo = { ...(decoderInfo || {}), ...result.decoderInfo };
                iteration++;
                if (this.options.verbose) console.log(`  🔄 Pass ${iteration}: ${result.transforms} transforms`);
            } catch (error) {
                if (this.options.verbose) console.error(`  ❌ Pass ${iteration} error:`, error.message);
                break;
            }
        }

        if (totalTransforms > 0) this.stats.deobfuscated++;
        this.stats.transforms += totalTransforms;

        // ── Hybrid fallback: DYNAMIC decode when static left decoder calls behind ──
        // Runs the file in an isolated VM (deps stubbed, anti-debug neutralized) to
        // get 100%-accurate strings for RC4/self-defending files.
        let dynamicDecoded = 0;
        if (options.dynamic !== false && baseDecoderNames.length) {
            let remaining = 0;
            try {
                const chk = this.babel.parse(currentCode, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
                const nameSet = new Set(baseDecoderNames);
                this.traverse(chk, { CallExpression: (p) => { const c = p.node.callee; if (this.t.isIdentifier(c) && nameSet.has(c.name)) remaining++; } });
            } catch (e) {}

            if (remaining > 0) {
                try {
                    const dyn = this._dynamicDecode(currentCode, baseDecoderNames, deadline);
                    if (dyn.count > 0) {
                        const ast2 = this.babel.parse(currentCode, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
                        dynamicDecoded = this._backfillDecoded(ast2, baseDecoderNames, dyn.map);
                        if (dynamicDecoded > 0) {
                            currentCode = this.generator(ast2, { compact: false, comments: true }).code;
                            totalTransforms += dynamicDecoded;
                            // fold the now-literal string concatenations that were revealed
                            let prev = '';
                            for (let k = 0; k < 4 && currentCode !== prev && Date.now() < deadline; k++) {
                                prev = currentCode;
                                try { const r = this._performPass(currentCode, deadline, liveDecoders, baseDecoderNames); currentCode = r.code; totalTransforms += r.transforms; } catch (e) { break; }
                            }
                            decoderInfo = { ...(decoderInfo || {}), detected: true, dynamicDecoded, mode: 'hybrid' };
                            if (this.options.verbose) console.log(`  🧪 Dynamic decode: ${dynamicDecoded} call(s) resolved via sandbox`);
                        }
                    } else if (dyn.error && this.options.verbose) {
                        console.warn('  ⚠️ Dynamic decode error:', dyn.error);
                    }
                } catch (e) {
                    if (this.options.verbose) console.warn('  ⚠️ Dynamic decode skipped:', e.message);
                }
            }
        }

        // ── Optional: rename obfuscated identifiers to readable names ──
        if (options.rename || this.options.rename) {
            try {
                const ast = this.babel.parse(currentCode, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
                const renamed = this._renameIdentifiers(ast);
                if (renamed > 0) {
                    currentCode = this.generator(ast, { compact: false, comments: true }).code;
                    totalTransforms += renamed;
                }
            } catch (e) {
                if (this.options.verbose) console.warn('  ⚠️ Rename skipped:', e.message);
            }
        }

        // ── Final pass: split a webpack bundle into labelled, readable modules ──
        let webpackModules = 0;
        if (!options.skipSplit) {
            try {
                const split = this._splitWebpack(currentCode);
                if (split && split.count > 0) { currentCode = split.code; webpackModules = split.count; totalTransforms += split.count; }
            } catch (e) {
                if (this.options.verbose) console.warn('  ⚠️ Webpack split skipped:', e.message);
            }
        }

        return {
            code: currentCode,
            original: code,
            transformations: totalTransforms,
            iterations: iteration,
            wasObfuscated: totalTransforms > 5,
            stringArrayDecoder: decoderInfo,
            dynamicDecoded: dynamicDecoded || null,
            requiredFiles: this._detectRequires(code),
            webpackModules: webpackModules || null
        };
    }

    /**
     * Detect require()/import dependencies and report them (no stubbing decision
     * here — the caller decides). Returns { modules:[...], external:[...] }.
     * external = specifiers that are NOT relative (bare package names).
     */
    _detectRequires(code) {
        const t = this.t;
        let ast;
        try { ast = this.babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } }); }
        catch (e) { return { modules: [], external: [], relative: [] }; }

        const mods = new Set();
        this.traverse(ast, {
            CallExpression: (p) => {
                const c = p.node.callee;
                if (t.isIdentifier(c, { name: 'require' }) && p.node.arguments.length === 1 && t.isStringLiteral(p.node.arguments[0])) {
                    mods.add(p.node.arguments[0].value);
                }
            },
            ImportDeclaration: (p) => { if (t.isStringLiteral(p.node.source)) mods.add(p.node.source.value); }
        });

        const modules = [...mods];
        const relative = modules.filter(m => m.startsWith('./') || m.startsWith('../') || m.startsWith('/'));
        const external = modules.filter(m => !relative.includes(m));
        return { modules, external, relative };
    }

    /**
     * DYNAMIC decode: run the whole file in an isolated VM (deps stubbed,
     * anti-debug neutralized, timers no-op'd) so the array + rotation + decoders
     * set themselves up naturally, then query each decoder for every literal
     * (index, key) call site. Returns a map { "name\0[args]": decodedString }.
     * This is what gets RC4/self-defending files to 100%.
     */
    _dynamicDecode(code, baseNames, deadline) {
        const t = this.t;
        if (!baseNames || !baseNames.length) return { map: {}, count: 0 };

        let ast;
        try { ast = this.babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } }); }
        catch (e) { return { map: {}, count: 0 }; }

        const nameSet = new Set(baseNames);
        const asVal = (a) => {
            if (t.isStringLiteral(a) || t.isNumericLiteral(a) || t.isBooleanLiteral(a)) return { ok: true, v: a.value };
            if (t.isUnaryExpression(a) && a.operator === '-' && t.isNumericLiteral(a.argument)) return { ok: true, v: -a.argument.value };
            return { ok: false };
        };

        const calls = new Map();
        this.traverse(ast, {
            CallExpression: (p) => {
                const c = p.node.callee;
                if (!t.isIdentifier(c) || !nameSet.has(c.name)) return;
                const vals = [];
                for (const a of p.node.arguments) { const r = asVal(a); if (!r.ok) return; vals.push(r.v); }
                const key = c.name + '\u0000' + JSON.stringify(vals);
                if (!calls.has(key)) calls.set(key, { name: c.name, args: vals, key });
            }
        });
        if (calls.size === 0) return { map: {}, count: 0 };

        const q = [...calls.values()].map(cl =>
            `try{__JR[${JSON.stringify(cl.key)}]=${cl.name}(${cl.args.map(v => JSON.stringify(v)).join(',')});}catch(e){}`
        ).join('');

        const neutralize = (s) => (s || '').replace(
            /new\s+[\w$]+\s*\([^()]*\)\s*(?:\[[^\]]*\]|\.\s*[\w$]+)\s*\(\s*\)/g, 'void 0'
        );
        // Cap any rotation/anti-debug while(true) loops so the sandbox can't hang.
        const capLoops = (s) => s.replace(
            /while\s*\(\s*(?:!!\[\]|!\[\]|true|1|0x1)\s*\)/g,
            'for (var __jsg = 0; __jsg < 50000; __jsg++)'
        );

        // Wrap top-level expression statements in try/catch so a throwing
        // top-level call (e.g. a decode before rotation, or self-defending IIFE)
        // can't abort the whole harness — decoders (declarations) stay in scope.
        let safeBody;
        try {
            const bAst = this.babel.parse(capLoops(neutralize(code)), { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
            bAst.program.body = bAst.program.body.map(stmt =>
                t.isExpressionStatement(stmt)
                    ? t.tryStatement(t.blockStatement([stmt]), t.catchClause(t.identifier('__e'), t.blockStatement([])))
                    : stmt
            );
            safeBody = this.generator(bAst, { compact: false }).code;
        } catch (e) {
            safeBody = capLoops(neutralize(code));
        }

        const harness = safeBody + '\n;var __JR={};' + q + '\n__JR;';

        // Deep no-op proxy for stubbed deps / browser globals (never throws).
        const deepNoop = new Proxy(function () {}, {
            get: () => deepNoop, apply: () => deepNoop, construct: () => deepNoop, has: () => true
        });
        const sandbox = {
            require: () => deepNoop,
            module: { exports: {} }, exports: {},
            setInterval: () => 0, setTimeout: () => 0, clearInterval: () => 0, clearTimeout: () => 0,
            console: { log() {}, warn() {}, error() {}, info() {} },
            atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
            btoa: (s) => Buffer.from(String(s), 'binary').toString('base64'),
            Buffer
        };
        sandbox.window = sandbox.self = sandbox.global = sandbox.document = sandbox.navigator = deepNoop;

        let result;
        try {
            const budget = Math.max(2000, Math.min(10000, (deadline || Date.now() + 10000) - Date.now()));
            result = vm.runInNewContext(harness, vm.createContext(sandbox), { timeout: budget });
        } catch (e) { return { map: {}, count: 0, error: e.message }; }
        if (!result || typeof result !== 'object') return { map: {}, count: 0 };

        const map = {};
        let count = 0;
        for (const k of Object.keys(result)) {
            if (typeof result[k] === 'string') { map[k] = result[k]; count++; }
        }
        return { map, count };
    }

    /** Replace decoder(index,key) call sites with dynamically-decoded strings. */
    _backfillDecoded(ast, baseNames, map) {
        const t = this.t;
        const nameSet = new Set(baseNames);
        const asVal = (a) => {
            if (t.isStringLiteral(a) || t.isNumericLiteral(a) || t.isBooleanLiteral(a)) return { ok: true, v: a.value };
            if (t.isUnaryExpression(a) && a.operator === '-' && t.isNumericLiteral(a.argument)) return { ok: true, v: -a.argument.value };
            return { ok: false };
        };
        let count = 0;
        this.traverse(ast, {
            CallExpression: (p) => {
                const c = p.node.callee;
                if (!t.isIdentifier(c) || !nameSet.has(c.name)) return;
                const vals = [];
                for (const a of p.node.arguments) { const r = asVal(a); if (!r.ok) return; vals.push(r.v); }
                const key = c.name + '\u0000' + JSON.stringify(vals);
                if (Object.prototype.hasOwnProperty.call(map, key)) { p.replaceWith(t.stringLiteral(map[key])); count++; }
            }
        });
        return count;
    }

    /**
     * Perform a single deobfuscation pass over freshly-parsed code.
     */
    _performPass(code, deadline, live, baseNames) {
        const t = this.t;
        let transforms = 0;
        let decoderInfo = null;

        const ast = this.babel.parse(code, {
            sourceType: 'unambiguous',
            parserOpts: { allowReturnOutsideFunction: true, allowSuperOutsideMethod: true, errorRecovery: true }
        });

        // ── Phase 1: scope-aware inlining (guarded so a throw won't abort the pass) ──
        try { transforms += this._inlineConstants(ast); } catch (e) {}
        try { transforms += this._inlineConstObjects(ast); } catch (e) {}
        try { transforms += this._inlineWrapperObjects(ast); } catch (e) {}

        // Resolve obfuscator.io decoder proxies: local wrappers like
        //   function f(a,b){ return DECODER(b - -0x3b5, a); }
        // get inlined so calls reach the base decoder with (foldable) literal args.
        if (baseNames && baseNames.length) {
            try { transforms += this._inlineDecoderProxies(ast, new Set(baseNames)); } catch (e) {}
        }

        // ── Phase 2: expression-level transforms ──
        let nodeBudget = this.options.maxNodes;

        try {
        this.traverse(ast, {
            enter: (p) => {
                if (--nodeBudget < 0) { p.stop(); return; }
                if (Date.now() > deadline) { p.stop(); return; }
            },

            // ----- String literal decoding (round-trip guarded) -----
            StringLiteral: (path) => {
                const value = path.node.value;
                if (typeof value !== 'string' || !value) return;

                // \xNN escapes
                if (/\\x[0-9a-fA-F]{2}/.test(value)) {
                    const decoded = value.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
                    if (decoded !== value) { path.node.value = decoded; transforms++; return; }
                }
                // \uNNNN escapes
                if (/\\u[0-9a-fA-F]{4}/.test(value)) {
                    const decoded = value.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
                    if (decoded !== value) { path.node.value = decoded; transforms++; return; }
                }
                // pure-hex string, only if it round-trips and decodes to printable text
                if (/^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0 && value.length >= 6) {
                    const decoded = this._safeHex(value);
                    if (decoded !== null) { path.node.value = decoded; transforms++; return; }
                }
                // base64, only if it round-trips and decodes to meaningful printable text
                if (/^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length % 4 === 0 && value.length >= 8) {
                    const decoded = this._safeBase64(value);
                    if (decoded !== null) { path.node.value = decoded; transforms++; return; }
                }
            },

            // ----- Constant folding via Babel evaluate (broad + safe) -----
            BinaryExpression: (path) => { if (this._tryEvaluate(path)) transforms++; },
            UnaryExpression: (path) => {
                // void 0 / void <expr> -> undefined
                if (path.node.operator === 'void') {
                    path.replaceWith(t.identifier('undefined')); transforms++; return;
                }
                if (this._tryEvaluate(path)) transforms++;
            },
            LogicalExpression: (path) => { if (this._tryEvaluate(path)) transforms++; },

            // ----- Known decoder calls -----
            CallExpression: (path) => {
                const { callee, arguments: args } = path.node;

                // atob("...")
                if (t.isIdentifier(callee, { name: 'atob' }) && args.length === 1 && t.isStringLiteral(args[0])) {
                    const decoded = this._safeBase64(args[0].value, true);
                    if (decoded !== null) { path.replaceWith(t.stringLiteral(decoded)); transforms++; }
                    return;
                }
                // decodeURIComponent("...") / unescape("...")
                if (t.isIdentifier(callee) && /^(decodeURIComponent|unescape)$/.test(callee.name) &&
                    args.length === 1 && t.isStringLiteral(args[0])) {
                    try {
                        const fn = callee.name === 'unescape' ? unescape : decodeURIComponent;
                        const out = fn(args[0].value);
                        if (/^[\x09\x0A\x0D\x20-\x7E]+$/.test(out)) { path.replaceWith(t.stringLiteral(out)); transforms++; }
                    } catch (e) {}
                    return;
                }
                // String.fromCharCode(...nums)
                if (t.isMemberExpression(callee) &&
                    t.isIdentifier(callee.object, { name: 'String' }) &&
                    t.isIdentifier(callee.property, { name: 'fromCharCode' }) &&
                    args.length && args.every(a => t.isNumericLiteral(a))) {
                    try { path.replaceWith(t.stringLiteral(String.fromCharCode(...args.map(a => a.value)))); transforms++; } catch (e) {}
                    return;
                }
                // [literals].join(sep) / .reverse()
                if (t.isMemberExpression(callee) && t.isArrayExpression(callee.object)) {
                    const arr = callee.object.elements;
                    if (arr.length && arr.every(el => el && t.isLiteral(el))) {
                        const vals = arr.map(el => el.value);
                        if (t.isIdentifier(callee.property, { name: 'join' })) {
                            const sep = args.length && t.isStringLiteral(args[0]) ? args[0].value : ',';
                            path.replaceWith(t.stringLiteral(vals.join(sep))); transforms++; return;
                        }
                        if (t.isIdentifier(callee.property, { name: 'reverse' })) {
                            path.replaceWith(t.arrayExpression([...arr].reverse())); transforms++; return;
                        }
                    }
                }
            },

            // ----- Member cleanup -----
            MemberExpression: (path) => {
                const { computed, property, object } = path.node;
                // obj["prop"] -> obj.prop
                if (computed && t.isStringLiteral(property) && /^[A-Za-z_$][\w$]*$/.test(property.value)) {
                    path.node.property = t.identifier(property.value);
                    path.node.computed = false; transforms++; return;
                }
                // [literals][n] -> element
                if (computed && t.isNumericLiteral(property) && t.isArrayExpression(object)) {
                    const idx = property.value;
                    if (idx >= 0 && idx < object.elements.length && object.elements[idx] && t.isLiteral(object.elements[idx])) {
                        path.replaceWith(object.elements[idx]); transforms++;
                    }
                }
            },

            // ----- Dead code / branch simplification -----
            IfStatement: (path) => {
                const ev = path.get('test').evaluate();
                if (ev.confident) {
                    if (ev.value) path.replaceWith(path.node.consequent);
                    else if (path.node.alternate) path.replaceWith(path.node.alternate);
                    else path.remove();
                    transforms++;
                }
            },
            ConditionalExpression: (path) => {
                const ev = path.get('test').evaluate();
                if (ev.confident) { path.replaceWith(ev.value ? path.node.consequent : path.node.alternate); transforms++; }
            },
            SequenceExpression: (path) => {
                if (path.node.expressions.length === 1) { path.replaceWith(path.node.expressions[0]); transforms++; }
            },

            // Render hex/binary/octal literals as decimal (0x10 -> 16) for readability
            NumericLiteral: (path) => {
                const raw = path.node.extra && path.node.extra.raw;
                if (raw && /^[+-]?0[xXbBoO]/.test(raw)) { delete path.node.extra; transforms++; }
            }
        });
        } catch (e) {
            if (this.options.verbose) console.warn('  ⚠️ Phase 2 stopped early:', e.message);
        }

        // ── Phase 3: evaluate base-decoder calls with now-literal args via VM ──
        if (live && baseNames && baseNames.length) {
            try {
                const r = this._evalLiveDecoders(ast, live, baseNames);
                transforms += r.count;
                if (r.count > 0) decoderInfo = { detected: true, decodedCalls: (decoderInfo?.decodedCalls || 0) + r.count };
            } catch (e) {}
        }

        let out;
        try { out = this.generator(ast, { compact: false, comments: true }).code; }
        catch (e) { out = code; transforms = 0; } // keep input on generation failure
        return { code: out, transforms, decoderInfo };
    }

    /**
     * Detect, execute, and inline the script's own string-array decoder.
     *
     * Handles the dominant obfuscator.io / enterprise pattern:
     *   1. an encoded string array (function or var)
     *   2. an IIFE that rotates the array until a checksum passes
     *   3. a decoder function f(index, key) that indexes + RC4/base64-decodes
     *      using a key embedded in the script itself
     *
     * We lift (1)+(2)+(3) into an isolated VM, run them with THEIR key, then
     * replace every f(...)/alias(...) call with the resulting string literal.
     * Returns { code, count, info }. No-ops safely if the pattern isn't found.
     */
    _liftStringArrayDecoder(code, deadline) {
        const t = this.t;
        const gen = (node) => this.generator(node, { compact: false }).code;

        let ast;
        try {
            ast = this.babel.parse(code, {
                sourceType: 'unambiguous',
                parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true, allowSuperOutsideMethod: true }
            });
        } catch (e) { return { code, count: 0, live: null, baseNames: [], info: null }; }

        // --- 1) Locate the encoded string-array provider ---
        let arrayName = null, arraySource = null, arrayLen = 0;
        const looksLikeArray = (elements) => {
            if (!elements || elements.length < 3) return false;
            const strs = elements.filter(e => e && t.isStringLiteral(e)).length;
            return strs >= elements.length * 0.6;
        };

        this.traverse(ast, {
            VariableDeclarator: (p) => {
                if (arrayName) return;
                const { id, init } = p.node;
                if (t.isIdentifier(id) && t.isArrayExpression(init) && looksLikeArray(init.elements)) {
                    arrayName = id.name; arrayLen = init.elements.length;
                    arraySource = 'var ' + arrayName + '=' + gen(init) + ';';
                }
            },
            FunctionDeclaration: (p) => {
                if (arrayName || !p.node.id) return;
                const body = p.node.body.body || [];
                let arrNode = null;
                const ret = body.find(s => t.isReturnStatement(s));
                if (ret && t.isArrayExpression(ret.argument)) arrNode = ret.argument;
                if (!arrNode) {
                    for (const s of body) {
                        if (t.isVariableDeclaration(s)) {
                            const d = s.declarations.find(d => t.isArrayExpression(d.init));
                            if (d) { arrNode = d.init; break; }
                        }
                    }
                }
                if (arrNode && looksLikeArray(arrNode.elements)) {
                    arrayName = p.node.id.name; arrayLen = arrNode.elements.length;
                    arraySource = gen(p.node);
                }
            }
        });

        if (!arrayName) return { code, count: 0, live: null, baseNames: [], info: null };

        // --- 2) Rotator IIFE + 3) decoder functions that reference the array ---
        let rotatorSource = '';
        const decoders = {};
        this.traverse(ast, {
            ExpressionStatement: (p) => {
                const ex = p.node.expression;
                if (t.isCallExpression(ex)) {
                    const src = gen(p.node);
                    if (src.length < 24000 && src.includes(arrayName) && /parseInt|push|shift|while/.test(src)) {
                        rotatorSource += src + '\n';
                    }
                }
            },
            FunctionDeclaration: (p) => {
                const name = p.node.id && p.node.id.name;
                if (!name || name === arrayName) return;
                const src = gen(p.node);
                if (src.length < 24000 && src.includes(arrayName)) decoders[name] = src;
            }
        });

        if (Object.keys(decoders).length === 0) return { code, count: 0, live: null, baseNames: [], info: null };

        // --- 4) Execute the lifted decoder in an isolated VM (uses THEIR key) ---
        // Neutralize self-defending anti-debug traps before VM execution. These
        // are calls like `new _0x2cdb81(decoder).ybwJnh()` that recursively call
        // the decoder with a bad key (throwing in RC4) and corrupt setup. We strip
        // ONLY within the VM harness — the emitted output is never touched.
        const neutralize = (src) => (src || '').replace(
            /new\s+[\w$]+\s*\([^()]*\)\s*(?:\[[^\]]*\]|\.\s*[\w$]+)\s*\(\s*\)/g,
            'void 0'
        );

        // Minify harness sources to a single line. obfuscator.io decoders can be
        // anti-tamper: they read their OWN source via `'' + decoderFn` and check
        // for newlines (charCode 10). Pretty-printed source breaks them; the
        // original is minified to one line, so we reproduce that by compacting.
        const minify = (src) => {
            try {
                const a = this.babel.parse(src, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
                return this.generator(a, { compact: true, comments: false }).code;
            } catch (e) { return String(src).replace(/\n/g, ' '); }
        };

        const guardedRotator = minify(neutralize(rotatorSource)).replace(
            /while\s*\(\s*(?:!!\[\]|!\[\]|true|1|0x1)\s*\)/g,
            'for (var __jsg = 0; __jsg < 20000; __jsg++)'
        );

        const harness =
            minify(arraySource) + '\n' +
            guardedRotator + '\n' +
            Object.values(decoders).map(d => minify(neutralize(d))).join('\n') + '\n' +
            '({' + Object.keys(decoders).map(n => JSON.stringify(n) + ':' + n).join(',') + '});';

        let live;
        try {
            const sandbox = {
                atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
                btoa: (s) => Buffer.from(String(s), 'binary').toString('base64')
            };
            const budget = Math.max(2000, Math.min(8000, (deadline || Date.now() + 8000) - Date.now()));
            live = vm.runInNewContext(harness, vm.createContext(sandbox), { timeout: budget });
        } catch (e) {
            return { code, count: 0, live: null, baseNames: Object.keys(decoders), info: { detected: true, arrayLength: arrayLen, decoders: Object.keys(decoders), decodedCalls: 0, error: e.message } };
        }
        if (!live || typeof live !== 'object') return { code, count: 0, live: null, baseNames: Object.keys(decoders), info: null };

        // --- 5) Resolve simple decoder aliases: var b = a; ---
        const alias = {};
        this.traverse(ast, {
            VariableDeclarator: (p) => {
                const { id, init } = p.node;
                if (t.isIdentifier(id) && t.isIdentifier(init) && live[init.name]) alias[id.name] = init.name;
            }
        });

        // --- 6) Replace every decoder/alias call with its decoded string ---
        let count = 0;
        const litArg = (a) =>
            t.isStringLiteral(a) || t.isNumericLiteral(a) ||
            (t.isUnaryExpression(a) && a.operator === '-' && t.isNumericLiteral(a.argument));
        const argVal = (a) => t.isUnaryExpression(a) ? -a.argument.value : a.value;

        this.traverse(ast, {
            CallExpression: (p) => {
                const callee = p.node.callee;
                if (!t.isIdentifier(callee)) return;
                const name = live[callee.name] ? callee.name : (alias[callee.name] || null);
                if (!name) return;
                const args = p.node.arguments;
                if (!args.length || !args.every(litArg)) return;
                try {
                    const out = live[name](...args.map(argVal));
                    if (typeof out === 'string' && out.length) { p.replaceWith(t.stringLiteral(out)); count++; }
                } catch (e) { /* leave this call alone */ }
            }
        });

        const info = {
            detected: true,
            arrayLength: arrayLen,
            decoders: Object.keys(decoders),
            aliases: Object.keys(alias),
            decodedCalls: count
        };

        const baseNames = Object.keys(decoders);
        if (count === 0) return { code, count: 0, live, baseNames, info };
        return { code: gen(ast), count, live, baseNames, info };
    }

    /**
     * Unwrap eval-packers: eval("..."), eval(function(p,a,c,k,e,d){...}(...)),
     * and chained eval wrappers. Runs the packer (NOT eval) in an isolated VM
     * to recover the original source, then re-parses it in place.
     */
    _unpackEval(code, deadline) {
        const t = this.t;
        let cur = code, total = 0, changed = true, rounds = 0;

        while (changed && rounds < 6) {
            changed = false; rounds++;
            if (deadline && Date.now() > deadline) break;

            let ast;
            try {
                ast = this.babel.parse(cur, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
            } catch (e) { break; }

            const jobs = [];
            this.traverse(ast, {
                CallExpression: (p) => {
                    const node = p.node;
                    if (!t.isIdentifier(node.callee, { name: 'eval' }) || node.arguments.length !== 1) return;
                    const arg = node.arguments[0];
                    if (t.isStringLiteral(arg)) { jobs.push({ path: p, code: arg.value }); return; }
                    if (t.isCallExpression(arg) || t.isFunctionExpression(arg)) {
                        try {
                            const src = '(' + this.generator(arg, { compact: true }).code + ')';
                            const out = vm.runInNewContext(src, vm.createContext({
                                atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
                                btoa: (s) => Buffer.from(String(s), 'binary').toString('base64')
                            }), { timeout: 2000 });
                            if (typeof out === 'string' && out.length) jobs.push({ path: p, code: out });
                        } catch (e) { /* not a static packer */ }
                    }
                }
            });

            for (const job of jobs) {
                try {
                    const inner = this.babel.parse(job.code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
                    const stmt = job.path.getStatementParent();
                    if (stmt && inner.program.body.length) {
                        stmt.replaceWithMultiple(inner.program.body);
                        total++; changed = true;
                    }
                } catch (e) { /* leave as-is */ }
            }

            if (changed) {
                try { cur = this.generator(ast, { compact: false }).code; } catch (e) { break; }
            }
        }

        return { code: cur, count: total };
    }

    /**
     * Split a webpack bundle into labelled, readable module blocks.
     * Finds the modules container (object/array of module functions) and emits
     * each module behind a "// ===== Module <id> =====" header. Best-effort,
     * readability-focused (does not resolve the require graph).
     */
    _splitWebpack(code) {
        const t = this.t;
        let ast;
        try {
            ast = this.babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
        } catch (e) { return { code, count: 0 }; }

        const isModuleFn = (n) =>
            (t.isFunctionExpression(n) || t.isArrowFunctionExpression(n)) && n.params.length >= 1 && n.params.length <= 3;

        let container = null;
        this.traverse(ast, {
            ObjectExpression: (p) => {
                if (container) return;
                const props = p.node.properties;
                if (props.length < 2) return;
                const fnProps = props.filter(pr => t.isObjectProperty(pr) && isModuleFn(pr.value));
                if (fnProps.length >= 2 && fnProps.length >= props.length * 0.8 && this._webpackScore(fnProps.map(fp => fp.value)) >= 0.5) container = { type: 'object', node: p.node };
            },
            ArrayExpression: (p) => {
                if (container) return;
                const els = p.node.elements.filter(Boolean);
                if (els.length < 2) return;
                const fnEls = els.filter(isModuleFn);
                if (fnEls.length >= 2 && fnEls.length >= els.length * 0.8 && this._webpackScore(fnEls) >= 0.5) container = { type: 'array', node: p.node };
            }
        });

        if (!container) return { code, count: 0 };

        const blocks = [];
        const gen = (n) => this.generator(n, { compact: false }).code;

        if (container.type === 'object') {
            for (const pr of container.node.properties) {
                if (!t.isObjectProperty(pr)) continue;
                const key = t.isStringLiteral(pr.key) ? pr.key.value : (t.isIdentifier(pr.key) ? pr.key.name : (t.isNumericLiteral(pr.key) ? pr.key.value : '?'));
                blocks.push('// ===== Module ' + JSON.stringify(key) + ' =====\n' + gen(pr.value));
            }
        } else {
            container.node.elements.forEach((el, i) => {
                if (!el) return;
                blocks.push('// ===== Module ' + i + ' =====\n' + gen(el));
            });
        }

        if (blocks.length < 2) return { code, count: 0 };

        const header = '/* J-Shadow: webpack bundle split into ' + blocks.length + ' module(s) for review.\n' +
            '   (require graph not resolved — this is a readability view) */\n\n';
        return { code: header + blocks.join('\n\n'), count: blocks.length };
    }

    /** Heuristic: do these module functions actually look like webpack modules? */
    _webpackScore(fns) {
        if (!fns.length) return 0;
        let hits = 0;
        for (const fn of fns) {
            let src = '';
            try { src = this.generator(fn, { compact: true }).code; } catch (e) {}
            if (/\b(module|exports|__webpack_require__|__webpack_exports__)\b/.test(src) || (fn.params && fn.params.length === 3)) hits++;
        }
        return hits / fns.length;
    }

    /**
     * Inline obfuscator.io wrapper-function objects:
     *   var _o = { 'VRBIT': (a,b)=>a/b, 'XqXnz': (f)=>f() };
     *   _o.VRBIT(x, y)  ->  x / y        _o['XqXnz'](g)  ->  g()
     * Replaces each wrapper call with the inlined expression (params substituted).
     */
    _inlineWrapperObjects(ast) {
        const t = this.t;
        let count = 0;

        this.traverse(ast, {
            VariableDeclarator: (path) => {
                const { id, init } = path.node;
                if (!t.isIdentifier(id) || !t.isObjectExpression(init) || init.properties.length === 0) return;
                const binding = path.scope.getBinding(id.name);
                if (!binding || !binding.constant) return;

                // Build a map: key -> { params, returnExpr }. Every property must be a
                // simple function whose body is a single `return <expr>`.
                const specs = {};
                let ok = true;
                for (const pr of init.properties) {
                    if (!t.isObjectProperty(pr)) { ok = false; break; }
                    const key = t.isStringLiteral(pr.key) ? pr.key.value : (t.isIdentifier(pr.key) ? pr.key.name : null);
                    const fn = pr.value;
                    if (key === null || !(t.isFunctionExpression(fn) || t.isArrowFunctionExpression(fn))) { ok = false; break; }
                    if (!fn.params.every(p => t.isIdentifier(p))) { ok = false; break; }
                    let ret = null;
                    if (t.isBlockStatement(fn.body)) {
                        if (fn.body.body.length === 1 && t.isReturnStatement(fn.body.body[0])) ret = fn.body.body[0].argument;
                    } else { ret = fn.body; }
                    if (!ret) { ok = false; break; }
                    specs[key] = { params: fn.params.map(p => p.name), ret };
                }
                if (!ok || Object.keys(specs).length === 0) return;

                for (const ref of binding.referencePaths) {
                    try {
                        const member = ref.parentPath;
                        if (!member || !member.isMemberExpression() || member.node.object !== ref.node) continue;
                        const callPath = member.parentPath;
                        if (!callPath || !callPath.isCallExpression() || callPath.node.callee !== member.node) continue;

                        const prop = member.node.property;
                        let key = null;
                        if (member.node.computed && t.isStringLiteral(prop)) key = prop.value;
                        else if (!member.node.computed && t.isIdentifier(prop)) key = prop.name;
                        if (key === null || !specs[key]) continue;

                        const spec = specs[key];
                        const args = callPath.node.arguments;
                        const map = {};
                        spec.params.forEach((pn, i) => { if (i < args.length) map[pn] = args[i]; });
                        callPath.replaceWith(this._subst(spec.ret, map));
                        count++;
                    } catch (e) { /* leave this call */ }
                }
            }
        });

        return count;
    }

    /**
     * Rename obfuscated identifiers (_0x1a2b, a0_0x4295, ...) into readable,
     * scope-safe names: fn_N / decode_N for functions, a_N for params, v_N for
     * variables. Uses Babel bindings so every reference is updated consistently.
     * Opt-in via options.rename (or the CLI --rename flag).
     */
    _renameIdentifiers(ast) {
        const t = this.t;
        const isObf = (n) => typeof n === 'string' &&
            (/_0x[0-9a-fA-F]{2,}/.test(n) || /^[A-Za-z]\d*_0x[0-9a-fA-F]+$/.test(n));
        let count = 0;
        const c = { fn: 0, v: 0, a: 0, decode: 0, strings: 0 };

        const classify = (binding) => {
            if (binding.kind === 'param') return 'a';
            const p = binding.path;
            let fn = null;
            if (p.isFunctionDeclaration()) fn = p.node;
            else if (p.isVariableDeclarator() && (t.isFunctionExpression(p.node.init) || t.isArrowFunctionExpression(p.node.init))) fn = p.node.init;
            if (fn) {
                let src = '';
                try { src = this.generator(fn.body || fn, { compact: true }).code; } catch (e) {}
                if (/\batob\b|fromCharCode|charCodeAt/.test(src)) return 'decode';
                if (/return\s*\[/.test(src) && /['"]/.test(src)) return 'strings';
                return 'fn';
            }
            return 'v';
        };
        const baseFor = { a: 'a', v: 'v', fn: 'fn', decode: 'decode', strings: 'stringArr' };

        this.traverse(ast, {
            Scopable(path) {
                const names = Object.keys(path.scope.bindings);
                for (const name of names) {
                    if (!isObf(name)) continue;
                    const binding = path.scope.bindings[name];
                    if (!binding) continue;
                    const kind = classify(binding);
                    let newName;
                    do { newName = baseFor[kind] + '_' + (++c[kind]); }
                    while (path.scope.hasBinding(newName));
                    try { path.scope.rename(name, newName); count++; } catch (e) {}
                }
            }
        });
        return count;
    }

    /**
     * Substitute identifier params with argument nodes inside a cloned AST node,
     * WITHOUT invoking a nested Babel traversal (which can overflow the stack when
     * called from within another traversal). Skips non-computed member property
     * names and object-property keys.
     */
    _subst(node, map) {
        const t = this.t;
        const clone = t.cloneNode(node, true);
        const SKIP = new Set(['type', 'loc', 'start', 'end', 'range', 'leadingComments', 'trailingComments', 'innerComments', 'extra', 'comments']);
        const repl = (n) => (n && t.isIdentifier(n) && Object.prototype.hasOwnProperty.call(map, n.name)) ? t.cloneNode(map[n.name], true) : n;
        const rec = (n) => {
            if (!n || typeof n !== 'object' || !n.type) return;
            if (t.isMemberExpression(n)) {
                n.object = repl(n.object); rec(n.object);
                if (n.computed) { n.property = repl(n.property); rec(n.property); }
                return;
            }
            if (t.isObjectProperty(n)) {
                if (n.computed) { n.key = repl(n.key); rec(n.key); }
                n.value = repl(n.value); rec(n.value);
                return;
            }
            for (const key of Object.keys(n)) {
                if (SKIP.has(key)) continue;
                const child = n[key];
                if (Array.isArray(child)) {
                    for (let i = 0; i < child.length; i++) { child[i] = repl(child[i]); rec(child[i]); }
                } else if (child && typeof child === 'object' && child.type) {
                    n[key] = repl(child); rec(n[key]);
                }
            }
        };
        rec(clone);
        return clone;
    }

    /**
     * Inline scalar properties of const object literals:
     *   var _c = { _a: 0x3b8, _b: 'JvDg' };  _c._a -> 0x3b8,  _c['_b'] -> 'JvDg'
     * obfuscator.io hoists offsets/keys into these objects; inlining them lets
     * the surrounding arithmetic fold to literals.
     */
    _inlineConstObjects(ast) {
        const t = this.t;
        let count = 0;

        this.traverse(ast, {
            VariableDeclarator: (path) => {
                const { id, init } = path.node;
                if (!t.isIdentifier(id) || !t.isObjectExpression(init) || init.properties.length === 0) return;
                const binding = path.scope.getBinding(id.name);
                if (!binding || !binding.constant) return;

                const props = {};
                let hasScalar = false;
                for (const pr of init.properties) {
                    if (!t.isObjectProperty(pr)) continue;
                    const key = t.isStringLiteral(pr.key) ? pr.key.value : (t.isIdentifier(pr.key) ? pr.key.name : (t.isNumericLiteral(pr.key) ? pr.key.value : null));
                    if (key === null) continue;
                    const v = pr.value;
                    if (t.isStringLiteral(v) || t.isNumericLiteral(v) || t.isBooleanLiteral(v) || t.isNullLiteral(v)) { props[key] = v; hasScalar = true; }
                }
                if (!hasScalar) return;

                for (const ref of binding.referencePaths) {
                    try {
                        const m = ref.parentPath;
                        if (!m || !m.isMemberExpression() || m.node.object !== ref.node) continue;
                        const prop = m.node.property;
                        let key = null;
                        if (m.node.computed && t.isStringLiteral(prop)) key = prop.value;
                        else if (!m.node.computed && t.isIdentifier(prop)) key = prop.name;
                        if (key === null || !(key in props)) continue;
                        m.replaceWith(t.cloneNode(props[key], true));
                        count++;
                    } catch (e) {}
                }
            }
        });
        return count;
    }

    /**
     * Inline obfuscator.io decoder proxy functions (transitively). A proxy is a
     * function whose body is `return CALLEE(args)` where CALLEE is a known base
     * decoder or another proxy. Calls to the proxy are replaced with the inner
     * call (params substituted), so after folding they reach the base decoder
     * with literal arguments. `known` grows with each discovered proxy.
     */
    _inlineDecoderProxies(ast, known) {
        const t = this.t;
        let count = 0;

        // Single detection + inline round. Transitive/nested proxies resolve
        // across the outer pass loop (each pass re-parses fresh), which avoids
        // re-traversing a mutated AST (a source of stack overflows).
        const proxies = {};
        this.traverse(ast, {
            Function: (path) => {
                let name = null;
                const fn = path.node;
                if (path.isFunctionDeclaration() && fn.id) name = fn.id.name;
                else if (path.parentPath && path.parentPath.isVariableDeclarator() && t.isIdentifier(path.parentPath.node.id)) name = path.parentPath.node.id.name;
                if (!name || known.has(name) || proxies[name]) return;
                if (!fn.params.every(p => t.isIdentifier(p))) return;

                let ret = null;
                if (t.isBlockStatement(fn.body)) {
                    if (fn.body.body.length === 1 && t.isReturnStatement(fn.body.body[0])) ret = fn.body.body[0].argument;
                } else ret = fn.body;
                if (!ret || !t.isCallExpression(ret) || !t.isIdentifier(ret.callee)) return;
                if (!known.has(ret.callee.name)) return;
                proxies[name] = { params: fn.params.map(p => p.name), ret };
            }
        });

        if (Object.keys(proxies).length === 0) return 0;

        this.traverse(ast, {
            CallExpression: (p) => {
                const c = p.node.callee;
                if (!t.isIdentifier(c) || !proxies[c.name]) return;
                try {
                    const spec = proxies[c.name];
                    const args = p.node.arguments;
                    const map = {};
                    spec.params.forEach((pn, i) => { if (i < args.length) map[pn] = args[i]; });
                    p.replaceWith(this._subst(spec.ret, map));
                    count++;
                } catch (e) {}
            }
        });

        return count;
    }

    /**
     * Evaluate base-decoder calls whose arguments are now literals, using the
     * VM-lifted decoder functions (which apply the script's own RC4/base64 + key).
     */
    _evalLiveDecoders(ast, live, baseNames) {
        const t = this.t;
        const names = new Set(baseNames);
        let count = 0;

        const litVal = (a) => {
            if (t.isStringLiteral(a) || t.isNumericLiteral(a)) return { ok: true, v: a.value };
            if (t.isUnaryExpression(a) && a.operator === '-' && t.isNumericLiteral(a.argument)) return { ok: true, v: -a.argument.value };
            if (t.isBooleanLiteral(a)) return { ok: true, v: a.value };
            return { ok: false };
        };

        this.traverse(ast, {
            CallExpression: (p) => {
                const c = p.node.callee;
                if (!t.isIdentifier(c) || !names.has(c.name) || typeof live[c.name] !== 'function') return;
                const argPaths = p.get('arguments');
                const vals = [];
                for (let i = 0; i < p.node.arguments.length; i++) {
                    const a = p.node.arguments[i];
                    const r = litVal(a);
                    if (r.ok) { vals.push(r.v); continue; }
                    // try to fold the argument (e.g. 0x198 - 0xbd) if it's small enough
                    try {
                        if (this._exprSize(a, 200) < 200) {
                            const ev = argPaths[i].evaluate();
                            if (ev.confident && (typeof ev.value === 'string' || typeof ev.value === 'number')) { vals.push(ev.value); continue; }
                        }
                    } catch (e) {}
                    return; // arg not resolvable yet — try again next pass
                }
                try {
                    const out = live[c.name](...vals);
                    if (typeof out === 'string' && out.length) { p.replaceWith(t.stringLiteral(out)); count++; }
                } catch (e) { /* leave call for a later pass */ }
            }
        });
        return { count };
    }

    /**
     * Full debundle: deobfuscate, then extract each webpack module into its own
     * unit with the require graph resolved (require(id) -> require('./file')).
     * Returns { isBundle, modules:[{id,name,code,deps}], entry, deobfuscated } .
     */
    async debundle(code) {
        const deob = await this.process(code, { skipSplit: true });
        const struct = this._extractModules(deob.code);
        if (!struct) return { isBundle: false, deobfuscated: deob.code };
        return { isBundle: true, ...struct, deobfuscated: deob.code };
    }

    /** Map a webpack module id to a safe relative filename. */
    _idToName(id) {
        if (typeof id === 'string') {
            let n = id.replace(/^\.?\/+/, '');
            n = n.replace(/[?#].*$/, '');           // strip query/hash
            n = n.replace(/[^\w./\-]/g, '_');        // sanitize
            if (!/\.[cm]?jsx?$/.test(n)) n += '.js';
            return n;
        }
        return 'module_' + id + '.js';
    }

    /** Compute a relative import specifier from one module file to another. */
    _relImport(fromName, toName) {
        const fromDir = path.posix.dirname('/' + fromName);
        const to = '/' + toName.replace(/\.[cm]?jsx?$/, '');
        let rel = path.posix.relative(fromDir, to);
        if (!rel.startsWith('.')) rel = './' + rel;
        return rel;
    }

    /**
     * Extract webpack modules with require-graph resolution.
     * Returns { modules, entry, moduleCount } or null if not a bundle.
     */
    _extractModules(code) {
        const t = this.t;
        let ast;
        try {
            ast = this.babel.parse(code, { sourceType: 'unambiguous', parserOpts: { errorRecovery: true, allowReturnOutsideFunction: true } });
        } catch (e) { return null; }

        const isModuleFn = (n) =>
            (t.isFunctionExpression(n) || t.isArrowFunctionExpression(n)) && n.params.length >= 1 && n.params.length <= 3;

        // locate the modules container
        let container = null;
        this.traverse(ast, {
            ObjectExpression: (p) => {
                if (container) return;
                const props = p.node.properties;
                if (props.length < 2) return;
                const fnProps = props.filter(pr => t.isObjectProperty(pr) && isModuleFn(pr.value));
                if (fnProps.length >= 2 && fnProps.length >= props.length * 0.8 && this._webpackScore(fnProps.map(fp => fp.value)) >= 0.5) container = { type: 'object', node: p.node };
            },
            ArrayExpression: (p) => {
                if (container) return;
                const els = p.node.elements.filter(Boolean);
                if (els.length < 2) return;
                const fnEls = els.filter(isModuleFn);
                if (fnEls.length >= 2 && fnEls.length >= els.length * 0.8 && this._webpackScore(fnEls) >= 0.5) container = { type: 'array', node: p.node };
            }
        });
        if (!container) return null;

        // gather raw modules
        const keyOf = (k) => t.isStringLiteral(k) ? k.value : (t.isIdentifier(k) ? k.name : (t.isNumericLiteral(k) ? k.value : null));
        const raw = [];
        if (container.type === 'object') {
            for (const pr of container.node.properties) {
                if (!t.isObjectProperty(pr) || !isModuleFn(pr.value)) continue;
                const id = keyOf(pr.key);
                if (id !== null) raw.push({ id, fnNode: pr.value });
            }
        } else {
            container.node.elements.forEach((el, i) => { if (el && isModuleFn(el)) raw.push({ id: i, fnNode: el }); });
        }
        if (raw.length < 2) return null;

        const idToName = {};
        raw.forEach(m => { idToName[m.id] = this._idToName(m.id); });

        // rewrite requires + collect deps per module
        const modules = raw.map(m => {
            const requireParam = (m.fnNode.params[2] && t.isIdentifier(m.fnNode.params[2])) ? m.fnNode.params[2].name : null;
            const deps = new Set();
            const clone = t.cloneNode(m.fnNode, true);

            if (requireParam) {
                const wrapper = t.file(t.program([t.expressionStatement(clone)]));
                try {
                    this.traverse(wrapper, {
                        CallExpression: (p) => {
                            const c = p.node.callee;
                            if (t.isIdentifier(c, { name: requireParam }) && p.node.arguments.length === 1) {
                                const arg = p.node.arguments[0];
                                let depId = null;
                                if (t.isNumericLiteral(arg) || t.isStringLiteral(arg)) depId = arg.value;
                                if (depId !== null && idToName[depId] !== undefined) {
                                    deps.add(depId);
                                    const rel = this._relImport(idToName[m.id], idToName[depId]);
                                    p.replaceWith(t.callExpression(t.identifier('require'), [t.stringLiteral(rel)]));
                                }
                            }
                        }
                    });
                } catch (e) { /* leave requires as-is */ }
            }

            const body = clone.body;
            let moduleCode;
            if (t.isBlockStatement(body)) {
                moduleCode = body.body.map(s => this.generator(s, { compact: false }).code).join('\n');
            } else {
                moduleCode = 'module.exports = ' + this.generator(body, { compact: false }).code + ';';
            }

            return { id: m.id, name: idToName[m.id], code: moduleCode, deps: [...deps] };
        });

        // best-effort entry detection: a require-style call with a known id at top level
        let entry = null;
        const knownIds = new Set(raw.map(m => String(m.id)));
        this.traverse(ast, {
            CallExpression: (p) => {
                if (entry !== null) return;
                if (p.getFunctionParent()) return; // must be top-level (outside modules)
                const args = p.node.arguments;
                if (args.length === 1 && (t.isNumericLiteral(args[0]) || t.isStringLiteral(args[0]))) {
                    if (knownIds.has(String(args[0].value))) entry = args[0].value;
                }
            }
        });

        return { modules, entry, moduleCount: modules.length };
    }

    /**
     * Scope-aware constant inlining + string-array index resolution.
     * Returns the number of transforms applied.
     */
    _inlineConstants(ast) {
        const t = this.t;
        let count = 0;

        this.traverse(ast, {
            VariableDeclarator: (path) => {
                const id = path.node.id;
                const init = path.node.init;
                if (!t.isIdentifier(id) || !init) return;

                const binding = path.scope.getBinding(id.name);
                if (!binding || !binding.constant) return;

                // Scalar literal -> inline at every reference
                if (t.isStringLiteral(init) || t.isNumericLiteral(init) || t.isBooleanLiteral(init) || t.isNullLiteral(init)) {
                    let inlined = 0;
                    for (const ref of binding.referencePaths) {
                        try {
                            if (!ref.node) continue;
                            ref.replaceWith(t.cloneNode(init, true));
                            inlined++;
                        } catch (e) {}
                    }
                    if (inlined > 0) {
                        count += inlined;
                        try { path.remove(); } catch (e) {}
                    }
                    return;
                }

                // Array of literals -> resolve `arr[N]` references to the element.
                // NOTE: only safe when the array is never rotated/reassigned (binding.constant).
                if (t.isArrayExpression(init) && init.elements.length &&
                    init.elements.every(el => el && t.isLiteral(el))) {
                    let resolved = 0;
                    let remaining = 0;
                    for (const ref of binding.referencePaths) {
                        try {
                            const parent = ref.parentPath;
                            if (parent && parent.isMemberExpression({ computed: true }) &&
                                parent.node.object === ref.node && t.isNumericLiteral(parent.node.property)) {
                                const idx = parent.node.property.value;
                                if (idx >= 0 && idx < init.elements.length && init.elements[idx]) {
                                    parent.replaceWith(t.cloneNode(init.elements[idx], true));
                                    resolved++;
                                    continue;
                                }
                            }
                            remaining++;
                        } catch (e) { remaining++; }
                    }
                    if (resolved > 0) count += resolved;
                    if (resolved > 0 && remaining === 0) { try { path.remove(); } catch (e) {} }
                }
            }
        });

        return count;
    }

    /**
     * Try Babel's static evaluator; replace with a literal only when confident
     * and the result is a primitive. Returns true if a replacement happened.
     */
    _tryEvaluate(path) {
        try {
            // Guard: skip evaluating very large expression trees (obfuscator.io
            // number-obfuscation builds huge nested arithmetic that overflows the
            // evaluator's recursion). Small offset math still folds fine.
            if (this._exprSize(path.node, 400) >= 400) return false;
            const ev = path.evaluate();
            if (!ev.confident) return false;
            const v = ev.value;
            const ty = typeof v;
            if (v === null || ty === 'string' || ty === 'number' || ty === 'boolean' || ty === 'undefined') {
                // skip no-op (already a literal of same value)
                if (this.t.isLiteral(path.node) && path.node.value === v) return false;
                path.replaceWith(this.t.valueToNode(v));
                return true;
            }
        } catch (e) {}
        return false;
    }

    /** Count AST nodes under `node` up to `cap` (bounded, cheap). */
    _exprSize(node, cap) {
        let n = 0;
        const stack = [node];
        const SKIP = new Set(['type', 'loc', 'start', 'end', 'range', 'leadingComments', 'trailingComments', 'innerComments', 'extra', 'comments']);
        while (stack.length) {
            if (n >= cap) return cap;
            const cur = stack.pop();
            if (!cur || typeof cur !== 'object') continue;
            if (cur.type) n++;
            for (const k of Object.keys(cur)) {
                if (SKIP.has(k)) continue;
                const v = cur[k];
                if (Array.isArray(v)) { for (const x of v) if (x && typeof x === 'object') stack.push(x); }
                else if (v && typeof v === 'object' && v.type) stack.push(v);
            }
        }
        return n;
    }

    /** Hex decode guarded by printable + round-trip checks. */
    _safeHex(value) {
        try {
            const decoded = Buffer.from(value, 'hex').toString('utf8');
            if (!/^[\x09\x0A\x0D\x20-\x7E]+$/.test(decoded)) return null;
            if (Buffer.from(decoded, 'utf8').toString('hex') !== value.toLowerCase()) return null;
            if (!/[A-Za-z]/.test(decoded)) return null;
            return decoded;
        } catch (e) { return null; }
    }

    /** Base64 decode guarded by printable + round-trip (+ meaningfulness unless forced). */
    _safeBase64(value, force = false) {
        try {
            const decoded = Buffer.from(value, 'base64').toString('utf8');
            if (decoded.length < 2) return null;
            if (!/^[\x09\x0A\x0D\x20-\x7E]+$/.test(decoded)) return null;
            // round-trip guard prevents mangling of non-base64 that slips the regex
            const reenc = Buffer.from(decoded, 'utf8').toString('base64').replace(/=+$/, '');
            if (reenc !== value.replace(/=+$/, '')) return null;
            if (!force && !/[A-Za-z]/.test(decoded)) return null;
            return decoded;
        } catch (e) { return null; }
    }

    getStats() { return { ...this.stats, ready: this.isReady() }; }
}

module.exports = JShadowEngine;
