#!/usr/bin/env node
'use strict';
const vm = require('vm');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const bridge = require('./bridge');
const { htmlTokens } = require('./tokenizer');
const { THTMLQuery } = require('./html_query');
const { SchemeProxy, createSchemeFromContext } = require('./scheme_bridge');

const rl = readline.createInterface({ input: process.stdin, terminal: false });

let scriptCache = {};

function output(type, data) {
    process.stdout.write(JSON.stringify({ type, data }) + '\n');
}

function buildSandbox() {
    return {
        // bridge objects
        THTTPJob: bridge.THTTPJob,
        TURL: bridge.TURL,
        TReportItem: bridge.TReportItem,
        TKBaseItem: bridge.TKBaseItem,
        TList: bridge.TList,
        TStringList: bridge.TStringList,
        THTMLQuery: THTMLQuery,

        // global functions
        AddReportItem: bridge.AddReportItem,
        AddKBItem: bridge.AddKBItem,
        ScriptProgress: bridge.ScriptProgress,
        ComputeProgress: function(c, m) { return m > 0 ? Math.floor(100 * c / m) : 0; },
        getGlobalValue: bridge.getGlobalValue,
        setGlobalValue: bridge.setGlobalValue,
        getCurrentScheme: bridge.getCurrentScheme,
        getCurrentDirectory: bridge.getCurrentDirectory,
        getCurrentFile: bridge.getCurrentFile,
        getNewFiles: bridge.getNewFiles,
        getCookies: bridge.getCookies,
        setCookies: bridge.setCookies,
        getServerInfo: bridge.getServerInfo,
        getSiteRoot: bridge.getSiteRoot,
        getHTTPWorker: bridge.getHTTPWorker,
        addStoredInjectionEntry: bridge.addStoredInjectionEntry,
        getStoredInjectionList: bridge.getStoredInjectionList,
        addHTTPJobToCrawler: bridge.addHTTPJobToCrawler,
        addHTTPRequestToCrawler: bridge.addHTTPRequestToCrawler,
        THTTPRequest: bridge.THTTPRequest,
        htmlTokens: htmlTokens,
        addLinkToCrawler: bridge.addLinkToCrawler,
        getHostByName: bridge.getHostByName,
        strFromRawData: bridge.strFromRawData,
        TSocket: bridge.TSocket,
        random: bridge.random,
        Plain2SHA1: bridge.Plain2SHA1,
        Plain2MD5: bridge.Plain2MD5,
        plain2md5: bridge.plain2md5,
        getFileName: bridge.getFileName,
        getFileExt: bridge.getFileExt,
        trace: bridge.trace,
        LogError: bridge.LogError,
        sleep: bridge.sleep,
        getParserData: bridge.getParserData,
        url2plain: bridge.url2plain,
        plain2url: bridge.plain2url,
        b642plain: bridge.b642plain,
        plain2b64: bridge.plain2b64,
        alert2: bridge.alert2,
        getSiteFileWithPath: bridge.getSiteFileWithPath,
        terminate: bridge.terminate,
        ScriptAbort: bridge.ScriptAbort,

        // JS builtins - only add what VM contexts don't provide natively
        Buffer: Buffer,
        parseInt: parseInt,
        parseFloat: parseFloat,
        isNaN: isNaN,
        isFinite: isFinite,
        encodeURIComponent: encodeURIComponent,
        decodeURIComponent: decodeURIComponent,
        encodeURI: encodeURI,
        decodeURI: decodeURI,
        console: {
            log: (...args) => bridge.trace(args.join(' ')),
            error: (...args) => bridge.LogError(args.join(' ')),
        },
        undefined: undefined,

        // scan context (set per command)
        scanURL: null,
        ScanURL: null,
        scanUrl: null,
        scanHost: '',
        ScanHost: '',
        scanIP: '',
        ScanIP: '',
        oobDomain: '',
        SetGlobalValue: bridge.setGlobalValue,
    };
}

function resolveIncludes(code, scriptsDir, visited) {
    visited = visited || new Set();
    const includesDir = path.join(scriptsDir, 'Includes');

    return code.replace(/^#include\s+([^;\s]+)\s*;?\s*$/gm, (match, rawFile) => {
        const file = rawFile.replace(/^["']|["']$/g, '');
        if (visited.has(file)) return `// [already included: ${file}]`;
        visited.add(file);

        const filePath = path.join(includesDir, file);
        try {
            let content = fs.readFileSync(filePath, 'utf-8');
            content = resolveIncludes(content, scriptsDir, visited);
            return `// ---- BEGIN ${file} ----\n${content}\n// ---- END ${file} ----`;
        } catch (e) {
            return `// [include not found: ${file}]`;
        }
    });
}

function resolveRequires(code, scriptsDir) {
    return code.replace(/^#require\s+([^;\s]+)\s*;?\s*$/gm, (match, file) => {
        return `// [require: ${file} - handled by orchestrator]`;
    });
}

function stripPragmas(code) {
    return code
        .replace(/^#noretest\s*;?\s*$/gm, '// [pragma: noretest]')
        .replace(/^#engine\s+[\d.]+\s*;?\s*$/gm, (m) => `// [pragma: ${m.trim()}]`);
}

function preprocessScript(scriptPath, scriptsDir) {
    if (scriptCache[scriptPath]) return scriptCache[scriptPath];

    let code = fs.readFileSync(scriptPath, 'utf-8');
    code = stripPragmas(code);
    code = resolveIncludes(code, scriptsDir, new Set());
    code = resolveRequires(code, scriptsDir);

    // wrap in a function to contain scope
    const wrapped = `(function() {\n${code}\n\n// auto-call startTesting if defined\nif (typeof startTesting === 'function') startTesting();\n})();`;

    scriptCache[scriptPath] = wrapped;
    return wrapped;
}

function executeScript(scriptPath, scriptsDir, context) {
    const code = preprocessScript(scriptPath, scriptsDir);
    const sandbox = buildSandbox();

    // set scan context
    if (context.scanURL) {
        const urlObj = new bridge.TURL(context.scanURL);
        sandbox.scanURL = urlObj;
        sandbox.ScanURL = urlObj;
        sandbox.scanUrl = urlObj;
        sandbox.scanHost = urlObj.host || '';
        sandbox.ScanHost = sandbox.scanHost;
    }
    sandbox.scanIP = context.scanIP || '';
    sandbox.ScanIP = sandbox.scanIP;
    sandbox.oobDomain = context.oobDomain || '6u.gg';

    if (context.scheme) {
        const schemeProxy = new SchemeProxy(context.scheme);
        bridge.SHELL_STATE.currentScheme = schemeProxy;
        sandbox.scheme = schemeProxy;
    }
    if (context.directory) {
        bridge.SHELL_STATE.currentDirectory = context.directory;
    }
    if (context.scanURL) {
        bridge.SHELL_STATE.scanURL = context.scanURL;
    }
    if (context.serverInfo) {
        bridge.SHELL_STATE.serverInfo = context.serverInfo;
    }
    if (context.siteTree) {
        bridge.SHELL_STATE.siteTree = context.siteTree;
    }
    if (context.file) {
        bridge.SHELL_STATE.currentFile = context.file;
    }
    if (context.discoveredFiles) {
        const fileList = new bridge.TList();
        for (const f of context.discoveredFiles) {
            fileList.add(f);
        }
        bridge.SHELL_STATE.discoveredFiles = fileList;
    }
    if (context.cookies !== undefined) {
        bridge.SHELL_STATE.cookies = context.cookies;
    }

    const vmContext = vm.createContext(sandbox);
    try {
        vm.runInContext(code, vmContext, {
            filename: path.basename(scriptPath),
            timeout: 300000, // 5 min per script
        });
        return { success: true, findings: bridge.SHELL_STATE.findings.length };
    } catch (e) {
        if (e.message === '__terminate__') {
            return { success: true, findings: bridge.SHELL_STATE.findings.length };
        }
        return { success: false, error: e.message, stack: e.stack };
    }
}

// ---- Command Handler ----
function handleCommand(cmd) {
    switch (cmd.action) {
        case 'init': {
            bridge.SHELL_CONFIG.scriptsDir = cmd.scriptsDir || '';
            bridge.SHELL_CONFIG.timeout = cmd.timeout || 15;
            bridge.SHELL_CONFIG.proxy = cmd.proxy || null;
            bridge.SHELL_CONFIG.delay = cmd.delay || 1.0;
            bridge.SHELL_CONFIG.verbose = cmd.verbose || false;
            if (cmd.headers) {
                Object.assign(bridge.SHELL_CONFIG.defaultHeaders, cmd.headers);
            }
            output('ready', { scriptsDir: bridge.SHELL_CONFIG.scriptsDir });
            break;
        }

        case 'execute': {
            const result = executeScript(cmd.scriptPath, cmd.scriptsDir || bridge.SHELL_CONFIG.scriptsDir, cmd.context || {});
            output('result', result);
            break;
        }

        case 'set_context': {
            if (cmd.scheme) bridge.SHELL_STATE.currentScheme = cmd.scheme;
            if (cmd.directory) bridge.SHELL_STATE.currentDirectory = cmd.directory;
            if (cmd.serverInfo) bridge.SHELL_STATE.serverInfo = cmd.serverInfo;
            if (cmd.siteTree) bridge.SHELL_STATE.siteTree = cmd.siteTree;
            if (cmd.globalValues) {
                Object.assign(bridge.SHELL_STATE.globalValues, cmd.globalValues);
            }
            output('ack', { action: 'set_context' });
            break;
        }

        case 'get_findings': {
            output('findings', {
                findings: bridge.SHELL_STATE.findings,
                kbase: bridge.SHELL_STATE.kbase,
                requestCount: bridge.SHELL_STATE.requestCount,
            });
            break;
        }

        case 'clear_findings': {
            bridge.SHELL_STATE.findings = [];
            bridge.SHELL_STATE.kbase = [];
            output('ack', { action: 'clear_findings' });
            break;
        }

        case 'preprocess': {
            try {
                const code = preprocessScript(cmd.scriptPath, cmd.scriptsDir || bridge.SHELL_CONFIG.scriptsDir);
                output('preprocessed', { length: code.length, path: cmd.scriptPath });
            } catch (e) {
                output('error', { message: e.message });
            }
            break;
        }

        case 'ping': {
            output('pong', { ts: Date.now() });
            break;
        }

        case 'shutdown': {
            output('bye', { requestCount: bridge.SHELL_STATE.requestCount });
            process.exit(0);
        }

        default:
            output('error', { message: `Unknown action: ${cmd.action}` });
    }
}

// ---- Main IPC Loop ----
output('boot', { version: '1.0', node: process.version });

rl.on('line', (line) => {
    try {
        const cmd = JSON.parse(line.trim());
        handleCommand(cmd);
    } catch (e) {
        output('error', { message: `Parse error: ${e.message}`, line: line.substring(0, 200) });
    }
});

rl.on('close', () => process.exit(0));

process.on('uncaughtException', (e) => {
    output('error', { message: `Uncaught: ${e.message}`, stack: e.stack });
});
