'use strict';
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const { URL } = require('url');

// ---- THTTPResponse ----
class THTTPResponse {
    constructor() {
        this.body = '';
        this.msg2 = 0;
        this.headers = {};
        this._headerKeys = {};
        this._multiHeaders = {};
    }

    headerValue(name) {
        const key = name.toLowerCase();
        return this.headers[key] || '';
    }

    headerValues(name, list) {
        const key = name.toLowerCase();
        const vals = this._multiHeaders[key] || [];
        if (list && typeof list.add === 'function') {
            list.clear();
            for (const v of vals) list.add(v);
        }
        return vals;
    }

    headerExists(name) {
        return name.toLowerCase() in this.headers;
    }

    _addHeader(name, value) {
        const key = name.toLowerCase();
        this.headers[key] = value;
        if (!this._multiHeaders[key]) this._multiHeaders[key] = [];
        this._multiHeaders[key].push(value);
    }

    get headersString() {
        let s = '';
        for (const [k, vals] of Object.entries(this._multiHeaders)) {
            for (const v of vals) s += `${k}: ${v}\r\n`;
        }
        return s;
    }

    toString() {
        return `HTTP/1.1 ${this.msg2}\r\n${this.headersString}\r\n${this.body}`;
    }
}

// ---- THTTPRequest (helper for addHeader, also standalone) ----
class THTTPRequest {
    constructor(job) {
        if (job) {
            this._job = job;
        } else {
            this._job = { _reqHeaders: {}, _body: '', verb: 'GET', URI: '/' };
        }
        this.URI = this._job.URI || '/';
        this.Verb = this._job.verb || 'GET';
        this.body = this._job._body || '';
    }

    addHeader(name, value, replace) {
        this._job._reqHeaders[name] = value;
    }

    copyFrom(other) {
        if (other && other._job) {
            this._job._reqHeaders = Object.assign({}, other._job._reqHeaders);
            this._job._body = other._job._body;
        } else if (other && other._reqHeaders) {
            this._job._reqHeaders = Object.assign({}, other._reqHeaders);
        }
    }

    headerExists(name) {
        const key = name.toLowerCase();
        for (const k of Object.keys(this._job._reqHeaders)) {
            if (k.toLowerCase() === key) return true;
        }
        return false;
    }

    headerValue(name) {
        const key = name.toLowerCase();
        for (const [k, v] of Object.entries(this._job._reqHeaders)) {
            if (k.toLowerCase() === key) return v;
        }
        return '';
    }

    get headersString() {
        let s = '';
        for (const [k, v] of Object.entries(this._job._reqHeaders)) {
            s += `${k}: ${v}\r\n`;
        }
        return s;
    }

    toString() {
        const url = this._job._buildUrl ? this._job._buildUrl() : this.URI;
        return `${this.Verb || this._job.verb} ${url} HTTP/1.1\r\n${this.headersString}\r\n${this.body || this._job._body || ''}`;
    }
}

// ---- THTTPJob ----
class THTTPJob {
    constructor() {
        this.url = null;
        this.verb = 'GET';
        this.URI = '/';
        this._reqHeaders = {};
        this._body = '';
        this.response = new THTTPResponse();
        this.request = new THTTPRequest(this);
        this.Request = this.request;
        this.wasError = false;
        this.notFound = false;
        this.responseDuration = 0;
        this.responseStatus = 0;
        this.errorCode = 0;
        this.secure = false;
        this.hasAspectData = false;
        this.addCookies = true;
        this.retries = 3;
        this.autoHostHeader = true;
        this._host = '';
        this._postData = '';
    }

    set postData(v) { this._body = v; this._postData = v; }
    get postData() { return this._postData; }

    setURL(turlOrStr) {
        if (turlOrStr && typeof turlOrStr === 'object') {
            this.url = turlOrStr;
        } else if (typeof turlOrStr === 'string') {
            this.url = new TURL(turlOrStr);
        }
    }

    get uri() { return this.URI; }
    set uri(v) { this.URI = v; }

    get host() {
        if (this._host) return this._host;
        if (this.url && typeof this.url === 'object' && this.url.host) return this.url.host;
        return '';
    }
    set host(v) { this._host = v; }

    _buildUrl() {
        let base = '';
        if (this.url && typeof this.url === 'object' && this.url.url) {
            base = this.url.url;
        } else if (typeof this.url === 'string') {
            base = this.url;
        }
        if (!base) return this.URI;
        try {
            const u = new URL(base);
            if (this.URI && this.URI !== '/') {
                u.pathname = this.URI;
            }
            return u.toString();
        } catch {
            return base + this.URI;
        }
    }

    execute() {
        const url = this._buildUrl();
        if (!url) { this.wasError = true; return; }

        const args = [
            '-s', '-S', '-i',
            '--max-time', String(SHELL_CONFIG.timeout || 15),
            '-k'
        ];

        if (SHELL_CONFIG.proxy) {
            args.push('-x', SHELL_CONFIG.proxy);
        }

        if (this.verb) args.push('-X', this.verb);

        const headers = Object.assign({}, SHELL_CONFIG.defaultHeaders || {}, this._reqHeaders);
        for (const [k, v] of Object.entries(headers)) {
            args.push('-H', `${k}: ${v}`);
        }

        if (this._body) {
            args.push('-d', this._body);
        }

        args.push('--', url);

        const start = Date.now();
        try {
            const result = spawnSync('curl', args, {
                encoding: 'buffer',
                timeout: (SHELL_CONFIG.timeout || 15) * 1000 + 5000,
                maxBuffer: 10 * 1024 * 1024
            });

            this.responseDuration = Date.now() - start;

            if (result.error || result.status !== 0) {
                this.wasError = true;
                return;
            }

            const raw = result.stdout.toString('utf-8');
            this._parseRawResponse(raw);

            SHELL_STATE.requestCount++;
        } catch (e) {
            this.wasError = true;
            this.responseDuration = Date.now() - start;
        }
    }

    _parseRawResponse(raw) {
        const headerEnd = raw.indexOf('\r\n\r\n');
        let headerBlock, body;

        if (headerEnd === -1) {
            const altEnd = raw.indexOf('\n\n');
            if (altEnd === -1) {
                headerBlock = raw;
                body = '';
            } else {
                headerBlock = raw.substring(0, altEnd);
                body = raw.substring(altEnd + 2);
            }
        } else {
            headerBlock = raw.substring(0, headerEnd);
            body = raw.substring(headerEnd + 4);
        }

        // handle 100 Continue
        if (headerBlock.startsWith('HTTP/') && headerBlock.includes('100')) {
            const next = body.indexOf('\r\n\r\n');
            if (next !== -1) {
                headerBlock = body.substring(0, next);
                body = body.substring(next + 4);
            }
        }

        this.response.body = body;

        const lines = headerBlock.split(/\r?\n/);
        if (lines.length > 0) {
            const statusMatch = lines[0].match(/HTTP\/[\d.]+ (\d+)/);
            if (statusMatch) {
                this.response.msg2 = parseInt(statusMatch[1]);
                this.responseStatus = this.response.msg2;
            }
        }

        for (let i = 1; i < lines.length; i++) {
            const idx = lines[i].indexOf(':');
            if (idx !== -1) {
                const name = lines[i].substring(0, idx).trim();
                const value = lines[i].substring(idx + 1).trim();
                this.response._addHeader(name, value);
            }
        }

        this.notFound = (this.responseStatus === 404);
        this.secure = this._buildUrl().startsWith('https');
    }

    addAspectHeaders() {
        this._reqHeaders['Acunetix-Aspect'] = 'enabled';
        this._reqHeaders['Acunetix-Aspect-Password'] = 'genki';
    }

    getAspectData() { return []; }
}

// ---- TURL ----
class TURL {
    constructor(urlStr) {
        if (typeof urlStr === 'object' && urlStr.url) {
            urlStr = urlStr.url;
        }
        this._raw = urlStr || '';
        try {
            this._parsed = new URL(this._raw);
        } catch {
            this._parsed = null;
        }
    }

    get url() {
        return this._parsed ? this._parsed.toString() : this._raw;
    }
    set url(v) {
        this._raw = v;
        try { this._parsed = new URL(v); } catch { this._parsed = null; }
    }

    get path() { return this._parsed ? this._parsed.pathname : '/'; }
    set path(v) { if (this._parsed) this._parsed.pathname = v; }

    get getVar() { return this._parsed ? this._parsed.search.replace(/^\?/, '') : ''; }
    set getVar(v) {
        if (this._parsed) this._parsed.search = v ? '?' + v : '';
    }

    get scheme() { return this._parsed ? this._parsed.protocol.replace(':', '') : 'http'; }
    get port() {
        if (this._parsed && this._parsed.port) return parseInt(this._parsed.port);
        return this.scheme === 'https' ? 443 : 80;
    }
    get Port() { return this._parsed && this._parsed.port ? this._parsed.port : ''; }
    get host() { return this._parsed ? this._parsed.hostname : ''; }
    get hostPort() {
        const h = this.host;
        const p = this._parsed && this._parsed.port ? this._parsed.port : '';
        return p ? `${h}:${p}` : h;
    }

    get uri() { return this._parsed ? (this._parsed.pathname + this._parsed.search) : '/'; }
    set uri(v) {
        if (this._parsed) {
            const parts = v.split('?');
            this._parsed.pathname = parts[0];
            if (parts.length > 1) this._parsed.search = '?' + parts.slice(1).join('?');
        }
    }

    canonicalize(relUrl) {
        if (!relUrl) return new TURL(this.url);
        try {
            const resolved = new URL(relUrl, this.url);
            return new TURL(resolved.toString());
        } catch {
            return new TURL(relUrl);
        }
    }

    toString() { return this.url; }
}

// ---- TReportItem ----
class TReportItem {
    constructor() {
        this.name = '';
        this.affects = '';
        this.alertPath = '';
        this.parameter = '';
        this.parameterValue = '';
        this.details = '';
        this.Details = '';
        this.severity = '';
        this._xmlFile = '';
        this._httpInfo = null;
    }

    LoadFromFile(fname) {
        this._xmlFile = fname;
        const xmlPath = path.join(SHELL_CONFIG.scriptsDir, 'XML', fname);
        try {
            const content = fs.readFileSync(xmlPath, 'utf-8');
            const nameMatch = content.match(/<name>(.*?)<\/name>/s);
            const sevMatch = content.match(/<severity>(.*?)<\/severity>/s);
            if (nameMatch) this.name = nameMatch[1].trim();
            if (sevMatch) this.severity = sevMatch[1].trim();
        } catch {
            this.name = fname.replace('.xml', '');
        }
    }

    setHttpInfo(job) {
        this._httpInfo = {
            url: job._buildUrl ? job._buildUrl() : '',
            verb: job.verb || '',
            status: job.responseStatus || 0,
            requestHeaders: Object.assign({}, job._reqHeaders || {}),
            responseBody: job.response ? job.response.body.substring(0, 2000) : ''
        };
        if (job.request) this.request = job.request.toString();
        if (job.response) {
            this.response = job.response.headersString;
            this.fullResponse = job.response.toString();
        }
    }
}

// ---- TKBaseItem ----
class TKBaseItem {
    constructor() {
        this.Name = '';
        this.Text = '';
    }
}

// ---- TList ----
class TList {
    constructor() { this._items = []; }
    add(item) { this._items.push(item); return this._items.length - 1; }
    item(i) { return this._items[i]; }
    getFile(i) { return this._items[i]; }
    get count() { return this._items.length; }
    clear() { this._items = []; }
    indexOf(item) { return this._items.indexOf(item); }
}

// ---- TStringList ----
class TStringList {
    constructor() { this._items = []; }
    add(item) { this._items.push(String(item)); }
    indexOf(item) { return this._items.indexOf(String(item)); }
    get count() { return this._items.length; }
    item(i) { return this._items[i]; }
    clear() { this._items = []; }
}

// ---- Global State ----
const SHELL_CONFIG = {
    scriptsDir: '',
    timeout: 15,
    proxy: null,
    delay: 1.0,
    defaultHeaders: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
    },
    verbose: false,
};

const SHELL_STATE = {
    findings: [],
    kbase: [],
    globalValues: {},
    requestCount: 0,
    siteTree: null,
    currentScheme: null,
    currentDirectory: null,
    currentFile: null,
    scanURL: '',
    serverInfo: {},
    storedInjections: {},
    discoveredFiles: null,
    cookies: '',
};

// ---- Global Functions (matching AWVS engine) ----

function AddReportItem(ri) {
    const finding = {
        name: ri.name || ri.Name || '',
        severity: ri.severity || 'medium',
        affects: ri.affects || ri.Affects || '',
        alertPath: ri.alertPath || ri.AlertPath || '',
        parameter: ri.parameter || '',
        parameterValue: ri.parameterValue || '',
        details: ri.details || ri.Details || '',
        xmlFile: ri._xmlFile || '',
        httpInfo: ri._httpInfo || null,
        timestamp: new Date().toISOString(),
    };
    SHELL_STATE.findings.push(finding);
    _output('finding', finding);
}

function AddKBItem(kbi) {
    const item = { name: kbi.Name, text: kbi.Text };
    SHELL_STATE.kbase.push(item);
    _output('kbase', item);
}

function ScriptProgress(percent) {
    _output('progress', { percent: percent });
}

function getGlobalValue(key) {
    return SHELL_STATE.globalValues[key];
}

function setGlobalValue(key, value, persistent) {
    SHELL_STATE.globalValues[key] = value;
}

function getCurrentScheme() {
    return SHELL_STATE.currentScheme;
}

function getCurrentDirectory() {
    const dir = SHELL_STATE.currentDirectory || { path: '/', Name: '', name: '' };
    if (!dir.isMarkedAs) {
        dir.isMarkedAs = function(flag) { return (dir._markedFlags || 0) & flag ? true : false; };
    }
    if (!dir.response) dir.response = new THTTPResponse();
    if (!dir.request) dir.request = new THTTPRequest({ _reqHeaders: {}, _body: '', verb: 'GET', URI: dir.path || '/' });
    if (dir.fullPath === undefined) dir.fullPath = dir.path || '/';
    if (dir.isDir === undefined) dir.isDir = true;
    if (dir.isFile === undefined) dir.isFile = false;
    if (dir.notFound === undefined) dir.notFound = false;
    if (dir.ignored === undefined) dir.ignored = false;
    if (dir.scanSiteFile === undefined) dir.scanSiteFile = true;
    if (!dir.url && SHELL_STATE.scanURL) dir.url = new TURL(SHELL_STATE.scanURL);
    if (dir.getFirstChild === undefined) dir.getFirstChild = function() { return null; };
    if (dir.getNextSibling === undefined) dir.getNextSibling = function() { return null; };
    if (dir.getFirstVariation === undefined) dir.getFirstVariation = function() { return null; };
    return dir;
}

function getCurrentFile() {
    const sf = SHELL_STATE.currentFile || null;
    const url = SHELL_STATE.scanURL || '';
    let filePath = '/';
    let fileName = '';
    try {
        const u = new URL(url);
        filePath = u.pathname;
        const parts = filePath.split('/');
        fileName = parts[parts.length - 1] || '';
    } catch {}
    const file = sf || {
        name: fileName,
        Name: fileName,
        path: filePath.substring(0, filePath.lastIndexOf('/') + 1) || '/',
        fullPath: filePath,
        isFile: !!fileName && fileName.includes('.'),
        isDir: !fileName || !fileName.includes('.'),
        url: url,
    };
    if (!file.response) file.response = new THTTPResponse();
    if (!file.request) file.request = new THTTPRequest({ _reqHeaders: {}, _body: '', verb: 'GET', URI: file.path || '/' });
    if (!file.isMarkedAs) file.isMarkedAs = function(flag) { return (file._markedFlags || 0) & flag ? true : false; };
    if (file.fullPath === undefined) file.fullPath = file.path || '/';
    if (file.Name === undefined) file.Name = file.name || '';
    if (file.getFirstChild === undefined) file.getFirstChild = function() { return null; };
    if (file.getNextSibling === undefined) file.getNextSibling = function() { return null; };
    if (file.getFirstVariation === undefined) file.getFirstVariation = function() { return null; };
    if (file.notFound === undefined) file.notFound = false;
    if (file.ignored === undefined) file.ignored = false;
    if (file.scanSiteFile === undefined) file.scanSiteFile = true;
    if (file.schemeCount === undefined) file.schemeCount = 0;
    return file;
}

function getServerInfo() {
    const si = SHELL_STATE.serverInfo || {};
    const varMap = {
        '${Platform_OS}': 'platform_os',
        '${WebServerBanner}': 'banner',
        '${WebServer}': 'banner',
        '${X-Powered-By}': 'poweredby',
        '${ResponsiveServer}': 'banner',
    };
    function resolveVar(variable) {
        const mapped = varMap[variable];
        if (mapped) return si[mapped] || '';
        return si[variable] || '';
    }
    if (typeof si.hasTechnology !== 'function') {
        si.hasTechnology = function(name) {
            const techs = si.technologies || [];
            const n = name.toLowerCase();
            for (const t of techs) {
                if (t.toLowerCase() === n) return true;
            }
            const banner = (si.banner || '').toLowerCase();
            const pb = (si.poweredby || '').toLowerCase();
            if (banner.includes(n) || pb.includes(n)) return true;
            return false;
        };
        si.match = function(variable, value) {
            const v = resolveVar(variable);
            return v.toLowerCase().includes(value.toLowerCase());
        };
        si.getValue = function(variable) {
            return resolveVar(variable);
        };
    }
    return si;
}

function getSiteRoot(flags) {
    if (SHELL_STATE.siteTree) {
        const tree = SHELL_STATE.siteTree;
        if (typeof tree.getFirstChild !== 'function') {
            return makeSiteFile(tree);
        }
        return tree;
    }
    return makeSiteFile({
        path: '/', Name: '', name: '', fullPath: '/',
        isDir: true, isFile: false,
    });
}

function getNewFiles(flags) {
    const list = SHELL_STATE.discoveredFiles || new TList();
    for (let i = 0; i < list.count; i++) {
        const sf = list.item(i);
        if (sf && !sf.isMarkedAs) {
            sf.isMarkedAs = function(flag) { return (sf._markedFlags || 0) & flag ? true : false; };
            if (!sf.response) sf.response = new THTTPResponse();
            if (!sf.request) sf.request = new THTTPRequest({ _reqHeaders: {}, _body: '', verb: 'GET', URI: sf.path || '/' });
            if (sf.fullPath === undefined) sf.fullPath = sf.path || '/';
            if (sf.Name === undefined) sf.Name = sf.name || '';
            if (sf.notFound === undefined) sf.notFound = false;
            if (sf.ignored === undefined) sf.ignored = false;
            if (sf.scanSiteFile === undefined) sf.scanSiteFile = true;
            if (sf.isFile === undefined) sf.isFile = true;
            if (sf.isDir === undefined) sf.isDir = false;
            if (sf.hasVariations === undefined) sf.hasVariations = false;
            if (sf.schemeCount === undefined) sf.schemeCount = 0;
            if (!sf.getFirstChild) sf.getFirstChild = function() { return null; };
            if (!sf.getNextSibling) sf.getNextSibling = function() { return null; };
            if (!sf.getFirstVariation) sf.getFirstVariation = function() { return null; };
            if (!sf.getScheme) sf.getScheme = function() { return null; };
        }
    }
    return list;
}

function getCookies() {
    return SHELL_STATE.cookies || '';
}

function setCookies(cookies) {
    SHELL_STATE.cookies = cookies;
}

function getHostByName(hostname) {
    try {
        const result = spawnSync('getent', ['hosts', hostname], { encoding: 'utf-8', timeout: 5000 });
        if (result.stdout) {
            const ip = result.stdout.trim().split(/\s+/)[0];
            if (ip) return ip;
        }
        const dig = spawnSync('dig', ['+short', hostname], { encoding: 'utf-8', timeout: 5000 });
        if (dig.stdout) {
            const ip = dig.stdout.trim().split('\n')[0];
            if (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip;
        }
    } catch {}
    return '';
}

function getHTTPWorker() {
    return new THTTPWorker();
}

function addStoredInjectionEntry(type, data) {
    if (!SHELL_STATE.storedInjections[type]) {
        SHELL_STATE.storedInjections[type] = [];
    }
    SHELL_STATE.storedInjections[type].push(data);
}

function getStoredInjectionList(type) {
    return SHELL_STATE.storedInjections[type] || [];
}

function addHTTPJobToCrawler(job, a, b) {
    // stub - adds discovered URL to crawler queue
}

function random(max) {
    return Math.floor(Math.random() * max);
}

function Plain2SHA1(str) {
    const crypto = require('crypto');
    return crypto.createHash('sha1').update(str).digest('hex');
}

function Plain2MD5(str) {
    const crypto = require('crypto');
    return crypto.createHash('md5').update(str).digest('hex');
}

function getFileName(f) {
    const parts = f.split('/');
    const last = parts[parts.length - 1];
    const dotIdx = last.lastIndexOf('.');
    return dotIdx > 0 ? last.substring(0, dotIdx) : last;
}

function getFileExt(f) {
    const dotIdx = f.lastIndexOf('.');
    return dotIdx > 0 ? f.substring(dotIdx) : '';
}

function trace(msg) {
    if (SHELL_CONFIG.verbose) {
        _output('trace', { message: String(msg) });
    }
}

function LogError(msg) {
    _output('error', { message: String(msg) });
}

function sleep(ms) {
    spawnSync('sleep', [String(ms / 1000)], { timeout: ms + 1000 });
}

function getParserData(body, contentType) {
    const pd = { body: body || '', contentType: contentType || '' };
    pd.getForms = function() {
        const forms = [];
        const html = pd.body;
        const re = /<form[\s>]/gi;
        let m;
        while ((m = re.exec(html)) !== null) {
            const formStart = m.index;
            const endTag = html.indexOf('</form>', formStart);
            const formHtml = endTag !== -1 ? html.substring(formStart, endTag + 7) : html.substring(formStart);
            const actionMatch = formHtml.match(/action=["']([^"']*)/i);
            const methodMatch = formHtml.match(/method=["']([^"']*)/i);
            const form = {
                action: actionMatch ? actionMatch[1] : '',
                method: methodMatch ? methodMatch[1] : 'GET',
                html: formHtml,
                inputs: [],
            };
            const inputRe = /<input[^>]*>/gi;
            let im;
            while ((im = inputRe.exec(formHtml)) !== null) {
                const nameMatch = im[0].match(/name=["']([^"']*)/i);
                const typeMatch = im[0].match(/type=["']([^"']*)/i);
                const valMatch = im[0].match(/value=["']([^"']*)/i);
                if (nameMatch) {
                    form.inputs.push({
                        name: nameMatch[1],
                        type: typeMatch ? typeMatch[1] : 'text',
                        value: valMatch ? valMatch[1] : '',
                    });
                }
            }
            forms.push(form);
        }
        const list = new TList();
        for (const f of forms) list.add(f);
        return list;
    };
    pd.getLinks = function() { return new TList(); };
    pd.getComments = function() { return new TList(); };
    return pd;
}

function url2plain(encoded) {
    try { return decodeURIComponent(encoded); } catch { return encoded; }
}

function plain2url(str) {
    return encodeURIComponent(str);
}

function b642plain(b64) {
    return Buffer.from(b64, 'base64').toString('utf-8');
}

function plain2b64(str) {
    return Buffer.from(str, 'utf-8').toString('base64');
}

function plain2md5(str) {
    return Plain2MD5(str);
}

function alert2(msg) {
    _output('trace', { message: `[ALERT] ${msg}` });
}

// ---- TSocket (TCP socket stub) ----
class TSocket {
    constructor() {
        this.host = '';
        this.port = 0;
        this.timeout = 10000;
        this.connected = false;
        this._buffer = '';
    }
    Connect(host, port) {
        if (host) this.host = host;
        if (port) this.port = port;
        try {
            const net = require('net');
            const sock = new net.Socket();
            sock.setTimeout(this.timeout);
            const result = spawnSync('node', ['-e', `
                const net = require('net');
                const s = net.createConnection(${port}, '${host.replace(/'/g, '')}');
                s.setTimeout(${this.timeout});
                s.on('connect', () => { process.stdout.write('OK'); s.destroy(); });
                s.on('error', () => { process.stdout.write('ERR'); });
                s.on('timeout', () => { process.stdout.write('ERR'); s.destroy(); });
            `], { timeout: this.timeout + 2000, encoding: 'utf-8' });
            this.connected = (result.stdout || '').includes('OK');
        } catch {
            this.connected = false;
        }
        return this.connected;
    }
    connect(host, port) { return this.Connect(host, port); }
    Send(data) { this._buffer = data; return data.length; }
    send(data) { return this.Send(data); }
    Recv(maxLen) { return ''; }
    recv(maxLen) { return ''; }
    Close() { this.connected = false; }
    close() { this.connected = false; }
}

function addLinkToCrawler(uri, root) {
    _output('trace', { message: `[CRAWL] Discovered link: ${uri}` });
}

function addHTTPRequestToCrawler(req) {
    const uri = (req && req.URI) || '';
    _output('trace', { message: `[CRAWL] HTTP request queued: ${req && req.Verb || 'GET'} ${uri}` });
}

function strFromRawData() {
    let result = '';
    for (let i = 0; i < arguments.length; i++) {
        result += String.fromCharCode(arguments[i] & 0xFF);
    }
    return result;
}

// ---- THTTPWorker (batch execution) ----
class THTTPWorker {
    constructor() { this._queue = []; }

    addRequest(job) { this._queue.push(job); }

    executeRequests(list) {
        const jobs = list || this._queue;
        const items = jobs._items ? jobs._items : (Array.isArray(jobs) ? jobs : [jobs]);
        for (const job of items) {
            if (job && typeof job.execute === 'function') {
                job.execute();
                if (SHELL_CONFIG.delay > 0) {
                    const delayMs = Math.floor(SHELL_CONFIG.delay * 1000);
                    spawnSync('sleep', [String(SHELL_CONFIG.delay)], { timeout: delayMs + 2000 });
                }
            }
        }
    }
}

// ---- Site File stub (tree node for PostScan/PostCrawl) ----
function makeSiteFile(props) {
    const sf = Object.assign({
        name: '',
        Name: '',
        path: '/',
        url: null,
        notFound: false,
        ignored: false,
        scanSiteFile: true,
        schemeCount: 0,
        internalId: 0,
        response: new THTTPResponse(),
        request: new THTTPRequest({ _reqHeaders: {}, _body: '', verb: 'GET', URI: '/' }),
        _children: [],
        _siblings: [],
        _variations: [],
        _markedFlags: 0,
    }, props || {});
    if (!sf.fullPath) sf.fullPath = sf.path || '/';
    if (sf.isFile === undefined) sf.isFile = !sf.fullPath.endsWith('/');
    if (sf.isDir === undefined) sf.isDir = sf.fullPath.endsWith('/');
    sf.isMarkedAs = function(flag) { return (sf._markedFlags & flag) !== 0; };
    sf.getFirstChild = function() { return sf._children.length > 0 ? sf._children[0] : null; };
    sf.getNext = function() {
        if (sf._parent && sf._parent._children) {
            const idx = sf._parent._children.indexOf(sf);
            if (idx >= 0 && idx + 1 < sf._parent._children.length) return sf._parent._children[idx + 1];
        }
        return null;
    };
    sf.getNextSibling = sf.getNext;
    sf.getFirstVariation = function() { return sf._variations.length > 0 ? sf._variations[0] : null; };
    sf.hasVariations = sf._variations.length > 0;
    if (!sf._schemes) sf._schemes = [];
    sf.schemeCount = sf._schemes.length;
    sf.getScheme = function(i) {
        if (i < sf._schemes.length) return sf._schemes[i];
        return null;
    };
    return sf;
}

function getSiteFileWithPath(pathStr, flag) {
    const scanUrl = SHELL_STATE.scanURL || '';
    let fullPath = pathStr || '/';
    return makeSiteFile({
        name: fullPath.split('/').pop() || '',
        Name: fullPath.split('/').pop() || '',
        path: fullPath,
        url: scanUrl ? new TURL(scanUrl) : null,
    });
}

function terminate() {
    throw new Error('__terminate__');
}

function ScriptAbort() {
    throw new Error('__terminate__');
}

// ---- Output helper ----
function _output(type, data) {
    const msg = JSON.stringify({ type, data }) + '\n';
    process.stdout.write(msg);
}

module.exports = {
    THTTPJob, THTTPResponse, THTTPRequest, TURL, TSocket,
    TReportItem, TKBaseItem, TList, TStringList,
    THTTPWorker, SHELL_CONFIG, SHELL_STATE,
    AddReportItem, AddKBItem, ScriptProgress,
    getGlobalValue, setGlobalValue,
    getCurrentScheme, getCurrentDirectory, getCurrentFile, getServerInfo, getNewFiles, getCookies, setCookies,
    getSiteRoot, getHTTPWorker,
    getSiteFileWithPath, makeSiteFile, terminate, ScriptAbort,
    addStoredInjectionEntry, getStoredInjectionList,
    addHTTPJobToCrawler, addHTTPRequestToCrawler, addLinkToCrawler, getHostByName, random,
    Plain2SHA1, Plain2MD5, plain2md5, getFileName, getFileExt,
    trace, LogError, sleep,
    getParserData, url2plain, plain2url, b642plain, plain2b64, alert2,
    strFromRawData,
    _output,
};
