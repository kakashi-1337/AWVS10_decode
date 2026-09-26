'use strict';

class HTMLToken {
    constructor() {
        this.isTag = false;
        this.isText = false;
        this.isComment = false;
        this.tagName = '';
        this._params = [];
        this.text = '';
        this.raw = '';
        this.isClosing = false;
        this.isSelfClosing = false;
    }

    get paramCount() { return this._params.length; }

    getParamName(i) {
        return i < this._params.length ? this._params[i].name : '';
    }

    getParamValue(i) {
        return i < this._params.length ? this._params[i].value : '';
    }

    getParamQuote(i) {
        return i < this._params.length ? this._params[i].quote : '';
    }
}

class TokenIterator {
    constructor(tokens) {
        this._tokens = tokens;
        this._pos = 0;
    }

    nextToken() {
        if (this._pos >= this._tokens.length) return null;
        return this._tokens[this._pos++];
    }

    get length() { return this._tokens.length; }
}

function htmlTokens(html) {
    const tokens = [];
    let pos = 0;
    const len = html.length;

    while (pos < len) {
        if (html[pos] === '<') {
            if (html.substring(pos, pos + 4) === '<!--') {
                const endComment = html.indexOf('-->', pos + 4);
                const token = new HTMLToken();
                token.isComment = true;
                if (endComment === -1) {
                    token.text = html.substring(pos + 4);
                    token.raw = html.substring(pos);
                    pos = len;
                } else {
                    token.text = html.substring(pos + 4, endComment);
                    token.raw = html.substring(pos, endComment + 3);
                    pos = endComment + 3;
                }
                tokens.push(token);
                continue;
            }

            const tagEnd = _findTagEnd(html, pos);
            if (tagEnd === -1) {
                const token = new HTMLToken();
                token.isText = true;
                token.text = html.substring(pos);
                token.raw = token.text;
                tokens.push(token);
                pos = len;
                continue;
            }

            const rawTag = html.substring(pos, tagEnd + 1);
            const tagContent = html.substring(pos + 1, tagEnd);
            const token = _parseTag(tagContent);
            token.raw = rawTag;
            tokens.push(token);
            pos = tagEnd + 1;
        } else {
            const nextTag = html.indexOf('<', pos);
            const token = new HTMLToken();
            token.isText = true;
            if (nextTag === -1) {
                token.text = html.substring(pos);
                pos = len;
            } else {
                token.text = html.substring(pos, nextTag);
                pos = nextTag;
            }
            token.raw = token.text;
            tokens.push(token);
        }
    }

    const iter = new TokenIterator(tokens);
    iter.forEach = function(fn) { tokens.forEach(fn); };
    iter[Symbol.iterator] = function*() { for (const t of tokens) yield t; };
    return iter;
}

function _findTagEnd(html, start) {
    let pos = start + 1;
    let inSingle = false;
    let inDouble = false;

    while (pos < html.length) {
        const ch = html[pos];
        if (ch === '"' && !inSingle) inDouble = !inDouble;
        else if (ch === "'" && !inDouble) inSingle = !inSingle;
        else if (ch === '>' && !inSingle && !inDouble) return pos;
        pos++;
    }
    return -1;
}

function _parseTag(content) {
    const token = new HTMLToken();
    token.isTag = true;

    let trimmed = content.trim();

    let closingPrefix = '';
    if (trimmed.startsWith('/')) {
        token.isClosing = true;
        closingPrefix = '/';
        trimmed = trimmed.substring(1).trim();
    }

    if (trimmed.endsWith('/')) {
        token.isSelfClosing = true;
        trimmed = trimmed.substring(0, trimmed.length - 1).trim();
    }

    const spaceIdx = trimmed.search(/[\s\/]/);
    if (spaceIdx === -1) {
        token.tagName = closingPrefix + trimmed.toUpperCase();
        return token;
    }

    token.tagName = closingPrefix + trimmed.substring(0, spaceIdx).toUpperCase();
    let rest = trimmed.substring(spaceIdx).trim();

    while (rest.length > 0) {
        rest = rest.replace(/^[\s\/]+/, '');
        if (rest.length === 0) break;

        let eqIdx = rest.indexOf('=');
        let spIdx = rest.search(/\s/);

        if (eqIdx === -1 && spIdx === -1) {
            token._params.push({ name: rest.toUpperCase(), value: '', quote: '' });
            break;
        }

        if (eqIdx === -1 || (spIdx !== -1 && spIdx < eqIdx)) {
            const name = rest.substring(0, spIdx === -1 ? rest.length : spIdx);
            token._params.push({ name: name.toUpperCase(), value: '', quote: '' });
            rest = spIdx === -1 ? '' : rest.substring(spIdx).trim();
            continue;
        }

        const name = rest.substring(0, eqIdx).trim();
        rest = rest.substring(eqIdx + 1).trim();

        let value = '';
        let quote = '';

        if (rest[0] === '"' || rest[0] === "'") {
            quote = rest[0];
            const endQuote = rest.indexOf(quote, 1);
            if (endQuote === -1) {
                value = rest.substring(1);
                rest = '';
            } else {
                value = rest.substring(1, endQuote);
                rest = rest.substring(endQuote + 1).trim();
            }
        } else {
            const nextSpace = rest.search(/[\s>]/);
            if (nextSpace === -1) {
                value = rest;
                rest = '';
            } else {
                value = rest.substring(0, nextSpace);
                rest = rest.substring(nextSpace).trim();
            }
        }

        token._params.push({ name: name.toUpperCase(), value, quote });
    }

    return token;
}

module.exports = { htmlTokens, HTMLToken };
