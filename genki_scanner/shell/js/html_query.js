'use strict';
const { htmlTokens } = require('./tokenizer');

class THTMLQuery {
    constructor() {
        this._html = '';
    }

    set html(v) { this._html = v; }
    get html() { return this._html; }

    executeHtmlQuery(query) {
        if (!this._html || !query) return false;

        const conditions = _parseQuery(query);
        if (conditions.length === 0) return false;

        const tokens = htmlTokens(this._html);
        return _matchTokens(tokens, conditions, this._html);
    }
}

function _parseQuery(query) {
    const parts = query.split('|');
    const conditions = [];

    for (const part of parts) {
        const eqIdx = part.indexOf('=');
        if (eqIdx === -1) continue;

        const key = part.substring(0, eqIdx).trim().toLowerCase();
        const value = part.substring(eqIdx + 1).trim();
        conditions.push({ key, value });
    }

    return conditions;
}

function _matchTokens(tokens, conditions, html) {
    const tagCond = conditions.find(c => c.key === 'tag');
    const tagName = tagCond ? tagCond.value.toLowerCase() : null;

    for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];

        if (tagName && token.isTag && token.tagName === tagName && !token.isClosing) {
            if (_matchConditions(token, tokens, i, conditions, html)) return true;
        }

        if (!tagName) {
            if (token.isTag && !token.isClosing) {
                if (_matchConditions(token, tokens, i, conditions, html)) return true;
            }
        }
    }

    return false;
}

function _matchConditions(token, tokens, tokenIdx, conditions, html) {
    for (const cond of conditions) {
        switch (cond.key) {
            case 'tag':
                if (token.tagName !== cond.value.toLowerCase()) return false;
                break;

            case 'textwithin': {
                let found = false;
                for (let j = tokenIdx + 1; j < tokens.length; j++) {
                    if (tokens[j].isTag && tokens[j].isClosing && tokens[j].tagName === token.tagName) break;
                    if (tokens[j].isText && tokens[j].text.indexOf(cond.value) !== -1) { found = true; break; }
                }
                if (!found) return false;
                break;
            }

            case 'textwithinci': {
                let found = false;
                const searchVal = cond.value.toLowerCase();
                for (let j = tokenIdx + 1; j < tokens.length; j++) {
                    if (tokens[j].isTag && tokens[j].isClosing && tokens[j].tagName === token.tagName) break;
                    if (tokens[j].isText && tokens[j].text.toLowerCase().indexOf(searchVal) !== -1) { found = true; break; }
                }
                if (!found) return false;
                break;
            }

            default: {
                let matched = false;
                for (let p = 0; p < token.paramCount; p++) {
                    if (token.getParamName(p) === cond.key) {
                        if (cond.value === '*' || token.getParamValue(p).indexOf(cond.value) !== -1) {
                            matched = true;
                            break;
                        }
                    }
                }
                if (cond.key !== 'tag' && !matched) return false;
                break;
            }
        }
    }
    return true;
}

module.exports = { THTMLQuery };
