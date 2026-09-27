'use strict';
const bridge = require('./bridge');

class COMCollection {
    constructor(arr) { this._arr = arr || []; this.length = this._arr.length; this.count = this._arr.length; }
    item(i) { return i < this._arr.length ? this._arr[i] : undefined; }
    [Symbol.iterator]() { return this._arr[Symbol.iterator](); }
}

class VariationValues {
    constructor(valuesObj, inputs) {
        this._values = valuesObj || {};
        this._inputs = inputs || [];
    }
    item(inputIndex) {
        if (inputIndex < this._inputs.length) {
            const name = this._inputs[inputIndex].name;
            return name in this._values ? this._values[name] : this._inputs[inputIndex].value;
        }
        return '';
    }
}

class SchemeProxy {
    constructor(data) {
        this._data = data || {};
        this._inputs = (data.inputs || []).map(inp => ({
            name: inp.name || '',
            value: inp.value || '',
            type: inp.type || 'URL encoded GET',
            flags: inp.flags || 0,
        }));
        this._variations = data.variations || [{}];
        this._currentVariation = 0;
        this.path = data.path || '/';
        this.hash = data.hash || '';
        this.internalId = data.internalId || '';
        this.variationHash = data.variationHash || '';
    }

    get inputCount() { return this._inputs.length; }
    get variationCount() { return this._variations.length; }

    getInputName(i) {
        return i < this._inputs.length ? this._inputs[i].name : '';
    }

    getInputValue(i) {
        return i < this._inputs.length ? this._inputs[i].value : '';
    }

    getInputTypeStr(i) {
        return i < this._inputs.length ? this._inputs[i].type : '';
    }

    setInputValue(i, value) {
        if (i >= 0 && i < this._inputs.length) {
            this._inputs[i].value = String(value);
        }
    }

    setEncodedInputValue(i, value) {
        if (i >= 0 && i < this._inputs.length) {
            this._inputs[i].value = String(value);
            this._inputs[i]._encoded = true;
        }
    }

    inputHasFlag(i, flag) {
        if (i < this._inputs.length) {
            return (this._inputs[i].flags & flag) !== 0;
        }
        return false;
    }

    loadVariation(idx) {
        if (idx < this._variations.length) {
            this._currentVariation = idx;
            const values = this._variations[idx];
            for (let i = 0; i < this._inputs.length; i++) {
                if (this._inputs[i].name in values) {
                    this._inputs[i].value = values[this._inputs[i].name];
                }
            }
        }
    }

    selectVariationsForInput(inputIndex) {
        const result = [];
        for (let i = 0; i < this._variations.length; i++) {
            result.push(i);
        }
        return new COMCollection(result.length > 0 ? result : [0]);
    }

    setTempInputName(i, name) {
        if (i < this._inputs.length) {
            this._inputs[i]._origName = this._inputs[i].name;
            this._inputs[i].name = String(name);
        }
    }

    restoreInputName(i) {
        if (i < this._inputs.length && this._inputs[i]._origName !== undefined) {
            this._inputs[i].name = this._inputs[i]._origName;
            delete this._inputs[i]._origName;
        }
    }

    getInputFlags(i) {
        return i < this._inputs.length ? this._inputs[i].flags : 0;
    }

    get hasFileInput() {
        for (const inp of this._inputs) {
            if (inp.type === 'File' || (inp.flags & 0x10)) return true;
        }
        return false;
    }

    get targetHasAcuSensor() { return false; }

    getVariation(idx) {
        const v = idx < this._variations.length ? this._variations[idx] : {};
        return new VariationValues(v, this._inputs);
    }

    randomizeValues() {
        const chars = 'abcdefghijklmnopqrstuvwxyz';
        for (let i = 0; i < this._inputs.length; i++) {
            if (!this._inputs[i].value) {
                let rnd = '';
                for (let j = 0; j < 5; j++) {
                    rnd += chars[Math.floor(Math.random() * chars.length)];
                }
                this._inputs[i].value = rnd;
            }
        }
    }

    populateRequest(job) {
        const url = job.url;
        let getParams = [];
        let postParams = [];
        let cookieParts = [];
        let jsonBody = {};
        let hasJsonBody = false;

        for (const inp of this._inputs) {
            if (inp.type === 'URL encoded GET') {
                getParams.push(encodeURIComponent(inp.name) + '=' + encodeURIComponent(inp.value));
            } else if (inp.type === 'URL encoded POST') {
                postParams.push(encodeURIComponent(inp.name) + '=' + encodeURIComponent(inp.value));
            } else if (inp.type === 'JSON body') {
                jsonBody[inp.name] = inp.value;
                hasJsonBody = true;
            } else if (inp.type === 'Cookie') {
                cookieParts.push(inp.name + '=' + inp.value);
            } else if (inp.type === 'HTTP Header') {
                job.request.addHeader(inp.name, inp.value);
            }
        }

        if (getParams.length > 0) {
            const base = job.URI || '/';
            const sep = base.includes('?') ? '&' : '?';
            job.URI = base + sep + getParams.join('&');
        }

        if (hasJsonBody) {
            job.postData = JSON.stringify(jsonBody);
            job.verb = job.verb || 'POST';
            job.request.addHeader('Content-Type', 'application/json');
        } else if (postParams.length > 0) {
            job.postData = postParams.join('&');
            job.verb = 'POST';
            job.request.addHeader('Content-Type', 'application/x-www-form-urlencoded');
        }

        if (cookieParts.length > 0) {
            job.request.addHeader('Cookie', cookieParts.join('; '));
        }
    }
}

function createSchemeFromContext(ctx) {
    if (!ctx || !ctx.scheme) return null;
    return new SchemeProxy(ctx.scheme);
}

module.exports = { SchemeProxy, createSchemeFromContext };
