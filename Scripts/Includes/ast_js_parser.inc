// ast_js_parser.inc - JavaScript AST parser (acorn.js)
// Original parser was truncated during AWVS10 decode - only fragment survived.
// Stub: provide minimal interface so dependent scripts don't crash.
var acorn = {
    parse: function(code, opts) {
        return { type: "Program", body: [], sourceType: "script" };
    },
    tokenizer: function(code, opts) {
        return { getToken: function() { return { type: { label: "eof" } }; } };
    },
    version: "0.0.0-stub"
};
