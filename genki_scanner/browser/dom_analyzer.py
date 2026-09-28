"""
In-browser DOM XSS analyzer. Runs inside the browser context to detect
live DOM XSS vulnerabilities by tracing source-to-sink data flows.
"""

DOM_XSS_ANALYZER_JS = """
(function() {
    const results = { sources: [], sinks: [], flows: [], clobbering: [] };

    // --- Detect DOM XSS sources ---
    const sourceChecks = [
        { name: 'location.hash', value: location.hash },
        { name: 'location.search', value: location.search },
        { name: 'location.href', value: location.href },
        { name: 'document.URL', value: document.URL },
        { name: 'document.documentURI', value: document.documentURI },
        { name: 'document.referrer', value: document.referrer },
        { name: 'document.baseURI', value: document.baseURI },
        { name: 'window.name', value: window.name },
    ];

    for (const src of sourceChecks) {
        if (src.value && src.value.length > 0) {
            results.sources.push({ name: src.name, value: src.value.substring(0, 200) });
        }
    }

    // --- Detect dangerous sinks in inline scripts ---
    const scripts = document.querySelectorAll('script:not([src])');
    const sinkPatterns = [
        { pattern: /\.innerHTML\s*=/, name: 'innerHTML' },
        { pattern: /\.outerHTML\s*=/, name: 'outerHTML' },
        { pattern: /document\.write\s*\(/, name: 'document.write' },
        { pattern: /document\.writeln\s*\(/, name: 'document.writeln' },
        { pattern: /eval\s*\(/, name: 'eval' },
        { pattern: /setTimeout\s*\(\s*[^,]*(?:location|document|window)/, name: 'setTimeout' },
        { pattern: /setInterval\s*\(\s*[^,]*(?:location|document|window)/, name: 'setInterval' },
        { pattern: /new\s+Function\s*\(/, name: 'Function' },
        { pattern: /\.src\s*=\s*[^;]*(?:location|document|hash|search)/, name: 'src_assign' },
        { pattern: /\.href\s*=\s*[^;]*(?:location|document|hash|search)/, name: 'href_assign' },
        { pattern: /\$\s*\(\s*[^)]*(?:location|document\.URL|hash|search)/, name: 'jquery_selector' },
        { pattern: /\.html\s*\(\s*[^)]*(?:location|document|hash|search)/, name: 'jquery_html' },
        { pattern: /insertAdjacentHTML\s*\(/, name: 'insertAdjacentHTML' },
        { pattern: /setHTMLUnsafe\s*\(/, name: 'setHTMLUnsafe' },
        { pattern: /createContextualFragment\s*\(/, name: 'createContextualFragment' },
    ];

    const flowPatterns = [
        { source: /(?:location\.hash|location\.search|document\.URL|window\.name|document\.referrer)/, sinks: sinkPatterns },
    ];

    for (const script of scripts) {
        const code = script.textContent;
        for (const sink of sinkPatterns) {
            if (sink.pattern.test(code)) {
                results.sinks.push({ name: sink.name, context: code.substring(0, 300) });
            }
        }

        // Source-to-sink flow detection
        for (const flow of flowPatterns) {
            if (flow.source.test(code)) {
                for (const sink of flow.sinks) {
                    if (sink.pattern.test(code)) {
                        results.flows.push({
                            source: flow.source.toString(),
                            sink: sink.name,
                            code: code.substring(0, 500),
                        });
                    }
                }
            }
        }
    }

    // --- Detect DOM clobbering vectors ---
    const clobs = [
        'defaultAvatar', 'config', 'CONFIG', 'settings', 'SETTINGS',
        'base_url', 'baseUrl', 'BASE_URL', 'apiUrl', 'API_URL',
        'redirect', 'callback', 'returnUrl', 'next',
    ];
    for (const name of clobs) {
        const el = document.getElementById(name) || document.getElementsByName(name)[0];
        if (el) {
            results.clobbering.push({
                id: name,
                tag: el.tagName,
                type: el.type || '',
            });
        }
    }

    // --- Detect postMessage handlers without origin check ---
    const scriptTexts = Array.from(scripts).map(s => s.textContent).join('\\n');
    if (/addEventListener\s*\(\s*['"]message['"]/.test(scriptTexts)) {
        if (!/\.origin\s*[!=]==?\s*['"]/.test(scriptTexts) && !/event\.origin/.test(scriptTexts)) {
            results.flows.push({
                source: 'postMessage',
                sink: 'message_handler_no_origin_check',
                code: 'postMessage listener without origin validation',
            });
        }
    }

    return results;
})();
"""

FORM_DISCOVERY_JS = """
(function() {
    const forms = [];
    document.querySelectorAll('form').forEach(form => {
        const inputs = [];
        form.querySelectorAll('input, select, textarea').forEach(inp => {
            inputs.push({
                name: inp.name || '',
                type: inp.type || 'text',
                value: inp.value || '',
                id: inp.id || '',
                placeholder: inp.placeholder || '',
                required: inp.required || false,
            });
        });
        forms.push({
            action: form.action || window.location.href,
            method: (form.method || 'GET').toUpperCase(),
            id: form.id || '',
            enctype: form.enctype || '',
            inputs: inputs,
        });
    });
    return forms;
})();
"""

COOKIE_SECURITY_JS = """
(function() {
    const cookies = document.cookie.split(';').map(c => c.trim()).filter(c => c);
    const results = [];
    for (const cookie of cookies) {
        const [name, ...valueParts] = cookie.split('=');
        const value = valueParts.join('=');
        results.push({
            name: name.trim(),
            value_length: value.length,
            has_value: value.length > 0,
            js_accessible: true,
        });
    }
    return results;
})();
"""

CSP_ANALYZER_JS = """
(function() {
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    const result = {
        has_csp_meta: !!cspMeta,
        csp_content: cspMeta ? cspMeta.getAttribute('content') : null,
        unsafe_inline: false,
        unsafe_eval: false,
        wildcard_src: false,
        missing_frame_ancestors: true,
    };
    if (result.csp_content) {
        result.unsafe_inline = result.csp_content.includes("'unsafe-inline'");
        result.unsafe_eval = result.csp_content.includes("'unsafe-eval'");
        result.wildcard_src = /\\*(?:\\s|;|$)/.test(result.csp_content);
        result.missing_frame_ancestors = !result.csp_content.includes('frame-ancestors');
    }
    return result;
})();
"""


class DOMAnalyzer:
    def __init__(self, engine):
        self.engine = engine

    async def analyze(self, page, url: str) -> dict:
        nav = await self.engine.navigate(page, url)
        if nav.get("error"):
            return {"error": nav["error"]}

        results = {}

        try:
            results["dom_xss"] = await page.evaluate(DOM_XSS_ANALYZER_JS)
        except Exception as e:
            results["dom_xss"] = {"error": str(e)}

        try:
            results["forms"] = await page.evaluate(FORM_DISCOVERY_JS)
        except Exception:
            results["forms"] = []

        try:
            results["cookies"] = await page.evaluate(COOKIE_SECURITY_JS)
        except Exception:
            results["cookies"] = []

        try:
            results["csp"] = await page.evaluate(CSP_ANALYZER_JS)
        except Exception:
            results["csp"] = {}

        results["url"] = url
        results["final_url"] = nav.get("url", url)
        results["title"] = nav.get("title", "")
        results["status"] = nav.get("status", 0)

        return results
