"""
XSS detection module.
Ported from AWVS10: classXSS.inc

Multi-phase approach:
1. Send probe to detect reflection point and context
2. Select context-specific payloads
3. Verify execution via DOM-aware pattern matching
"""
import re
import random
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base import BaseModule
from ..core.reporter import Finding
from ..payloads.xss_payloads import (
    TEXT_CONTEXT_PAYLOADS,
    ATTR_DOUBLE_QUOTE_PAYLOADS,
    ATTR_SINGLE_QUOTE_PAYLOADS,
    ATTR_NO_QUOTE_PAYLOADS,
    SCRIPT_CONTEXT_PAYLOADS,
    TEMPLATE_INJECTION_PAYLOADS,
    TEMPLATE_EXPECTED,
    DOM_XSS_SOURCES,
    DOM_XSS_SINKS,
    C2_PAYLOADS,
    C2_BLIND_PAYLOADS,
    CSP_BYPASSES,
    CSP_CSS_EXFIL,
    MXSS_PAYLOADS,
    POLYGLOT_PAYLOADS,
    DOM_CLOBBERING_PAYLOADS,
    MARKDOWN_XSS,
    rand_token,
    OOB_DOMAIN,
)


class ReflectionContext:
    TEXT = "text"
    ATTR_DOUBLE = "attr_double_quote"
    ATTR_SINGLE = "attr_single_quote"
    ATTR_NONE = "attr_no_quote"
    SCRIPT = "script"
    COMMENT = "comment"
    NONE = "none"


class SimpleHTMLAnalyzer(HTMLParser):
    def __init__(self, marker):
        super().__init__()
        self.marker = marker.lower()
        self.contexts = []
        self._in_script = False
        self._in_comment = False
        self._current_tag = ""

    def handle_starttag(self, tag, attrs):
        self._current_tag = tag
        if tag == "script":
            self._in_script = True
        for attr_name, attr_val in attrs:
            if attr_val and self.marker in attr_val.lower():
                raw = self.get_starttag_text() or ""
                if f'"{attr_val}"' in raw or f"={attr_val}" in raw:
                    pattern = re.search(
                        rf'''({attr_name}\s*=\s*)(["']?)([^"'>\s]*{re.escape(self.marker)}[^"'>\s]*)''',
                        raw,
                        re.IGNORECASE,
                    )
                    if pattern:
                        quote = pattern.group(2)
                        if quote == '"':
                            self.contexts.append(ReflectionContext.ATTR_DOUBLE)
                        elif quote == "'":
                            self.contexts.append(ReflectionContext.ATTR_SINGLE)
                        else:
                            self.contexts.append(ReflectionContext.ATTR_NONE)
                    else:
                        self.contexts.append(ReflectionContext.ATTR_DOUBLE)

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
        self._current_tag = ""

    def handle_data(self, data):
        if self.marker in data.lower():
            if self._in_script:
                self.contexts.append(ReflectionContext.SCRIPT)
            else:
                self.contexts.append(ReflectionContext.TEXT)

    def handle_comment(self, data):
        if self.marker in data.lower():
            self.contexts.append(ReflectionContext.COMMENT)


class XSSModule(BaseModule):
    name = "xss"
    description = "Cross-Site Scripting (Reflected, DOM, Template Injection)"

    def run(self, url: str, params: dict = None):
        self.log(f"Testing: {url}")
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            query_params.update({k: [v] for k, v in params.items()})

        if not query_params:
            self._test_dom_xss(url)
            return

        for param_name in query_params:
            original_value = query_params[param_name][0]
            self.log(f"Testing param: {param_name}")
            self._test_reflected(url, parsed, query_params, param_name, original_value)

        self._test_dom_xss(url)
        self._test_template_injection(url, parsed, query_params)
        self._test_blind_xss(url, parsed, query_params)
        self._test_polyglot(url, parsed, query_params)

    def _build_url(self, parsed, query_params, param_name, payload):
        modified = dict(query_params)
        modified[param_name] = [payload]
        query_string = urlencode({k: v[0] for k, v in modified.items()})
        return urlunparse(parsed._replace(query=query_string))

    def _detect_context(self, body: str, marker: str) -> list[str]:
        if marker.lower() not in body.lower():
            return []

        analyzer = SimpleHTMLAnalyzer(marker)
        try:
            analyzer.feed(body)
        except Exception:
            pass

        if analyzer.contexts:
            return analyzer.contexts

        if marker in body:
            return [ReflectionContext.TEXT]
        return []

    def _verify_xss(self, body: str, token: str) -> bool:
        patterns = [
            rf"<script[^>]*>[^<]*{re.escape(token)}[^<]*</script>",
            rf"<[^>]+on\w+\s*=\s*[\"']?[^\"'>]*{re.escape(token)}",
            rf"<img[^>]+onerror\s*=\s*[^>]*{re.escape(token)}",
            rf"<svg[^>]+onload\s*=\s*[^>]*{re.escape(token)}",
            rf"<details[^>]+ontoggle\s*=\s*[^>]*{re.escape(token)}",
        ]
        for p in patterns:
            if re.search(p, body, re.IGNORECASE | re.DOTALL):
                return True
        return False

    def _test_reflected(self, url, parsed, query_params, param_name, original_value):
        probe = f"gkprobe{rand_token()}"
        probe_url = self._build_url(parsed, query_params, param_name, probe)
        probe_resp = self.http.get(probe_url)
        if not probe_resp or probe not in probe_resp.text:
            return

        contexts = self._detect_context(probe_resp.text, probe)
        if not contexts:
            return

        self.log(f"  Reflection found in: {', '.join(set(contexts))}")

        payload_sets = []
        for ctx in set(contexts):
            if ctx == ReflectionContext.TEXT:
                payload_sets.extend(TEXT_CONTEXT_PAYLOADS)
            elif ctx == ReflectionContext.ATTR_DOUBLE:
                payload_sets.extend(ATTR_DOUBLE_QUOTE_PAYLOADS)
            elif ctx == ReflectionContext.ATTR_SINGLE:
                payload_sets.extend(ATTR_SINGLE_QUOTE_PAYLOADS)
            elif ctx == ReflectionContext.ATTR_NONE:
                payload_sets.extend(ATTR_NO_QUOTE_PAYLOADS)
            elif ctx == ReflectionContext.SCRIPT:
                payload_sets.extend(SCRIPT_CONTEXT_PAYLOADS)
            elif ctx == ReflectionContext.COMMENT:
                payload_sets.extend(TEXT_CONTEXT_PAYLOADS)

        for payload_fn in payload_sets:
            payload = payload_fn()
            token = re.search(r"alert\(['\"]?(\w+)['\"]?\)", payload)
            if not token:
                continue
            token_val = token.group(1)

            test_url = self._build_url(parsed, query_params, param_name, payload)
            resp = self.http.get(test_url)
            if not resp:
                continue

            if self._verify_xss(resp.text, token_val):
                self.reporter.add(Finding(
                    vuln_type="Cross-Site Scripting (Reflected)",
                    severity="HIGH",
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Token '{token_val}' reflected in executable context",
                    details=f"Reflection context: {', '.join(set(contexts))}",
                ))
                return

    def _test_dom_xss(self, url):
        resp = self.http.get(url)
        if not resp:
            return

        body = resp.text
        found_sources = [s for s in DOM_XSS_SOURCES if s in body]
        found_sinks = [s for s in DOM_XSS_SINKS if s in body]

        if found_sources and found_sinks:
            for source in found_sources:
                for sink in found_sinks:
                    source_line = None
                    sink_line = None
                    for i, line in enumerate(body.split("\n"), 1):
                        if source in line and not source_line:
                            source_line = i
                        if sink in line and not sink_line:
                            sink_line = i

                    if source_line and sink_line:
                        self.reporter.add(Finding(
                            vuln_type="Potential DOM-based XSS",
                            severity="MEDIUM",
                            url=url,
                            evidence=f"Source: {source} (line {source_line}), Sink: {sink} (line {sink_line})",
                            details="Manual verification required. Source flows to sink in client-side JS.",
                        ))
                        return

    def _test_template_injection(self, url, parsed, query_params):
        if not query_params:
            return

        for param_name in query_params:
            for engine, payload in TEMPLATE_INJECTION_PAYLOADS:
                expected = TEMPLATE_EXPECTED.get(payload)
                if not expected:
                    continue

                test_url = self._build_url(parsed, query_params, param_name, payload)
                resp = self.http.get(test_url)
                if not resp:
                    continue

                if expected in resp.text and payload not in resp.text:
                    self.reporter.add(Finding(
                        vuln_type="Server-Side Template Injection (SSTI)",
                        severity="CRITICAL",
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Expression {payload} evaluated to {expected}",
                        details=f"Potential engine: {engine}",
                    ))
                    return

    def _test_blind_xss(self, url, parsed, query_params):
        if not query_params:
            return
        for param_name in query_params:
            for payload in C2_BLIND_PAYLOADS:
                test_url = self._build_url(parsed, query_params, param_name, payload)
                self.http.get(test_url)
            self.log(f"  Blind XSS payloads sent for {param_name} (check {OOB_DOMAIN} for callbacks)")

    def _test_polyglot(self, url, parsed, query_params):
        if not query_params:
            return
        for param_name in query_params:
            for payload in POLYGLOT_PAYLOADS:
                test_url = self._build_url(parsed, query_params, param_name, payload)
                resp = self.http.get(test_url)
                if not resp:
                    continue
                if "alert(" in resp.text and "<" in payload and payload[:10] in resp.text:
                    self.reporter.add(Finding(
                        vuln_type="Cross-Site Scripting (Polyglot)",
                        severity="HIGH",
                        url=url,
                        parameter=param_name,
                        payload=payload[:80] + "..." if len(payload) > 80 else payload,
                        evidence="Polyglot payload reflected with executable context markers",
                    ))
                    return
