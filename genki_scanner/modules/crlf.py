"""
CRLF Injection detection module.
Ported from AWVS10: classCRLFInjection.inc
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base import BaseModule
from ..core.reporter import Finding


class CRLFModule(BaseModule):
    name = "crlf"
    description = "CRLF Injection / HTTP Response Splitting"

    PAYLOADS = [
        ("%0d%0aX-Genki-Injected: true", "X-Genki-Injected"),
        ("%0aX-Genki-Injected: true", "X-Genki-Injected"),
        ("%0dX-Genki-Injected: true", "X-Genki-Injected"),
        ("%E5%98%8A%E5%98%8DX-Genki-Injected: true", "X-Genki-Injected"),
        ("%0d%0a%0d%0a<script>alert(1)</script>", "<script>alert(1)</script>"),
        ("%23%0d%0aX-Genki-Injected: true", "X-Genki-Injected"),
        ("%25%30%61X-Genki-Injected: true", "X-Genki-Injected"),
        ("%%0d0aX-Genki-Injected: true", "X-Genki-Injected"),
    ]

    def run(self, url: str, params: dict = None):
        self.log(f"Testing: {url}")
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            query_params.update({k: [v] for k, v in params.items()})

        self._test_path_crlf(url, parsed)

        for param_name in query_params:
            original_value = query_params[param_name][0]
            self._test_param_crlf(url, parsed, query_params, param_name, original_value)

    def _test_path_crlf(self, url, parsed):
        for payload, marker in self.PAYLOADS[:3]:
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{payload}"
            resp = self.http.get(test_url, allow_redirects=False)
            if not resp:
                continue

            injected_header = resp.headers.get("X-Genki-Injected", "")
            if injected_header:
                self.reporter.add(Finding(
                    vuln_type="CRLF Injection (Path)",
                    severity="MEDIUM",
                    url=url,
                    payload=payload,
                    evidence=f"Injected header reflected: X-Genki-Injected: {injected_header}",
                    details="HTTP Response Splitting via path. Can lead to XSS, cache poisoning.",
                ))
                return

            if marker in resp.text and "<script>" in payload:
                self.reporter.add(Finding(
                    vuln_type="CRLF Injection to XSS (Path)",
                    severity="HIGH",
                    url=url,
                    payload=payload,
                    evidence="Script tag injected via CRLF in response body",
                ))
                return

    def _test_param_crlf(self, url, parsed, query_params, param_name, original_value):
        for payload, marker in self.PAYLOADS:
            test_value = original_value + payload
            test_url = self._build_url(parsed, query_params, param_name, test_value)
            resp = self.http.get(test_url, allow_redirects=False)
            if not resp:
                continue

            injected_header = resp.headers.get("X-Genki-Injected", "")
            if injected_header:
                self.reporter.add(Finding(
                    vuln_type="CRLF Injection",
                    severity="MEDIUM",
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Injected header: X-Genki-Injected: {injected_header}",
                ))
                return

    def _build_url(self, parsed, query_params, param_name, payload):
        modified = dict(query_params)
        modified[param_name] = [payload]
        query_string = urlencode({k: v[0] for k, v in modified.items()})
        return urlunparse(parsed._replace(query=query_string))
