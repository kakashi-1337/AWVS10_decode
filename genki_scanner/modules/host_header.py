"""
Host Header Injection detection module.
Ported from AWVS10: PostCrawl Host Header checks
"""
import re
from urllib.parse import urlparse

from .base import BaseModule
from ..core.reporter import Finding


class HostHeaderModule(BaseModule):
    name = "host_header"
    description = "Host Header Injection"

    EVIL_HOST = "evil.6u.gg"

    def run(self, url: str, params: dict = None):
        self.log(f"Testing: {url}")
        self._test_host_override(url)
        self._test_x_forwarded_host(url)
        self._test_absolute_url(url)

    def _test_host_override(self, url):
        resp = self.http.get(url, headers={"Host": self.EVIL_HOST})
        if not resp:
            return
        resp_body = resp.content.decode('utf-8', errors='replace')

        if self._check_reflection(resp_body, self.EVIL_HOST):
            self.reporter.add(Finding(
                vuln_type="Host Header Injection",
                severity="MEDIUM",
                url=url,
                payload=f"Host: {self.EVIL_HOST}",
                evidence="Injected host reflected in response body",
                details="Can lead to password reset poisoning, cache poisoning, SSRF.",
            ))

    def _test_x_forwarded_host(self, url):
        headers_to_test = [
            ("X-Forwarded-Host", self.EVIL_HOST),
            ("X-Host", self.EVIL_HOST),
            ("X-Forwarded-Server", self.EVIL_HOST),
            ("X-Original-URL", f"https://{self.EVIL_HOST}/"),
            ("X-Rewrite-URL", f"https://{self.EVIL_HOST}/"),
        ]

        for header_name, header_value in headers_to_test:
            resp = self.http.get(url, headers={header_name: header_value})
            if not resp:
                continue

            resp_body = resp.content.decode('utf-8', errors='replace')
            if self._check_reflection(resp_body, self.EVIL_HOST):
                self.reporter.add(Finding(
                    vuln_type="Host Header Injection via X-Forwarded-Host",
                    severity="MEDIUM",
                    url=url,
                    payload=f"{header_name}: {header_value}",
                    evidence="Injected host reflected in response body",
                    details=f"Header {header_name} is processed and reflected. Check password reset, emails, redirects.",
                ))
                return

    def _test_absolute_url(self, url):
        parsed = urlparse(url)
        resp = self.http.request(
            "GET",
            url,
            headers={"Host": self.EVIL_HOST},
        )
        if not resp:
            return

        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if self.EVIL_HOST in location:
                self.reporter.add(Finding(
                    vuln_type="Host Header Injection (Redirect)",
                    severity="MEDIUM",
                    url=url,
                    payload=f"Host: {self.EVIL_HOST}",
                    evidence=f"Location: {location}",
                    details="Server redirects using injected Host header value.",
                ))

    def _check_reflection(self, body: str, marker: str) -> bool:
        patterns = [
            rf'(href|src|action)\s*=\s*["\'][^"\']*{re.escape(marker)}',
            rf'(url|redirect|location)\s*[:=]\s*["\']?[^"\'>\s]*{re.escape(marker)}',
            rf'<meta[^>]*content\s*=\s*["\'][^"\']*{re.escape(marker)}',
            rf'<form[^>]*action\s*=\s*["\'][^"\']*{re.escape(marker)}',
            rf'<link[^>]*href\s*=\s*["\'][^"\']*{re.escape(marker)}',
        ]
        for p in patterns:
            if re.search(p, body, re.IGNORECASE):
                return True
        return False
