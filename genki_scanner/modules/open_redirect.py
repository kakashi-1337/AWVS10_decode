"""
Open Redirect detection module.
Ported from AWVS10: Open_Redirect.script
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base import BaseModule
from ..core.reporter import Finding


class OpenRedirectModule(BaseModule):
    name = "redirect"
    description = "Open Redirect"

    MARKER = "6u.gg"

    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri", "return",
        "return_url", "returnUrl", "returnTo", "return_to", "next",
        "dest", "destination", "redir", "redirect_to", "out", "view",
        "login_url", "logout", "goto", "target", "rurl", "forward",
        "continue", "callback", "path", "ref", "site",
    ]

    PATH_PAYLOADS = [
        "//{marker}",
        "//{marker}/%2e%2e",
        "////{marker}/%2e%2e",
        "https://{marker}",
        "http://{marker}",
        "/\\{marker}",
        "\\{marker}",
        "/%09/{marker}",
        "/{marker}%00",
        "////{marker}",
        "//{marker}@{marker}",
    ]

    def run(self, url: str, params: dict = None):
        self.log(f"Testing: {url}")
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            query_params.update({k: [v] for k, v in params.items()})

        self._test_path_based(url, parsed)

        tested_params = set()
        for param_name in query_params:
            tested_params.add(param_name)
            self._test_param(url, parsed, query_params, param_name)

        for param_name in self.REDIRECT_PARAMS:
            if param_name not in tested_params and param_name not in query_params:
                modified = dict(query_params)
                modified[param_name] = [""]
                self._test_param(url, parsed, modified, param_name)

    def _test_param(self, url, parsed, query_params, param_name):
        payloads = [
            f"https://{self.MARKER}",
            f"http://{self.MARKER}",
            f"//{self.MARKER}",
            f"//{self.MARKER}/%2e%2e",
            f"https://{self.MARKER}/%2e%2e",
            f"/\\{self.MARKER}",
        ]

        for payload in payloads:
            test_url = self._build_url(parsed, query_params, param_name, payload)
            resp = self.http.get(test_url, allow_redirects=False)
            if not resp:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if self._marker_in_location(location):
                    self.reporter.add(Finding(
                        vuln_type="Open Redirect",
                        severity="MEDIUM",
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Location: {location}",
                        details=f"HTTP {resp.status_code} redirect to attacker-controlled domain",
                    ))
                    return

            if resp.status_code == 200:
                body_lower = resp.text.lower()
                for tag in ["meta", "script"]:
                    if self.MARKER in body_lower:
                        import re
                        meta_match = re.search(
                            rf'<meta[^>]*url\s*=\s*["\']?[^"\']*{re.escape(self.MARKER)}',
                            resp.text,
                            re.IGNORECASE,
                        )
                        js_match = re.search(
                            rf'(window\.location|location\.href|location\.replace)\s*[=(]\s*["\'][^"\']*{re.escape(self.MARKER)}',
                            resp.text,
                            re.IGNORECASE,
                        )
                        if meta_match or js_match:
                            self.reporter.add(Finding(
                                vuln_type="Open Redirect (Meta/JS)",
                                severity="MEDIUM",
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence="Redirect marker found in meta refresh or JS redirect",
                            ))
                            return
                        break

    def _test_path_based(self, url, parsed):
        for payload_tpl in self.PATH_PAYLOADS:
            payload = payload_tpl.format(marker=self.MARKER)
            test_url = f"{parsed.scheme}://{parsed.netloc}{payload}"
            resp = self.http.get(test_url, allow_redirects=False)
            if not resp:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if self._marker_in_location(location):
                    self.reporter.add(Finding(
                        vuln_type="Open Redirect (Path-based)",
                        severity="MEDIUM",
                        url=url,
                        payload=payload,
                        evidence=f"Location: {location}",
                    ))
                    return

    def _marker_in_location(self, location: str) -> bool:
        loc = location.lower()
        marker = self.MARKER.lower()
        return (
            loc.startswith(f"http://{marker}")
            or loc.startswith(f"https://{marker}")
            or loc.startswith(f"//{marker}")
            or loc.startswith(marker)
        )

    def _build_url(self, parsed, query_params, param_name, payload):
        modified = dict(query_params)
        modified[param_name] = [payload]
        query_string = urlencode({k: v[0] for k, v in modified.items()})
        return urlunparse(parsed._replace(query=query_string))
