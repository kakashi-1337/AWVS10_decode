"""
Local File Inclusion / Directory Traversal module.
Ported from AWVS10: classDirectoryTraversal.inc, classFileInclusion.inc
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base import BaseModule
from ..core.reporter import Finding
from ..payloads.traversal import (
    UNIX_TRAVERSAL,
    WINDOWS_TRAVERSAL,
    PHP_WRAPPERS,
    JAVA_TRAVERSAL,
    detect_traversal_success,
    detect_include_error,
)


class LFIModule(BaseModule):
    name = "lfi"
    description = "Local File Inclusion / Directory Traversal"

    def run(self, url: str, params: dict = None):
        self.log(f"Testing: {url}")
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            query_params.update({k: [v] for k, v in params.items()})

        if not query_params:
            self.log("No parameters to test")
            return

        for param_name in query_params:
            original_value = query_params[param_name][0]
            self.log(f"Testing param: {param_name}")

            baseline = self.http.get(url)
            if not baseline:
                continue

            baseline_has_error, _ = detect_include_error(baseline.text)

            for payload_list, os_type in [
                (UNIX_TRAVERSAL, "unix"),
                (WINDOWS_TRAVERSAL, "windows"),
                (JAVA_TRAVERSAL, "java"),
            ]:
                for payload in payload_list:
                    test_url = self._build_url(parsed, query_params, param_name, payload)
                    resp = self.http.get(test_url)
                    if not resp:
                        continue

                    found, evidence = detect_traversal_success(resp.text)
                    if found:
                        self.reporter.add(Finding(
                            vuln_type="Directory Traversal / LFI",
                            severity="HIGH",
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            details=f"OS target: {os_type}",
                        ))
                        return

            for payload in PHP_WRAPPERS:
                test_url = self._build_url(parsed, query_params, param_name, payload)
                resp = self.http.get(test_url)
                if not resp:
                    continue

                if "php://filter" in payload and "convert.base64" in payload:
                    import re
                    import base64
                    b64_match = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", resp.text)
                    if b64_match:
                        try:
                            decoded = base64.b64decode(b64_match.group(0)).decode("utf-8", errors="ignore")
                            if "<?php" in decoded or "<?" in decoded:
                                self.reporter.add(Finding(
                                    vuln_type="Local File Inclusion (PHP filter)",
                                    severity="HIGH",
                                    url=url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Base64 decoded PHP source ({len(decoded)} bytes)",
                                    details="php://filter wrapper successfully read source code",
                                ))
                                return
                        except Exception:
                            pass

                found, evidence = detect_include_error(resp.text)
                if found and not baseline_has_error:
                    self.reporter.add(Finding(
                        vuln_type="Local File Inclusion (PHP include error)",
                        severity="MEDIUM",
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=evidence,
                        details="PHP include/require error triggered, may lead to RCE via log poisoning or wrappers",
                    ))
                    return

    def _build_url(self, parsed, query_params, param_name, payload):
        modified = dict(query_params)
        modified[param_name] = [payload]
        query_string = urlencode({k: v[0] for k, v in modified.items()})
        return urlunparse(parsed._replace(query=query_string))
