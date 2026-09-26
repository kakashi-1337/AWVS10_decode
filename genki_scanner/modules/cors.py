"""
CORS misconfiguration detection module.
Ported from AWVS10: PostCrawl CORS check

Tests:
1. Arbitrary origin reflection
2. Null origin acceptance
3. Subdomain wildcard bypass
4. Credentials with wildcard
"""
from urllib.parse import urlparse

from .base import BaseModule
from ..core.reporter import Finding


class CORSModule(BaseModule):
    name = "cors"
    description = "CORS Misconfiguration"

    def run(self, url: str, params: dict = None):
        self.log(f"Testing: {url}")
        parsed = urlparse(url)
        base_domain = parsed.hostname

        self._test_arbitrary_origin(url, base_domain)
        self._test_null_origin(url)
        self._test_subdomain_bypass(url, base_domain)
        self._test_prefix_bypass(url, base_domain)

    def _check_cors(self, url: str, origin: str) -> tuple[bool, bool, str]:
        resp = self.http.get(url, headers={"Origin": origin})
        if not resp:
            return False, False, ""

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        return acao == origin or acao == "*", acac == "true", acao

    def _test_arbitrary_origin(self, url, base_domain):
        evil = "https://evil.6u.gg"
        reflected, creds, acao = self._check_cors(url, evil)
        if reflected and creds:
            self.reporter.add(Finding(
                vuln_type="CORS: Arbitrary Origin with Credentials",
                severity="HIGH",
                url=url,
                payload=f"Origin: {evil}",
                evidence=f"ACAO: {acao}, ACAC: true",
                details="Any origin can read authenticated responses. Full account takeover possible via CSRF-like attack.",
            ))
        elif reflected:
            self.reporter.add(Finding(
                vuln_type="CORS: Arbitrary Origin Reflection",
                severity="MEDIUM",
                url=url,
                payload=f"Origin: {evil}",
                evidence=f"ACAO: {acao}",
                details="Origin is reflected but credentials not allowed. Data leakage possible for unauthenticated endpoints.",
            ))

    def _test_null_origin(self, url):
        reflected, creds, acao = self._check_cors(url, "null")
        if reflected and creds:
            self.reporter.add(Finding(
                vuln_type="CORS: Null Origin with Credentials",
                severity="HIGH",
                url=url,
                payload="Origin: null",
                evidence=f"ACAO: {acao}, ACAC: true",
                details="Null origin accepted with credentials. Exploitable via sandboxed iframe.",
            ))

    def _test_subdomain_bypass(self, url, base_domain):
        evil = f"https://evil.{base_domain}"
        reflected, creds, acao = self._check_cors(url, evil)
        if reflected and creds:
            self.reporter.add(Finding(
                vuln_type="CORS: Subdomain Wildcard with Credentials",
                severity="MEDIUM",
                url=url,
                payload=f"Origin: {evil}",
                evidence=f"ACAO: {acao}, ACAC: true",
                details="Any subdomain accepted. XSS on any subdomain leads to full CORS bypass.",
            ))

    def _test_prefix_bypass(self, url, base_domain):
        evil = f"https://{base_domain}.6u.gg"
        reflected, creds, acao = self._check_cors(url, evil)
        if reflected:
            self.reporter.add(Finding(
                vuln_type="CORS: Origin Prefix Match Bypass",
                severity="MEDIUM",
                url=url,
                payload=f"Origin: {evil}",
                evidence=f"ACAO: {acao}",
                details="Domain prefix matching. Attacker can register lookalike domain.",
            ))
