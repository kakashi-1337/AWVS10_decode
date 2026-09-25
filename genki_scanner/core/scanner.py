"""
Main scanner engine. Orchestrates modules against target URLs.
"""
from urllib.parse import urlparse

from .config import ScanConfig
from .http_client import HTTPClient
from .curl_client import CurlClient
from .reporter import Reporter

from ..modules.sqli import SQLiModule
from ..modules.xss import XSSModule
from ..modules.lfi import LFIModule
from ..modules.cors import CORSModule
from ..modules.open_redirect import OpenRedirectModule
from ..modules.crlf import CRLFModule
from ..modules.host_header import HostHeaderModule
from ..modules.info_disclosure import InfoDisclosureModule
from ..modules.ssrf import SSRFModule
from ..modules.nosqli import NoSQLiModule


ALL_MODULES = {
    "sqli": SQLiModule,
    "xss": XSSModule,
    "lfi": LFIModule,
    "cors": CORSModule,
    "redirect": OpenRedirectModule,
    "crlf": CRLFModule,
    "host_header": HostHeaderModule,
    "info": InfoDisclosureModule,
    "ssrf": SSRFModule,
    "nosqli": NoSQLiModule,
}


class GenkiScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.http = HTTPClient(config)
        self.curl = CurlClient(config)
        self.reporter = Reporter(config.output_file)

    def scan(self, urls: list[str], modules: list[str] = None, params: dict = None):
        selected = modules or list(ALL_MODULES.keys())

        print(f"\n{'=' * 60}")
        print(f"GENKI SCANNER v1.0")
        print(f"Genki Tech Labs / Anbu Black Ops")
        print(f"{'=' * 60}")
        print(f"Targets: {len(urls)}")
        print(f"Modules: {', '.join(selected)}")
        print(f"Delay: {self.config.delay}s (+jitter)")
        print(f"Timeout: {self.config.timeout}s")
        if self.config.proxy:
            print(f"Proxy: {self.config.proxy}")
        print(f"{'=' * 60}\n")

        for url in urls:
            url = self._normalize_url(url)
            if not self._in_scope(url):
                print(f"[SKIP] Out of scope: {url}")
                continue

            print(f"\n[TARGET] {url}")
            print("-" * 40)

            for mod_name in selected:
                if mod_name not in ALL_MODULES:
                    print(f"  [WARN] Unknown module: {mod_name}")
                    continue

                mod_class = ALL_MODULES[mod_name]
                mod = mod_class(self.http, self.reporter)
                try:
                    mod.run(url, params)
                except KeyboardInterrupt:
                    print("\n[!] Interrupted by user")
                    break
                except Exception as e:
                    if self.config.verbose:
                        print(f"  [ERROR] {mod_name}: {e}")

        self.reporter.summary(self.http.request_count + self.curl.request_count)

    def single_module(self, url: str, module_name: str, params: dict = None):
        url = self._normalize_url(url)
        if module_name not in ALL_MODULES:
            print(f"Unknown module: {module_name}")
            return
        mod = ALL_MODULES[module_name](self.http, self.reporter)
        mod.run(url, params)
        self.reporter.summary(self.http.request_count)

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _in_scope(self, url: str) -> bool:
        if not self.config.scope_domains:
            return True
        parsed = urlparse(url)
        return any(
            parsed.hostname == d or parsed.hostname.endswith(f".{d}")
            for d in self.config.scope_domains
        )
