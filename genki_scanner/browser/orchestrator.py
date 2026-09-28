"""
Browser orchestrator - ties browser engine, crawler, and DOM analyzer
to the scanner pipeline. Crawl with a real browser, then scan findings.
"""
import asyncio
import json
import time

from .engine import BrowserEngine
from .crawler import BrowserCrawler
from .dom_analyzer import DOMAnalyzer
from ..core.config import ScanConfig
from ..core.scanner import GenkiScanner


class BrowserOrchestrator:
    def __init__(self, config: ScanConfig, browser_config: dict = None):
        self.config = config
        self.browser_config = browser_config or {}

        if config.proxy:
            self.browser_config["proxy"] = config.proxy
        if config.delay:
            self.browser_config["delay_range"] = (config.delay, config.delay * 2)
        if config.cookies:
            cookie_list = []
            for cookie_str in config.cookies.split(";"):
                if "=" in cookie_str:
                    name, value = cookie_str.strip().split("=", 1)
                    cookie_list.append({
                        "name": name.strip(),
                        "value": value.strip(),
                        "url": config.target,
                    })
            self.browser_config["cookies"] = cookie_list
        if config.headers:
            self.browser_config["headers"] = config.headers

    async def run(self, urls: list[str], modules: list[str] = None,
                  crawl: bool = True, max_depth: int = 3, max_pages: int = 100):
        print(f"\n{'=' * 60}")
        print("GENKI SCANNER v1.0 - BROWSER MODE")
        print("Genki Tech Labs / Anbu Black Ops")
        print(f"{'=' * 60}")
        print(f"Targets: {len(urls)}")
        print(f"Browser: Stealth Chromium")
        print(f"Crawl: {'ON' if crawl else 'OFF'} (depth={max_depth}, max={max_pages})")
        print(f"{'=' * 60}\n")

        engine = BrowserEngine(self.browser_config)
        await engine.start()

        try:
            all_scan_urls = set()
            all_forms = []
            all_findings = []

            for url in urls:
                if not url.startswith(("http://", "https://")):
                    url = "https://" + url

                if crawl:
                    crawler = BrowserCrawler(
                        engine,
                        scope_domains=self.config.scope_domains,
                        max_depth=max_depth,
                        max_pages=max_pages,
                    )
                    result = await crawler.crawl(url)
                    all_scan_urls.update(result.urls)
                    all_forms.extend(result.forms)

                    if result.api_endpoints:
                        print(f"\n[API] Discovered endpoints:")
                        for ep in sorted(result.api_endpoints):
                            print(f"  {ep}")
                            all_scan_urls.add(ep)
                else:
                    all_scan_urls.add(url)

                dom = DOMAnalyzer(engine)
                page = await engine.new_page()
                dom_result = await dom.analyze(page, url)
                await page.close()

                if dom_result.get("dom_xss", {}).get("flows"):
                    print(f"\n[DOM XSS] Source-to-sink flows detected:")
                    for flow in dom_result["dom_xss"]["flows"]:
                        print(f"  {flow['source']} -> {flow['sink']}")
                        all_findings.append({
                            "type": "DOM XSS (Browser-verified)",
                            "severity": "HIGH",
                            "url": url,
                            "source": str(flow["source"]),
                            "sink": flow["sink"],
                        })

                if dom_result.get("dom_xss", {}).get("clobbering"):
                    print(f"\n[DOM CLOBBER] Clobberable elements:")
                    for clob in dom_result["dom_xss"]["clobbering"]:
                        print(f"  id={clob['id']} tag={clob['tag']}")

                if dom_result.get("csp", {}).get("unsafe_eval"):
                    print(f"\n[CSP] unsafe-eval detected - XSS escalation possible")

                if dom_result.get("cookies"):
                    js_cookies = [c for c in dom_result["cookies"] if c["js_accessible"]]
                    if js_cookies:
                        print(f"\n[COOKIES] {len(js_cookies)} JS-accessible cookies (missing HttpOnly)")

            browser_cookies = await engine.get_cookies()

            print(f"\n[SCAN] Browser crawl complete. {len(all_scan_urls)} URLs discovered.")
            print(f"[SCAN] {len(all_forms)} forms found.")
            print(f"[SCAN] Starting vulnerability scan...\n")

            if browser_cookies and not self.config.cookies:
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in browser_cookies)
                self.config.cookies = cookie_str

            scanner = GenkiScanner(self.config)

            scan_urls = list(all_scan_urls)
            scanner.scan(scan_urls, modules)

            for form in all_forms:
                if form["method"] == "GET" and form["params"]:
                    form_params = {p["name"]: p.get("value", "") for p in form["params"]}
                    scanner.scan([form["action"]], modules, form_params)

            total_requests = engine.request_count + scanner.http.request_count + scanner.curl.request_count
            print(f"\n[TOTAL] Browser: {engine.request_count} | Scanner: {scanner.http.request_count + scanner.curl.request_count} | Total: {total_requests}")

        finally:
            await engine.stop()


def run_browser_scan(config: ScanConfig, urls: list[str], modules: list[str] = None,
                     browser_config: dict = None, crawl: bool = True,
                     max_depth: int = 3, max_pages: int = 100):
    orchestrator = BrowserOrchestrator(config, browser_config)
    asyncio.run(orchestrator.run(
        urls, modules, crawl=crawl,
        max_depth=max_depth, max_pages=max_pages,
    ))
