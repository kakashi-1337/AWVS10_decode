"""
Browser-based crawler. Discovers URLs, forms, parameters, and API endpoints
by navigating with a real browser. Handles JS-rendered SPAs.
"""
import re
import asyncio
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict

from playwright.async_api import Page


class CrawlResult:
    def __init__(self):
        self.urls = set()
        self.forms = []
        self.params = defaultdict(set)
        self.api_endpoints = set()
        self.js_files = set()
        self.cookies = []
        self.headers = {}

    def summary(self):
        return {
            "urls": len(self.urls),
            "forms": len(self.forms),
            "params": sum(len(v) for v in self.params.values()),
            "api_endpoints": len(self.api_endpoints),
            "js_files": len(self.js_files),
        }


class BrowserCrawler:
    def __init__(self, engine, scope_domains=None, max_depth=3, max_pages=100):
        self.engine = engine
        self.scope_domains = scope_domains or []
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.result = CrawlResult()

    async def crawl(self, start_url: str) -> CrawlResult:
        parsed = urlparse(start_url)
        if not self.scope_domains:
            self.scope_domains = [parsed.hostname]

        print(f"\n[CRAWLER] Starting: {start_url}")
        print(f"[CRAWLER] Scope: {', '.join(self.scope_domains)}")
        print(f"[CRAWLER] Max depth: {self.max_depth}, Max pages: {self.max_pages}")

        page = await self.engine.new_page()

        page.on("request", lambda req: self._intercept_request(req))
        page.on("response", lambda resp: asyncio.ensure_future(self._intercept_response(resp)))

        await self._crawl_recursive(page, start_url, 0)

        await page.close()

        print(f"\n[CRAWLER] Done: {self.result.summary()}")
        return self.result

    async def _crawl_recursive(self, page: Page, url: str, depth: int):
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return

        normalized = self._normalize_url(url)
        if normalized in self.visited:
            return
        if not self._in_scope(url):
            return

        self.visited.add(normalized)
        self.result.urls.add(url)

        print(f"  [CRAWL] [{depth}] {url}")

        nav = await self.engine.navigate(page, url)
        if nav.get("error"):
            return

        await self._extract_forms(page, url)
        await self._extract_params(page, url)
        links = await self._extract_links(page, url)
        await self._extract_js_files(page, url)
        await self._extract_api_from_js(page)

        for link in links:
            if len(self.visited) >= self.max_pages:
                break
            await self._crawl_recursive(page, link, depth + 1)

    async def _extract_links(self, page: Page, base_url: str) -> list:
        links = set()
        try:
            elements = await page.query_selector_all("a[href], area[href]")
            for el in elements:
                href = await el.get_attribute("href")
                if href:
                    full = urljoin(base_url, href)
                    if self._in_scope(full) and not self._is_static(full):
                        links.add(full)

            onclick_els = await page.query_selector_all("[onclick]")
            for el in onclick_els:
                onclick = await el.get_attribute("onclick")
                if onclick:
                    urls = re.findall(r"(?:location\.href|window\.location|location\.assign|location\.replace)\s*[=(]\s*['\"]([^'\"]+)['\"]", onclick)
                    for u in urls:
                        full = urljoin(base_url, u)
                        if self._in_scope(full):
                            links.add(full)

        except Exception:
            pass
        return list(links)

    async def _extract_forms(self, page: Page, base_url: str):
        try:
            forms = await page.query_selector_all("form")
            for form in forms:
                action = await form.get_attribute("action") or base_url
                method = (await form.get_attribute("method") or "GET").upper()
                action_url = urljoin(base_url, action)

                inputs = await form.query_selector_all("input, select, textarea")
                params = []
                for inp in inputs:
                    name = await inp.get_attribute("name")
                    input_type = await inp.get_attribute("type") or "text"
                    value = await inp.get_attribute("value") or ""
                    if name:
                        params.append({
                            "name": name,
                            "type": input_type,
                            "value": value,
                        })

                if params:
                    form_data = {
                        "action": action_url,
                        "method": method,
                        "params": params,
                    }
                    self.result.forms.append(form_data)
                    print(f"    [FORM] {method} {action_url} ({len(params)} params)")

        except Exception:
            pass

    async def _extract_params(self, page: Page, url: str):
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        for param_name in query:
            self.result.params[url].add(param_name)

    async def _extract_js_files(self, page: Page, base_url: str):
        try:
            scripts = await page.query_selector_all("script[src]")
            for script in scripts:
                src = await script.get_attribute("src")
                if src:
                    full = urljoin(base_url, src)
                    self.result.js_files.add(full)
        except Exception:
            pass

    async def _extract_api_from_js(self, page: Page):
        try:
            api_endpoints = await page.evaluate("""
                () => {
                    const scripts = document.querySelectorAll('script:not([src])');
                    const endpoints = new Set();
                    const patterns = [
                        /fetch\\s*\\(\\s*['"`](\\/api\\/[^'"`]+)['"`]/g,
                        /\\.(?:get|post|put|delete|patch)\\s*\\(\\s*['"`](\\/api\\/[^'"`]+)['"`]/g,
                        /(?:url|endpoint|path)\\s*[:=]\\s*['"`](\\/api\\/[^'"`]+)['"`]/g,
                        /XMLHttpRequest[^]*?\\.open\\s*\\([^,]*,\\s*['"`]([^'"`]+)['"`]/g,
                    ];
                    for (const script of scripts) {
                        const text = script.textContent;
                        for (const pattern of patterns) {
                            let match;
                            pattern.lastIndex = 0;
                            while ((match = pattern.exec(text)) !== null) {
                                endpoints.add(match[1]);
                            }
                        }
                    }
                    return [...endpoints];
                }
            """)
            for ep in api_endpoints:
                self.result.api_endpoints.add(ep)
        except Exception:
            pass

    def _intercept_request(self, request):
        url = request.url
        if "/api/" in url or "/graphql" in url or "/rest/" in url:
            if self._in_scope(url):
                self.result.api_endpoints.add(url)

    async def _intercept_response(self, response):
        try:
            url = response.url
            ct = response.headers.get("content-type", "")
            if "json" in ct and ("/api/" in url or "/graphql" in url):
                if self._in_scope(url):
                    self.result.api_endpoints.add(url)
        except Exception:
            pass

    def _in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            return any(
                parsed.hostname == d or (parsed.hostname and parsed.hostname.endswith(f".{d}"))
                for d in self.scope_domains
            )
        except Exception:
            return False

    def _is_static(self, url: str) -> bool:
        static_ext = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                      ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
                      ".webm", ".mp3", ".pdf", ".zip", ".tar", ".gz"}
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in static_ext)

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
