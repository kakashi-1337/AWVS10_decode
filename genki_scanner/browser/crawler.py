"""
Browser-based crawler. Discovers URLs, forms, parameters, and API endpoints
by navigating with a real browser. Handles JS-rendered SPAs.

Enhanced: full XHR/fetch interception with method/body/header capture,
JS bundle API extraction, SPA route discovery via interaction.
"""
import json
import re
import asyncio
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set

from playwright.async_api import Page, Request, Response


@dataclass
class ApiCall:
    """Captured XHR/fetch call with full request context."""
    url: str
    method: str
    content_type: str = ""
    request_body: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_status: int = 0
    response_body: str = ""
    response_content_type: str = ""
    params: Dict[str, str] = field(default_factory=dict)
    json_fields: List[str] = field(default_factory=list)


class CrawlResult:
    def __init__(self):
        self.urls: Set[str] = set()
        self.forms: List[dict] = []
        self.params: Dict[str, Set[str]] = defaultdict(set)
        self.api_endpoints: Set[str] = set()
        self.api_calls: List[ApiCall] = []
        self.js_files: Set[str] = set()
        self.cookies: list = []
        self.headers: dict = {}
        self.rendered_html: Dict[str, str] = {}
        self.spa_routes: Set[str] = set()
        self.tokens_found: List[dict] = []

    def summary(self):
        return {
            "urls": len(self.urls),
            "forms": len(self.forms),
            "params": sum(len(v) for v in self.params.values()),
            "api_endpoints": len(self.api_endpoints),
            "api_calls": len(self.api_calls),
            "js_files": len(self.js_files),
            "spa_routes": len(self.spa_routes),
            "rendered_pages": len(self.rendered_html),
        }


_STATIC_EXT = frozenset({
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
    ".webm", ".mp3", ".pdf", ".zip", ".tar", ".gz", ".map",
})

_XHR_RESOURCE_TYPES = frozenset({"xhr", "fetch"})

_API_PATH_PATTERNS = re.compile(
    r"(?:/api/|/v[0-9]+/|/graphql|/rest/|/auth/|/login|/signup|"
    r"/register|/token|/oauth|/webhook|/callback|/socket\.io|/ws)",
    re.IGNORECASE,
)

_TOKEN_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "api_key"),
    (r'(?:Bearer\s+)([a-zA-Z0-9_\-\.]{20,})', "bearer_token"),
    (r'(?:token|secret|password)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "secret"),
    (r'(?:aws_access_key_id)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "aws_key"),
]

_ROUTE_PATTERNS = [
    # Vue Router
    re.compile(r'(?:path|route)\s*:\s*["\'](/[^"\']*)["\']', re.IGNORECASE),
    # React Router
    re.compile(r'<Route\s+(?:[^>]*?)path\s*=\s*["\'](/[^"\']*)["\']', re.IGNORECASE),
    # Angular
    re.compile(r'(?:path|redirectTo)\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE),
    # Generic URL patterns in JS
    re.compile(r'(?:url|endpoint|href|path|route)\s*[:=]\s*[`"\'](/[a-zA-Z0-9_/\-:{}]+)[`"\']'),
]

_API_EXTRACT_PATTERNS = [
    # fetch/axios/$.ajax calls - broader than /api/ only
    re.compile(r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']', re.IGNORECASE),
    re.compile(r'\.(?:get|post|put|delete|patch|head|options)\s*\(\s*[`"\']([^`"\']+)[`"\']', re.IGNORECASE),
    re.compile(r'(?:url|endpoint|baseURL|apiUrl)\s*[:=]\s*[`"\']([^`"\']+)[`"\']'),
    re.compile(r'XMLHttpRequest[^]*?\.open\s*\([^,]*,\s*[`"\']([^`"\']+)[`"\']'),
    # Template literals with base URL
    re.compile(r'`([^`]*\$\{[^}]+\}[^`]*)`'),
]


class BrowserCrawler:
    def __init__(self, engine, scope_domains=None, max_depth=3, max_pages=100):
        self.engine = engine
        self.scope_domains = scope_domains or []
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.result = CrawlResult()
        self._pending_responses: Dict[str, Request] = {}
        self._base_url = ""

    async def crawl(self, start_url: str) -> CrawlResult:
        parsed = urlparse(start_url)
        if not self.scope_domains:
            self.scope_domains = [parsed.hostname]
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"

        print(f"\n[CRAWLER] Starting: {start_url}")
        print(f"[CRAWLER] Scope: {', '.join(self.scope_domains)}")
        print(f"[CRAWLER] Max depth: {self.max_depth}, Max pages: {self.max_pages}")

        page = await self.engine.new_page()

        page.on("request", lambda req: self._intercept_request(req))
        page.on("response", lambda resp: asyncio.ensure_future(self._intercept_response(resp)))

        await self._crawl_recursive(page, start_url, 0)

        # SPA interaction pass: click interactive elements to trigger more API calls
        await self._spa_interact(page, start_url)

        # JS bundle analysis: download and parse external JS files for API routes
        await self._analyze_js_bundles(page)

        await page.close()

        self._dedupe_api_calls()

        summary = self.result.summary()
        print(f"\n[CRAWLER] Done: {summary['urls']} URLs, {summary['forms']} forms, "
              f"{summary['api_calls']} API calls, {summary['spa_routes']} SPA routes, "
              f"{summary['rendered_pages']} rendered pages")
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

        # Capture rendered DOM
        rendered = await self._capture_rendered_html(page)
        if rendered:
            self.result.rendered_html[url] = rendered

        await self._extract_forms(page, url)
        await self._extract_params(page, url)
        links = await self._extract_links(page, url)
        await self._extract_js_files(page, url)
        await self._extract_api_from_inline_js(page)

        for link in links:
            if len(self.visited) >= self.max_pages:
                break
            await self._crawl_recursive(page, link, depth + 1)

    # ---- Rendered DOM Capture ----

    async def _capture_rendered_html(self, page: Page) -> str:
        try:
            return await page.evaluate("document.documentElement.outerHTML")
        except Exception:
            return ""

    # ---- Enhanced Request/Response Interception ----

    def _intercept_request(self, request: Request):
        url = request.url
        resource_type = request.resource_type

        if not self._in_scope(url):
            return

        # Capture ALL XHR/fetch calls, not just /api/ pattern
        if resource_type in _XHR_RESOURCE_TYPES:
            method = request.method
            post_data = request.post_data or ""
            headers = dict(request.headers) if request.headers else {}
            content_type = headers.get("content-type", "")

            call = ApiCall(
                url=url,
                method=method,
                content_type=content_type,
                request_body=post_data,
                request_headers=headers,
            )

            # Parse request parameters
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for k, v in query_params.items():
                call.params[k] = v[0] if v else ""

            # Parse JSON request body
            if post_data and "json" in content_type:
                try:
                    body = json.loads(post_data)
                    if isinstance(body, dict):
                        call.json_fields = list(body.keys())
                        for k, v in body.items():
                            call.params[k] = str(v) if not isinstance(v, (dict, list)) else json.dumps(v)
                except (json.JSONDecodeError, ValueError):
                    pass

            # Parse form-encoded body
            if post_data and "form" in content_type:
                try:
                    form_params = parse_qs(post_data, keep_blank_values=True)
                    for k, v in form_params.items():
                        call.params[k] = v[0] if v else ""
                except Exception:
                    pass

            self.result.api_calls.append(call)
            self.result.api_endpoints.add(url)

            # Track for response correlation
            self._pending_responses[url] = call

            if len(self.result.api_calls) <= 50:
                short_url = url.split("?")[0] if "?" in url else url
                n_params = len(call.params)
                body_info = f", body: {len(post_data)}b" if post_data else ""
                print(f"    [API] {method} {short_url} ({n_params} params{body_info})")

        # Also capture document/navigation requests to non-static paths
        elif resource_type in ("document", "navigation"):
            if not self._is_static(url):
                self.result.urls.add(url)

    async def _intercept_response(self, response: Response):
        try:
            url = response.url
            ct = response.headers.get("content-type", "")
            status = response.status

            if not self._in_scope(url):
                return

            # Correlate with pending request
            if url in self._pending_responses:
                call = self._pending_responses[url]
                call.response_status = status
                call.response_content_type = ct

                # Parse JSON response to discover field names
                if "json" in ct and status < 400:
                    try:
                        body = await response.text()
                        call.response_body = body[:4096]
                        data = json.loads(body)
                        resp_fields = self._extract_json_fields(data)
                        for f in resp_fields:
                            if f not in call.json_fields:
                                call.json_fields.append(f)
                    except Exception:
                        pass

            # Detect API endpoints from response content-type
            if "json" in ct and self._in_scope(url):
                self.result.api_endpoints.add(url)

        except Exception:
            pass

    @staticmethod
    def _extract_json_fields(data, prefix="", max_depth=3) -> List[str]:
        """Recursively extract field names from JSON response."""
        if max_depth <= 0:
            return []
        fields = []
        if isinstance(data, dict):
            for k, v in data.items():
                full_key = f"{prefix}.{k}" if prefix else k
                fields.append(full_key)
                if isinstance(v, dict):
                    fields.extend(BrowserCrawler._extract_json_fields(v, full_key, max_depth - 1))
                elif isinstance(v, list) and v and isinstance(v[0], dict):
                    fields.extend(BrowserCrawler._extract_json_fields(v[0], f"{full_key}[]", max_depth - 1))
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            fields.extend(BrowserCrawler._extract_json_fields(data[0], prefix, max_depth - 1))
        return fields

    # ---- SPA Interaction (click through to discover more routes) ----

    async def _spa_interact(self, page: Page, base_url: str):
        """Click navigation elements in SPAs to trigger route changes and API calls."""
        try:
            # Find clickable navigation elements
            nav_selectors = [
                "nav a", "nav button",
                "[role='navigation'] a", "[role='navigation'] button",
                ".nav a", ".navbar a", ".sidebar a", ".menu a",
                "[class*='nav'] a", "[class*='menu'] a", "[class*='sidebar'] a",
                "[data-toggle]", "[data-target]",
                "button[class*='tab']", "[role='tab']",
                ".dropdown-toggle", "[aria-haspopup]",
            ]

            clicked = set()
            for selector in nav_selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    for el in elements[:10]:
                        try:
                            text = (await el.inner_text()).strip()[:50]
                            href = await el.get_attribute("href")

                            key = text or href or ""
                            if not key or key in clicked or key == "#":
                                continue
                            clicked.add(key)

                            # Click and wait for navigation/network
                            pre_url = page.url
                            await el.click(timeout=3000)
                            await asyncio.sleep(0.5)

                            try:
                                await page.wait_for_load_state("networkidle", timeout=3000)
                            except Exception:
                                pass

                            post_url = page.url
                            if post_url != pre_url:
                                self.result.spa_routes.add(post_url)
                                if self._in_scope(post_url) and not self._is_static(post_url):
                                    self.result.urls.add(post_url)
                                    rendered = await self._capture_rendered_html(page)
                                    if rendered:
                                        self.result.rendered_html[post_url] = rendered
                                    await self._extract_forms(page, post_url)
                                    print(f"    [SPA] Route: {post_url}")

                        except Exception:
                            continue
                except Exception:
                    continue

            if clicked:
                # Go back to start for other extractors
                try:
                    await self.engine.navigate(page, base_url)
                except Exception:
                    pass

        except Exception:
            pass

    # ---- JS Bundle Analysis ----

    async def _analyze_js_bundles(self, page: Page):
        """Download and parse JS bundle files for API endpoints, routes, and secrets."""
        analyzed = 0
        for js_url in list(self.result.js_files):
            if analyzed >= 20:
                break
            if not self._in_scope(js_url):
                continue

            try:
                resp = await page.evaluate(f"""
                    async () => {{
                        try {{
                            const r = await fetch("{js_url}");
                            const t = await r.text();
                            return t.substring(0, 500000);
                        }} catch {{ return ""; }}
                    }}
                """)
                if not resp or len(resp) < 100:
                    continue

                analyzed += 1
                self._parse_js_content(resp, js_url)

            except Exception:
                continue

        if analyzed:
            print(f"    [JS] Analyzed {analyzed} bundles, "
                  f"found {len(self.result.spa_routes)} routes, "
                  f"{len(self.result.tokens_found)} tokens")

    def _parse_js_content(self, js_text: str, source_url: str):
        """Extract API endpoints, routes, and tokens from JS bundle content."""
        base = self._base_url

        # Extract API endpoints
        for pattern in _API_EXTRACT_PATTERNS:
            for match in pattern.finditer(js_text):
                endpoint = match.group(1)
                if endpoint.startswith("/"):
                    full = base + endpoint
                    if self._in_scope(full):
                        self.result.api_endpoints.add(full)
                elif endpoint.startswith("http"):
                    if self._in_scope(endpoint):
                        self.result.api_endpoints.add(endpoint)

        # Extract SPA routes
        for pattern in _ROUTE_PATTERNS:
            for match in pattern.finditer(js_text):
                route = match.group(1)
                if route.startswith("/") and len(route) > 1:
                    full = base + route
                    self.result.spa_routes.add(full)
                    if not self._is_static(full):
                        self.result.urls.add(full)

        # Extract tokens/secrets
        for pattern_str, token_type in _TOKEN_PATTERNS:
            for match in re.finditer(pattern_str, js_text):
                self.result.tokens_found.append({
                    "type": token_type,
                    "value": match.group(1)[:8] + "...",
                    "source": source_url.split("/")[-1],
                    "full_value": match.group(1),
                })

    # ---- Form Extraction (from rendered DOM) ----

    async def _extract_forms(self, page: Page, base_url: str):
        try:
            forms_data = await page.evaluate("""
                () => {
                    const results = [];
                    // Standard <form> elements
                    for (const form of document.querySelectorAll('form')) {
                        const params = [];
                        for (const el of form.querySelectorAll('input, select, textarea')) {
                            const name = el.name || el.getAttribute('name');
                            if (!name) continue;
                            params.push({
                                name: name,
                                type: el.type || el.tagName.toLowerCase(),
                                value: el.value || el.getAttribute('value') || '',
                                placeholder: el.placeholder || '',
                            });
                        }
                        if (params.length > 0) {
                            results.push({
                                action: form.action || window.location.href,
                                method: (form.method || 'GET').toUpperCase(),
                                params: params,
                            });
                        }
                    }
                    // Vue/React/Angular form-like components (inputs not in <form>)
                    const orphanInputs = [];
                    for (const el of document.querySelectorAll('input, select, textarea')) {
                        if (el.closest('form')) continue;
                        const name = el.name || el.id || el.getAttribute('data-name')
                                    || el.getAttribute('v-model') || el.getAttribute('ng-model')
                                    || el.getAttribute('formControlName');
                        if (!name) continue;
                        orphanInputs.push({
                            name: name,
                            type: el.type || el.tagName.toLowerCase(),
                            value: el.value || '',
                            placeholder: el.placeholder || '',
                        });
                    }
                    if (orphanInputs.length > 0) {
                        results.push({
                            action: window.location.href,
                            method: 'POST',
                            params: orphanInputs,
                            _spa_form: true,
                        });
                    }
                    return results;
                }
            """)

            for form in forms_data:
                # Avoid duplicates
                action = form["action"]
                method = form["method"]
                params = form["params"]
                key = f"{method}:{action}:{','.join(p['name'] for p in params)}"
                if not hasattr(self, '_seen_forms'):
                    self._seen_forms = set()
                if key in self._seen_forms:
                    continue
                self._seen_forms.add(key)

                self.result.forms.append(form)
                spa_tag = " (SPA)" if form.get("_spa_form") else ""
                print(f"    [FORM] {method} {action} ({len(params)} params{spa_tag})")

        except Exception:
            pass

    async def _extract_links(self, page: Page, base_url: str) -> list:
        links = set()
        try:
            found = await page.evaluate("""
                () => {
                    const links = new Set();
                    // <a> and <area> hrefs
                    for (const el of document.querySelectorAll('a[href], area[href]')) {
                        const href = el.href;
                        if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:'))
                            links.add(href);
                    }
                    // router-link (Vue)
                    for (const el of document.querySelectorAll('[to]')) {
                        const to = el.getAttribute('to');
                        if (to && to.startsWith('/'))
                            links.add(new URL(to, window.location.origin).href);
                    }
                    // Angular routerLink
                    for (const el of document.querySelectorAll('[routerLink]')) {
                        const rl = el.getAttribute('routerLink');
                        if (rl && rl.startsWith('/'))
                            links.add(new URL(rl, window.location.origin).href);
                    }
                    // onclick handlers
                    for (const el of document.querySelectorAll('[onclick]')) {
                        const oc = el.getAttribute('onclick');
                        const m = oc.match(/(?:location\\.href|window\\.location|location\\.assign|location\\.replace)\\s*[=(]\\s*['"]([^'"]+)['"]/);
                        if (m) links.add(new URL(m[1], window.location.origin).href);
                    }
                    return [...links];
                }
            """)
            for url in found:
                if self._in_scope(url) and not self._is_static(url):
                    links.add(url)
        except Exception:
            pass
        return list(links)

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

    async def _extract_api_from_inline_js(self, page: Page):
        """Extract API endpoints from inline scripts in the rendered DOM."""
        try:
            api_endpoints = await page.evaluate("""
                () => {
                    const scripts = document.querySelectorAll('script:not([src])');
                    const endpoints = new Set();
                    const patterns = [
                        /fetch\\s*\\(\\s*[`'"]([^`'"]+)[`'"]/g,
                        /\\.(?:get|post|put|delete|patch)\\s*\\(\\s*[`'"]([^`'"]+)[`'"]/g,
                        /(?:url|endpoint|baseURL|apiUrl|path)\\s*[:=]\\s*[`'"]([^`'"]+)[`'"]/g,
                        /XMLHttpRequest[^]*?\\.open\\s*\\([^,]*,\\s*[`'"]([^`'"]+)[`'"]/g,
                        /\\$\\.(?:ajax|get|post|getJSON)\\s*\\(\\s*[`'"]([^`'"]+)[`'"]/g,
                    ];
                    for (const script of scripts) {
                        const text = script.textContent;
                        for (const pattern of patterns) {
                            let match;
                            pattern.lastIndex = 0;
                            while ((match = pattern.exec(text)) !== null) {
                                const ep = match[1];
                                if (ep.startsWith('/') || ep.startsWith('http'))
                                    endpoints.add(ep.startsWith('/') ?
                                        new URL(ep, window.location.origin).href : ep);
                            }
                        }
                    }
                    // Also check window.__INITIAL_STATE__, __NUXT__, __NEXT_DATA__
                    const stateVars = ['__INITIAL_STATE__', '__NUXT__', '__NEXT_DATA__',
                                       '__APP_DATA__', '__PRELOADED_STATE__'];
                    for (const v of stateVars) {
                        try {
                            const data = window[v];
                            if (data) {
                                const str = JSON.stringify(data);
                                const urlMatches = str.match(/(?:https?:)?\\/{2}[^"'\\s]+|(?:\\/api\\/|\\/v[0-9]+\\/)[^"'\\s,}\\]]+/g);
                                if (urlMatches) {
                                    for (const u of urlMatches) {
                                        if (u.startsWith('/'))
                                            endpoints.add(new URL(u, window.location.origin).href);
                                        else if (u.startsWith('http'))
                                            endpoints.add(u);
                                    }
                                }
                            }
                        } catch {}
                    }
                    return [...endpoints];
                }
            """)
            for ep in api_endpoints:
                if self._in_scope(ep):
                    self.result.api_endpoints.add(ep)
        except Exception:
            pass

    # ---- Helpers ----

    def _dedupe_api_calls(self):
        """Deduplicate API calls by method + normalized URL."""
        seen = set()
        unique = []
        for call in self.result.api_calls:
            key = f"{call.method}:{self._normalize_url(call.url)}"
            if key not in seen:
                seen.add(key)
                unique.append(call)
        self.result.api_calls = unique

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
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in _STATIC_EXT)

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
