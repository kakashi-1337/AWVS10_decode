"""
Browser Bridge - Connects the Playwright stealth browser to the shell pipeline.
Crawls with anti-fingerprint + CF bypass, builds the AWVS-compatible site tree.
"""
import asyncio
from urllib.parse import urlparse

from .site_tree import SiteTree, Scheme


def crawl_with_browser(target_urls, config=None, max_depth=3, max_pages=100):
    """
    Crawl targets using the stealth browser engine and return an AWVS-compatible SiteTree.
    Uses the existing browser engine/crawler from genki_scanner.browser.
    """
    config = config or {}
    return asyncio.run(_async_crawl(target_urls, config, max_depth, max_pages))


async def _async_crawl(target_urls, config, max_depth, max_pages):
    from ..browser.engine import BrowserEngine
    from ..browser.crawler import BrowserCrawler
    from ..browser.dom_analyzer import DOMAnalyzer

    browser_config = {
        "headless": config.get("headless", True),
        "viewport": config.get("viewport", "laptop"),
    }
    if config.get("proxy"):
        browser_config["proxy"] = config["proxy"]
    if config.get("delay"):
        browser_config["delay_range"] = (config["delay"], config["delay"] * 2)

    engine = BrowserEngine(browser_config)
    await engine.start()

    trees = {}

    try:
        for url in target_urls:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            parsed = urlparse(url)
            scope = [parsed.hostname]
            tree = SiteTree(url)

            print(f"\n  [BROWSER] Crawling {url}")
            print(f"  [BROWSER] Stealth mode + CF bypass active")

            crawler = BrowserCrawler(
                engine,
                scope_domains=scope,
                max_depth=max_depth,
                max_pages=max_pages,
            )
            result = await crawler.crawl(url)

            for discovered_url in result.urls:
                site_file = tree.add_url(discovered_url)

            for form in result.forms:
                tree.add_form(
                    form["action"],
                    form["method"],
                    form.get("params", form.get("inputs", [])),
                )

            for api_call in result.api_calls:
                tree.add_api_call(api_call)

            for api_ep in result.api_endpoints:
                if api_ep not in tree.all_files:
                    tree.add_api_endpoint(api_ep)

            for route in getattr(result, "spa_routes", set()):
                if route.startswith(("http://", "https://")):
                    full_url = route
                else:
                    full_url = f"{parsed.scheme}://{parsed.hostname}{route}"
                if full_url not in tree.all_files:
                    tree.add_url(full_url)

            api_call_count = len(result.api_calls)
            api_ep_count = len(result.api_endpoints)
            spa_count = len(getattr(result, "spa_routes", set()))
            rendered_count = len(getattr(result, "rendered_html", {}))
            print(f"  [BROWSER] {len(result.urls)} URLs, {len(result.forms)} forms, "
                  f"{api_call_count} API calls, {api_ep_count} API endpoints, "
                  f"{spa_count} SPA routes, {rendered_count} rendered pages")

            dom = DOMAnalyzer(engine)
            page = await engine.new_page()
            dom_result = await dom.analyze(page, url)
            await page.close()

            if dom_result.get("dom_xss", {}).get("flows"):
                print(f"  [BROWSER] {len(dom_result['dom_xss']['flows'])} DOM XSS flows detected (pre-scan)")

            _mark_reflection_inputs(tree, engine)

            tree._rendered_html = getattr(result, "rendered_html", {})
            tree._tokens_found = getattr(result, "tokens_found", [])

            cookies = await engine.get_cookies()
            tree._browser_cookies = cookies

            storage = await _extract_storage(engine, url)
            tree._storage = storage
            if storage.get("localStorage") or storage.get("sessionStorage"):
                ls_count = len(storage.get("localStorage", {}))
                ss_count = len(storage.get("sessionStorage", {}))
                print(f"  [BROWSER] Storage: {ls_count} localStorage, {ss_count} sessionStorage keys")

            trees[url] = tree

    finally:
        await engine.stop()

    return trees


async def _extract_storage(engine, url):
    """Extract localStorage and sessionStorage keys/values from the page."""
    storage = {"localStorage": {}, "sessionStorage": {}}
    try:
        page = await engine.new_page()
        await page.goto(url, wait_until="networkidle", timeout=15000)
        storage["localStorage"] = await page.evaluate("""() => {
            const data = {};
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    data[key] = localStorage.getItem(key);
                }
            } catch(e) {}
            return data;
        }""")
        storage["sessionStorage"] = await page.evaluate("""() => {
            const data = {};
            try {
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    data[key] = sessionStorage.getItem(key);
                }
            } catch(e) {}
            return data;
        }""")
        await page.close()
    except Exception:
        pass
    return storage


def _mark_reflection_inputs(tree, engine):
    """
    Check which inputs are reflected in responses.
    Sets the REFLECTION_TESTS flag, matching AWVS10's optimization.
    """
    import requests as req_lib

    for scheme in tree.all_schemes:
        if not scheme.inputs:
            continue

        for i, inp in enumerate(scheme.inputs):
            if not inp.value:
                continue
            try:
                resp = req_lib.get(scheme.url, timeout=10, verify=False)
                body = resp.content.decode('utf-8', errors='replace')
                if inp.value in body:
                    inp.flags |= Scheme.INPUT_FLAG_REFLECTION_TESTS
            except Exception:
                pass


def build_tree_from_urls(urls):
    """Build a basic site tree from a list of URLs without browser crawling."""
    trees = {}
    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        tree = SiteTree(url)
        tree.add_url(url)
        trees[url] = tree
    return trees
