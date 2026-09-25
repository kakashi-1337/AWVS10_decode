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

            for api_ep in result.api_endpoints:
                tree.add_url(api_ep)

            print(f"  [BROWSER] {len(result.urls)} URLs, {len(result.forms)} forms, {len(result.api_endpoints)} API endpoints")

            dom = DOMAnalyzer(engine)
            page = await engine.new_page()
            dom_result = await dom.analyze(page, url)
            await page.close()

            if dom_result.get("dom_xss", {}).get("flows"):
                print(f"  [BROWSER] {len(dom_result['dom_xss']['flows'])} DOM XSS flows detected (pre-scan)")

            _mark_reflection_inputs(tree, engine)

            cookies = await engine.get_cookies()
            tree._browser_cookies = cookies

            trees[url] = tree

    finally:
        await engine.stop()

    return trees


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
                if inp.value in resp.text:
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
