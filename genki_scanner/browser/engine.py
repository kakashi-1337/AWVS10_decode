"""
Browser engine - stealth Chromium with anti-fingerprint and CF bypass.
Wraps Playwright with human-like behavior simulation.
"""
import asyncio
import random
import time
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page

from .stealth import STEALTH_JS, CF_TURNSTILE_WAIT_JS, VIEWPORT_PROFILES, USER_AGENTS


class BrowserEngine:
    def __init__(self, config=None):
        self.config = config or {}
        self.headless = self.config.get("headless", True)
        self.proxy = self.config.get("proxy")
        self.timeout = self.config.get("timeout", 30000)
        self.delay_range = self.config.get("delay_range", (0.5, 2.0))
        self.viewport = self.config.get("viewport", "laptop")
        self.cookies = self.config.get("cookies", [])
        self.extra_headers = self.config.get("headers", {})

        self._playwright = None
        self._browser = None
        self._context = None
        self.request_count = 0

    async def start(self):
        self._playwright = await async_playwright().start()

        vp = VIEWPORT_PROFILES.get(self.viewport, VIEWPORT_PROFILES["laptop"])
        ua = random.choice(USER_AGENTS)

        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
            "--disable-infobars",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-popup-blocking",
            "--disable-extensions",
            "--disable-component-extensions-with-background-pages",
            "--disable-default-apps",
            "--metrics-recording-only",
            "--no-sandbox",
        ]

        if self.headless:
            launch_args.append("--headless=new")

        proxy_settings = None
        if self.proxy:
            proxy_settings = {"server": self.proxy}

        self._browser = await self._playwright.chromium.launch(
            executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
            args=launch_args,
            proxy=proxy_settings,
            headless=False,
        )

        self._context = await self._browser.new_context(
            viewport=vp,
            user_agent=ua,
            locale="en-US",
            timezone_id="America/New_York",
            color_scheme="light",
            java_script_enabled=True,
            bypass_csp=False,
            ignore_https_errors=True,
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                **self.extra_headers,
            },
        )

        if self.cookies:
            await self._context.add_cookies(self.cookies)

        await self._context.add_init_script(STEALTH_JS)

        return self

    async def stop(self):
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def new_page(self) -> Page:
        page = await self._context.new_page()
        page.set_default_timeout(self.timeout)
        return page

    async def navigate(self, page: Page, url: str, wait_cf=True) -> dict:
        await self._human_delay()
        self.request_count += 1

        start = time.time()
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout)
        except Exception as e:
            return {
                "url": url,
                "status": 0,
                "error": str(e),
                "elapsed": time.time() - start,
            }

        elapsed = time.time() - start

        if wait_cf and response:
            is_cf = await self._detect_cloudflare(page)
            if is_cf:
                await self._handle_cloudflare(page)
                response = page

        status = response.status if hasattr(response, "status") else 200
        body = await page.content()
        final_url = page.url

        return {
            "url": final_url,
            "status": status,
            "body": body,
            "elapsed": elapsed,
            "title": await page.title(),
        }

    async def _detect_cloudflare(self, page: Page) -> bool:
        indicators = [
            "cf-browser-verification",
            "challenge-platform",
            "challenge-running",
            "cf-please-wait",
            "Checking your browser",
            "challenges.cloudflare.com",
            "Just a moment...",
            "Attention Required",
        ]
        body = await page.content()
        return any(ind in body for ind in indicators)

    async def _handle_cloudflare(self, page: Page):
        print("  [BROWSER] Cloudflare challenge detected, waiting...")

        await page.evaluate(CF_TURNSTILE_WAIT_JS)

        for attempt in range(30):
            await asyncio.sleep(2)

            still_cf = await self._detect_cloudflare(page)
            if not still_cf:
                print("  [BROWSER] Cloudflare challenge passed")
                return

            turnstile = await page.query_selector('iframe[src*="challenges.cloudflare.com"]')
            if turnstile:
                box = await turnstile.bounding_box()
                if box:
                    x = box["x"] + box["width"] / 2 + random.uniform(-5, 5)
                    y = box["y"] + box["height"] / 2 + random.uniform(-5, 5)
                    await self._human_mouse_move(page, x, y)
                    await page.mouse.click(x, y)
                    await asyncio.sleep(3)

            checkbox = await page.query_selector('input[type="checkbox"]')
            if checkbox:
                await checkbox.click()
                await asyncio.sleep(3)

        print("  [BROWSER] Cloudflare challenge timeout")

    async def _human_delay(self):
        lo, hi = self.delay_range
        delay = random.uniform(lo, hi)
        await asyncio.sleep(delay)

    async def _human_mouse_move(self, page: Page, target_x: float, target_y: float):
        steps = random.randint(5, 15)
        current_x = random.uniform(100, 500)
        current_y = random.uniform(100, 400)

        for i in range(steps):
            progress = (i + 1) / steps
            ease = progress * progress * (3 - 2 * progress)
            x = current_x + (target_x - current_x) * ease + random.uniform(-2, 2)
            y = current_y + (target_y - current_y) * ease + random.uniform(-2, 2)
            await page.mouse.move(x, y)
            await asyncio.sleep(random.uniform(0.01, 0.05))

    async def _human_type(self, page: Page, selector: str, text: str):
        element = await page.query_selector(selector)
        if not element:
            return
        await element.click()
        for char in text:
            await page.keyboard.type(char, delay=random.uniform(30, 120))

    async def get_cookies(self) -> list:
        if self._context:
            return await self._context.cookies()
        return []

    async def set_cookies(self, cookies: list):
        if self._context:
            await self._context.add_cookies(cookies)

    async def screenshot(self, page: Page, path: str):
        await page.screenshot(path=path, full_page=True)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()
