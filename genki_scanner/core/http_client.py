import time
import random
import requests
import urllib3
from typing import Optional
from .config import ScanConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPClient:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(config.get_headers())
        self.session.verify = config.verify_ssl
        if config.get_proxies():
            self.session.proxies.update(config.get_proxies())
        if config.cookies:
            self.session.cookies.update(config.cookies)
        self._last_request_time = 0.0
        self.request_count = 0

    def _rate_limit(self):
        elapsed = time.time() - self._last_request_time
        jitter = random.uniform(0.1, 0.5)
        wait = self.config.delay + jitter - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request_time = time.time()

    def request(
        self,
        method: str,
        url: str,
        data: Optional[str] = None,
        headers: Optional[dict] = None,
        allow_redirects: Optional[bool] = None,
        timeout: Optional[int] = None,
    ) -> Optional[requests.Response]:
        self._rate_limit()
        redir = allow_redirects if allow_redirects is not None else self.config.follow_redirects
        tout = timeout or self.config.timeout

        for attempt in range(self.config.max_retries + 1):
            try:
                resp = self.session.request(
                    method,
                    url,
                    data=data,
                    headers=headers,
                    allow_redirects=redir,
                    timeout=tout,
                )
                self.request_count += 1
                return resp
            except requests.exceptions.RequestException:
                if attempt < self.config.max_retries:
                    time.sleep(2 ** attempt)
                    continue
                return None

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, data=None, **kwargs):
        return self.request("POST", url, data=data, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def timed_request(self, method, url, **kwargs):
        self._rate_limit()
        tout = kwargs.pop("timeout", self.config.timeout)
        start = time.time()
        try:
            resp = self.session.request(
                method,
                url,
                allow_redirects=self.config.follow_redirects,
                timeout=tout,
                **kwargs,
            )
            elapsed = time.time() - start
            self.request_count += 1
            return resp, elapsed
        except requests.exceptions.Timeout:
            return None, time.time() - start
        except requests.exceptions.RequestException:
            return None, 0
