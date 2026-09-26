import dataclasses
from typing import Optional


@dataclasses.dataclass
class ScanConfig:
    target: str = ""
    threads: int = 1
    delay: float = 1.0
    timeout: int = 15
    max_retries: int = 2
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    verify_ssl: bool = False
    proxy: Optional[str] = None
    cookies: Optional[dict] = None
    headers: Optional[dict] = None
    follow_redirects: bool = False
    verbose: bool = False
    output_file: Optional[str] = None
    callback_domain: Optional[str] = None
    scope_domains: Optional[list] = None

    def get_proxies(self):
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        return None

    def get_headers(self):
        h = {"User-Agent": self.user_agent}
        if self.headers:
            h.update(self.headers)
        return h
