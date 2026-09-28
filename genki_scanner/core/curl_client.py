"""
Curl-based HTTP client for requests that need raw control.
Useful for bypassing certain protections that filter python-requests.
"""
import subprocess
import json
import time
import random
import shlex
from typing import Optional
from .config import ScanConfig


class CurlResponse:
    def __init__(self, status_code: int, headers: dict, body: str, elapsed: float):
        self.status_code = status_code
        self.headers = headers
        self.text = body
        self.content = body.encode("utf-8", errors="replace")
        self.elapsed_seconds = elapsed

    @property
    def ok(self):
        return 200 <= self.status_code < 400


class CurlClient:
    def __init__(self, config: ScanConfig):
        self.config = config
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
        allow_redirects: bool = False,
        timeout: Optional[int] = None,
        raw_args: Optional[list] = None,
    ) -> Optional[CurlResponse]:
        self._rate_limit()
        tout = timeout or self.config.timeout

        cmd = [
            "curl", "-s",
            "-w", "\n__GENKI_STATUS__%{http_code}__GENKI_TIME__%{time_total}",
            "-X", method.upper(),
            "--max-time", str(tout),
            "--connect-timeout", str(min(tout, 10)),
        ]

        if not self.config.verify_ssl:
            cmd.append("-k")

        if not allow_redirects:
            cmd.append("--max-redirs")
            cmd.append("0")
        else:
            cmd.append("-L")

        cmd.extend(["-H", f"User-Agent: {self.config.user_agent}"])

        if self.config.proxy:
            cmd.extend(["-x", self.config.proxy])

        if self.config.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.config.cookies.items())
            cmd.extend(["-b", cookie_str])

        all_headers = dict(self.config.get_headers())
        if headers:
            all_headers.update(headers)
        for hname, hval in all_headers.items():
            if hname.lower() != "user-agent":
                cmd.extend(["-H", f"{hname}: {hval}"])

        if data:
            cmd.extend(["-d", data])

        cmd.extend(["-D", "-"])

        if raw_args:
            cmd.extend(raw_args)

        cmd.append(url)

        start = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=tout + 5,
            )
            elapsed = time.time() - start
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

        output = result.stdout
        self.request_count += 1

        status_code = 0
        curl_time = elapsed
        status_marker = "__GENKI_STATUS__"
        time_marker = "__GENKI_TIME__"
        if status_marker in output:
            parts = output.split(status_marker)
            body_with_headers = parts[0]
            status_part = parts[1]
            try:
                if time_marker in status_part:
                    sc, ct = status_part.split(time_marker)
                    status_code = int(sc)
                    curl_time = float(ct)
                else:
                    status_code = int(status_part.strip())
            except ValueError:
                pass
        else:
            body_with_headers = output

        resp_headers = {}
        body = body_with_headers
        if "\r\n\r\n" in body_with_headers:
            header_block, body = body_with_headers.split("\r\n\r\n", 1)
            for line in header_block.split("\r\n"):
                if ":" in line:
                    hname, hval = line.split(":", 1)
                    resp_headers[hname.strip()] = hval.strip()

        return CurlResponse(status_code, resp_headers, body, curl_time)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, data=None, **kwargs):
        return self.request("POST", url, data=data, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def raw_curl(self, args: list, timeout: int = 30) -> tuple[str, str, int]:
        self._rate_limit()
        try:
            result = subprocess.run(
                ["curl"] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            self.request_count += 1
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "timeout", 1
        except Exception as e:
            return "", str(e), 1
