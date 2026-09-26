"""
JS Recon Pipeline - Offline JavaScript analysis for the shell runtime.

Flow:
  1. Harvest: collect all JS URLs from crawl results + page source
  2. Download: fetch each JS source (respects same-origin + source maps)
  3. Deobfuscate: run jshadow-universal on obfuscated files
  4. Analyze: extract endpoints, secrets, routes, crypto usage
  5. Feed: inject discovered API endpoints back into site tree

Works offline after initial download - jshadow does pure static/sandbox
analysis, no live network needed for deobfuscation.
"""
import json
import os
import re
import hashlib
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WORKERS_DIR = Path(__file__).parent / "js_workers"
JSHADOW_DIR = WORKERS_DIR / "jshadow-universal"


def _run_node(script_path, input_data=None, args=None, timeout=120):
    cmd = ["node", str(script_path)]
    if args:
        cmd.extend(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout,
            input=json.dumps(input_data) if input_data else None,
            cwd=str(script_path.parent),
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500]}
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"raw": result.stdout[:2000]}
    except subprocess.TimeoutExpired:
        return {"error": f"timeout ({timeout}s)"}
    except FileNotFoundError:
        return {"error": "node not found"}


class JSRecon:
    """Offline JS analysis pipeline: harvest -> download -> deobfuscate -> analyze."""

    def __init__(self, target_url, config=None, verbose=False):
        self.target_url = target_url
        self.config = config or {}
        self.verbose = verbose
        parsed = urlparse(target_url)
        self.base_domain = parsed.hostname
        self.base_scheme = parsed.scheme

        self.js_urls = set()
        self.sources = {}       # url -> raw source code
        self.deobfuscated = {}  # url -> cleaned source code
        self.analysis = {}      # url -> analysis results

        self.endpoints = []
        self.secrets = []
        self.routes = []
        self.crypto_usage = []

        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })

        self._save_dir = Path(self.config.get("js_save_dir", "/tmp/genki_js_recon"))
        self._save_dir.mkdir(parents=True, exist_ok=True)

    def harvest_from_html(self, html, page_url=None):
        """Extract JS URLs from HTML source."""
        page_url = page_url or self.target_url
        # <script src="...">
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            self._add_js_url(m.group(1), page_url)
        # Inline script blocks with significant code
        for m in re.finditer(r'<script[^>]*>([\s\S]*?)</script>', html, re.I):
            body = m.group(1).strip()
            if len(body) > 100:
                h = hashlib.md5(body.encode()).hexdigest()[:12]
                inline_key = f"inline://{self.base_domain}/{h}"
                self.js_urls.add(inline_key)
                self.sources[inline_key] = body

    def harvest_from_urls(self, urls):
        """Add JS URLs from crawl results."""
        for url in urls:
            if self._is_js_url(url):
                self.js_urls.add(url)

    def harvest_from_site_tree(self, site_tree):
        """Extract JS URLs from site tree discovered files."""
        if not site_tree:
            return
        for url in site_tree.all_files:
            if self._is_js_url(url):
                self.js_urls.add(url)

    def download_all(self, timeout=15):
        """Download all discovered JS sources. Returns count of successful downloads."""
        count = 0
        for url in sorted(self.js_urls):
            if url in self.sources:
                count += 1
                continue
            if url.startswith("inline://"):
                continue

            try:
                resp = self._session.get(url, timeout=timeout)
                if resp.status_code == 200 and len(resp.content) > 50:
                    content_type = resp.headers.get("Content-Type", "")
                    if "javascript" in content_type or "text/" in content_type or not content_type:
                        source = resp.content.decode("utf-8", errors="replace")
                        self.sources[url] = source
                        count += 1

                        safe_name = re.sub(r'[^\w\-.]', '_', urlparse(url).path.split('/')[-1] or 'script')
                        save_path = self._save_dir / safe_name
                        save_path.write_text(source, encoding="utf-8")

                        # Check for source map
                        sm_match = re.search(r'//[#@]\s*sourceMappingURL=(\S+)', source)
                        if sm_match:
                            sm_url = urljoin(url, sm_match.group(1))
                            self._fetch_source_map(sm_url, url)

                        if self.verbose:
                            print(f"    [JS] {len(source):,} bytes: {url}")
            except Exception as e:
                if self.verbose:
                    print(f"    [JS] FAIL {url}: {e}")
        return count

    def deobfuscate_all(self):
        """Run jshadow-universal on all downloaded sources.
        Works fully offline - no network needed."""
        jshadow_index = JSHADOW_DIR / "index.js"
        if not jshadow_index.exists():
            if self.verbose:
                print("    [JSHADOW] Not found, skipping deobfuscation")
            return 0

        count = 0
        for url, source in self.sources.items():
            if len(source) < 100:
                continue
            if not self._looks_obfuscated(source):
                self.deobfuscated[url] = source
                count += 1
                continue

            result = _run_node(
                jshadow_index,
                input_data={"source": source, "filename": url.split("/")[-1]},
                timeout=60,
            )

            if result.get("error"):
                if self.verbose:
                    print(f"    [JSHADOW] Error on {url}: {result['error'][:100]}")
                self.deobfuscated[url] = source
            else:
                cleaned = result.get("code") or result.get("deobfuscated") or source
                self.deobfuscated[url] = cleaned
                if cleaned != source and self.verbose:
                    ratio = len(cleaned) / max(len(source), 1)
                    print(f"    [JSHADOW] {url.split('/')[-1]}: {ratio:.0%} of original")
            count += 1
        return count

    def analyze_all(self):
        """Run js-analyzer on all sources (deobfuscated preferred).
        Extracts endpoints, secrets, routes, crypto patterns."""
        analyzer_path = WORKERS_DIR / "js-analyzer.cjs"
        sources = self.deobfuscated if self.deobfuscated else self.sources

        for url, source in sources.items():
            if len(source) < 50:
                continue

            if analyzer_path.exists():
                result = _run_node(
                    analyzer_path,
                    input_data={"source": source},
                    timeout=30,
                )
                if not result.get("error"):
                    self.analysis[url] = result
                    self._collect_from_analysis(url, result)
                    continue

            # Fallback: Python regex extraction
            self._python_analyze(url, source)

    def get_api_endpoints(self):
        """Return all discovered API endpoints as absolute URLs."""
        seen = set()
        result = []
        for ep in self.endpoints:
            path = ep.get("path", "")
            if not path or path in seen:
                continue
            seen.add(path)
            if path.startswith("http"):
                result.append(path)
            elif path.startswith("/"):
                result.append(f"{self.base_scheme}://{self.base_domain}{path}")
            else:
                result.append(f"{self.base_scheme}://{self.base_domain}/{path}")
        return result

    def get_summary(self):
        """Return a summary dict of all findings."""
        return {
            "js_files_discovered": len(self.js_urls),
            "js_files_downloaded": len(self.sources),
            "js_files_deobfuscated": sum(
                1 for u in self.deobfuscated
                if self.deobfuscated[u] != self.sources.get(u, "")
            ),
            "endpoints": self.endpoints,
            "secrets": self.secrets,
            "routes": self.routes,
            "crypto_usage": self.crypto_usage,
            "api_endpoints": self.get_api_endpoints(),
        }

    # -- internal helpers --

    def _add_js_url(self, src, base_url):
        url = urljoin(base_url, src)
        if self._is_js_url(url):
            self.js_urls.add(url)

    @staticmethod
    def _is_js_url(url):
        parsed = urlparse(url)
        path = parsed.path.lower()
        if path.endswith(('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx')):
            return True
        if 'javascript' in parsed.query.lower():
            return True
        # Common JS CDN paths
        if any(cdn in url for cdn in ('cdn.', 'assets.', 'static.', 'bundle', 'chunk', 'vendor', 'app.', 'main.')):
            if not path.endswith(('.css', '.png', '.jpg', '.svg', '.woff', '.ttf', '.ico')):
                return True
        return False

    @staticmethod
    def _looks_obfuscated(source):
        indicators = 0
        if re.search(r'_0x[0-9a-f]{4,}', source):
            indicators += 3
        if re.search(r'\\x[0-9a-f]{2}', source):
            indicators += 1
        if re.search(r'eval\s*\(', source):
            indicators += 1
        if re.search(r'String\.fromCharCode', source):
            indicators += 1
        if re.search(r'atob\s*\(', source):
            indicators += 1
        # High entropy variable names
        short_vars = re.findall(r'\b[a-zA-Z_$]{1,2}\d{1,3}\b', source[:5000])
        if len(short_vars) > 50:
            indicators += 2
        # Packed code
        if re.search(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k", source):
            indicators += 3
        return indicators >= 2

    def _fetch_source_map(self, sm_url, js_url):
        try:
            resp = self._session.get(sm_url, timeout=10)
            if resp.status_code == 200:
                sm_data = resp.json()
                sources = sm_data.get("sources", [])
                contents = sm_data.get("sourcesContent", [])
                for i, src_path in enumerate(sources):
                    if i < len(contents) and contents[i]:
                        key = f"sourcemap://{src_path}"
                        self.sources[key] = contents[i]
                        if self.verbose:
                            print(f"    [SRCMAP] {src_path} ({len(contents[i]):,} bytes)")
        except Exception:
            pass

    def _collect_from_analysis(self, url, result):
        for ep in result.get("endpoints", []):
            ep["source_file"] = url
            self.endpoints.append(ep)
        for secret in result.get("secrets", []):
            secret["source_file"] = url
            self.secrets.append(secret)
        for route in result.get("routes", []):
            route["source_file"] = url
            self.routes.append(route)
        for crypto in result.get("crypto", []):
            crypto["source_file"] = url
            self.crypto_usage.append(crypto)

    def _python_analyze(self, url, source):
        """Fallback Python-based analysis when Node.js workers unavailable."""
        # API endpoints
        for m in re.finditer(
            r'''(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch|HttpClient|http\.)\s*\(\s*[`'"](\/[^`'"]{2,})[`'"]''',
            source
        ):
            self.endpoints.append({"path": m.group(1), "source_file": url, "method": "inferred"})

        # Route definitions
        for m in re.finditer(
            r'''(?:path|route|to)\s*[:=]\s*[`'"](\/[^`'"]{2,})[`'"]''',
            source
        ):
            self.routes.append({"path": m.group(1), "source_file": url})

        # Secrets / API keys
        secret_re = re.compile(
            r'''(?:api[_-]?key|secret|token|password|auth|bearer|private[_-]?key|access[_-]?key)\s*[:=]\s*[`'"]([\w\-./+=]{8,})[`'"]''',
            re.I,
        )
        for m in secret_re.finditer(source):
            self.secrets.append({"key": m.group(0)[:80], "value": m.group(1)[:40], "source_file": url})

        # Crypto usage
        for m in re.finditer(
            r'''(?:crypto\.subtle|CryptoJS|sjcl|forge|nacl|tweetnacl|bcrypt|scrypt)\.(\w+)''',
            source,
        ):
            self.crypto_usage.append({"lib": m.group(0), "method": m.group(1), "source_file": url})

        self.analysis[url] = {
            "endpoints": [e for e in self.endpoints if e.get("source_file") == url],
            "secrets": [s for s in self.secrets if s.get("source_file") == url],
        }


def run_js_recon(target_url, site_tree=None, html=None, verbose=False, config=None):
    """Run the full JS recon pipeline. Returns summary dict.

    Usage:
        results = run_js_recon("https://target.com", site_tree=tree, html=body)
    """
    recon = JSRecon(target_url, config=config, verbose=verbose)

    if html:
        recon.harvest_from_html(html)
    if site_tree:
        recon.harvest_from_site_tree(site_tree)

    if not recon.js_urls:
        return {"js_files_discovered": 0}

    recon.download_all()
    recon.deobfuscate_all()
    recon.analyze_all()

    return recon.get_summary()
