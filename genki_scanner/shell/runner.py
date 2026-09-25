"""
Shell Runner - Python orchestrator for AWVS10 decoded script execution.
Spawns a Node.js runtime, manages phases, feeds scripts in order.
Full pipeline: tech detect -> crawl -> dir enum -> scan all phases -> report.

Phase data wiring:
  PerServer  - runs each script once per target
  PerFolder  - runs each script per discovered directory
  PerFile    - runs each script per discovered file
  PerScheme  - runs each script per discovered input scheme (params to fuzz)
  PostCrawl  - runs each script once with full file list via getNewFiles()
  PostScan   - runs each script once at the end
"""
import json
import os
import re
import subprocess
import sys
import time
import signal
import socket
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs

from .tech_detect import detect_technologies, WAF_SIGNATURES
from .site_tree import SiteTree, Scheme, SiteFile


PHASE_ORDER = [
    ("PerServer", "server"),
    ("PerFolder", "folder"),
    ("PerFile", "file"),
    ("PerScheme", "scheme"),
    ("PostCrawl", "postcrawl"),
    ("PostScan", "postscan"),
]

NETWORK_PHASE = ("Network", "network")
WEBAPPS_PHASE = ("WebApps", "webapps")

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
    8000, 8080, 8443, 8888, 9200, 9300, 27017,
]

OOB_DOMAIN = "6u.gg"


class NodeRuntime:
    """Manages a persistent Node.js child process for script execution."""

    def __init__(self, verbose=False):
        self.proc = None
        self.verbose = verbose
        self._buffer = ""

    def start(self):
        js_dir = os.path.join(os.path.dirname(__file__), "js")
        runtime_path = os.path.join(js_dir, "runtime.js")

        self.proc = subprocess.Popen(
            ["node", runtime_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        boot = self._read_message()
        if boot and boot.get("type") == "boot":
            if self.verbose:
                print(f"  [SHELL] Node.js {boot['data'].get('node', '?')} runtime started")
            return True
        return False

    def stop(self):
        if self.proc:
            try:
                self._send({"action": "shutdown"})
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
            self.proc = None

    def _send(self, cmd):
        if not self.proc or self.proc.poll() is not None:
            raise RuntimeError("Node runtime not running")
        line = json.dumps(cmd) + "\n"
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

    def _read_message(self):
        if not self.proc:
            return None
        line = self.proc.stdout.readline()
        if not line:
            return None
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError:
            return {"type": "raw", "data": line.strip()}

    def _read_until(self, expected_type, timeout=600):
        start = time.time()
        while time.time() - start < timeout:
            msg = self._read_message()
            if msg is None:
                if self.proc and self.proc.poll() is not None:
                    raise RuntimeError("Node runtime died")
                time.sleep(0.01)
                continue
            if msg.get("type") == expected_type:
                return msg
            yield msg
        raise TimeoutError(f"Timeout waiting for {expected_type}")

    def init(self, scripts_dir, config):
        self._send({
            "action": "init",
            "scriptsDir": scripts_dir,
            "timeout": config.get("timeout", 15),
            "proxy": config.get("proxy"),
            "delay": config.get("delay", 1.0),
            "verbose": config.get("verbose", False),
            "headers": config.get("headers", {}),
        })
        for msg in self._read_until("ready"):
            self._handle_intermediate(msg)

    def execute_script(self, script_path, context):
        self._send({
            "action": "execute",
            "scriptPath": script_path,
            "context": context,
        })

        findings = []
        for msg in self._read_until("result"):
            self._handle_intermediate(msg, findings)

        result = self._read_until("result")
        return findings

    def execute_script_full(self, script_path, context, callback=None):
        self._send({
            "action": "execute",
            "scriptPath": script_path,
            "context": context,
        })

        findings = []
        while True:
            msg = self._read_message()
            if msg is None:
                if self.proc and self.proc.poll() is not None:
                    break
                time.sleep(0.01)
                continue

            if msg["type"] == "result":
                return msg["data"], findings
            elif msg["type"] == "finding":
                findings.append(msg["data"])
                if callback:
                    callback("finding", msg["data"])
            elif msg["type"] == "kbase":
                if callback:
                    callback("kbase", msg["data"])
            elif msg["type"] == "progress":
                if callback:
                    callback("progress", msg["data"])
            elif msg["type"] == "error":
                if callback:
                    callback("error", msg["data"])
            elif msg["type"] == "trace":
                if self.verbose and callback:
                    callback("trace", msg["data"])

        return {"success": False, "error": "Runtime died"}, findings

    def set_context(self, **kwargs):
        self._send({"action": "set_context", **kwargs})
        for msg in self._read_until("ack"):
            self._handle_intermediate(msg)

    def get_findings(self):
        self._send({"action": "get_findings"})
        result = None
        for msg in self._read_until("findings"):
            pass
        return result

    def clear_findings(self):
        self._send({"action": "clear_findings"})
        for msg in self._read_until("ack"):
            pass

    def _handle_intermediate(self, msg, findings_list=None):
        if msg["type"] == "finding":
            if findings_list is not None:
                findings_list.append(msg["data"])
            if self.verbose:
                sev = msg["data"].get("severity", "?")
                name = msg["data"].get("name", "?")
                print(f"  [FINDING] [{sev.upper()}] {name}")
        elif msg["type"] == "error":
            print(f"  [ERROR] {msg['data'].get('message', '?')}")
        elif msg["type"] == "trace" and self.verbose:
            print(f"  [TRACE] {msg['data'].get('message', '')}")


class ShellOrchestrator:
    """Full pipeline orchestrator matching AWVS10's execution model."""

    def __init__(self, scripts_dir, config=None):
        self.scripts_dir = os.path.abspath(scripts_dir)
        self.config = config or {}
        self.runtime = NodeRuntime(verbose=self.config.get("verbose", False))
        self.all_findings = []
        self.stats = {"scripts_run": 0, "errors": 0, "phases": {}}
        self.site_trees = {}
        self.oob_domain = self.config.get("oob_domain", OOB_DOMAIN)

    def _list_scripts(self, phase_dir):
        full_path = os.path.join(self.scripts_dir, phase_dir)
        if not os.path.isdir(full_path):
            return []
        scripts = []
        for f in sorted(os.listdir(full_path)):
            if f.endswith(".script"):
                scripts.append(os.path.join(full_path, f))
        return scripts

    # ---- Technology / Server Detection ----

    def _detect_server(self, target_url):
        parsed = urlparse(target_url)
        info = {
            "banner": "",
            "poweredby": "",
            "platform_os": "Unknown",
            "technologies": [],
            "hostname": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "scheme": parsed.scheme,
            "waf": [],
            "cms": [],
            "frameworks": [],
            "js_frameworks": [],
            "cdn": [],
        }

        try:
            import requests
            resp = requests.get(
                target_url, timeout=10, verify=False,
                allow_redirects=True,
                headers={"User-Agent": self.config.get("headers", {}).get(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                )}
            )

            resp_headers = dict(resp.headers)
            cookies_str = resp.headers.get("Set-Cookie", "")

            tech_result = detect_technologies(resp_headers, resp.text, cookies_str)

            info["banner"] = resp_headers.get("Server", "")
            info["poweredby"] = resp_headers.get("X-Powered-By", "")
            info["technologies"] = tech_result["technologies"]
            info["waf"] = tech_result["waf"]
            info["platform_os"] = tech_result["os"]
            info["cms"] = tech_result.get("cms", [])
            info["frameworks"] = tech_result.get("frameworks", [])
            info["js_frameworks"] = tech_result.get("js_frameworks", [])
            info["cdn"] = tech_result.get("cdn", [])
            info["response_headers"] = resp_headers
            info["status_code"] = resp.status_code
            info["_body"] = resp.text

        except Exception as e:
            print(f"  [WARN] Server probe failed: {e}")

        return info

    def _port_scan(self, hostname, ports=None):
        ports = ports or COMMON_PORTS
        open_ports = []
        print(f"\n  [PORTS] Scanning {len(ports)} common ports on {hostname}")

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    service = _get_service_name(port)
                    open_ports.append({"port": port, "service": service})
                    print(f"    [OPEN] {port}/{service}")
                sock.close()
            except Exception:
                pass

        if not open_ports:
            print("    [INFO] No additional open ports found")
        else:
            print(f"    [DONE] {len(open_ports)} open ports")

        return open_ports

    def _dir_enum(self, target_url, server_info):
        common_dirs = [
            ".git/HEAD", ".git/config", ".svn/entries", ".env",
            ".htaccess", "web.config", "robots.txt", "sitemap.xml",
            "crossdomain.xml", ".well-known/security.txt",
            "wp-login.php", "wp-admin/", "wp-json/wp/v2/users",
            "administrator/", "admin/", "login/", "api/",
            "graphql", ".DS_Store", "backup/", "old/",
            "test/", "staging/", "dev/", "debug/",
            "phpinfo.php", "info.php", "server-status", "server-info",
            "elmah.axd", "trace.axd",
            "actuator/health", "actuator/env", "actuator/beans",
            "swagger-ui.html", "swagger-ui/", "api-docs",
            "v1/", "v2/", "api/v1/", "api/v2/",
            ".aws/credentials", "config.json", "config.yml",
            "docker-compose.yml", "Dockerfile",
            "package.json", "composer.json", "Gemfile",
            "wp-config.php.bak", "wp-config.php.old",
            "database.sql", "dump.sql", "backup.sql",
            ".vscode/", ".idea/",
            "cgi-bin/", "scripts/", "includes/",
        ]

        cms = server_info.get("cms", [])
        if "WordPress" in cms or "WordPress" in server_info.get("technologies", []):
            common_dirs.extend([
                "wp-content/debug.log", "wp-content/uploads/",
                "wp-includes/version.php", "xmlrpc.php",
                "wp-cron.php", "readme.html", "license.txt",
                "wp-content/plugins/", "wp-content/themes/",
            ])
        if "Drupal" in cms or "Drupal" in server_info.get("technologies", []):
            common_dirs.extend([
                "CHANGELOG.txt", "core/CHANGELOG.txt",
                "sites/default/settings.php",
                "user/login", "node/1",
            ])
        if "Joomla" in cms or "Joomla" in server_info.get("technologies", []):
            common_dirs.extend([
                "configuration.php", "htaccess.txt",
                "language/en-GB/", "README.txt",
            ])

        print(f"\n  [DIRS] Checking {len(common_dirs)} paths")
        found = []
        import requests

        base = target_url.rstrip("/")
        delay = self.config.get("delay", 1.0)

        for path in common_dirs:
            try:
                url = f"{base}/{path}"
                resp = requests.get(
                    url, timeout=8, verify=False,
                    allow_redirects=False,
                    headers=self.config.get("headers", {}),
                )

                if resp.status_code in (200, 301, 302, 403):
                    status = resp.status_code
                    size = len(resp.content)
                    if size > 0 and status != 404:
                        entry = {
                            "path": path,
                            "status": status,
                            "size": size,
                            "content_type": resp.headers.get("Content-Type", ""),
                        }

                        sensitive = _check_sensitive(path, resp.text, status)
                        if sensitive:
                            entry["sensitive"] = True
                            entry["finding_type"] = sensitive
                            sev = "high" if sensitive in ("git_exposed", "env_file", "backup_file", "credentials") else "medium"
                            self.all_findings.append({
                                "name": f"Sensitive path: {path}",
                                "severity": sev,
                                "affects": url,
                                "details": f"Status {status}, Size {size}B, Type: {sensitive}",
                                "phase": "DirEnum",
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            })
                            print(f"    [!] [{sev.upper()}] {path} ({status}, {size}B) - {sensitive}")
                        elif self.config.get("verbose"):
                            print(f"    [+] {path} ({status}, {size}B)")

                        found.append(entry)

                time.sleep(delay * 0.3)

            except Exception:
                pass

        print(f"    [DONE] {len(found)} paths found")
        return found

    # ---- Site Tree Building (SPA-aware) ----

    def _extract_from_html(self, html, base_url):
        """Extract links, forms, script srcs, and inline API refs from HTML."""
        parsed_base = urlparse(base_url)
        links = set()
        forms = []
        api_endpoints = set()

        emails_found = set()
        for match in re.finditer(r'<a\s[^>]*href=["\']([^"\'#]+)["\']', html, re.I):
            href = match.group(1)
            if href.startswith('mailto:'):
                email = href[7:].split('?')[0].strip()
                if email and '@' in email:
                    emails_found.add(email)
                continue
            if href.startswith(('javascript:', 'tel:', 'data:')):
                continue
            full_url = urljoin(base_url, href)
            if urlparse(full_url).hostname == parsed_base.hostname:
                links.add(full_url.split('#')[0])

        for match in re.finditer(r'<(?:script|link)\s[^>]*(?:src|href)=["\']([^"\']+)["\']', html, re.I):
            src = match.group(1)
            full_url = urljoin(base_url, src)
            if urlparse(full_url).hostname == parsed_base.hostname:
                links.add(full_url)

        for match in re.finditer(r'<img\s[^>]*src=["\']([^"\']+)["\']', html, re.I):
            src = match.group(1)
            full_url = urljoin(base_url, src)
            if urlparse(full_url).hostname == parsed_base.hostname:
                links.add(full_url)

        form_pattern = re.compile(r'<form\s([^>]*)>(.*?)</form>', re.I | re.S)
        for fm in form_pattern.finditer(html):
            attrs = fm.group(1)
            body = fm.group(2)

            action = base_url
            method = 'GET'

            action_match = re.search(r'action=["\']([^"\']+)["\']', attrs, re.I)
            if action_match:
                action = urljoin(base_url, action_match.group(1))
            method_match = re.search(r'method=["\']([^"\']+)["\']', attrs, re.I)
            if method_match:
                method = method_match.group(1).upper()

            inputs = []
            for inp_match in re.finditer(r'<(?:input|textarea|select)\s([^>]*)/?>', body, re.I):
                inp_attrs = inp_match.group(1)
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp_attrs, re.I)
                if not name_m:
                    continue
                value_m = re.search(r'value=["\']([^"\']*)["\']', inp_attrs, re.I)
                type_m = re.search(r'type=["\']([^"\']+)["\']', inp_attrs, re.I)
                inputs.append({
                    'name': name_m.group(1),
                    'value': value_m.group(1) if value_m else '',
                    'type': type_m.group(1) if type_m else 'text',
                })

            if inputs:
                forms.append({'action': action, 'method': method, 'inputs': inputs})

        for match in re.finditer(r'(?:api|endpoint|url)\s*[:=]\s*["\']([/][^"\']+)["\']', html, re.I):
            ep = urljoin(base_url, match.group(1))
            if urlparse(ep).hostname == parsed_base.hostname:
                api_endpoints.add(ep)

        return links, forms, api_endpoints, emails_found

    def _extract_api_from_js(self, js_code, base_url):
        """Extract API endpoints from JavaScript source code (SPA bundles)."""
        endpoints = set()
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        patterns = [
            r'(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post|put|delete|patch))\s*\(\s*["\']([/][^"\']*)["\']',
            r'(?:url|endpoint|apiUrl|baseUrl|base_url|API_URL|API_BASE|apiBase)\s*[:=]\s*["\']([/][^"\']+)["\']',
            r'\.(?:get|post|put|delete|patch|head|options)\s*(?:<[^>]*>)?\s*\(\s*["\']([/][^"\']+)["\']',
            r'(?:path|route)\s*:\s*["\']([/][a-zA-Z0-9/_\-:]+)["\']',
            r'[`]([/](?:api|rest|v\d+)[/][^`\n]{3,60})[`]',
            r'["\']([/][^"\']*graphql[^"\']*)["\']',
            r'["\']([/](?:api|rest|service|backend)[/][^"\']{2,80})["\']',
        ]

        static_exts = {'.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico',
                       '.woff', '.woff2', '.ttf', '.eot', '.map'}

        for pat in patterns:
            for match in re.finditer(pat, js_code, re.I):
                path = match.group(1)
                if not path or path.startswith('//'):
                    continue
                ext = os.path.splitext(path.split('?')[0])[1].lower()
                if ext in static_exts:
                    continue
                endpoints.add(base + path)

        return endpoints

    def _build_site_tree(self, target_url, server_info):
        """Build site tree from browser crawl data or basic HTTP extraction."""
        if target_url in self.site_trees:
            tree = self.site_trees[target_url]
            print(f"  [TREE] Browser crawl: {len(tree.all_files)} files, "
                  f"{len(tree.all_schemes)} schemes, {len(tree.all_directories)} dirs")
            return tree

        tree = SiteTree(target_url)
        tree.add_url(target_url)
        tree._cookies = ""

        print(f"\n  [TREE] Building site tree from HTTP responses")

        try:
            import requests as req_lib
            headers = dict(self.config.get("headers", {}))
            if "User-Agent" not in headers:
                headers["User-Agent"] = (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                )

            body = server_info.get("_body", "")
            if not body:
                resp = req_lib.get(target_url, timeout=10, verify=False,
                                  headers=headers, allow_redirects=True)
                body = resp.text
                cookie_header = resp.headers.get("Set-Cookie", "")
            else:
                cookie_header = server_info.get("response_headers", {}).get("Set-Cookie", "")

            links, forms, api_endpoints, mailto_emails = self._extract_from_html(body, target_url)

            parsed_base = urlparse(target_url)
            same_host = [l for l in links if urlparse(l).hostname == parsed_base.hostname]

            for link in same_host[:200]:
                tree.add_url(link)

            for form in forms:
                tree.add_form(form['action'], form['method'], form.get('inputs', []))

            js_urls = [l for l in same_host
                       if re.search(r'\.js(\?|$)', urlparse(l).path.split('/')[-1])]

            all_api_eps = set(api_endpoints)
            if js_urls:
                print(f"  [TREE] Scanning {min(len(js_urls), 15)} JS files for API endpoints")

            delay = self.config.get("delay", 1.0)
            for js_url in js_urls[:15]:
                try:
                    js_resp = req_lib.get(js_url, timeout=10, verify=False, headers=headers)
                    if js_resp.status_code == 200 and len(js_resp.text) > 50:
                        js_api_eps = self._extract_api_from_js(js_resp.text, target_url)
                        all_api_eps.update(js_api_eps)
                    time.sleep(delay * 0.3)
                except Exception:
                    pass

            for ep in all_api_eps:
                if urlparse(ep).hostname == parsed_base.hostname:
                    tree.add_url(ep)

            cookie_parts = []
            for c in cookie_header.split(','):
                c = c.strip()
                if '=' in c:
                    cookie_parts.append(c.split(';')[0].strip())
            tree._cookies = '; '.join(cookie_parts)

            # Also add discovered directories from dir_enum if available
            dir_results = server_info.get("directories", [])
            for d in dir_results:
                dpath = d.get("path", "")
                if dpath:
                    durl = urljoin(target_url.rstrip('/') + '/', dpath)
                    tree.add_url(durl)

            print(f"  [TREE] {len(tree.all_files)} files, {len(tree.all_schemes)} schemes, "
                  f"{len(tree.all_directories)} dirs")
            if all_api_eps:
                print(f"  [TREE] {len(all_api_eps)} API endpoints from JS analysis")

        except Exception as e:
            print(f"  [WARN] Site tree extraction failed: {e}")

        self.site_trees[target_url] = tree
        return tree

    # ---- Context Building ----

    def _build_context(self, target_url, server_info, **extra):
        ctx = {
            "scanURL": target_url,
            "scanIP": server_info.get("hostname", ""),
            "serverInfo": server_info,
            "oobDomain": self.oob_domain,
        }
        if "siteTree" in extra and extra["siteTree"] and hasattr(extra["siteTree"], 'to_js_object'):
            extra["siteTree"] = extra["siteTree"].to_js_object()
        ctx.update(extra)
        return ctx

    def _on_script_event(self, event_type, data):
        if event_type == "finding":
            self.all_findings.append(data)
            sev = data.get("severity", "info").upper()
            name = data.get("name", "Unknown")
            print(f"    [!] [{sev}] {name}")
            details = data.get("details", "")
            if details:
                print(f"        {details[:120]}")
        elif event_type == "error":
            print(f"    [ERR] {data.get('message', '?')}")
            self.stats["errors"] += 1
        elif event_type == "progress":
            pass

    # ---- Main Pipeline ----

    def run(self, targets, phases=None, modules=None):
        print(f"\n{'=' * 60}")
        print("GENKI SHELL v1.1 - AWVS10 Script Runtime")
        print("Genki Tech Labs / Anbu Black Ops")
        print(f"{'=' * 60}")
        print(f"Targets: {len(targets)}")
        print(f"Scripts: {self.scripts_dir}")
        print(f"OOB Domain: {self.oob_domain}")
        print(f"{'=' * 60}\n")

        self.runtime.start()
        self.runtime.init(self.scripts_dir, self.config)

        try:
            for target in targets:
                if not target.startswith(("http://", "https://")):
                    target = "https://" + target
                self._scan_target(target, phases, modules)
        finally:
            self.runtime.stop()

        self._print_summary()
        return self.all_findings

    def _scan_target(self, target_url, phases=None, modules=None):
        print(f"\n[TARGET] {target_url}")
        print("-" * 50)

        # Phase 0: Technology Detection
        print("\n  [PHASE 0] Technology Detection")
        server_info = self._detect_server(target_url)
        print(f"  Server: {server_info.get('banner', 'Unknown')}")
        print(f"  OS: {server_info.get('platform_os', 'Unknown')}")
        if server_info.get("poweredby"):
            print(f"  Powered: {server_info['poweredby']}")
        if server_info.get("technologies"):
            print(f"  Tech: {', '.join(server_info['technologies'])}")
        if server_info.get("waf"):
            print(f"  WAF: {', '.join(server_info['waf'])}")
        if server_info.get("cms"):
            print(f"  CMS: {', '.join(server_info['cms'])}")
        if server_info.get("frameworks"):
            print(f"  Frameworks: {', '.join(server_info['frameworks'])}")
        if server_info.get("js_frameworks"):
            print(f"  JS Frameworks: {', '.join(server_info['js_frameworks'])}")

        # Phase 0.5: Port Scan
        parsed = urlparse(target_url)
        if not phases or "ports" in (phases or []):
            open_ports = self._port_scan(parsed.hostname)
            server_info["open_ports"] = open_ports
        else:
            server_info["open_ports"] = []

        # Phase 1: Browser Crawl (if enabled)
        if self.config.get("browser"):
            self._browser_crawl(target_url)

        # Phase 1.5: Directory Enumeration
        if not phases or "dirs" in (phases or []):
            dir_results = self._dir_enum(target_url, server_info)
            server_info["directories"] = dir_results

        # Phase 1.7: Build Site Tree (from browser crawl or basic HTTP extraction)
        site_tree = self._build_site_tree(target_url, server_info)

        # Phase 2+: AWVS Script Phases
        active_phases = phases or [p[0] for p in PHASE_ORDER]

        for phase_name, phase_type in PHASE_ORDER:
            if phase_name not in active_phases:
                continue
            self._run_phase(phase_name, phase_type, target_url, server_info, site_tree)

        if "Network" in active_phases or not phases:
            pass

        if "WebApps" in active_phases or not phases:
            self._run_phase("WebApps", "webapps", target_url, server_info, site_tree)

    def _browser_crawl(self, target_url):
        try:
            from .browser_bridge import crawl_with_browser
            trees = crawl_with_browser(
                [target_url],
                config=self.config,
                max_depth=self.config.get("max_depth", 3),
                max_pages=self.config.get("max_pages", 100),
            )
            if target_url in trees:
                self.site_trees[target_url] = trees[target_url]
                tree = trees[target_url]
                print(f"  [CRAWL] {len(tree.all_files)} pages, "
                      f"{len(tree.all_schemes)} schemes, {len(tree.all_directories)} dirs")
        except ImportError:
            print("  [WARN] Browser module not available (pip install playwright)")
        except Exception as e:
            print(f"  [WARN] Browser crawl failed: {e}")

    # ---- Phase Execution (per-item iteration) ----

    def _run_phase(self, phase_name, phase_type, target_url, server_info, site_tree=None):
        scripts = self._list_scripts(phase_name)
        if not scripts:
            return

        self.stats["phases"][phase_name] = {"total": len(scripts), "run": 0, "findings": 0}

        if phase_type in ("server", "postscan", "webapps"):
            self._run_phase_single(phase_name, scripts, target_url, server_info, site_tree)

        elif phase_type == "postcrawl":
            self._run_phase_postcrawl(phase_name, scripts, target_url, server_info, site_tree)

        elif phase_type == "folder":
            self._run_phase_per_folder(phase_name, scripts, target_url, server_info, site_tree)

        elif phase_type == "file":
            self._run_phase_per_file(phase_name, scripts, target_url, server_info, site_tree)

        elif phase_type == "scheme":
            self._run_phase_per_scheme(phase_name, scripts, target_url, server_info, site_tree)

    def _run_phase_single(self, phase_name, scripts, target_url, server_info, site_tree):
        """Run each script once (PerServer, PostScan, WebApps)."""
        print(f"\n  [{phase_name.upper()}] {len(scripts)} scripts")
        context = self._build_context(target_url, server_info, siteTree=site_tree)
        for i, script_path in enumerate(scripts):
            self._execute_one(script_path, context, phase_name, i, len(scripts))

    def _run_phase_postcrawl(self, phase_name, scripts, target_url, server_info, site_tree):
        """Run each script once with discovered files list and cookies."""
        discovered = []
        if site_tree:
            for url, sf in site_tree.all_files.items():
                p = urlparse(url).path or '/'
                discovered.append({
                    'url': url,
                    'path': p,
                    'Name': os.path.basename(p) or 'index',
                    'name': os.path.basename(p) or 'index',
                })

        cookies = getattr(site_tree, '_cookies', '') if site_tree else ''
        if not cookies:
            cookies = getattr(site_tree, '_browser_cookies', '') if site_tree else ''
            if isinstance(cookies, list):
                cookies = '; '.join(f"{c.get('name', '')}={c.get('value', '')}" for c in cookies)

        print(f"\n  [{phase_name.upper()}] {len(scripts)} scripts ({len(discovered)} discovered files)")
        context = self._build_context(
            target_url, server_info,
            siteTree=site_tree,
            discoveredFiles=discovered,
            cookies=cookies,
        )
        for i, script_path in enumerate(scripts):
            self._execute_one(script_path, context, phase_name, i, len(scripts))

    def _run_phase_per_folder(self, phase_name, scripts, target_url, server_info, site_tree):
        """Run each script per discovered directory."""
        directories = sorted(site_tree.all_directories) if site_tree else ['/']
        print(f"\n  [{phase_name.upper()}] {len(scripts)} scripts x {len(directories)} directories")

        for dir_idx, dir_path in enumerate(directories):
            dir_name = dir_path.rstrip('/').split('/')[-1] or '/'
            if self.config.get("verbose"):
                print(f"    Dir [{dir_idx+1}/{len(directories)}] {dir_path}")

            context = self._build_context(
                target_url, server_info,
                siteTree=site_tree,
                directory={'path': dir_path, 'Name': dir_name, 'name': dir_path},
            )

            dir_findings_before = len(self.all_findings)
            for i, script_path in enumerate(scripts):
                self._execute_one(
                    script_path, context, phase_name, i, len(scripts),
                    silent=not self.config.get("verbose"),
                )

            dir_new = len(self.all_findings) - dir_findings_before
            if dir_new:
                print(f"    Dir [{dir_idx+1}/{len(directories)}] {dir_path} -> {dir_new} findings")

        total_run = self.stats["phases"][phase_name]["run"]
        total_findings = self.stats["phases"][phase_name]["findings"]
        print(f"    [DONE] {total_run} executions, {total_findings} findings")

    def _run_phase_per_file(self, phase_name, scripts, target_url, server_info, site_tree):
        """Run each script per discovered file."""
        files = []
        if site_tree:
            for url, sf in site_tree.all_files.items():
                p = urlparse(url).path or '/'
                files.append({
                    'url': url,
                    'path': p,
                    'Name': os.path.basename(p) or 'index',
                    'name': os.path.basename(p) or 'index',
                })

        if not files:
            p = urlparse(target_url).path or '/'
            files = [{'url': target_url, 'path': p,
                       'Name': os.path.basename(p) or 'index',
                       'name': os.path.basename(p) or 'index'}]

        print(f"\n  [{phase_name.upper()}] {len(scripts)} scripts x {len(files)} files")

        for file_idx, file_ctx in enumerate(files):
            if self.config.get("verbose"):
                print(f"    File [{file_idx+1}/{len(files)}] {file_ctx['path']}")

            context = self._build_context(
                target_url, server_info,
                siteTree=site_tree,
                file=file_ctx,
            )

            file_findings_before = len(self.all_findings)
            for i, script_path in enumerate(scripts):
                self._execute_one(
                    script_path, context, phase_name, i, len(scripts),
                    silent=not self.config.get("verbose"),
                )

            file_new = len(self.all_findings) - file_findings_before
            if file_new:
                print(f"    File [{file_idx+1}/{len(files)}] {file_ctx['path']} -> {file_new} findings")

        total_run = self.stats["phases"][phase_name]["run"]
        total_findings = self.stats["phases"][phase_name]["findings"]
        print(f"    [DONE] {total_run} executions, {total_findings} findings")

    def _run_phase_per_scheme(self, phase_name, scripts, target_url, server_info, site_tree):
        """Run each script per discovered input scheme (the real fuzzing)."""
        schemes = site_tree.all_schemes if site_tree else []
        if not schemes:
            print(f"\n  [{phase_name.upper()}] {len(scripts)} scripts x 0 schemes (no inputs discovered)")
            return

        print(f"\n  [{phase_name.upper()}] {len(scripts)} scripts x {len(schemes)} schemes")

        for sch_idx, scheme in enumerate(schemes):
            label = f"{scheme.method} {scheme.path} ({len(scheme.inputs)} inputs)"
            if self.config.get("verbose"):
                print(f"    Scheme [{sch_idx+1}/{len(schemes)}] {label}")

            context = self._build_context(
                target_url, server_info,
                siteTree=site_tree,
                scheme=scheme.to_js_object(),
            )

            sch_findings_before = len(self.all_findings)
            for i, script_path in enumerate(scripts):
                self._execute_one(
                    script_path, context, phase_name, i, len(scripts),
                    silent=not self.config.get("verbose"),
                )

            sch_new = len(self.all_findings) - sch_findings_before
            if sch_new:
                print(f"    Scheme [{sch_idx+1}/{len(schemes)}] {label} -> {sch_new} findings")

        total_run = self.stats["phases"][phase_name]["run"]
        total_findings = self.stats["phases"][phase_name]["findings"]
        print(f"    [DONE] {total_run} executions, {total_findings} findings")

    def _execute_one(self, script_path, context, phase_name, idx, total,
                     extra="", silent=False):
        """Execute a single script and track results."""
        script_name = os.path.basename(script_path)

        if not silent:
            label = f" ({extra})" if extra else ""
            print(f"    [{idx+1}/{total}] {script_name}{label}", end="", flush=True)

        findings_before = len(self.all_findings)
        result, findings = self.runtime.execute_script_full(
            script_path, context, callback=self._on_script_event if not silent else self._on_script_event_quiet
        )

        self.stats["scripts_run"] += 1
        self.stats["phases"][phase_name]["run"] += 1

        new_findings = len(self.all_findings) - findings_before
        self.stats["phases"][phase_name]["findings"] += new_findings

        if not silent:
            if result.get("success"):
                status = f" [{new_findings} findings]" if new_findings else ""
                print(f" OK{status}")
            else:
                err = result.get("error", "unknown")
                if "not found" in err.lower() or "include" in err.lower():
                    print(f" SKIP ({err[:60]})")
                else:
                    print(f" ERR ({err[:60]})")

        return result, new_findings

    def _on_script_event_quiet(self, event_type, data):
        """Event handler for silent mode -- still collect findings."""
        if event_type == "finding":
            self.all_findings.append(data)
            sev = data.get("severity", "info").upper()
            name = data.get("name", "Unknown")
            print(f"\n    [!] [{sev}] {name}")
        elif event_type == "error":
            self.stats["errors"] += 1

    # ---- Summary & Output ----

    def _print_summary(self):
        print(f"\n{'=' * 60}")
        print("SCAN SUMMARY")
        print(f"{'=' * 60}")
        print(f"Scripts run: {self.stats['scripts_run']}")
        print(f"Errors: {self.stats['errors']}")
        print(f"Total findings: {len(self.all_findings)}")

        if self.all_findings:
            by_severity = {}
            for f in self.all_findings:
                sev = f.get("severity", "info").lower()
                by_severity[sev] = by_severity.get(sev, 0) + 1

            for sev in ["critical", "high", "medium", "low", "info"]:
                count = by_severity.get(sev, 0)
                if count:
                    print(f"  {sev.upper()}: {count}")

        print(f"\nPhase breakdown:")
        for phase, stats in self.stats["phases"].items():
            print(f"  {phase}: {stats['run']}/{stats['total']} scripts, {stats['findings']} findings")

        print(f"{'=' * 60}\n")

    def save_results(self, output_file):
        with open(output_file, "w") as f:
            json.dump({
                "findings": self.all_findings,
                "stats": self.stats,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }, f, indent=2)
        print(f"[SAVED] Results -> {output_file}")


def _get_service_name(port):
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 111: "rpc",
        135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
        445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
        1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
        5432: "postgres", 5900: "vnc", 6379: "redis",
        8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
        8888: "http-alt2", 9200: "elasticsearch", 9300: "es-transport",
        27017: "mongodb",
    }
    return services.get(port, "unknown")


def _check_sensitive(path, body, status):
    if status == 403:
        return None

    p = path.lower()

    if ".git/HEAD" in path and "ref:" in body:
        return "git_exposed"
    if ".git/config" in path and "[core]" in body:
        return "git_exposed"
    if p == ".env" and ("=" in body and ("DB_" in body or "API_" in body or "SECRET" in body)):
        return "env_file"
    if ".svn/entries" in path and body.strip().startswith(("8", "9", "10", "12")):
        return "svn_exposed"
    if p.endswith((".bak", ".old", ".orig", ".save", ".swp", ".tmp")):
        return "backup_file"
    if p.endswith((".sql",)) and ("CREATE TABLE" in body or "INSERT INTO" in body):
        return "database_dump"
    if "phpinfo" in p and "PHP Version" in body:
        return "phpinfo"
    if p in ("web.config",) and "<configuration" in body:
        return "config_file"
    if "actuator" in p and status == 200:
        return "spring_actuator"
    if "swagger" in p and status == 200:
        return "api_docs"
    if p == "crossdomain.xml" and '<allow-access-from domain="*"' in body:
        return "permissive_crossdomain"
    if ".aws/credentials" in p and "aws_access_key" in body.lower():
        return "credentials"
    if "docker-compose" in p and "services:" in body:
        return "docker_config"
    if p in ("package.json", "composer.json", "gemfile") and status == 200:
        return "dependency_file"
    if "debug.log" in p and status == 200 and len(body) > 100:
        return "debug_log"

    return None
