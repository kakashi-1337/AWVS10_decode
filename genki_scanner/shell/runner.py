"""
Shell Runner - Python orchestrator for AWVS10 decoded script execution.
Spawns a Node.js runtime, manages phases, feeds scripts in order.
Full pipeline: tech detect -> crawl -> dir enum -> scan all phases -> report.
"""
import json
import os
import subprocess
import sys
import time
import signal
import socket
from pathlib import Path
from urllib.parse import urlparse

from .tech_detect import detect_technologies, WAF_SIGNATURES


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

    def _build_context(self, target_url, server_info, **extra):
        ctx = {
            "scanURL": target_url,
            "scanIP": server_info.get("hostname", ""),
            "serverInfo": server_info,
            "oobDomain": self.oob_domain,
        }
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

    def run(self, targets, phases=None, modules=None):
        print(f"\n{'=' * 60}")
        print("GENKI SHELL v1.0 - AWVS10 Script Runtime")
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

        # Phase 0.5: Port Scan
        parsed = urlparse(target_url)
        if not phases or "ports" in (phases or []):
            open_ports = self._port_scan(parsed.hostname)
            server_info["open_ports"] = open_ports
        else:
            server_info["open_ports"] = []

        # Phase 1: Browser Crawl
        if self.config.get("browser"):
            self._browser_crawl(target_url)

        # Phase 1.5: Directory Enumeration
        if not phases or "dirs" in (phases or []):
            dir_results = self._dir_enum(target_url, server_info)
            server_info["directories"] = dir_results

        # Phase 2+: AWVS Script Phases
        active_phases = phases or [p[0] for p in PHASE_ORDER]

        for phase_name, phase_type in PHASE_ORDER:
            if phase_name not in active_phases:
                continue
            self._run_phase(phase_name, phase_type, target_url, server_info)

        if "Network" in active_phases or not phases:
            pass

        if "WebApps" in active_phases or not phases:
            self._run_phase("WebApps", "webapps", target_url, server_info)

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
                print(f"  [CRAWL] {len(tree.all_files)} pages, {len(tree.all_schemes)} schemes, {len(tree.all_directories)} dirs")
        except ImportError:
            print("  [WARN] Browser module not available (pip install playwright)")
        except Exception as e:
            print(f"  [WARN] Browser crawl failed: {e}")

    def _run_phase(self, phase_name, phase_type, target_url, server_info):
        scripts = self._list_scripts(phase_name)
        if not scripts:
            return

        print(f"\n  [{phase_name.upper()}] {len(scripts)} scripts")
        self.stats["phases"][phase_name] = {"total": len(scripts), "run": 0, "findings": 0}

        context = self._build_context(target_url, server_info)

        for i, script_path in enumerate(scripts):
            script_name = os.path.basename(script_path)
            print(f"    [{i+1}/{len(scripts)}] {script_name}", end="", flush=True)

            findings_before = len(self.all_findings)
            result, findings = self.runtime.execute_script_full(
                script_path, context, callback=self._on_script_event
            )

            self.stats["scripts_run"] += 1
            self.stats["phases"][phase_name]["run"] += 1

            new_findings = len(self.all_findings) - findings_before
            self.stats["phases"][phase_name]["findings"] += new_findings

            if result.get("success"):
                status = f" [{new_findings} findings]" if new_findings else ""
                print(f" OK{status}")
            else:
                err = result.get("error", "unknown")
                if "not found" in err.lower() or "include" in err.lower():
                    print(f" SKIP ({err[:60]})")
                else:
                    print(f" ERR ({err[:60]})")

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
    if p == "crossdomain.xml" and "<allow-access-from domain=\"*\"" in body:
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
