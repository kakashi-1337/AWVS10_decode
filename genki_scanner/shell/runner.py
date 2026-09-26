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
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import signal
import socket
import urllib3
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .tech_detect import detect_technologies, WAF_SIGNATURES, detect_from_storage, detect_from_cookies_list
from .site_tree import SiteTree, Scheme, SiteFile
from . import colors as C
from .wappalyzer import detect as wap_detect, categorize as wap_categorize

try:
    from .smuggler import run_smuggler_scan
    HAS_SMUGGLER = True
except ImportError:
    HAS_SMUGGLER = False

try:
    from .profundis import ProfundisClient
    HAS_PROFUNDIS = True
except ImportError:
    HAS_PROFUNDIS = False

try:
    from .iast import TaintTracker, run_iast_scan
    HAS_IAST = True
except ImportError:
    HAS_IAST = False

try:
    from .js_recon import JSRecon, run_js_recon
    HAS_JS_RECON = True
except ImportError:
    HAS_JS_RECON = False


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

# Maps script name prefixes (lowered) to required tech keywords.
# --- Smart Script Filtering ---
# Two-layer system:
# 1. TECH_FILTER: prefix-based. If script name starts with a key,
#    it only runs when ANY keyword from the value list appears in the
#    detected tech set.
# 2. SCRIPT_TECH_MAP: exact-name mapping for scripts that don't follow
#    prefix conventions. Same logic: only run when a keyword matches.
# Scripts matching neither map always run (generic checks).
TECH_FILTER = {
    # CMS
    "wordpress": ["wordpress", "wp-"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "magento": ["magento"],
    "typo3": ["typo3"],
    "umbraco": ["umbraco"],
    "dotnetnuke": ["dotnetnuke", "dnn"],
    "mediawiki": ["mediawiki"],
    "vbulletin": ["vbulletin"],
    "movabletype": ["movable type", "movabletype"],
    "pmwiki": ["pmwiki"],
    "moinmoin": ["moinmoin"],
    "ektroncms": ["ektron"],
    "xcart": ["x-cart", "xcart"],
    "gallery": ["gallery2", "gallery3"],
    "plone": ["plone", "zope"],
    "liferay": ["liferay"],
    "sharepoint": ["sharepoint"],
    "mantisbt": ["mantis"],
    "nagios": ["nagios"],
    "openx": ["openx", "revive"],
    "ipb": ["invision", "ipb", "ips community"],
    "roundcube": ["roundcube"],
    "horde": ["horde"],
    "kayakofusion": ["kayako"],
    "zabbix": ["zabbix"],
    "symphony": ["symphony cms"],
    # PHP frameworks / tools
    "laravel": ["laravel"],
    "symfony": ["symfony"],
    "codeigniter": ["codeigniter"],
    "cakephp": ["cakephp"],
    "zend": ["zend"],
    "phpmyadmin": ["phpmyadmin", "php"],
    "phpliteadmin": ["phpliteadmin", "php"],
    "phpthumb": ["phpthumb", "php"],
    "timthumb": ["timthumb", "php"],
    "php_cgi": ["php"],
    "phpfpm": ["php"],
    "php_hash": ["php"],
    "phpmoadmin": ["php", "mongodb"],
    "nginx_php": ["php"],
    # Java / J2EE
    "j2ee": ["java", "tomcat", "jboss", "weblogic", "glassfish", "wildfly", "jetty"],
    "jboss": ["jboss", "wildfly", "java"],
    "struts2": ["struts", "java"],
    "spring": ["spring", "java"],
    "primefaces": ["primefaces", "jsf", "java"],
    "oracle_jsf": ["jsf", "java"],
    "jsp_auth": ["java", "tomcat", "jsp"],
    "jaas": ["java"],
    "gwt": ["gwt", "java"],
    "tomcat": ["tomcat", "java"],
    "glassfish": ["glassfish", "java"],
    "jetty": ["jetty", "java"],
    "weblogic": ["weblogic", "java"],
    "jenkins": ["jenkins", "java"],
    "jira": ["jira", "atlassian", "java"],
    "java_": ["java", "tomcat", "jboss", "weblogic", "glassfish", "wildfly", "jetty"],
    "jmx_": ["java"],
    # .NET / IIS
    "asp_net": ["asp.net", "iis", ".net"],
    "aspnet": ["asp.net", "iis", ".net"],
    "iis": ["iis", "asp.net", ".net"],
    "elmah": ["asp.net", ".net"],
    "ms15-034": ["iis"],
    "ms12-050": ["sharepoint"],
    "ajaxcontroltoolkit": ["asp.net", ".net"],
    # Node.js
    "nodejs": ["node.js", "express", "next.js", "nuxt", "koa", "fastify", "hapi"],
    # Ruby
    "rails": ["rails", "ruby"],
    "webrick": ["webrick", "ruby"],
    "rubyonrails": ["rails", "ruby"],
    # Python
    "django": ["django", "python"],
    "flask": ["flask", "python"],
    "pyramid": ["pyramid", "python"],
    "tornado": ["tornado", "python"],
    "python_": ["python", "django", "flask", "tornado", "pyramid"],
    # Go
    "golang": ["go", "gin", "echo", "fiber"],
    # ColdFusion / CFML
    "coldfusion": ["coldfusion", "adobe coldfusion", "lucee"],
    "railo": ["railo", "lucee"],
    # IBM / Oracle
    "lotus": ["lotus", "domino"],
    "ibm_wcm": ["ibm", "websphere"],
    "ibm_websphere": ["ibm", "websphere"],
    "oracle_": ["oracle", "java"],
    # Infrastructure
    "hadoop": ["hadoop"],
    "elasticsearch": ["elasticsearch"],
    "mongodb": ["mongodb"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "lighttpd": ["lighttpd"],
    "frontpage": ["frontpage"],
    "parallels": ["plesk"],
    "plesk": ["plesk"],
    "citrix": ["citrix"],
    "vmware": ["vmware"],
    "barracuda": ["barracuda"],
    "log4shell": ["java", "log4j"],
    "spring4shell": ["spring", "java"],
}

# Exact script name -> required tech keywords (lowercase, without .script)
SCRIPT_TECH_MAP = {
    "ajp_audit": ["java", "tomcat", "jboss"],
    "snoop_servlet": ["java", "tomcat", "jboss", "weblogic", "glassfish"],
    "webinfwebxml_audit": ["java", "tomcat", "jboss", "weblogic"],
    "ioncube_loader_wizard": ["php"],
    "unprotected_phpmyadmin_interface": ["php", "phpmyadmin"],
    "phpmoadmin_remote_code_execution": ["php", "mongodb"],
    "movable_type_4_rce": ["movable type", "movabletype", "perl"],
    "fantastico_filelist": ["php", "cpanel"],
    "arbitrary_file_existence_disclosure_in_action_pack": ["rails", "ruby"],
    "clientaccesspolicy_xml": [".net", "silverlight", "asp.net"],
}

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
            encoding="utf-8",
            errors="replace",
        )

        boot = self._read_message()
        if boot and boot.get("type") == "boot":
            if self.verbose:
                print(f"  {C.ok('[SHELL]')} Node.js {C.bold(boot['data'].get('node', '?'))} runtime started")
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
            elif msg["type"] == "http_log":
                if callback:
                    callback("http_log", msg["data"])
            elif msg["type"] == "catchall_filtered":
                if callback:
                    callback("catchall_filtered", msg["data"])
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
                print(f"  {C.BYLW}[FINDING]{C.RST} [{C.sev(sev.upper())}] {name}")
        elif msg["type"] == "error":
            print(f"  {C.err('[ERROR]')} {msg['data'].get('message', '?')}")
        elif msg["type"] == "trace" and self.verbose:
            print(f"  {C.dim('[TRACE]')} {msg['data'].get('message', '')}")


SOFT_404_KEYWORDS = [
    "not found", "page not found", "404", "doesn't exist", "does not exist",
    "no longer available", "we couldn't find", "we could not find",
    "nothing here", "page you requested", "this page isn't available",
    "requested url was not found", "the page you are looking for",
    "oops", "sorry", "error page", "page introuvable",
]


class Soft404Detector:
    """Detects custom error pages that return HTTP 200 instead of 404."""

    def __init__(self, target_url, headers=None, delay=1.0):
        self._target = target_url.rstrip('/')
        self._headers = headers or {}
        self._delay = delay
        self._fingerprints = []
        self._calibrated = False

    def calibrate(self):
        import requests
        probes = [
            f"/genki_404_probe_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}/",
            f"/this-page-definitely-does-not-exist-{int(time.time())}.html",
            f"/genki_nonexistent_{os.urandom(4).hex()}.aspx",
        ]
        for probe_path in probes:
            try:
                resp = requests.get(
                    self._target + probe_path,
                    timeout=8, verify=False, allow_redirects=True,
                    headers=self._headers,
                )
                if resp.status_code == 200:
                    body = resp.content.decode('utf-8', errors='replace')
                    self._fingerprints.append({
                        'length': len(body),
                        'hash': hashlib.sha256(self._normalize_body(body).encode()).hexdigest(),
                        'title': self._extract_title(body),
                    })
                time.sleep(self._delay * 0.3)
            except Exception:
                pass
        self._calibrated = True

    def is_soft_404(self, status, body, url=''):
        if status != 200:
            return False

        body_lower = body.lower()
        title = self._extract_title(body)
        title_lower = title.lower()

        keyword_hits = sum(1 for kw in SOFT_404_KEYWORDS if kw in body_lower)
        title_match = any(kw in title_lower for kw in ["not found", "404", "error", "oops"])
        body_hash = hashlib.sha256(self._normalize_body(body).encode()).hexdigest()

        fp_match = False
        if self._fingerprints:
            for fp in self._fingerprints:
                if body_hash == fp['hash']:
                    fp_match = True
                    break
                if fp['length'] > 100 and abs(len(body) - fp['length']) < max(50, fp['length'] * 0.05):
                    fp_match = True
                    break

        if fp_match and keyword_hits >= 1:
            return True
        if keyword_hits >= 3:
            return True
        if title_match and keyword_hits >= 1:
            return True
        if fp_match and title_match:
            return True

        return False

    @staticmethod
    def _normalize_body(body):
        body = re.sub(r'<script[^>]*>.*?</script>', '', body, flags=re.S | re.I)
        body = re.sub(r'<style[^>]*>.*?</style>', '', body, flags=re.S | re.I)
        body = re.sub(r'<!--.*?-->', '', body, flags=re.S)
        body = re.sub(r'\s+', ' ', body).strip()
        return body

    @staticmethod
    def _extract_title(html):
        m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
        return m.group(1).strip() if m else ''


class ShellOrchestrator:
    """Full pipeline orchestrator matching AWVS10's execution model."""

    def __init__(self, scripts_dir, config=None):
        self.scripts_dir = os.path.abspath(scripts_dir)
        self.config = config or {}
        self.runtime = NodeRuntime(verbose=self.config.get("verbose", False))
        self.all_findings = []
        self._finding_keys = set()
        self.stats = {"scripts_run": 0, "errors": 0, "phases": {}}
        self.site_trees = {}
        self.soft404 = None
        self.oob_domain = self.config.get("oob_domain", OOB_DOMAIN)
        self._detected_techs = set()
        self._detected_tech_tokens = set()
        self._scan_dir = None
        self._http_log_fh = None
        self._vuln_http_log_fh = None
        self._dir_enum_progress = {"done": 0, "total": 0, "found": 0, "status": "idle"}
        self._last_server_info = {}
        self._catchall_sig = None

    def _init_scan_dir(self, target_url):
        parsed = urlparse(target_url)
        safe_host = re.sub(r'[^\w.-]', '_', parsed.hostname or 'unknown')
        ts = time.strftime("%Y%m%d_%H%M%S")
        scan_name = f"{safe_host}_{ts}"
        self._scan_dir = os.path.join(os.getcwd(), "scans", scan_name)
        os.makedirs(self._scan_dir, exist_ok=True)
        self._http_log_fh = open(os.path.join(self._scan_dir, "http_raw.jsonl"), "w")
        self._vuln_http_log_fh = open(os.path.join(self._scan_dir, "vuln_http_raw.jsonl"), "w")
        return self._scan_dir

    def _close_logs(self):
        if self._http_log_fh:
            self._http_log_fh.close()
            self._http_log_fh = None
        if self._vuln_http_log_fh:
            self._vuln_http_log_fh.close()
            self._vuln_http_log_fh = None

    def _log_http(self, data):
        if self._http_log_fh:
            self._http_log_fh.write(json.dumps(data) + "\n")
            self._http_log_fh.flush()

    def _log_vuln_http(self, finding_data):
        if self._vuln_http_log_fh and finding_data.get("httpInfo"):
            entry = {
                "finding": finding_data.get("name", ""),
                "severity": finding_data.get("severity", ""),
                "affects": finding_data.get("affects", ""),
                "parameter": finding_data.get("parameter", ""),
                "parameterValue": finding_data.get("parameterValue", ""),
                "timestamp": finding_data.get("timestamp", ""),
                "http": finding_data["httpInfo"],
            }
            self._vuln_http_log_fh.write(json.dumps(entry) + "\n")
            self._vuln_http_log_fh.flush()

    def _build_tech_set(self, server_info):
        """Build a lowercase set of all detected technologies for filtering.
        Merges basic detection + Wappalyzer results into a unified keyword set.
        """
        techs = set()
        for key in ("technologies", "cms", "frameworks", "js_frameworks", "waf", "cdn"):
            for t in server_info.get(key, []):
                techs.add(t.lower())
        for key in ("banner", "poweredby"):
            val = server_info.get(key, "")
            if val:
                techs.add(val.lower())

        for det in server_info.get("wappalyzer", []):
            techs.add(det["name"].lower())
            for cat in det.get("categories", []):
                cat_lower = cat.lower()
                if "java" in cat_lower and "javascript" not in cat_lower:
                    techs.add("java")
                if cat == "Programming languages":
                    techs.add(det["name"].lower())

        _LANG_ALIASES = {
            "node.js": "node.js", "express": "node.js",
            "next.js": "node.js", "nuxt.js": "node.js",
            "koa": "node.js", "fastify": "node.js",
            "php": "php", "laravel": "php", "symfony": "php",
            "codeigniter": "php", "cakephp": "php", "wordpress": "php",
            "drupal": "php", "joomla": "php", "magento": "php",
            "ruby on rails": "ruby", "ruby": "ruby",
            "django": "python", "flask": "python", "tornado": "python",
            "pyramid": "python", "python": "python",
            "java": "java", "apache tomcat": "java", "apache struts": "java",
            "spring": "java", "jboss": "java", "wildfly": "java",
            "glassfish": "java", "weblogic": "java", "jetty": "java",
            "jsp": "java", "jsf": "java",
            "asp.net": ".net", "iis": ".net",
            "coldfusion": "coldfusion", "adobe coldfusion": "coldfusion",
            "lucee": "coldfusion",
        }
        expanded = set()
        for t in techs:
            lang = _LANG_ALIASES.get(t)
            if lang:
                expanded.add(lang)
        techs.update(expanded)

        self._detected_techs = techs
        tokens = set()
        for t in techs:
            tokens.add(t)
            for part in re.split(r'[\s/,;]+', t):
                if len(part) > 1:
                    tokens.add(part)
        self._detected_tech_tokens = tokens
        return techs

    def _tech_keywords_match(self, keywords):
        """Check if ANY keyword from a filter rule matches the detected stack.
        Uses exact token match against _detected_tech_tokens to avoid
        substring false positives (e.g. 'gin' matching 'nginx').
        """
        return bool(self._detected_tech_tokens & set(keywords))

    def _script_matches_tech(self, script_name):
        """Check if a script is relevant to detected tech stack."""
        name_lower = script_name.lower().replace(".script", "")

        if name_lower in SCRIPT_TECH_MAP:
            return self._tech_keywords_match(SCRIPT_TECH_MAP[name_lower])

        for prefix, keywords in TECH_FILTER.items():
            if name_lower.startswith(prefix):
                return self._tech_keywords_match(keywords)

        return True

    def _list_scripts(self, phase_dir, filter_tech=False):
        full_path = os.path.join(self.scripts_dir, phase_dir)
        if not os.path.isdir(full_path):
            return []
        scripts = []
        skipped = 0
        for f in sorted(os.listdir(full_path)):
            if f.endswith(".script"):
                if filter_tech and self._detected_techs and not self._script_matches_tech(f):
                    skipped += 1
                    continue
                scripts.append(os.path.join(full_path, f))
        if skipped and self.config.get("verbose"):
            print(f"    {C.dim(f'[FILTER] Skipped {skipped} scripts (not applicable to detected stack)')}")
        return scripts, skipped

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
            debug = self.config.get("debug", False)
            if debug:
                print(f"  {C.dim('[DEBUG] GET ' + target_url)}")
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
            if debug:
                srv = resp_headers.get("Server", "?")
                ct = resp_headers.get("Content-Type", "?")[:60]
                print(f"  {C.dim(f'[DEBUG] <- {resp.status_code} | {len(resp.content)}B | Server: {srv} | CT: {ct}')}")
                for hk, hv in resp_headers.items():
                    print(f"  {C.dim('[DEBUG]   ' + hk + ': ' + hv[:120])}")

            body_text = resp.content.decode('utf-8', errors='replace')
            tech_result = detect_technologies(resp_headers, body_text, cookies_str)

            info["banner"] = resp_headers.get("Server", "")
            info["poweredby"] = resp_headers.get("X-Powered-By", "")

            if not info["banner"] and tech_result.get("technologies"):
                for tech in tech_result["technologies"]:
                    tl = tech.lower()
                    if "nginx" in tl:
                        info["banner"] = "Nginx"
                        break
                    elif "apache" in tl and "tomcat" not in tl:
                        info["banner"] = "Apache"
                        break
                    elif "iis" in tl:
                        info["banner"] = "IIS"
                        break
                    elif "litespeed" in tl:
                        info["banner"] = "LiteSpeed"
                        break
                    elif "caddy" in tl:
                        info["banner"] = "Caddy"
                        break
            info["technologies"] = tech_result["technologies"]
            info["waf"] = tech_result["waf"]
            info["platform_os"] = tech_result["os"]
            info["cms"] = tech_result.get("cms", [])
            info["frameworks"] = tech_result.get("frameworks", [])
            info["js_frameworks"] = tech_result.get("js_frameworks", [])
            info["cdn"] = tech_result.get("cdn", [])
            info["response_headers"] = resp_headers
            info["status_code"] = resp.status_code
            info["_body"] = body_text

            wap_results = wap_detect(resp_headers, body_text, cookies_str, target_url)
            wap_groups = wap_categorize(wap_results)
            info["wappalyzer"] = wap_results
            info["wappalyzer_groups"] = wap_groups

            for det in wap_results:
                name = det["name"]
                if name not in info["technologies"]:
                    info["technologies"].append(name)
                for cat in det["categories"]:
                    if cat in ("Web frameworks",) and name not in info["frameworks"]:
                        info["frameworks"].append(name)
                    elif cat in ("JavaScript frameworks", "JavaScript libraries") and name not in info["js_frameworks"]:
                        info["js_frameworks"].append(name)
                    elif cat in ("CMS", "Ecommerce", "Blogs") and name not in info["cms"]:
                        info["cms"].append(name)
                    elif cat in ("CDN", "PaaS", "Hosting") and name not in info["cdn"]:
                        info["cdn"].append(name)
                    elif cat == "Programming languages":
                        if name.lower() not in [t.lower() for t in info["technologies"]]:
                            info["technologies"].append(name)
                    elif cat == "Security" and name not in info["waf"]:
                        info["waf"].append(name)

        except Exception as e:
            print(f"  {C.warn('[WARN]')} Server probe failed: {e}")

        return info

    def _detect_catchall_early(self, target_url):
        """Detect SPA/catch-all by probing random nonexistent paths before scripts run."""
        import requests
        import uuid
        headers = self.config.get("headers", {})
        base = target_url.rstrip("/")
        probes = [
            f"/{uuid.uuid4().hex[:12]}",
            f"/{uuid.uuid4().hex[:8]}.txt",
            f"/{uuid.uuid4().hex[:10]}/",
            f"/_{uuid.uuid4().hex[:6]}.php",
            f"/{uuid.uuid4().hex[:8]}.json",
            f"/{uuid.uuid4().hex[:7]}.xml",
        ]
        responses = []
        delay = self.config.get("delay", 1.0) * 0.3
        for path in probes:
            try:
                resp = requests.get(
                    f"{base}{path}", timeout=8, verify=False,
                    allow_redirects=False, headers=headers,
                )
                responses.append((path, f"{base}{path}", resp))
                time.sleep(delay)
            except Exception:
                pass
        if not responses:
            return None
        return _detect_catchall(responses)

    def _port_scan(self, hostname, ports=None):
        ports = ports or COMMON_PORTS
        open_ports = []
        print(f"\n  {C.info('[PORTS]')} Scanning {len(ports)} common ports on {C.bold(hostname)}")

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    service = _get_service_name(port)
                    open_ports.append({"port": port, "service": service})
                    print(f"    {C.BGRN}[OPEN]{C.RST} {C.bold(str(port))}/{service}")
                sock.close()
            except Exception:
                pass

        if not open_ports:
            print(f"    {C.dim('[INFO] No additional open ports found')}")
        else:
            print(f"    {C.ok(f'[DONE]')} {C.bold(str(len(open_ports)))} open ports")

        return open_ports

    def _dir_enum(self, target_url, server_info, background=False):
        wordlist = _build_stack_wordlist(server_info, self._detected_techs)
        total = len(wordlist)
        label = "[DIRS:BG]" if background else "[DIRS]"
        print(f"\n  {C.info(label)} Checking {total} paths (stack-tuned)")

        import requests
        base = target_url.rstrip("/")
        delay = self.config.get("delay", 1.0)
        headers = self.config.get("headers", {})
        verbose = self.config.get("verbose", False)
        debug = self.config.get("debug", False)

        raw_responses = []
        blocked_paths = []
        self._dir_enum_progress = {"done": 0, "total": total, "found": 0, "status": "fuzzing"}

        for i, path in enumerate(wordlist):
            try:
                url = f"{base}/{path}"
                resp = requests.get(
                    url, timeout=8, verify=False,
                    allow_redirects=False, headers=headers,
                )
                if debug:
                    ct = resp.headers.get("Content-Type", "?")[:40]
                    print(f"    {C.dim(f'[DEBUG] {resp.status_code} {len(resp.content):>6}B {ct:40s} {path}')}")
                raw_responses.append((path, url, resp))
                if resp.status_code in (403, 404):
                    blocked_paths.append((path, url, resp))
                time.sleep(delay * 0.3)
            except Exception:
                pass

            self._dir_enum_progress["done"] = i + 1
            interval = 25 if total < 200 else 100 if total < 1000 else 250 if total < 5000 else 500
            if not debug and (i + 1) % interval == 0:
                pct = int((i + 1) / total * 100)
                hits = self._dir_enum_progress["found"]
                bar_len = 20
                filled = int(bar_len * pct / 100)
                bar = f"{'#' * filled}{'-' * (bar_len - filled)}"
                print(f"    {C.dim(f'{label} [{bar}] {pct}% ({i+1}/{total}) | {hits} found')}")

        self._dir_enum_progress["status"] = "bypass"
        if blocked_paths:
            sens_count = sum(1 for p, _, _ in blocked_paths if _resolve_validator(p[0] if isinstance(p, tuple) else p))
            if sens_count:
                print(f"    {C.dim(f'{label} Bypass probes on {len(blocked_paths)} blocked paths...')}")
            bypass_hits = self._url_rewrite_bypass(blocked_paths, base, headers, delay, verbose)
            raw_responses.extend(bypass_hits)

        self._dir_enum_progress["status"] = "validating"
        catchall_sig = _detect_catchall(raw_responses)
        if catchall_sig:
            ctype = catchall_sig.get("type", "unknown")
            csize = catchall_sig.get("size", 0)
            print(f"    {C.warn('[CATCHALL]')} Detected catch-all response: {ctype} ({csize}B) - filtering false positives")

        found = []
        git_head_ok = False
        git_config_ok = False
        for path, url, resp in raw_responses:
            status = resp.status_code
            if status not in (200, 301, 302, 403):
                continue
            size = len(resp.content)
            body_text = resp.content.decode('utf-8', errors='replace')

            if self.soft404 and status == 200 and self.soft404.is_soft_404(status, body_text, url):
                if verbose:
                    print(f"    {C.dim(f'[SOFT404] {path}')}")
                continue

            if catchall_sig and status == 200 and _matches_catchall(resp, catchall_sig):
                if verbose:
                    print(f"    {C.dim(f'[CATCHALL] {path} ({size}B)')}")
                continue

            result = _validate_finding(path, body_text, status, resp.headers)
            if not result:
                if verbose and size > 0:
                    print(f"    {C.dim(f'[UNVERIFIED] {path} ({status}, {size}B) - no content match')}")
                continue

            finding_type = result["type"]
            evidence = result.get("evidence", "")
            sev = result.get("severity", "medium")
            bypass_method = getattr(resp, '_bypass_method', None)
            entry = {
                "path": path,
                "status": status,
                "size": size,
                "content_type": resp.headers.get("Content-Type", ""),
                "finding_type": finding_type,
                "evidence": evidence[:200],
            }
            if bypass_method:
                entry["bypass"] = bypass_method
                evidence = f"[BYPASS: {bypass_method}] {evidence}"

            self._add_finding({
                "name": f"Sensitive path: {path}" + (f" (via {bypass_method})" if bypass_method else ""),
                "severity": sev,
                "affects": url,
                "details": f"Status {status}, Size {size}B, Type: {finding_type}" + (f", Bypass: {bypass_method}" if bypass_method else ""),
                "evidence": evidence[:500],
                "phase": "DirEnum",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            self._dir_enum_progress["found"] += 1
            bypass_tag = f" {C.BYLW}[BYPASS:{bypass_method}]{C.RST}" if bypass_method else ""
            print(f"    {C.sev_color(sev.upper())}[!] [{sev.upper()}]{C.RST} {path} ({status}, {size}B) - {finding_type}{bypass_tag}")
            if evidence and verbose:
                print(f"      {C.dim('Evidence: ' + evidence[:120])}")
            found.append(entry)

            if finding_type == "git_exposed":
                if ".git/HEAD" in path:
                    git_head_ok = True
                elif ".git/config" in path:
                    git_config_ok = True

        self._dir_enum_progress["status"] = "done"
        print(f"    {C.ok(f'{label} DONE')} {C.bold(str(len(found)))} verified paths found")

        if git_head_ok and git_config_ok:
            self._git_dump(base, headers, delay)

        return found

    def _url_rewrite_bypass(self, blocked_paths, base, headers, delay, verbose):
        import requests
        hits = []
        sensitive_blocked = []
        for path, url, resp in blocked_paths:
            validator = _resolve_validator(path)
            if validator or any(path.lower().startswith(p) for p in (
                ".git", ".env", ".svn", ".htpasswd", "web.config",
                "wp-config", "server-status", "server-info",
                "actuator", "swagger", "WEB-INF", "META-INF",
            )):
                sensitive_blocked.append((path, url, resp))

        if not sensitive_blocked:
            return hits

        print(f"    {C.info('[BYPASS]')} Testing {len(sensitive_blocked)} blocked paths with URL rewrite headers")

        for path, orig_url, orig_resp in sensitive_blocked:
            bypassed = False
            for technique in _URL_REWRITE_TECHNIQUES:
                if bypassed:
                    break
                try:
                    bypass_headers = dict(headers)
                    method = technique["name"]
                    ttype = technique["type"]
                    if ttype == "header_rewrite":
                        bypass_headers[technique["header"]] = f"/{path}"
                        probe_url = f"{base}/"
                    elif ttype == "header_ip":
                        bypass_headers[technique["header"]] = technique["value"]
                        probe_url = f"{base}/{path}"
                    elif ttype == "path_suffix":
                        probe_url = f"{base}/{path}{technique['suffix']}"
                    elif ttype == "double_encode":
                        encoded = path.replace("/", "%252f")
                        probe_url = f"{base}/{encoded}"
                    else:
                        continue

                    resp = requests.get(
                        probe_url, timeout=8, verify=False,
                        allow_redirects=False, headers=bypass_headers,
                    )
                    time.sleep(delay * 0.3)

                    if resp.status_code == 200 and len(resp.content) > 0:
                        if orig_resp.status_code != 200 or len(resp.content) != len(orig_resp.content):
                            resp._bypass_method = method
                            hits.append((path, orig_url, resp))
                            bypassed = True
                            if verbose:
                                print(f"      {C.BYLW}[HIT]{C.RST} {path} bypassed via {method} ({resp.status_code}, {len(resp.content)}B)")
                except Exception:
                    pass

        if hits:
            print(f"    {C.warn('[BYPASS]')} {C.bold(str(len(hits)))} paths bypassed WAF/proxy restrictions")
        else:
            if verbose:
                print(f"    {C.dim('[BYPASS] No bypasses found')}")

        return hits

    def _git_dump(self, base_url, headers, delay):
        """Auto-download exposed .git repository when confirmed."""
        import requests
        git_dir = os.path.join(self._scan_dir or ".", "git_dump")
        os.makedirs(git_dir, exist_ok=True)
        print(f"\n  {C.warn('[GIT-DUMP]')} Downloading exposed .git repository...")

        git_files = [
            "HEAD", "config", "packed-refs", "index",
            "refs/heads/master", "refs/heads/main", "refs/heads/develop",
            "refs/remotes/origin/HEAD",
            "description", "info/exclude", "info/refs",
            "logs/HEAD", "logs/refs/heads/master", "logs/refs/heads/main",
            "COMMIT_EDITMSG", "FETCH_HEAD", "ORIG_HEAD",
        ]
        downloaded = []
        refs_to_fetch = []

        for gf in git_files:
            try:
                url = f"{base_url}/.git/{gf}"
                resp = requests.get(url, timeout=8, verify=False,
                                    allow_redirects=False, headers=headers)
                if resp.status_code != 200 or len(resp.content) == 0:
                    continue
                body = resp.content.decode('utf-8', errors='replace')

                if gf == "HEAD" and "ref:" not in body:
                    continue
                if gf == "config" and "[core]" not in body:
                    continue

                out_path = os.path.join(git_dir, gf.replace("/", os.sep))
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(resp.content)
                downloaded.append(gf)

                if gf == "HEAD" and body.startswith("ref:"):
                    ref_path = body.strip().split("ref: ", 1)[1].strip()
                    refs_to_fetch.append(ref_path)
                if gf == "packed-refs":
                    for line in body.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            if len(parts) == 2:
                                refs_to_fetch.append(parts[1])

                time.sleep(delay * 0.3)
            except Exception:
                pass

        for ref in refs_to_fetch:
            if ref in [f"refs/{x}" for x in ["heads/master", "heads/main", "heads/develop", "remotes/origin/HEAD"]]:
                continue
            try:
                url = f"{base_url}/.git/{ref}"
                resp = requests.get(url, timeout=8, verify=False,
                                    allow_redirects=False, headers=headers)
                if resp.status_code == 200 and len(resp.content) > 0:
                    out_path = os.path.join(git_dir, ref.replace("/", os.sep))
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, "wb") as f:
                        f.write(resp.content)
                    downloaded.append(ref)
                time.sleep(delay * 0.3)
            except Exception:
                pass

        object_hashes = set()
        for gf in downloaded:
            fpath = os.path.join(git_dir, gf.replace("/", os.sep))
            try:
                with open(fpath, "r") as f:
                    content = f.read()
                for match in re.finditer(r'\b([0-9a-f]{40})\b', content):
                    object_hashes.add(match.group(1))
            except Exception:
                pass

        obj_count = 0
        for obj_hash in list(object_hashes)[:50]:
            try:
                prefix, suffix = obj_hash[:2], obj_hash[2:]
                url = f"{base_url}/.git/objects/{prefix}/{suffix}"
                resp = requests.get(url, timeout=8, verify=False,
                                    allow_redirects=False, headers=headers)
                if resp.status_code == 200 and len(resp.content) > 0:
                    out_path = os.path.join(git_dir, "objects", prefix, suffix)
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, "wb") as f:
                        f.write(resp.content)
                    obj_count += 1
                time.sleep(delay * 0.3)
            except Exception:
                pass

        total = len(downloaded) + obj_count
        if total > 0:
            self._add_finding({
                "name": "Git Repository Downloaded",
                "severity": "critical",
                "affects": f"{base_url}/.git/",
                "details": f"Downloaded {len(downloaded)} git files + {obj_count} objects to {git_dir}",
                "phase": "DirEnum",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            print(f"    {C.BRED}[CRITICAL]{C.RST} Downloaded {len(downloaded)} files + {obj_count} objects -> {git_dir}")
        else:
            print(f"    {C.dim('[GIT-DUMP] No files retrieved (403 or directory listing disabled)')}")

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
            print(f"  {C.info('[TREE]')} Browser crawl: {C.bold(str(len(tree.all_files)))} files, "
                  f"{C.bold(str(len(tree.all_schemes)))} schemes, {C.bold(str(len(tree.all_directories)))} dirs")
            return tree

        tree = SiteTree(target_url)
        tree.add_url(target_url)
        tree._cookies = ""

        print(f"\n  {C.info('[TREE]')} Building site tree from HTTP responses")

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
                body = resp.content.decode('utf-8', errors='replace')
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
                print(f"  {C.info('[TREE]')} Scanning {min(len(js_urls), 15)} JS files for API endpoints")

            delay = self.config.get("delay", 1.0)
            for js_url in js_urls[:15]:
                try:
                    js_resp = req_lib.get(js_url, timeout=10, verify=False, headers=headers)
                    js_body = js_resp.content.decode('utf-8', errors='replace')
                    if js_resp.status_code == 200 and len(js_body) > 50:
                        js_api_eps = self._extract_api_from_js(js_body, target_url)
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

            print(f"  {C.info('[TREE]')} {C.bold(str(len(tree.all_files)))} files, "
                  f"{C.bold(str(len(tree.all_schemes)))} schemes, "
                  f"{C.bold(str(len(tree.all_directories)))} dirs")
            if all_api_eps:
                print(f"  {C.info('[TREE]')} {C.bold(str(len(all_api_eps)))} API endpoints from JS analysis")

        except Exception as e:
            print(f"  {C.warn('[WARN]')} Site tree extraction failed: {e}")

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
        if self._catchall_sig:
            ctx["catchallSignature"] = self._catchall_sig
        if "siteTree" in extra and extra["siteTree"] and hasattr(extra["siteTree"], 'to_js_object'):
            extra["siteTree"] = extra["siteTree"].to_js_object()
        ctx.update(extra)
        return ctx

    @staticmethod
    def _finding_key(data):
        name = data.get("name", "")
        affects = data.get("affects", "")
        return f"{name}|{affects}"

    def _add_finding(self, data):
        key = self._finding_key(data)
        if key in self._finding_keys:
            return False
        self._finding_keys.add(key)
        self.all_findings.append(data)
        return True

    @staticmethod
    def _severity_label(sev):
        if isinstance(sev, int):
            return ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"][min(sev, 4)]
        return str(sev).upper()

    def _is_catchall_finding(self, data):
        """Check if a script finding is a SPA catch-all false positive."""
        if not self._catchall_sig:
            return False
        http_info = data.get("httpInfo")
        if not http_info:
            return False
        status = http_info.get("status", 0)
        body = http_info.get("responseBody", "")
        if status != 200 or not body:
            return False
        sig = self._catchall_sig
        body_bytes = body.encode("utf-8", errors="replace")
        if sig["type"] == "hash":
            return hashlib.sha256(body_bytes).hexdigest() == sig["hash"]
        if sig["type"] == "size":
            return abs(len(body_bytes) - sig["size"]) <= sig.get("tolerance", 50)
        return False

    def _on_script_event(self, event_type, data):
        debug = self.config.get("debug", False)
        if event_type == "finding":
            if self._is_catchall_finding(data):
                name = data.get("name", "?")
                if debug or self.config.get("verbose"):
                    print(f"    {C.dim(f'[CATCHALL] Suppressed false positive: {name}')}")
                return
            if not self._add_finding(data):
                return
            sev = self._severity_label(data.get("severity", 0))
            name = data.get("name", "Unknown")
            print(f"    {C.sev_color(sev)}[!] [{sev}]{C.RST} {name}")
            details = data.get("details", "")
            if details:
                print(f"        {C.dim(details[:120])}")
            self._log_vuln_http(data)
        elif event_type == "http_log":
            self._log_http(data)
            if debug:
                method = data.get("method", "GET")
                url = data.get("url", "?")
                status = data.get("status", "?")
                size = data.get("responseSize", data.get("response_size", "?"))
                dur = data.get("duration", data.get("elapsed", "?"))
                print(f"      {C.dim(f'[HTTP] {method} {url[:100]} -> {status} ({size}B, {dur}ms)')}")
        elif event_type == "error":
            print(f"    {C.err('[ERR]')} {data.get('message', '?')}")
            if debug:
                stack = data.get("stack", "")
                if stack:
                    for line in stack.split("\n")[:5]:
                        print(f"      {C.dim(line)}")
            self.stats["errors"] += 1
        elif event_type == "catchall_filtered":
            name = data.get("name", "?")
            if debug or self.config.get("verbose"):
                print(f"    {C.dim(f'[CATCHALL] Suppressed: {name}')}")
        elif event_type == "progress":
            pass

    # ---- Main Pipeline ----

    def run(self, targets, phases=None, modules=None):
        first_target = targets[0] if targets else "unknown"
        if not first_target.startswith(("http://", "https://")):
            first_target = "https://" + first_target
        scan_dir = self._init_scan_dir(first_target)

        print(f"\n{C.RED}{'=' * 60}{C.RST}")
        print(f"{C.BOLD}GENKI SHELL v1.1{C.RST} - AWVS10 Script Runtime")
        print(f"{C.MAG}Genki Tech Labs{C.RST} / {C.RED}Anbu Black Ops{C.RST}")
        print(f"{C.RED}{'=' * 60}{C.RST}")
        print(f"Targets: {C.bold(str(len(targets)))}")
        print(f"Scripts: {C.dim(self.scripts_dir)}")
        print(f"OOB Domain: {C.CYN}{self.oob_domain}{C.RST}")
        print(f"Output: {C.CYN}{scan_dir}{C.RST}")
        print(f"{C.RED}{'=' * 60}{C.RST}\n")

        self.runtime.start()
        self.runtime.init(self.scripts_dir, self.config)

        try:
            for target in targets:
                if not target.startswith(("http://", "https://")):
                    target = "https://" + target
                self._scan_target(target, phases, modules)
        finally:
            self.runtime.stop()
            self._close_logs()

        self._print_summary()
        self._auto_save()
        return self.all_findings

    def _scan_target(self, target_url, phases=None, modules=None):
        print(f"\n{C.BOLD}[TARGET]{C.RST} {C.CYN}{target_url}{C.RST}")
        print(f"{C.DIM}{'-' * 50}{C.RST}")

        # Phase 0: Technology Detection (Wappalyzer + custom signatures)
        print(f"\n  {C.BMAG}[PHASE 0]{C.RST} Technology Detection {C.DIM}(Wappalyzer 7600+ fingerprints){C.RST}")
        server_info = self._detect_server(target_url)
        self._last_server_info = server_info
        banner = server_info.get("banner", "")
        resp_hdrs = server_info.get("response_headers", {})
        raw_server = resp_hdrs.get("Server", "") if resp_hdrs else ""
        if banner and not raw_server:
            print(f"  Server: {C.bold(banner)} {C.DIM}(inferred from headers){C.RST}")
        else:
            print(f"  Server: {C.bold(banner or 'Unknown')}")
        os_val = server_info.get("platform_os", "Unknown")
        if os_val != "Unknown" and not raw_server:
            print(f"  OS: {C.bold(os_val)} {C.DIM}(inferred){C.RST}")
        else:
            print(f"  OS: {C.bold(os_val)}")
        if server_info.get("poweredby"):
            print(f"  Powered: {C.YLW}{server_info['poweredby']}{C.RST}")

        wap_results = server_info.get("wappalyzer", [])
        if wap_results:
            wap_groups = server_info.get("wappalyzer_groups", {})
            for group, techs in wap_groups.items():
                labels = []
                for t in techs:
                    label = t["name"]
                    if t["version"]:
                        label += f" {t['version']}"
                    labels.append(label)
                group_colors = {
                    "server": C.BOLD, "framework": C.BLU,
                    "cms": C.MAG, "language": C.CYN,
                    "js_framework": C.YLW, "cdn_proxy": C.DIM,
                    "security": C.RED, "analytics": C.DIM,
                }
                color = group_colors.get(group, C.CYN)
                print(f"  {group.replace('_', ' ').title()}: {color}{', '.join(labels)}{C.RST}")
            print(f"  {C.DIM}[WAP] {len(wap_results)} technologies identified{C.RST}")
        else:
            if server_info.get("technologies"):
                print(f"  Tech: {C.CYN}{', '.join(server_info['technologies'])}{C.RST}")
            if server_info.get("frameworks"):
                print(f"  Frameworks: {C.BLU}{', '.join(server_info['frameworks'])}{C.RST}")
            if server_info.get("js_frameworks"):
                print(f"  JS: {C.YLW}{', '.join(server_info['js_frameworks'])}{C.RST}")

        if server_info.get("waf"):
            print(f"  WAF: {C.RED}{', '.join(server_info['waf'])}{C.RST}")
        if server_info.get("cms"):
            print(f"  CMS: {C.MAG}{', '.join(server_info['cms'])}{C.RST}")

        # Phase 0.1: WAF Origin IP Discovery (via Profundis)
        profundis_key = self.config.get("profundis_api_key") or os.environ.get("PROFUNDIS_API_KEY")
        if server_info.get("waf") and HAS_PROFUNDIS and profundis_key:
            print(f"\n  {C.BMAG}[PROFUNDIS]{C.RST} Searching origin IPs behind WAF...")
            try:
                prof = ProfundisClient(api_key=profundis_key)
                origin_ips = prof.find_origin_ips(parsed.hostname)
                if origin_ips:
                    server_info["origin_ips"] = origin_ips
                    print(f"  {C.ok('[PROFUNDIS]')} Found {C.bold(str(len(origin_ips)))} candidate origin IPs:")
                    for ip in origin_ips[:5]:
                        print(f"    {C.CYN}{ip}{C.RST}")
                    if len(origin_ips) > 5:
                        print(f"    {C.dim(f'... and {len(origin_ips) - 5} more')}")
                else:
                    print(f"  {C.dim('[PROFUNDIS] No origin IPs discovered')}")
            except Exception as e:
                print(f"  {C.warn('[PROFUNDIS]')} Error: {e}")
        elif server_info.get("waf") and not HAS_PROFUNDIS:
            pass
        elif server_info.get("waf") and not profundis_key:
            print(f"  {C.dim('[PROFUNDIS] Set PROFUNDIS_API_KEY to discover origin IPs behind WAF')}")

        # Build tech filter set from detected stack
        tech_set = self._build_tech_set(server_info)
        if tech_set:
            display = sorted(t for t in tech_set if '/' not in t and len(t) > 2)[:12]
            print(f"  {C.dim('[FILTER] Stack: ')}{C.CYN}{', '.join(display)}{C.RST}")

        # Phase 0.3: Soft 404 Calibration
        print(f"\n  {C.info('[SOFT404]')} Calibrating custom error page detection")
        self.soft404 = Soft404Detector(
            target_url,
            headers=self.config.get("headers", {}),
            delay=self.config.get("delay", 1.0),
        )
        self.soft404.calibrate()
        if self.soft404._fingerprints:
            print(f"  {C.info('[SOFT404]')} {C.bold(str(len(self.soft404._fingerprints)))} fingerprints captured")
        else:
            print(f"  {C.info('[SOFT404]')} No custom 404 pages detected {C.dim('(server returns real 404s)')}")

        # Phase 0.4: SPA / Catch-all Detection
        self._catchall_sig = self._detect_catchall_early(target_url)
        if self._catchall_sig:
            csize = self._catchall_sig.get("size", 0)
            print(f"  {C.warn('[CATCHALL]')} SPA/catch-all detected ({csize}B) - script findings will be validated")
        else:
            print(f"  {C.dim('[CATCHALL] No catch-all behavior detected')}")

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

        # Phase 1.1: IAST Taint Tracking + DOM Invader (if browser enabled)
        if self.config.get("browser") and self.config.get("iast", True) and HAS_IAST:
            self._run_iast(target_url, server_info)

        # Phase 1.2: JS Recon - harvest, deobfuscate, analyze (offline after download)
        if HAS_JS_RECON and (not phases or "jsrecon" in (phases or [])):
            self._run_js_recon(target_url, server_info)

        # Phase 1.5: Directory Enumeration (background if full scan, foreground if dirs-only)
        import threading
        dir_thread = None
        dirs_only = phases and phases == ["dirs"]
        self._dir_enum_progress = {"done": 0, "total": 0, "found": 0, "status": "idle"}

        if not phases or "dirs" in (phases or []):
            if dirs_only:
                dir_results = self._dir_enum(target_url, server_info)
                server_info["directories"] = dir_results
            else:
                def _bg_dir_enum():
                    try:
                        results = self._dir_enum(target_url, server_info, background=True)
                        server_info["directories"] = results
                    except Exception as e:
                        print(f"    {C.warn('[DIRS:BG]')} Error: {e}")
                        server_info["directories"] = []

                dir_thread = threading.Thread(target=_bg_dir_enum, daemon=True)
                dir_thread.start()
                print(f"  {C.dim('[DIRS:BG] Running in background while scan continues...')}")

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

        if dir_thread and dir_thread.is_alive():
            prog = self._dir_enum_progress
            pct = int(prog["done"] / max(prog["total"], 1) * 100)
            print(f"\n  {C.info('[DIRS:BG]')} Waiting for fuzzing to finish ({pct}% done)...")
            dir_thread.join()
        elif dir_thread:
            print(f"\n  {C.ok('[DIRS:BG]')} Fuzzing completed during scan")

        # Phase 3: HTTP Smuggling / Desync Probes
        if HAS_SMUGGLER and (not phases or "smuggler" in (phases or [])):
            self._run_smuggler(target_url, server_info)

    def _run_smuggler(self, target_url, server_info):
        print(f"\n  {C.BMAG}[PHASE 3]{C.RST} HTTP Smuggling / Desync Probes {C.DIM}(CL.TE, TE.CL, TE.TE, CRLF, CL.0){C.RST}")
        try:
            results = run_smuggler_scan(target_url, verbose=self.config.get("verbose", False))

            confirmed = []
            possible = []

            scanners = results.get("scanners", {})
            for category, findings in scanners.items():
                for f in findings:
                    is_confirmed = getattr(f, "confirmed", False) if hasattr(f, "confirmed") else f.get("confirmed", False)
                    technique = getattr(f, "technique", "") if hasattr(f, "technique") else f.get("technique", "")
                    endpoint = getattr(f, "endpoint", target_url) if hasattr(f, "endpoint") else f.get("endpoint", target_url)
                    detail = getattr(f, "detail", "") if hasattr(f, "detail") else f.get("detail", "")
                    snippet = getattr(f, "response_snippet", "") if hasattr(f, "response_snippet") else f.get("response_snippet", "")
                    confidence = getattr(f, "confidence", "low") if hasattr(f, "confidence") else f.get("confidence", "low")

                    if is_confirmed:
                        confirmed.append(f)
                        self._add_finding({
                            "name": f"HTTP Desync: {technique}",
                            "severity": "High",
                            "type": "HTTP Request Smuggling",
                            "affects": endpoint,
                            "description": detail,
                            "evidence": snippet[:500],
                            "confidence": confidence,
                            "phase": "Smuggler",
                        })
                    elif confidence in ("high", "medium"):
                        possible.append(f)

            if confirmed:
                print(f"  {C.BRED}[CONFIRMED]{C.RST} {C.bold(str(len(confirmed)))} desync vulnerabilities found!")
                for c in confirmed:
                    t = getattr(c, "technique", "") if hasattr(c, "technique") else c.get("technique", "")
                    e = getattr(c, "endpoint", "") if hasattr(c, "endpoint") else c.get("endpoint", "")
                    d = getattr(c, "detail", "") if hasattr(c, "detail") else c.get("detail", "")
                    print(f"    {C.RED}{t}{C.RST} on {e}")
                    if d:
                        print(f"      {C.dim(d[:120])}")
            elif possible:
                print(f"  {C.YLW}[POSSIBLE]{C.RST} {len(possible)} potential desync indicators")
                for p in possible[:3]:
                    t = getattr(p, "technique", "") if hasattr(p, "technique") else p.get("technique", "")
                    conf = getattr(p, "confidence", "") if hasattr(p, "confidence") else p.get("confidence", "")
                    print(f"    {C.YLW}{t}{C.RST} (confidence: {conf})")
            else:
                print(f"  {C.dim('[SMUGGLER] No desync detected')}")

        except Exception as e:
            print(f"  {C.warn('[SMUGGLER]')} Error: {e}")

    def _run_iast(self, target_url, server_info):
        print(f"\n  {C.BMAG}[PHASE 1.1]{C.RST} IAST Taint Tracking + DOM Invader + OOB Callbacks")
        try:
            results = run_iast_scan(
                target_url,
                verbose=self.config.get("verbose", False),
                oob_domain=self.oob_domain,
            )

            iast_findings = results.get("findings", [])
            reflections = results.get("reflections", [])
            oob_data = results.get("oob", {})

            if reflections:
                print(f"  {C.ok('[IAST]')} {C.bold(str(len(reflections)))} taint reflections detected")
                for r in reflections[:5]:
                    sink = r.get("sink", "?")
                    source = r.get("source", "?")
                    ctx = r.get("context", "?")
                    print(f"    {C.YLW}{source}{C.RST} -> {C.RED}{sink}{C.RST} ({ctx})")

            oob_findings = oob_data.get("oob_findings", [])
            if oob_findings:
                print(f"  {C.BRED}[OOB]{C.RST} {C.bold(str(len(oob_findings)))} blind callback detections via {self.oob_domain}")
                for of in oob_findings[:5]:
                    print(f"    {C.RED}OOB{C.RST} {of.get('sink', '?')} -> {of.get('evidence', '')[:80]}")

            oob_planted = oob_data.get("oob_canaries_planted", 0)
            if oob_planted:
                print(f"  {C.info('[OOB]')} {oob_planted} OOB canaries planted (check {self.oob_domain} dashboard)")

            for f in iast_findings:
                sev = f.get("severity", "Medium")
                name = f.get("title", "DOM Taint Flow")
                if f.get("oob"):
                    name = f"OOB Callback: {f.get('sink', 'blind')}"
                self._add_finding({
                    "name": name,
                    "severity": sev,
                    "type": f.get("type", "Client-Side"),
                    "affects": f.get("url", target_url),
                    "description": f.get("description", ""),
                    "evidence": f.get("evidence", "")[:500],
                    "phase": "IAST",
                })

            if iast_findings:
                print(f"  {C.BRED}[IAST]{C.RST} {C.bold(str(len(iast_findings)))} confirmed client-side findings")
            elif not reflections:
                print(f"  {C.dim('[IAST] No taint flows detected')}")

        except ImportError:
            print(f"  {C.warn('[IAST]')} Playwright not available (pip install playwright)")
        except Exception as e:
            print(f"  {C.warn('[IAST]')} Error: {e}")

    def _run_js_recon(self, target_url, server_info):
        print(f"\n  {C.BMAG}[PHASE 1.2]{C.RST} JS Recon {C.DIM}(harvest -> deobfuscate -> analyze){C.RST}")
        try:
            site_tree = self.site_trees.get(target_url)
            html = server_info.get("_body", "")

            recon = JSRecon(target_url, config=self.config, verbose=self.config.get("verbose", False))

            # Harvest from page source + crawl results
            if html:
                recon.harvest_from_html(html)
            if site_tree:
                recon.harvest_from_site_tree(site_tree)

            js_count = len(recon.js_urls)
            if not js_count:
                print(f"  {C.dim('[JS RECON] No JavaScript files discovered')}")
                return

            print(f"  [JS RECON] Discovered {C.bold(str(js_count))} JS files")

            # Download all
            downloaded = recon.download_all()
            print(f"  [JS RECON] Downloaded {C.bold(str(downloaded))}/{js_count}")

            # Deobfuscate offline
            deob_count = recon.deobfuscate_all()
            actual_deob = sum(
                1 for u in recon.deobfuscated
                if recon.deobfuscated[u] != recon.sources.get(u, "")
            )
            if actual_deob:
                print(f"  {C.ok('[JSHADOW]')} Deobfuscated {C.bold(str(actual_deob))} files")

            # Analyze for endpoints/secrets
            recon.analyze_all()
            summary = recon.get_summary()

            endpoints = summary.get("api_endpoints", [])
            secrets = summary.get("secrets", [])

            if endpoints:
                print(f"  {C.ok('[JS RECON]')} {C.bold(str(len(endpoints)))} API endpoints extracted")
                for ep in endpoints[:8]:
                    print(f"    {C.CYN}{ep}{C.RST}")
                if len(endpoints) > 8:
                    print(f"    {C.dim(f'... and {len(endpoints) - 8} more')}")

                # Feed discovered endpoints back into site tree
                if site_tree:
                    for ep_url in endpoints:
                        site_tree.add_url(ep_url)
                    server_info["js_api_endpoints"] = endpoints

            if secrets:
                print(f"  {C.BRED}[JS RECON]{C.RST} {C.bold(str(len(secrets)))} potential secrets/keys found!")
                for s in secrets[:5]:
                    key = s.get("key", "")[:60]
                    src = s.get("source_file", "").split("/")[-1]
                    print(f"    {C.RED}{key}{C.RST} in {C.dim(src)}")
                for s in secrets:
                    self._add_finding({
                        "name": "Hardcoded Secret in JavaScript",
                        "severity": "High",
                        "type": "Information Disclosure",
                        "affects": s.get("source_file", target_url),
                        "description": f"Potential secret found: {s.get('key', '')[:80]}",
                        "evidence": s.get("value", "")[:100],
                        "phase": "JS Recon",
                    })

            routes = summary.get("routes", [])
            if routes:
                print(f"  [JS RECON] {C.bold(str(len(routes)))} client-side routes mapped")

            crypto = summary.get("crypto_usage", [])
            if crypto:
                print(f"  [JS RECON] {C.bold(str(len(crypto)))} crypto API calls detected")
                for c in crypto[:3]:
                    print(f"    {C.YLW}{c.get('lib', '')}{C.RST}")

            server_info["js_recon"] = summary

        except Exception as e:
            print(f"  {C.warn('[JS RECON]')} Error: {e}")

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
                print(f"  {C.ok('[CRAWL]')} {C.bold(str(len(tree.all_files)))} pages, "
                      f"{C.bold(str(len(tree.all_schemes)))} schemes, {C.bold(str(len(tree.all_directories)))} dirs")

                extra_tech = []
                if hasattr(tree, '_storage') and tree._storage:
                    storage_techs = detect_from_storage(tree._storage)
                    extra_tech.extend(storage_techs)
                if hasattr(tree, '_browser_cookies') and tree._browser_cookies:
                    cookie_techs = detect_from_cookies_list(tree._browser_cookies)
                    extra_tech.extend(cookie_techs)
                if extra_tech:
                    unique = list(dict.fromkeys(extra_tech))
                    si = self._last_server_info
                    for t in unique:
                        if t not in si.get("technologies", []):
                            si["technologies"].append(t)
                    self._build_tech_set(si)
                    print(f"  {C.info('[BROWSER]')} +{len(unique)} techs from cookies/storage: {C.CYN}{', '.join(unique)}{C.RST}")
        except ImportError:
            print(f"  {C.warn('[WARN]')} Browser module not available (pip install playwright)")
        except Exception as e:
            print(f"  {C.warn('[WARN]')} Browser crawl failed: {e}")

    # ---- Phase Execution (per-item iteration) ----

    def _run_phase(self, phase_name, phase_type, target_url, server_info, site_tree=None):
        do_filter = phase_type in ("webapps", "postcrawl", "server")
        scripts, skipped = self._list_scripts(phase_name, filter_tech=do_filter)
        if not scripts:
            if skipped:
                print(f"\n  {C.dim(f'[{phase_name.upper()}] All {skipped} scripts skipped (not applicable to stack)')}")
            return

        self.stats["phases"][phase_name] = {"total": len(scripts), "run": 0, "findings": 0, "skipped": skipped}

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
        print(f"\n  {C.BMAG}[{phase_name.upper()}]{C.RST} {C.bold(str(len(scripts)))} scripts")
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

        print(f"\n  {C.BMAG}[{phase_name.upper()}]{C.RST} {C.bold(str(len(scripts)))} scripts ({C.bold(str(len(discovered)))} discovered files)")
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
        print(f"\n  {C.BMAG}[{phase_name.upper()}]{C.RST} {C.bold(str(len(scripts)))} scripts x {C.bold(str(len(directories)))} directories")

        for dir_idx, dir_path in enumerate(directories):
            dir_name = dir_path.rstrip('/').split('/')[-1] or '/'
            if self.config.get("verbose"):
                print(f"    {C.dim(f'Dir [{dir_idx+1}/{len(directories)}]')} {dir_path}")

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
                print(f"    Dir [{dir_idx+1}/{len(directories)}] {dir_path} -> {C.BYLW}{dir_new} findings{C.RST}")

        total_run = self.stats["phases"][phase_name]["run"]
        total_findings = self.stats["phases"][phase_name]["findings"]
        print(f"    {C.ok('[DONE]')} {total_run} executions, {total_findings} findings")

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

        print(f"\n  {C.BMAG}[{phase_name.upper()}]{C.RST} {C.bold(str(len(scripts)))} scripts x {C.bold(str(len(files)))} files")

        for file_idx, file_ctx in enumerate(files):
            if self.config.get("verbose"):
                print(f"    {C.dim(f'File [{file_idx+1}/{len(files)}]')} {file_ctx['path']}")

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
                print(f"    File [{file_idx+1}/{len(files)}] {file_ctx['path']} -> {C.BYLW}{file_new} findings{C.RST}")

        total_run = self.stats["phases"][phase_name]["run"]
        total_findings = self.stats["phases"][phase_name]["findings"]
        print(f"    {C.ok('[DONE]')} {total_run} executions, {total_findings} findings")

    def _run_phase_per_scheme(self, phase_name, scripts, target_url, server_info, site_tree):
        """Run each script per discovered input scheme (the real fuzzing)."""
        schemes = site_tree.all_schemes if site_tree else []
        if not schemes:
            print(f"\n  {C.BMAG}[{phase_name.upper()}]{C.RST} {C.bold(str(len(scripts)))} scripts x {C.dim('0 schemes (no inputs discovered)')}")
            return

        print(f"\n  {C.BMAG}[{phase_name.upper()}]{C.RST} {C.bold(str(len(scripts)))} scripts x {C.bold(str(len(schemes)))} schemes")

        for sch_idx, scheme in enumerate(schemes):
            label = f"{scheme.method} {scheme.path} ({len(scheme.inputs)} inputs)"
            if self.config.get("verbose"):
                print(f"    {C.DIM}Scheme [{sch_idx+1}/{len(schemes)}] {label}{C.RST}")

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
                print(f"    Scheme [{sch_idx+1}/{len(schemes)}] {label} -> {C.BYLW}{sch_new} findings{C.RST}")

        total_run = self.stats["phases"][phase_name]["run"]
        total_findings = self.stats["phases"][phase_name]["findings"]
        print(f"    {C.ok('[DONE]')} {total_run} executions, {total_findings} findings")

    def _execute_one(self, script_path, context, phase_name, idx, total,
                     extra="", silent=False):
        """Execute a single script and track results."""
        script_name = os.path.basename(script_path)

        if not silent:
            label = f" ({extra})" if extra else ""
            print(f"    {C.DIM}[{idx+1}/{total}]{C.RST} {script_name}{label}", end="", flush=True)

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
                status = f" [{C.BYLW}{new_findings} findings{C.RST}]" if new_findings else ""
                print(f" {C.BGRN}OK{C.RST}{status}")
            else:
                err = result.get("error", "unknown")
                if "not found" in err.lower() or "include" in err.lower():
                    print(f" {C.YLW}SKIP{C.RST} {C.DIM}({err[:60]}){C.RST}")
                else:
                    print(f" {C.BRED}ERR{C.RST} {C.RED}({err[:60]}){C.RST}")

        return result, new_findings

    def _on_script_event_quiet(self, event_type, data):
        """Event handler for silent mode -- still collect findings."""
        if event_type == "finding":
            if self._is_catchall_finding(data):
                return
            if not self._add_finding(data):
                return
            sev = self._severity_label(data.get("severity", 0))
            name = data.get("name", "Unknown")
            print(f"\n    {C.BYLW}[!]{C.RST} [{C.sev(sev)}] {name}")
            self._log_vuln_http(data)
        elif event_type == "http_log":
            self._log_http(data)
        elif event_type == "error":
            self.stats["errors"] += 1

    # ---- Summary & Output ----

    def _print_summary(self):
        print(f"\n{C.RED}{'=' * 60}{C.RST}")
        print(f"{C.BOLD}SCAN SUMMARY{C.RST}")
        print(f"{C.RED}{'=' * 60}{C.RST}")
        print(f"Scripts run: {C.bold(str(self.stats['scripts_run']))}")
        errs = self.stats['errors']
        err_color = C.BGRN if errs == 0 else C.BRED
        print(f"Errors: {err_color}{errs}{C.RST}")
        print(f"Unique findings: {C.bold(str(len(self.all_findings)))}")

        if self.all_findings:
            by_severity = {}
            for f in self.all_findings:
                raw_sev = f.get("severity", "info")
                sev = self._severity_label(raw_sev).lower() if isinstance(raw_sev, int) else str(raw_sev).lower()
                by_severity[sev] = by_severity.get(sev, 0) + 1

            for sev in ["critical", "high", "medium", "low", "info"]:
                count = by_severity.get(sev, 0)
                if count:
                    print(f"  {C.sev(sev.upper())}: {C.bold(str(count))}")

        print(f"\n{C.BOLD}Phase breakdown:{C.RST}")
        for phase, stats in self.stats["phases"].items():
            skipped = stats.get('skipped', 0)
            skip_str = f", {C.DIM}{skipped} skipped{C.RST}" if skipped else ""
            print(f"  {C.MAG}{phase}{C.RST}: {stats['run']}/{stats['total']} scripts, {C.BYLW}{stats['findings']}{C.RST} findings{skip_str}")

        print(f"{C.RED}{'=' * 60}{C.RST}\n")

    def _auto_save(self):
        if not self._scan_dir:
            return
        summary_path = os.path.join(self._scan_dir, "summary.json")
        self.save_results(summary_path)

        if hasattr(self, '_last_server_info') and self._last_server_info:
            tech_path = os.path.join(self._scan_dir, "tech_stack.json")
            wap = self._last_server_info.get("wappalyzer", [])
            tech_data = {
                "banner": self._last_server_info.get("banner", ""),
                "os": self._last_server_info.get("platform_os", ""),
                "technologies": self._last_server_info.get("technologies", []),
                "frameworks": self._last_server_info.get("frameworks", []),
                "js_frameworks": self._last_server_info.get("js_frameworks", []),
                "cms": self._last_server_info.get("cms", []),
                "cdn": self._last_server_info.get("cdn", []),
                "waf": self._last_server_info.get("waf", []),
                "wappalyzer": [{"name": t["name"], "version": t["version"],
                                "confidence": t["confidence"], "categories": t["categories"]}
                               for t in wap],
            }
            with open(tech_path, "w") as f:
                json.dump(tech_data, f, indent=2)
            print(f"{C.BGRN}[SAVED]{C.RST} Tech stack -> {C.bold(tech_path)} {C.DIM}({len(wap)} wappalyzer detections){C.RST}")
        http_path = os.path.join(self._scan_dir, "http_raw.jsonl")
        vuln_path = os.path.join(self._scan_dir, "vuln_http_raw.jsonl")
        http_count = 0
        vuln_count = 0
        if os.path.exists(http_path):
            with open(http_path) as fh:
                http_count = sum(1 for _ in fh)
        if os.path.exists(vuln_path):
            with open(vuln_path) as fh:
                vuln_count = sum(1 for _ in fh)
        print(f"{C.BGRN}[SAVED]{C.RST} HTTP log -> {C.bold(http_path)} {C.DIM}({http_count} requests){C.RST}")
        print(f"{C.BGRN}[SAVED]{C.RST} Vuln HTTP -> {C.bold(vuln_path)} {C.DIM}({vuln_count} entries){C.RST}")

    def save_results(self, output_file):
        with open(output_file, "w") as f:
            json.dump({
                "findings": self.all_findings,
                "stats": self.stats,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }, f, indent=2)
        print(f"{C.BGRN}[SAVED]{C.RST} Summary -> {C.bold(output_file)}")


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


STACK_WORDLISTS = {
    "core": [
        ".git/HEAD", ".git/config", ".svn/entries", ".env", ".env.local",
        ".env.production", ".env.development", ".env.backup",
        ".htaccess", "web.config", "robots.txt", "sitemap.xml",
        "crossdomain.xml", ".well-known/security.txt",
        "admin/", "login/", "api/", "graphql",
        ".DS_Store", "backup/", "old/", "test/", "staging/", "dev/",
        ".aws/credentials", ".aws/config",
        "config.json", "config.yml", "config.yaml", "config.xml",
        "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
        "database.sql", "dump.sql", "backup.sql", "db.sql",
        ".vscode/", ".idea/", ".editorconfig",
        "debug/", "debug.log", "error.log", "access.log",
        "server-status", "server-info",
        "cgi-bin/", "scripts/", "includes/",
        "v1/", "v2/", "api/v1/", "api/v2/",
        ".well-known/openid-configuration",
        "favicon.ico", "humans.txt", "security.txt",
    ],
    "php": [
        "phpinfo.php", "info.php", "php.ini", "php-errors.log",
        "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save",
        "wp-config.php.swp", "wp-config.php~", "wp-config.txt",
        "config.php.bak", "config.php.old", "config.inc.php.bak",
        "settings.php.bak", "local.xml", "local.xml.bak",
        "adminer.php", "phpmyadmin/", "pma/", "myadmin/",
        "test.php", "shell.php", "cmd.php", "eval.php",
        ".htpasswd", ".user.ini", "php_errors.log",
    ],
    "wordpress": [
        "wp-login.php", "wp-admin/", "wp-json/wp/v2/users",
        "wp-content/debug.log", "wp-content/uploads/",
        "wp-includes/version.php", "xmlrpc.php",
        "wp-cron.php", "readme.html", "license.txt",
        "wp-content/plugins/", "wp-content/themes/",
        "wp-config.php.bak", "wp-config.php.old",
        "wp-json/", "wp-admin/install.php",
        "wp-admin/setup-config.php", "wp-admin/upgrade.php",
        "wp-content/uploads/wc-logs/",
        "wp-content/backup-db/", "wp-content/backups/",
        "wp-includes/certificates/ca-bundle.crt",
        ".wp-config.php.swp", "wp-config-sample.php",
    ],
    "drupal": [
        "CHANGELOG.txt", "core/CHANGELOG.txt",
        "sites/default/settings.php", "sites/default/default.settings.php",
        "user/login", "node/1", "admin/",
        "core/install.php", "update.php", "install.php",
        "sites/default/files/", "misc/drupal.js",
        "core/modules/system/system.info.yml",
    ],
    "joomla": [
        "administrator/", "administrator/manifests/files/joomla.xml",
        "configuration.php", "htaccess.txt",
        "language/en-GB/", "README.txt",
        "configuration.php.bak", "configuration.php.old",
        "administrator/components/", "plugins/",
    ],
    "java": [
        "actuator/health", "actuator/env", "actuator/beans",
        "actuator/configprops", "actuator/mappings", "actuator/info",
        "actuator/metrics", "actuator/loggers", "actuator/threaddump",
        "actuator/heapdump", "actuator/jolokia",
        "swagger-ui.html", "swagger-ui/", "swagger-ui/index.html",
        "api-docs", "v2/api-docs", "v3/api-docs",
        "swagger-resources/", "webjars/",
        "WEB-INF/web.xml", "WEB-INF/classes/", "META-INF/MANIFEST.MF",
        "manager/html", "jmx-console/", "web-console/",
        "status", "jolokia/", "console/",
        "solr/admin/", "solr/",
        "invoker/JMXInvokerServlet",
    ],
    ".net": [
        "web.config", "web.config.bak", "web.config.old",
        "elmah.axd", "trace.axd", "glimpse.axd",
        "applicationhost.config",
        "bin/", "App_Data/", "App_Code/",
        "global.asax", "default.aspx", "iisstart.htm",
        "appsettings.json", "appsettings.Development.json",
        "connectionstrings.config",
    ],
    "node.js": [
        "package.json", "package-lock.json", "yarn.lock",
        ".npmrc", ".yarnrc", ".nvmrc",
        "node_modules/", "npm-debug.log",
        ".env", ".env.local", ".env.development",
        "config/default.json", "config/production.json",
        "server.js", "app.js", "index.js",
        "next.config.js", "nuxt.config.js", "gatsby-config.js",
        "ecosystem.config.js", "pm2.json",
        "tsconfig.json", "nest-cli.json",
    ],
    "python": [
        "requirements.txt", "Pipfile", "Pipfile.lock", "setup.py",
        "manage.py", "wsgi.py", "settings.py",
        "config.py", "config.cfg", "instance/config.py",
        "app.py", "application.py", "main.py",
        ".flaskenv", "celeryconfig.py",
        "Procfile", "runtime.txt", "uwsgi.ini", "gunicorn.conf.py",
        "django/settings/", "alembic.ini", "alembic/",
    ],
    "ruby": [
        "Gemfile", "Gemfile.lock", "config/database.yml",
        "config/secrets.yml", "config/master.key",
        "config/credentials.yml.enc", "config/initializers/secret_token.rb",
        "db/schema.rb", "db/seeds.rb",
        "config/routes.rb", "Rakefile",
        "config/environment.rb", "config/boot.rb",
        ".ruby-version", ".ruby-gemset",
    ],
    "laravel": [
        ".env", ".env.backup", ".env.old", ".env.save",
        "storage/logs/laravel.log", "storage/framework/sessions/",
        "artisan", "composer.json", "composer.lock",
        "config/app.php", "config/database.php",
        "public/storage/", "bootstrap/cache/config.php",
        "storage/debugbar/", "telescope/",
        "horizon/", "_debugbar/open",
    ],
    "coldfusion": [
        "CFIDE/administrator/", "CFIDE/adminapi/",
        "CFIDE/scripts/", "CFIDE/componentutils/",
        "WEB-INF/web.xml", "crossdomain.xml",
    ],
}

_TECH_TO_WORDLIST = {
    "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
    "php": "php", "laravel": "laravel", "symfony": "php",
    "codeigniter": "php", "cakephp": "php", "magento": "php",
    "java": "java", "spring": "java", "apache tomcat": "java",
    "jboss": "java", "wildfly": "java", "jetty": "java",
    "jsp": "java", "jsf": "java", "glassfish": "java",
    "weblogic": "java", "apache struts": "java",
    "asp.net": ".net", "iis": ".net",
    "node.js": "node.js", "express": "node.js", "next.js": "node.js",
    "nuxt.js": "node.js", "fastify": "node.js", "koa": "node.js",
    "python": "python", "django": "python", "flask": "python",
    "tornado": "python", "pyramid": "python",
    "ruby": "ruby", "ruby on rails": "ruby",
    "coldfusion": "coldfusion", "adobe coldfusion": "coldfusion", "lucee": "coldfusion",
}


_SECLIST_STACK_FILES = {
    "core": [
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/raft-small-files.txt",
    ],
    "php": [
        "Discovery/Web-Content/Common-PHP-Filenames.txt",
    ],
    "wordpress": [
        "Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
        "Discovery/Web-Content/CMS/wp-themes.fuzz.txt",
    ],
    "drupal": [
        "Discovery/Web-Content/CMS/drupal.txt",
    ],
    "joomla": [
        "Discovery/Web-Content/CMS/joomla-plugins.txt",
        "Discovery/Web-Content/CMS/joomla-tests.txt",
    ],
    "java": [
        "Discovery/Web-Content/tomcat.txt",
        "Discovery/Web-Content/spring-boot.txt",
    ],
    ".net": [
        "Discovery/Web-Content/iis.txt",
        "Discovery/Web-Content/IIS.fuzz.txt",
    ],
    "node.js": [
        "Discovery/Web-Content/nodejs.txt",
    ],
    "ruby": [
        "Discovery/Web-Content/ror.txt",
        "Discovery/Web-Content/ruby.txt",
    ],
    "coldfusion": [
        "Discovery/Web-Content/coldfusion.txt",
    ],
    "apache": [
        "Discovery/Web-Content/apache.txt",
        "Discovery/Web-Content/Apache.fuzz.txt",
    ],
    "nginx": [
        "Discovery/Web-Content/nginx.txt",
    ],
    "cgi": [
        "Discovery/Web-Content/CGIs.txt",
    ],
}

_seclist_cache = {}

def _find_seclist_dir():
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "SecList"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "SecLists"),
        os.path.expanduser("~/SecLists"),
        os.path.expanduser("~/SecList"),
        "/opt/SecLists",
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    return None

def _load_seclist_file(seclist_dir, rel_path):
    cache_key = f"{seclist_dir}/{rel_path}"
    if cache_key in _seclist_cache:
        return _seclist_cache[cache_key]

    full = os.path.join(seclist_dir, rel_path)
    lines = []
    if os.path.isfile(full):
        try:
            with open(full, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if line.startswith("/"):
                            line = line[1:]
                        lines.append(line)
        except Exception:
            pass
    _seclist_cache[cache_key] = lines
    return lines


def _build_stack_wordlist(server_info, detected_techs):
    paths = list(STACK_WORDLISTS["core"])
    used_lists = set()

    all_techs = set()
    for key in ("technologies", "cms", "frameworks", "js_frameworks"):
        for t in server_info.get(key, []):
            all_techs.add(t.lower())
    all_techs.update(detected_techs)

    for tech in all_techs:
        wl_key = _TECH_TO_WORDLIST.get(tech)
        if wl_key and wl_key not in used_lists:
            used_lists.add(wl_key)
            paths.extend(STACK_WORDLISTS.get(wl_key, []))

    seclist_dir = _find_seclist_dir()
    if seclist_dir:
        sl_loaded = 0
        for sl_file in _SECLIST_STACK_FILES.get("core", []):
            entries = _load_seclist_file(seclist_dir, sl_file)
            paths.extend(entries)
            sl_loaded += len(entries)

        for wl_key in used_lists:
            for sl_file in _SECLIST_STACK_FILES.get(wl_key, []):
                entries = _load_seclist_file(seclist_dir, sl_file)
                paths.extend(entries)
                sl_loaded += len(entries)

        web_server = server_info.get("web_server", "").lower()
        for srv_key in ("apache", "nginx", "cgi"):
            if srv_key in web_server and srv_key not in used_lists:
                for sl_file in _SECLIST_STACK_FILES.get(srv_key, []):
                    entries = _load_seclist_file(seclist_dir, sl_file)
                    paths.extend(entries)
                    sl_loaded += len(entries)

        if sl_loaded > 0:
            print(f"    {C.dim(f'[SecList] Loaded {sl_loaded} paths from {seclist_dir}')}")

    seen = set()
    unique = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


_URL_REWRITE_TECHNIQUES = [
    # URL rewrite headers — proxy/WAF treats header as the real path
    {"name": "X-Original-URL", "type": "header_rewrite", "header": "X-Original-URL"},
    {"name": "X-Rewrite-URL", "type": "header_rewrite", "header": "X-Rewrite-URL"},
    # IP spoofing headers — bypass IP-based ACL
    {"name": "X-Forwarded-For", "type": "header_ip", "header": "X-Forwarded-For", "value": "127.0.0.1"},
    {"name": "X-Real-IP", "type": "header_ip", "header": "X-Real-IP", "value": "127.0.0.1"},
    {"name": "X-Custom-IP-Authorization", "type": "header_ip", "header": "X-Custom-IP-Authorization", "value": "127.0.0.1"},
    {"name": "X-Originating-IP", "type": "header_ip", "header": "X-Originating-IP", "value": "127.0.0.1"},
    # Path manipulation
    {"name": "path-dot-segment", "type": "path_suffix", "suffix": "/..;/"},
    {"name": "path-trailing-dot", "type": "path_suffix", "suffix": "."},
    {"name": "path-trailing-slash", "type": "path_suffix", "suffix": "/"},
    {"name": "path-semicolon", "type": "path_suffix", "suffix": ";"},
    {"name": "path-null-byte", "type": "path_suffix", "suffix": "%00"},
    {"name": "path-question", "type": "path_suffix", "suffix": "?"},
    {"name": "path-hash-bypass", "type": "path_suffix", "suffix": "%23"},
    {"name": "double-encode", "type": "double_encode"},
]


def _detect_catchall(raw_responses):
    ok_responses = [(p, u, r) for p, u, r in raw_responses if r.status_code == 200]
    if len(ok_responses) < 5:
        return None

    size_counts = {}
    hash_counts = {}
    for path, url, resp in ok_responses:
        size = len(resp.content)
        body_hash = hashlib.sha256(resp.content).hexdigest()
        size_counts[size] = size_counts.get(size, 0) + 1
        hash_counts[body_hash] = hash_counts.get(body_hash, 0) + 1

    threshold = len(ok_responses) * 0.5

    for body_hash, count in hash_counts.items():
        if count >= threshold:
            for path, url, resp in ok_responses:
                if hashlib.sha256(resp.content).hexdigest() == body_hash:
                    ct = resp.headers.get("Content-Type", "unknown")
                    return {"type": "hash", "hash": body_hash, "size": len(resp.content), "content_type": ct}

    for size, count in size_counts.items():
        if count >= threshold and size > 100:
            return {"type": "size", "size": size, "tolerance": max(50, int(size * 0.05))}

    return None


def _matches_catchall(resp, catchall_sig):
    if not catchall_sig:
        return False
    size = len(resp.content)
    if catchall_sig["type"] == "hash":
        return hashlib.sha256(resp.content).hexdigest() == catchall_sig["hash"]
    if catchall_sig["type"] == "size":
        return abs(size - catchall_sig["size"]) <= catchall_sig.get("tolerance", 50)
    return False


CONTENT_VALIDATORS = {
    ".git/HEAD": {
        "require_any": [r"^ref:\s+refs/heads/\S+\s*$", r"^[0-9a-f]{40}\s*$"],
        "reject_html": True, "max_size": 512,
        "severity": "high", "type": "git_exposed",
    },
    ".git/config": {
        "require_content": [r"\[core\]", r"(?:repositoryformatversion|filemode|bare|logallrefupdates)\s*="],
        "reject_html": True, "max_size": 10000,
        "severity": "high", "type": "git_exposed",
    },
    ".svn/entries": {
        "require_content": [r"^(8|9|10|11|12)\s*$"],
        "severity": "high", "type": "svn_exposed",
    },
    ".env": {
        "require_any": [r"(?:DB_|API_|SECRET|APP_KEY|AWS_|MAIL_|REDIS_)\w*\s*=", r"^\w+\s*=\s*\S+"],
        "reject_html": True,
        "severity": "high", "type": "env_file",
    },
    ".env.local": {"inherit": ".env"},
    ".env.production": {"inherit": ".env"},
    ".env.development": {"inherit": ".env"},
    ".env.backup": {"inherit": ".env"},
    ".htaccess": {
        "require_content": [r"(?:RewriteEngine|RewriteRule|RewriteCond|AuthType|Require|Options|DirectoryIndex|ErrorDocument)"],
        "severity": "medium", "type": "config_file",
    },
    ".htpasswd": {
        "require_content": [r"^\w+:\$?\w+\$"],
        "reject_html": True,
        "severity": "critical", "type": "credentials",
    },
    "web.config": {
        "require_content": [r"<configuration"],
        "severity": "medium", "type": "config_file",
    },
    "robots.txt": {
        "require_content": [r"(?:User-agent|Disallow|Allow|Sitemap)\s*:"],
        "severity": "info", "type": "robots_txt",
    },
    "sitemap.xml": {
        "require_content": [r"<urlset|<sitemapindex"],
        "severity": "info", "type": "sitemap",
    },
    "crossdomain.xml": {
        "require_content": [r"<cross-domain-policy"],
        "severity": "medium", "type": "crossdomain",
        "escalate": {"pattern": r'allow-access-from\s+domain="\*"', "severity": "high", "type": "permissive_crossdomain"},
    },
    "phpinfo.php": {
        "require_content": [r"PHP Version|phpinfo\(\)|PHP Credits"],
        "severity": "high", "type": "phpinfo",
    },
    "info.php": {"inherit": "phpinfo.php"},
    "package.json": {
        "require_json": True,
        "require_keys": ["name", "version", "dependencies", "devDependencies", "scripts"],
        "reject_html": True,
        "severity": "low", "type": "dependency_file",
    },
    "composer.json": {
        "require_json": True,
        "require_keys": ["name", "require", "description", "autoload"],
        "reject_html": True,
        "severity": "low", "type": "dependency_file",
    },
    "Gemfile": {
        "require_content": [r"(?:source\s+['\"]|gem\s+['\"])"],
        "reject_html": True,
        "severity": "low", "type": "dependency_file",
    },
    "Gemfile.lock": {
        "require_content": [r"(?:GEM|BUNDLED WITH|DEPENDENCIES)"],
        "reject_html": True,
        "severity": "low", "type": "dependency_file",
    },
    "requirements.txt": {
        "require_content": [r"^\w[\w.-]*\s*[=><!]"],
        "reject_html": True,
        "severity": "low", "type": "dependency_file",
    },
    "docker-compose.yml": {
        "require_content": [r"(?:services:|version:\s)"],
        "reject_html": True,
        "severity": "medium", "type": "docker_config",
    },
    "docker-compose.yaml": {"inherit": "docker-compose.yml"},
    "Dockerfile": {
        "require_content": [r"^FROM\s+\S+"],
        "reject_html": True,
        "severity": "medium", "type": "docker_config",
    },
    ".aws/credentials": {
        "require_content": [r"aws_access_key_id|aws_secret_access_key"],
        "reject_html": True,
        "severity": "critical", "type": "credentials",
    },
    ".aws/config": {
        "require_content": [r"\[(?:default|profile\s)"],
        "reject_html": True,
        "severity": "high", "type": "credentials",
    },
    "server-status": {
        "require_content": [r"Apache Server Status|Server Version:|Total Accesses:"],
        "severity": "medium", "type": "server_status",
    },
    "server-info": {
        "require_content": [r"Apache Server Information|Module Name"],
        "severity": "medium", "type": "server_info",
    },
    "elmah.axd": {
        "require_content": [r"Error Log for|ELMAH|Error\s+Log"],
        "severity": "high", "type": "error_log",
    },
    "trace.axd": {
        "require_content": [r"Application Trace|Request Details|Trace Information"],
        "severity": "high", "type": "trace_log",
    },
}

for _act in ["actuator/health", "actuator/env", "actuator/beans", "actuator/configprops",
             "actuator/mappings", "actuator/info", "actuator/metrics", "actuator/loggers",
             "actuator/threaddump", "actuator/heapdump", "actuator/jolokia"]:
    CONTENT_VALIDATORS[_act] = {
        "require_json_or": [r'"status"\s*:', r'"beans"\s*:', r'"activeProfiles"\s*:',
                            r'"systemProperties"\s*:', r'"contexts"\s*:',
                            r'"propertySources"\s*:', r'"measurements"\s*:'],
        "reject_html": True,
        "severity": "critical" if "env" in _act or "heapdump" in _act else "high",
        "type": "spring_actuator",
    }

for _sw in ["swagger-ui.html", "swagger-ui/", "swagger-ui/index.html", "api-docs",
            "v2/api-docs", "v3/api-docs", "swagger-resources/"]:
    CONTENT_VALIDATORS[_sw] = {
        "require_any": [r"swagger|openapi|\"info\"\s*:|\"paths\"\s*:|Swagger\s*UI"],
        "severity": "medium", "type": "api_docs",
    }

for _sql in ["database.sql", "dump.sql", "backup.sql", "db.sql"]:
    CONTENT_VALIDATORS[_sql] = {
        "require_content": [r"(?:CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE|ALTER\s+TABLE|--\s+MySQL|--\s+Dump)"],
        "reject_html": True,
        "severity": "critical", "type": "database_dump",
    }

for _log in ["debug.log", "error.log", "access.log", "php-errors.log", "npm-debug.log",
             "wp-content/debug.log", "storage/logs/laravel.log"]:
    CONTENT_VALIDATORS[_log] = {
        "require_content": [r"\d{4}[-/]\d{2}[-/]\d{2}|\[error\]|\[warning\]|Stack trace|Exception|Traceback"],
        "reject_html": True,
        "min_size": 100,
        "severity": "medium", "type": "debug_log",
    }

for _bak_ext in [".bak", ".old", ".orig", ".save", ".swp", ".tmp", "~"]:
    pass


_VALIDATORS_LOWER = None

def _get_validators_lower():
    global _VALIDATORS_LOWER
    if _VALIDATORS_LOWER is None:
        _VALIDATORS_LOWER = {k.lower().rstrip("/"): v for k, v in CONTENT_VALIDATORS.items()}
    return _VALIDATORS_LOWER

def _resolve_validator(path):
    vmap = _get_validators_lower()
    p_lower = path.lower().rstrip("/")

    v = vmap.get(p_lower)
    if v:
        if "inherit" in v:
            parent_key = v["inherit"].lower().rstrip("/")
            parent = vmap.get(parent_key, {})
            merged = dict(parent)
            merged.update({k: vv for k, vv in v.items() if k != "inherit"})
            return merged
        return v

    for key, v in vmap.items():
        if p_lower.endswith("/" + key) or p_lower == key:
            result = dict(v)
            if "inherit" in result:
                parent_key = result["inherit"].lower().rstrip("/")
                parent = vmap.get(parent_key, {})
                merged = dict(parent)
                merged.update({k: vv for k, vv in result.items() if k != "inherit"})
                return merged
            return result

    return None


def _validate_finding(path, body, status, headers):
    if status == 403:
        return {"type": "forbidden_interesting", "severity": "info",
                "evidence": f"403 Forbidden on {path}"}

    p_lower = path.lower()
    is_html = "<html" in body[:500].lower() or "<head" in body[:500].lower() or "<!doctype" in body[:500].lower()

    validator = _resolve_validator(path)

    if validator:
        if validator.get("reject_html") and is_html and status == 200:
            return None
        if validator.get("min_size") and len(body) < validator["min_size"]:
            return None
        if validator.get("max_size") and len(body) > validator["max_size"]:
            return None

        if validator.get("require_json"):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    req_keys = validator.get("require_keys", [])
                    if req_keys and not any(k in data for k in req_keys):
                        return None
                    found_keys = [k for k in req_keys if k in data]
                    evidence = f"JSON keys: {', '.join(found_keys[:5])}"
                    return {"type": validator["type"], "severity": validator["severity"], "evidence": evidence}
            except (json.JSONDecodeError, ValueError):
                return None

        if validator.get("require_json_or"):
            if is_html:
                return None
            matched = [p for p in validator["require_json_or"] if re.search(p, body[:2000], re.I)]
            if not matched:
                return None
            evidence_match = re.search(matched[0], body[:2000], re.I)
            evidence = body[max(0, evidence_match.start()-20):evidence_match.end()+50].strip() if evidence_match else ""
            return {"type": validator["type"], "severity": validator["severity"], "evidence": evidence}

        checks = validator.get("require_content", []) or validator.get("require_any", [])
        if checks:
            use_any = "require_any" in validator
            matches = []
            for pattern in checks:
                m = re.search(pattern, body[:5000], re.I | re.M)
                if m:
                    matches.append(m)
                    if use_any:
                        break

            if use_any and not matches:
                return None
            if not use_any and len(matches) < len(checks):
                return None

            if matches:
                m = matches[0]
                start = max(0, m.start() - 20)
                end = min(len(body), m.end() + 80)
                evidence = body[start:end].strip()
            else:
                evidence = ""

            result = {"type": validator["type"], "severity": validator["severity"], "evidence": evidence}
            esc = validator.get("escalate")
            if esc and re.search(esc["pattern"], body[:5000], re.I):
                result["severity"] = esc["severity"]
                result["type"] = esc["type"]
            return result

        return {"type": validator["type"], "severity": validator["severity"], "evidence": ""}

    if p_lower.endswith((".bak", ".old", ".orig", ".save", ".swp", ".tmp")):
        if is_html and len(body) < 1000:
            return None
        if status == 200 and len(body) > 50:
            base_name = re.sub(r'\.(bak|old|orig|save|swp|tmp)$', '', p_lower)
            evidence = f"Backup of {base_name}, {len(body)} bytes"
            return {"type": "backup_file", "severity": "high", "evidence": evidence}

    ct = headers.get("Content-Type", "").lower()
    if status in (301, 302):
        loc = headers.get("Location", "")
        if loc and not any(kw in loc.lower() for kw in ["login", "404", "error", "home", "index"]):
            return {"type": "redirect_interesting", "severity": "info",
                    "evidence": f"Redirects to {loc[:120]}"}

    return None
