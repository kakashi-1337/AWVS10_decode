"""
Profundis.io API Client for Genki Shell
Infrastructure search for WAF origin IP discovery.
Chains DNS history + cert analysis + favicon hash + ASN pivoting.
"""
import re
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ProfundisClient:
    """Synchronous client for the Profundis.io MCP API (JSON-RPC over HTTPS)."""

    def __init__(self, api_key, base_url="https://mcp.profundis.io", timeout=30):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._request_id = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_id(self):
        self._request_id += 1
        return self._request_id

    def _call(self, tool_name, arguments):
        """Send a JSON-RPC tools/call request and return parsed content texts."""
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        try:
            resp = requests.post(
                self.base_url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=False,
            )
            resp.raise_for_status()
            return self._parse_response(resp.json())
        except requests.exceptions.Timeout:
            print(f"[profundis] timeout calling {tool_name}")
            return []
        except requests.exceptions.ConnectionError as exc:
            print(f"[profundis] connection error calling {tool_name}: {exc}")
            return []
        except requests.exceptions.HTTPError as exc:
            print(f"[profundis] HTTP {exc.response.status_code} from {tool_name}")
            return []
        except (ValueError, KeyError) as exc:
            print(f"[profundis] bad response from {tool_name}: {exc}")
            return []

    @staticmethod
    def _parse_response(data):
        """Extract text strings from the MCP content array.

        Expected shape:
            {"result": {"content": [{"type": "text", "text": "..."}, ...]}}
        Returns a list of text strings.
        """
        try:
            content = data["result"]["content"]
            return [
                item["text"]
                for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            ]
        except (KeyError, TypeError):
            # Fallback: maybe the result is a plain error or a flat string
            if "error" in data:
                msg = data["error"]
                if isinstance(msg, dict):
                    msg = msg.get("message", msg)
                print(f"[profundis] API error: {msg}")
            return []

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def search(self, query, max_results=10):
        """General infrastructure search.

        Returns list of text result strings.
        """
        return self._call("search", {
            "query": query,
            "maxResults": max_results,
        })

    def deep_research(self, topic, depth=3):
        """Perform deep research on a topic.

        Higher depth values yield more thorough but slower results.
        Returns list of text result strings.
        """
        return self._call("deep_research", {
            "topic": topic,
            "depth": depth,
        })

    def analyze_url(self, url):
        """Analyze a specific URL for infrastructure details.

        Returns list of text result strings.
        """
        return self._call("analyze_url", {
            "url": url,
        })

    def find_origin_ips(self, domain):
        """Discover origin IPs behind a WAF/CDN by chaining multiple queries.

        Strategy:
          1. DNS history      - historical A records may reveal pre-WAF IPs
          2. SSL certificates - shared certs across IPs expose origins
          3. Favicon hashes   - same favicon served from a different IP
          4. ASN / hosting    - netblock and hosting provider info

        Returns a deduplicated list of candidate origin IP strings.
        """
        domain = domain.strip().lower()
        # Strip protocol if someone passes a URL
        domain = re.sub(r"^https?://", "", domain).split("/")[0]

        candidates = set()

        # -- 1. DNS history --
        dns_results = self.search(
            f"{domain} DNS history historical A records",
            max_results=10,
        )
        candidates.update(_extract_ips(dns_results))

        # -- 2. SSL certificate associations --
        ssl_results = self.search(
            f"{domain} SSL certificate alternative names shared certs",
            max_results=10,
        )
        candidates.update(_extract_ips(ssl_results))

        # -- 3. Favicon hash matches --
        favicon_results = self.search(
            f"{domain} favicon hash mmh3",
            max_results=10,
        )
        candidates.update(_extract_ips(favicon_results))

        # -- 4. ASN / hosting info --
        asn_results = self.search(
            f"{domain} ASN hosting provider IP range",
            max_results=10,
        )
        candidates.update(_extract_ips(asn_results))

        # Filter out obviously-wrong entries (loopback, link-local, etc.)
        return sorted(_filter_public_ips(candidates))

    def enrich_target(self, domain):
        """Full target enrichment: tech stack, prior vulnerabilities, bug reports.

        Returns a dict with keys: tech_stack, vulnerabilities, bug_reports,
        raw (list of all text results).
        """
        domain = domain.strip().lower()
        domain = re.sub(r"^https?://", "", domain).split("/")[0]

        enrichment = {
            "tech_stack": [],
            "vulnerabilities": [],
            "bug_reports": [],
            "raw": [],
        }

        # Tech stack
        tech = self.search(f"{domain} technology stack framework CMS", max_results=10)
        enrichment["tech_stack"] = tech
        enrichment["raw"].extend(tech)

        # Known vulnerabilities
        vulns = self.search(
            f"{domain} CVE vulnerability exploit disclosed", max_results=10
        )
        enrichment["vulnerabilities"] = vulns
        enrichment["raw"].extend(vulns)

        # Bug bounty / prior reports
        reports = self.search(
            f"{domain} bug bounty report HackerOne Bugcrowd", max_results=10
        )
        enrichment["bug_reports"] = reports
        enrichment["raw"].extend(reports)

        return enrichment


# ----------------------------------------------------------------------
# Standalone helpers
# ----------------------------------------------------------------------

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _extract_ips(texts):
    """Pull all IPv4 addresses out of a list of text strings."""
    ips = set()
    for text in texts:
        ips.update(_IP_RE.findall(text))
    return ips


def _filter_public_ips(ips):
    """Remove loopback, link-local, private-range, and multicast addresses."""
    public = []
    for ip in ips:
        octets = ip.split(".")
        if len(octets) != 4:
            continue
        first, second = int(octets[0]), int(octets[1])
        # 127.x.x.x  - loopback
        if first == 127:
            continue
        # 10.x.x.x   - private
        if first == 10:
            continue
        # 172.16-31.x.x - private
        if first == 172 and 16 <= second <= 31:
            continue
        # 192.168.x.x - private
        if first == 192 and second == 168:
            continue
        # 169.254.x.x - link-local
        if first == 169 and second == 254:
            continue
        # 0.x.x.x / 255.x.x.x
        if first == 0 or first >= 224:
            continue
        public.append(ip)
    return public


def find_origin_ips(domain, api_key):
    """Standalone convenience function for WAF origin IP discovery.

    Usage:
        ips = find_origin_ips("example.com", api_key="prof_xxxx")
    """
    client = ProfundisClient(api_key=api_key)
    return client.find_origin_ips(domain)
