"""
Information Disclosure detection module.
Ported from AWVS10: Various PerServer scripts

Checks for:
- Sensitive files and backups
- Server headers leaking version info
- Debug modes
- Stack traces
- phpinfo()
- .git/.svn/.env exposure
"""
import re
from urllib.parse import urlparse, urljoin

from .base import BaseModule
from ..core.reporter import Finding


class InfoDisclosureModule(BaseModule):
    name = "info"
    description = "Information Disclosure"

    SENSITIVE_PATHS = [
        (".env", "APP_KEY=|DB_PASSWORD=|AWS_SECRET", "Environment file"),
        (".git/HEAD", "ref: refs/", "Git repository exposed"),
        (".git/config", "[core]", "Git config exposed"),
        (".svn/entries", "dir\n", "SVN repository exposed"),
        (".DS_Store", "\x00\x00\x00\x01Bud1", "macOS DS_Store"),
        ("web.config", "<configuration>", "ASP.NET web.config"),
        ("wp-config.php.bak", "DB_NAME", "WordPress config backup"),
        ("config.php.bak", "password", "PHP config backup"),
        (".htaccess", "RewriteEngine|AuthType|Deny from", ".htaccess exposed"),
        ("crossdomain.xml", "<cross-domain-policy>", "Flash crossdomain policy"),
        ("clientaccesspolicy.xml", "<access-policy>", "Silverlight access policy"),
        ("robots.txt", "Disallow:", "robots.txt (info gathering)"),
        ("sitemap.xml", "<urlset", "Sitemap (info gathering)"),
        ("server-status", "Apache Server Status", "Apache server-status"),
        ("server-info", "Apache Server Information", "Apache server-info"),
        ("elmah.axd", "Error Log for", "ELMAH error log exposed"),
        ("trace.axd", "Application Trace", "ASP.NET trace exposed"),
        ("phpinfo.php", "phpinfo()", "phpinfo page"),
        ("info.php", "phpinfo()", "phpinfo page"),
        ("test.php", "phpinfo()", "phpinfo page"),
        ("debug/default/view", "Yii", "Yii debug mode"),
        ("_profiler", "Symfony", "Symfony profiler"),
        ("__debug__/", "Werkzeug", "Flask/Werkzeug debugger"),
        ("actuator/env", '"property"', "Spring Boot actuator"),
        ("actuator/health", '"status"', "Spring Boot actuator"),
        ("api/swagger.json", '"swagger"', "Swagger API docs"),
        ("swagger-ui.html", "swagger-ui", "Swagger UI"),
        (".well-known/security.txt", "Contact:", "security.txt"),
        ("backup.sql", "INSERT INTO|CREATE TABLE", "SQL backup file"),
        ("database.sql", "INSERT INTO|CREATE TABLE", "SQL backup file"),
        ("dump.sql", "INSERT INTO|CREATE TABLE", "SQL backup file"),
        ("admin/", "login|password|admin", "Admin panel"),
        ("wp-login.php", "wp-login", "WordPress login"),
        ("wp-json/wp/v2/users", '"slug"', "WordPress user enumeration"),
    ]

    HEADER_CHECKS = [
        ("Server", r"Apache/[\d.]+|nginx/[\d.]+|IIS/[\d.]+|PHP/[\d.]+", "Server version disclosure"),
        ("X-Powered-By", r"PHP/[\d.]+|ASP\.NET|Express|Ruby", "Technology disclosure"),
        ("X-AspNet-Version", r"[\d.]+", "ASP.NET version disclosure"),
        ("X-AspNetMvc-Version", r"[\d.]+", "ASP.NET MVC version disclosure"),
    ]

    MISSING_HEADERS = [
        ("X-Frame-Options", "Missing X-Frame-Options (clickjacking)"),
        ("X-Content-Type-Options", "Missing X-Content-Type-Options"),
        ("Content-Security-Policy", "Missing Content-Security-Policy"),
        ("Strict-Transport-Security", "Missing HSTS header"),
        ("X-XSS-Protection", "Missing X-XSS-Protection"),
    ]

    def run(self, url: str, params: dict = None):
        self.log(f"Testing: {url}")
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"

        self._check_headers(url)
        self._check_sensitive_files(base_url)

    def _check_headers(self, url):
        resp = self.http.get(url)
        if not resp:
            return

        for header, pattern, desc in self.HEADER_CHECKS:
            value = resp.headers.get(header, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                self.reporter.add(Finding(
                    vuln_type="Information Disclosure (Header)",
                    severity="LOW",
                    url=url,
                    evidence=f"{header}: {value}",
                    details=desc,
                ))

        for header, desc in self.MISSING_HEADERS:
            if header not in resp.headers:
                self.reporter.add(Finding(
                    vuln_type="Missing Security Header",
                    severity="INFO",
                    url=url,
                    evidence=f"Missing: {header}",
                    details=desc,
                ))

        body = resp.text
        error_patterns = [
            (r"Traceback \(most recent call last\)", "Python stack trace"),
            (r"at\s+[\w$.]+\([\w]+\.java:\d+\)", "Java stack trace"),
            (r"<b>Fatal error</b>:.*on line <b>\d+</b>", "PHP fatal error"),
            (r"Microsoft OLE DB Provider", "ASP database error"),
            (r"Stack Trace:</b>.*at\s+", "ASP.NET stack trace"),
        ]
        for pattern, desc in error_patterns:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                self.reporter.add(Finding(
                    vuln_type="Information Disclosure (Error)",
                    severity="LOW",
                    url=url,
                    evidence=desc,
                    details="Application error with stack trace or debug info exposed",
                ))
                break

    def _check_sensitive_files(self, base_url):
        for path, indicator, desc in self.SENSITIVE_PATHS:
            test_url = urljoin(base_url, path)
            resp = self.http.get(test_url)
            if not resp or resp.status_code != 200:
                continue

            if len(resp.text) < 5:
                continue

            indicators = indicator.split("|")
            for ind in indicators:
                if ind in resp.text:
                    severity = "LOW"
                    if any(s in path for s in [".env", ".git", "backup", "config", "phpinfo", "actuator", "debug"]):
                        severity = "HIGH" if ".env" in path or ".git" in path else "MEDIUM"

                    self.reporter.add(Finding(
                        vuln_type="Sensitive File Exposed",
                        severity=severity,
                        url=test_url,
                        evidence=f"Pattern matched: {ind}",
                        details=desc,
                    ))
                    break
