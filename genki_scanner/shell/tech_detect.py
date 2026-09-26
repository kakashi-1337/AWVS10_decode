"""
Technology Detection - Enhanced fingerprinting for modern stacks.
Replaces AWVS10's basic Server/X-Powered-By checks with comprehensive detection.
"""
import re

TECH_SIGNATURES = {
    "headers": {
        "server": {
            "Apache": ["apache", "httpd"],
            "Nginx": ["nginx"],
            "IIS": ["microsoft-iis", "iis"],
            "LiteSpeed": ["litespeed"],
            "Caddy": ["caddy"],
            "Cloudflare": ["cloudflare"],
            "Envoy": ["envoy"],
            "Traefik": ["traefik"],
            "Cowboy": ["cowboy"],
            "Gunicorn": ["gunicorn"],
            "Uvicorn": ["uvicorn"],
            "Kestrel": ["kestrel"],
            "Jetty": ["jetty"],
            "Tomcat": ["tomcat", "coyote"],
            "WildFly": ["wildfly"],
            "GlassFish": ["glassfish"],
            "WebLogic": ["weblogic"],
            "WebSphere": ["websphere"],
            "OpenResty": ["openresty"],
            "Tengine": ["tengine"],
            "Cherokee": ["cherokee"],
            "Lighttpd": ["lighttpd"],
            "Varnish": ["varnish"],
        },
        "x-powered-by": {
            "PHP": ["php"],
            "ASP.NET": ["asp.net"],
            "Express": ["express"],
            "Next.js": ["next.js"],
            "Nuxt": ["nuxt"],
            "Django": ["django", "wsgiserver"],
            "Flask": ["werkzeug"],
            "Rails": ["phusion passenger", "puma", "unicorn"],
            "Spring": ["spring"],
            "Laravel": ["laravel"],
            "WordPress": ["w3 total cache", "wp super cache"],
            "Plesk": ["plesk"],
        },
        "x-aspnet-version": {"ASP.NET": [""]},
        "x-aspnetmvc-version": {"ASP.NET MVC": [""]},
        "x-drupal-cache": {"Drupal": [""]},
        "x-generator": {
            "WordPress": ["wordpress"],
            "Drupal": ["drupal"],
            "Joomla": ["joomla"],
            "Ghost": ["ghost"],
            "Hugo": ["hugo"],
            "Jekyll": ["jekyll"],
        },
        "x-shopify-stage": {"Shopify": [""]},
        "x-wix-request-id": {"Wix": [""]},
        "x-amz-cf-id": {"AWS CloudFront": [""]},
        "x-amz-request-id": {"AWS S3": [""]},
        "x-cache": {
            "Fastly": ["fastly"],
            "CloudFront": ["cloudfront"],
            "Varnish": ["varnish"],
        },
        "x-vercel-id": {"Vercel": [""]},
        "x-netlify-request-id": {"Netlify": [""]},
        "x-firebase-hosting": {"Firebase": [""]},
        "cf-ray": {"Cloudflare": [""]},
        "fly-request-id": {"Fly.io": [""]},
        "x-render-origin-server": {"Render": [""]},
        "x-railway-request-id": {"Railway": [""]},
    },
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java/J2EE",
        "ASP.NET_SessionId": "ASP.NET",
        "ASPSESSIONID": "ASP Classic",
        "connect.sid": "Node.js",
        "csrftoken": "Django",
        "laravel_session": "Laravel",
        "_rails_session": "Rails",
        "rack.session": "Ruby/Rack",
        "wp-settings": "WordPress",
        "Drupal.visitor": "Drupal",
        "AWSALB": "AWS ALB",
        "AWSALBCORS": "AWS ALB",
        "__cfduid": "Cloudflare",
        "cf_clearance": "Cloudflare",
        "__cf_bm": "Cloudflare Bot Management",
        "_gh_sess": "GitHub",
        "grafana_session": "Grafana",
        "jenkins.session": "Jenkins",
        "XSRF-TOKEN": "Angular/Laravel",
    },
    "body_patterns": {
        "WordPress": [
            r'wp-content/', r'wp-includes/', r'wp-json/',
            r'<meta name="generator" content="WordPress',
        ],
        "Drupal": [
            r'sites/default/files', r'sites/all/',
            r'Drupal\.settings', r'drupal\.js',
        ],
        "Joomla": [
            r'/media/jui/', r'/templates/',
            r'<meta name="generator" content="Joomla',
        ],
        "React": [
            r'__NEXT_DATA__', r'_reactRootContainer', r'react-root', r'data-reactroot',
            r'static/js/main\.[a-f0-9]+\.js',
            r'<div\s+id=["\']root["\']>\s*</div>',
            r'react\.production\.min\.js', r'react-dom',
        ],
        "Angular": [
            r'ng-version', r'ng-app', r'data-ng-app', r'angular\.min\.js',
            r'<app-root[^>]*>',
            r'runtime\.[a-f0-9]+\.js', r'polyfills\.[a-f0-9]+\.js',
            r'main\.[a-f0-9]+\.js.*?polyfills\.[a-f0-9]+\.js',
        ],
        "Vue.js": [
            r'__vue__', r'v-cloak', r'data-v-[a-f0-9]', r'vue\.min\.js', r'vue\.js',
            r'chunk-vendors\.[a-f0-9]+\.js',
            r'<div\s+id=["\']app["\']>\s*</div>',
            r'/js/app\.[a-f0-9]+\.js',
            r'/css/app\.[a-f0-9]+\.css',
        ],
        "Vite": [
            r'/@vite/', r'type=["\']module["\'].*?/assets/index-[a-f0-9]+\.js',
            r'/assets/index-[a-f0-9]+\.(js|css)',
        ],
        "Svelte": [r'__svelte', r'svelte-', r'_app/immutable/'],
        "SvelteKit": [r'_app/immutable/', r'__sveltekit'],
        "jQuery": [r'jquery\.min\.js', r'jquery-\d+\.\d+'],
        "Bootstrap": [r'bootstrap\.min\.(css|js)', r'class="(container|row|col-)'],
        "Tailwind CSS": [r'tailwindcss', r'class="[^"]*\b(flex|grid|bg-|text-|p-|m-)\b'],
        "Next.js": [r'__NEXT_DATA__', r'_next/static', r'/_next/'],
        "Nuxt": [r'__NUXT__', r'_nuxt/'],
        "Gatsby": [r'gatsby-', r'___gatsby'],
        "Remix": [r'__remixContext', r'__remix'],
        "GraphQL": [r'/graphql', r'__schema', r'query\s*\{'],
        "Firebase": [r'firebaseapp\.com', r'firebase\.js'],
        "Stripe": [r'js\.stripe\.com', r'stripe-js'],
        "reCAPTCHA": [r'google\.com/recaptcha', r'grecaptcha'],
        "hCaptcha": [r'hcaptcha\.com', r'h-captcha'],
        "Cloudflare Turnstile": [r'challenges\.cloudflare\.com/turnstile'],
        "Webpack": [r'webpackJsonp', r'__webpack_require__', r'webpack\.runtime'],
    },
    "meta_generators": {
        "WordPress": "wordpress",
        "Drupal": "drupal",
        "Joomla": "joomla",
        "Ghost": "ghost",
        "Hugo": "hugo",
        "Jekyll": "jekyll",
        "Wix": "wix.com",
        "Squarespace": "squarespace",
        "Shopify": "shopify",
        "Blogger": "blogger",
        "TYPO3": "typo3",
        "Magento": "magento",
        "PrestaShop": "prestashop",
        "MediaWiki": "mediawiki",
    },
    "os_detection": {
        "Windows": {
            "headers": ["microsoft-iis", "asp.net", "aspmvc"],
            "paths": ["\\", "web.config"],
        },
        "Linux": {
            "headers": ["apache", "nginx", "ubuntu", "debian", "centos", "rhel"],
            "paths": ["/etc/passwd"],
        },
        "Unix": {
            "headers": ["freebsd", "openbsd", "solaris"],
        },
    },
}

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"server": "cloudflare", "cf-ray": ""},
        "status_codes": [403, 503],
        "body": ["cloudflare", "cf-browser-verification", "cf_chl_opt"],
    },
    "AWS WAF": {
        "headers": {"x-amzn-requestid": ""},
        "body": ["aws waf", "request blocked"],
    },
    "Akamai": {
        "headers": {"x-akamai-transformed": "", "server": "akamaighost"},
        "body": ["akamai", "reference #"],
    },
    "Imperva/Incapsula": {
        "headers": {"x-cdn": "imperva", "x-iinfo": ""},
        "body": ["incapsula", "_incapsula_"],
        "cookies": ["visid_incap_", "incap_ses_"],
    },
    "ModSecurity": {
        "headers": {"server": "modsecurity"},
        "body": ["modsecurity", "mod_security"],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": "", "server": "sucuri"},
        "body": ["sucuri", "cloudproxy"],
    },
    "F5 BIG-IP ASM": {
        "headers": {"server": "big-ip", "x-cnection": ""},
        "cookies": ["BIGipServer", "TS0"],
    },
    "Barracuda": {
        "headers": {"server": "barracuda"},
        "body": ["barracuda"],
    },
    "FortiWeb": {
        "headers": {"server": "fortiweb"},
        "cookies": ["FORTIWAFSID"],
    },
    "Wordfence": {
        "body": ["wordfence", "wfwaf-", "this request has been blocked"],
    },
    "DDoS-Guard": {
        "headers": {"server": "ddos-guard"},
    },
    "StackPath": {
        "headers": {"x-sp-url": "", "x-sp-wl": ""},
    },
    "Reblaze": {
        "headers": {"server": "reblaze"},
        "cookies": ["rbzid"],
    },
    "L7Ammune": {
        "headers": {"server": "l7ammune"},
    },
    "Wallarm": {
        "headers": {"server": "wallarm", "x-wallarm-waf-check": ""},
    },
    "Radware AppWall": {
        "headers": {"x-sl-compstate": ""},
        "cookies": ["reese84"],
    },
    "DataDome": {
        "headers": {"x-datadome": ""},
        "cookies": ["datadome"],
    },
    "PerimeterX": {
        "cookies": ["_px", "_pxhd"],
    },
}


def detect_technologies(resp_headers, resp_body, cookies_str=""):
    """
    Detect technologies from HTTP response.
    Returns dict with: technologies[], waf[], os, server, frameworks[]
    """
    result = {
        "technologies": [],
        "waf": [],
        "os": "Unknown",
        "server": "",
        "frameworks": [],
        "cms": [],
        "cdn": [],
        "js_frameworks": [],
    }

    headers_lower = {k.lower(): v.lower() for k, v in resp_headers.items()}
    body_lower = resp_body.lower() if resp_body else ""

    for header_name, tech_map in TECH_SIGNATURES["headers"].items():
        header_val = headers_lower.get(header_name, "")
        if not header_val and header_name not in headers_lower:
            continue
        for tech, patterns in tech_map.items():
            if not patterns or patterns == [""]:
                if header_name in headers_lower:
                    _add_tech(result, tech)
            else:
                for pat in patterns:
                    if pat in header_val:
                        _add_tech(result, tech)
                        break

    if cookies_str:
        for cookie_name, tech in TECH_SIGNATURES["cookies"].items():
            if cookie_name.lower() in cookies_str.lower():
                _add_tech(result, tech)

    set_cookie = headers_lower.get("set-cookie", "")
    if set_cookie:
        for cookie_name, tech in TECH_SIGNATURES["cookies"].items():
            if cookie_name.lower() in set_cookie:
                _add_tech(result, tech)

    for tech, patterns in TECH_SIGNATURES["body_patterns"].items():
        for pat in patterns:
            if re.search(pat, body_lower if "\\b" not in pat else resp_body, re.IGNORECASE):
                _add_tech(result, tech)
                break

    gen_match = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)',
        resp_body or "", re.IGNORECASE,
    )
    if gen_match:
        gen_val = gen_match.group(1).lower()
        for tech, pattern in TECH_SIGNATURES["meta_generators"].items():
            if pattern in gen_val:
                _add_tech(result, tech)

    _detect_from_header_heuristics(result, headers_lower, set_cookie)

    server_val = headers_lower.get("server", "")
    result["server"] = server_val

    if not server_val:
        inferred = _infer_server_from_headers(headers_lower)
        if inferred:
            result["server"] = inferred
            server_val = inferred
            _add_tech(result, inferred.split("/")[0])

    for os_name, sigs in TECH_SIGNATURES["os_detection"].items():
        for h in sigs.get("headers", []):
            if h in server_val or h in headers_lower.get("x-powered-by", ""):
                result["os"] = os_name
                break

    if result["os"] == "Unknown" and server_val:
        result["os"] = _infer_os(server_val, headers_lower)

    for waf_name, sigs in WAF_SIGNATURES.items():
        detected = False
        for hdr, val in sigs.get("headers", {}).items():
            h = headers_lower.get(hdr, "")
            if h and (not val or val in h):
                detected = True
                break
        if not detected:
            for pat in sigs.get("body", []):
                if pat in body_lower:
                    detected = True
                    break
        if not detected:
            for c in sigs.get("cookies", []):
                if c.lower() in set_cookie:
                    detected = True
                    break
        if detected and waf_name not in result["waf"]:
            result["waf"].append(waf_name)

    return result


def _add_tech(result, tech):
    if tech not in result["technologies"]:
        result["technologies"].append(tech)

    cms_list = ["WordPress", "Drupal", "Joomla", "Ghost", "Hugo", "Jekyll",
                "Wix", "Squarespace", "Shopify", "Magento", "PrestaShop",
                "MediaWiki", "TYPO3", "Blogger"]
    framework_list = ["Laravel", "Django", "Flask", "Rails", "Spring",
                      "Express", "ASP.NET", "ASP.NET MVC", "Next.js", "Nuxt"]
    js_list = ["React", "Angular", "Vue.js", "Svelte", "jQuery", "Bootstrap",
               "Tailwind CSS", "Gatsby"]
    cdn_list = ["Cloudflare", "AWS CloudFront", "Fastly", "Varnish",
                "Akamai", "Vercel", "Netlify", "Firebase"]

    if tech in cms_list and tech not in result["cms"]:
        result["cms"].append(tech)
    if tech in framework_list and tech not in result["frameworks"]:
        result["frameworks"].append(tech)
    if tech in js_list and tech not in result["js_frameworks"]:
        result["js_frameworks"].append(tech)
    if tech in cdn_list and tech not in result["cdn"]:
        result["cdn"].append(tech)


def _infer_server_from_headers(headers_lower):
    """Infer web server when Server header is missing, using ETag format and header fingerprints."""
    etag = headers_lower.get("etag", "")

    if etag:
        if re.match(r'^[wW]/"[0-9a-f]+-[0-9a-f]+"$', etag):
            return "Nginx"
        if re.match(r'^"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"$', etag):
            return "Apache"
        if re.match(r'^"[0-9a-f]{20,}"$', etag):
            return "IIS"
        if re.match(r'^[wW]/"[0-9a-f]{10,}-gzip"$', etag):
            return "Apache"

    if "x-aspnet-version" in headers_lower or "x-aspnetmvc-version" in headers_lower:
        return "IIS"
    if "x-powered-by" in headers_lower:
        xpb = headers_lower["x-powered-by"]
        if "asp.net" in xpb:
            return "IIS"
        if "express" in xpb or "next.js" in xpb:
            return "Node.js"
        if "php" in xpb:
            return "Nginx"
        if "servlet" in xpb or "jsp" in xpb:
            return "Tomcat"

    if "x-vercel-id" in headers_lower:
        return "Vercel"
    if "x-netlify-request-id" in headers_lower:
        return "Netlify"
    if "fly-request-id" in headers_lower:
        return "Fly.io"
    if "cf-ray" in headers_lower:
        return "Cloudflare"

    if "x-cache" in headers_lower:
        xc = headers_lower["x-cache"]
        if "fastly" in xc:
            return "Fastly"
        if "cloudfront" in xc:
            return "CloudFront"
        if "varnish" in xc:
            return "Varnish"

    return ""


def _detect_from_header_heuristics(result, headers_lower, set_cookie):
    """Detect technologies from header patterns that aren't direct name matches."""
    expires = headers_lower.get("expires", "")
    if "thu, 19 nov 1981 08:52:00 gmt" in expires:
        _add_tech(result, "PHP")

    pragma = headers_lower.get("pragma", "")
    cache = headers_lower.get("cache-control", "")
    if ("no-cache" in pragma and "no-store" in cache
            and "must-revalidate" in cache and "PHP" not in result["technologies"]):
        if "thu, 19 nov 1981" in expires:
            _add_tech(result, "PHP")

    if set_cookie:
        if "phpsessid" in set_cookie:
            _add_tech(result, "PHP")
        if "jsessionid" in set_cookie:
            _add_tech(result, "Java/J2EE")
        if "asp.net_sessionid" in set_cookie:
            _add_tech(result, "ASP.NET")
        if "laravel_session" in set_cookie:
            _add_tech(result, "Laravel")
            _add_tech(result, "PHP")
        if "connect.sid" in set_cookie:
            _add_tech(result, "Node.js")
        if "_rails_session" in set_cookie or "rack.session" in set_cookie:
            _add_tech(result, "Rails")
        if "csrftoken" in set_cookie and "django" not in str(result):
            _add_tech(result, "Django")

    xpb = headers_lower.get("x-powered-by", "")
    if xpb:
        if "php" in xpb:
            _add_tech(result, "PHP")
            ver = re.search(r'php[/\s]*([\d.]+)', xpb)
            if ver:
                result.setdefault("_php_version", ver.group(1))
        if "servlet" in xpb or "jsp" in xpb:
            _add_tech(result, "Java/J2EE")


def _infer_os(server_val, headers_lower):
    """Infer OS from inferred/detected server name and other header clues."""
    s = server_val.lower()
    if any(w in s for w in ("iis", "asp.net", "kestrel")):
        return "Windows"
    if any(w in s for w in ("nginx", "apache", "litespeed", "openresty",
                            "tengine", "gunicorn", "uvicorn", "caddy")):
        return "Linux"
    if "tomcat" in s or "jetty" in s or "wildfly" in s:
        return "Linux"
    xpb = headers_lower.get("x-powered-by", "")
    if "asp.net" in xpb:
        return "Windows"
    if "php" in xpb:
        return "Linux"
    expires = headers_lower.get("expires", "")
    if "thu, 19 nov 1981 08:52:00 gmt" in expires:
        return "Linux"
    return "Unknown"
