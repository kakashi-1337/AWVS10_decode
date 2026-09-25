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
        "React": [r'__NEXT_DATA__', r'_reactRootContainer', r'react-root', r'data-reactroot'],
        "Angular": [r'ng-version', r'ng-app', r'data-ng-app', r'angular\.min\.js'],
        "Vue.js": [r'__vue__', r'v-cloak', r'data-v-', r'vue\.min\.js', r'vue\.js'],
        "Svelte": [r'__svelte', r'svelte-'],
        "jQuery": [r'jquery\.min\.js', r'jquery-\d+\.\d+'],
        "Bootstrap": [r'bootstrap\.min\.(css|js)', r'class="(container|row|col-)'],
        "Tailwind CSS": [r'tailwindcss', r'class="[^"]*\b(flex|grid|bg-|text-|p-|m-)\b'],
        "Next.js": [r'__NEXT_DATA__', r'_next/static', r'/_next/'],
        "Nuxt": [r'__NUXT__', r'_nuxt/'],
        "Gatsby": [r'gatsby-', r'___gatsby'],
        "GraphQL": [r'/graphql', r'__schema', r'query\s*\{'],
        "Firebase": [r'firebaseapp\.com', r'firebase\.js'],
        "Stripe": [r'js\.stripe\.com', r'stripe-js'],
        "reCAPTCHA": [r'google\.com/recaptcha', r'grecaptcha'],
        "hCaptcha": [r'hcaptcha\.com', r'h-captcha'],
        "Cloudflare Turnstile": [r'challenges\.cloudflare\.com/turnstile'],
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
        "cookies": ["BIGipServer", "TS"],
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

    server_val = headers_lower.get("server", "")
    result["server"] = server_val

    for os_name, sigs in TECH_SIGNATURES["os_detection"].items():
        for h in sigs.get("headers", []):
            if h in server_val or h in headers_lower.get("x-powered-by", ""):
                result["os"] = os_name
                break

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
