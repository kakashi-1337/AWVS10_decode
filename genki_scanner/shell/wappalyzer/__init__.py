"""
Wappalyzer-compatible technology detection engine.
Uses the webappanalyzer/wappalyzer fingerprint database (7600+ technologies).
"""
import json
import os
import re
from functools import lru_cache

_DB_DIR = os.path.dirname(__file__)
_db_cache = None
_cats_cache = None


def _load_db():
    global _db_cache, _cats_cache
    if _db_cache is not None:
        return _db_cache, _cats_cache

    _db_cache = {}
    for fname in sorted(os.listdir(_DB_DIR)):
        if fname == "categories.json" or not fname.endswith(".json"):
            continue
        with open(os.path.join(_DB_DIR, fname), encoding="utf-8", errors="replace") as f:
            _db_cache.update(json.load(f))

    cats_path = os.path.join(_DB_DIR, "categories.json")
    _cats_cache = {}
    if os.path.exists(cats_path):
        with open(cats_path, encoding="utf-8", errors="replace") as f:
            _cats_cache = json.load(f)

    return _db_cache, _cats_cache


def _parse_pattern(raw):
    """Parse Wappalyzer pattern string into (regex, version_group, confidence).
    Format: pattern\\;version:\\1\\;confidence:50
    """
    parts = raw.split("\\;")
    pattern = parts[0]
    version = None
    confidence = 100
    for p in parts[1:]:
        if p.startswith("version:"):
            version = p[8:]
        elif p.startswith("confidence:"):
            try:
                confidence = int(p[11:])
            except ValueError:
                pass
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        compiled = None
    return compiled, version, confidence


def _extract_version(match, version_template):
    if not version_template or not match:
        return ""
    result = version_template
    for i in range(10):
        try:
            group_val = match.group(i) or ""
        except (IndexError, AttributeError):
            group_val = ""
        result = result.replace(f"\\{i}", group_val)
    return result.strip()


def _ensure_list(val):
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return val
    return []


def _ensure_dict(val):
    if isinstance(val, dict):
        return val
    return {}


def detect(headers, body, cookies_str="", url="", scripts=None):
    """
    Detect technologies from HTTP response data.

    Args:
        headers: dict of response headers {name: value}
        body: response body string
        cookies_str: cookie string from Set-Cookie or Cookie header
        url: the page URL
        scripts: list of script src URLs found in the page

    Returns:
        list of dicts: [{name, categories, version, confidence, website, implies}]
    """
    db, cats = _load_db()
    headers_lower = {k.lower(): str(v) for k, v in headers.items()}
    body = body or ""
    scripts = scripts or []

    detected = {}

    for tech_name, tech in db.items():
        matches = []

        for hdr_name, patterns in _ensure_dict(tech.get("headers")).items():
            hdr_val = headers_lower.get(hdr_name.lower(), "")
            if not hdr_val:
                continue
            for raw_pat in _ensure_list(patterns):
                rx, ver_tmpl, conf = _parse_pattern(raw_pat)
                if rx:
                    m = rx.search(hdr_val)
                    if m:
                        matches.append((conf, _extract_version(m, ver_tmpl)))

        for cookie_name, patterns in _ensure_dict(tech.get("cookies")).items():
            cookie_lower = cookies_str.lower() if cookies_str else ""
            sc = headers_lower.get("set-cookie", "")
            combined = cookie_lower + " " + sc
            if cookie_name.lower() not in combined:
                continue
            for raw_pat in _ensure_list(patterns):
                rx, ver_tmpl, conf = _parse_pattern(raw_pat)
                if rx:
                    m = rx.search(combined)
                    if m:
                        matches.append((conf, _extract_version(m, ver_tmpl)))
                else:
                    matches.append((100, ""))

        for raw_pat in _ensure_list(tech.get("html")):
            rx, ver_tmpl, conf = _parse_pattern(raw_pat)
            if rx:
                m = rx.search(body)
                if m:
                    matches.append((conf, _extract_version(m, ver_tmpl)))

        for meta_name, patterns in _ensure_dict(tech.get("meta")).items():
            meta_rx = re.compile(
                rf'<meta\s+[^>]*?name=["\']?{re.escape(meta_name)}["\']?\s+[^>]*?content=["\']([^"\']*)',
                re.IGNORECASE
            )
            meta_match = meta_rx.search(body)
            if not meta_match:
                meta_rx2 = re.compile(
                    rf'<meta\s+[^>]*?content=["\']([^"\']*)["\']?\s+[^>]*?name=["\']?{re.escape(meta_name)}',
                    re.IGNORECASE
                )
                meta_match = meta_rx2.search(body)
            if meta_match:
                meta_val = meta_match.group(1)
                for raw_pat in _ensure_list(patterns):
                    rx, ver_tmpl, conf = _parse_pattern(raw_pat)
                    if rx:
                        m = rx.search(meta_val)
                        if m:
                            matches.append((conf, _extract_version(m, ver_tmpl)))
                    elif not raw_pat or raw_pat == "":
                        matches.append((100, ""))

        for raw_pat in _ensure_list(tech.get("scriptSrc")):
            rx, ver_tmpl, conf = _parse_pattern(raw_pat)
            if rx:
                for src in scripts:
                    m = rx.search(src)
                    if m:
                        matches.append((conf, _extract_version(m, ver_tmpl)))
                        break
                for src_match in re.finditer(r'<script[^>]+src=["\']([^"\']+)', body, re.IGNORECASE):
                    m = rx.search(src_match.group(1))
                    if m:
                        matches.append((conf, _extract_version(m, ver_tmpl)))
                        break

        if url:
            for raw_pat in _ensure_list(tech.get("url")):
                rx, ver_tmpl, conf = _parse_pattern(raw_pat)
                if rx and rx.search(url):
                    matches.append((conf, ""))

        if not matches:
            continue

        best_conf = max(m[0] for m in matches)
        best_ver = ""
        for c, v in matches:
            if v:
                best_ver = v
                break

        cat_ids = tech.get("cats", [])
        cat_names = []
        for cid in cat_ids:
            cat_info = cats.get(str(cid))
            if cat_info:
                cat_names.append(cat_info["name"])

        detected[tech_name] = {
            "name": tech_name,
            "version": best_ver,
            "confidence": best_conf,
            "categories": cat_names,
            "cat_ids": cat_ids,
            "website": tech.get("website", ""),
            "implies": _ensure_list(tech.get("implies")),
        }

    _resolve_implies(detected, db, cats)

    return sorted(detected.values(), key=lambda x: (-x["confidence"], x["name"]))


def _resolve_implies(detected, db, cats, depth=0):
    if depth > 5:
        return
    new_implies = []
    for tech in list(detected.values()):
        for imp in tech.get("implies", []):
            imp_name = imp.split("\\;")[0]
            if imp_name in detected:
                continue
            if imp_name in db:
                imp_tech = db[imp_name]
                cat_ids = imp_tech.get("cats", [])
                cat_names = []
                for cid in cat_ids:
                    cat_info = cats.get(str(cid))
                    if cat_info:
                        cat_names.append(cat_info["name"])
                detected[imp_name] = {
                    "name": imp_name,
                    "version": "",
                    "confidence": 50,
                    "categories": cat_names,
                    "cat_ids": cat_ids,
                    "website": imp_tech.get("website", ""),
                    "implies": _ensure_list(imp_tech.get("implies")),
                }
                new_implies.append(imp_name)

    if new_implies:
        _resolve_implies(detected, db, cats, depth + 1)


def categorize(detections):
    """Group detection results by category for display."""
    groups = {
        "server": [],
        "framework": [],
        "cms": [],
        "language": [],
        "js_framework": [],
        "cdn_proxy": [],
        "security": [],
        "analytics": [],
        "other": [],
    }

    _cat_map = {
        "Web servers": "server", "Reverse proxies": "server",
        "Web frameworks": "framework", "JavaScript frameworks": "js_framework",
        "JavaScript libraries": "js_framework",
        "CMS": "cms", "Ecommerce": "cms", "Blogs": "cms",
        "Programming languages": "language",
        "CDN": "cdn_proxy", "PaaS": "cdn_proxy", "Hosting": "cdn_proxy",
        "Security": "security", "Access management": "security",
        "Analytics": "analytics", "Tag managers": "analytics",
    }

    for det in detections:
        placed = False
        for cat in det["categories"]:
            group = _cat_map.get(cat)
            if group:
                groups[group].append(det)
                placed = True
                break
        if not placed:
            groups["other"].append(det)

    return {k: v for k, v in groups.items() if v}
