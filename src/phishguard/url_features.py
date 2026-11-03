"""Lexical / host-based URL feature extraction and explainable heuristic rules.

No network access is required: everything is derived from the URL string, which
makes scanning fast, private and safe (we never visit the suspicious site).
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse, unquote

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "icu", "buzz", "cam",
                   "support", "zip", "country", "rest", "loan", "monster"}
MULTI_SUFFIX = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "org.uk", "co.nz", "com.cn", "co.za", "com.mx",
                "github.io", "netlify.app", "weebly.com", "000webhostapp.com", "blogspot.com",
                "firebaseapp.com", "webflow.io", "pages.dev", "herokuapp.com"}
KEYWORDS = ["login", "signin", "sign-in", "verify", "secure", "account", "update", "confirm", "banking",
            "password", "wallet", "suspend", "unlock", "invoice", "billing", "authenticate", "recover",
            "validate", "security", "alert", "webscr", "support"]
EXEC_EXT = (".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".jar", ".vbs", ".js", ".iso", ".dmg")

# brand -> set of registered domains that legitimately belong to the brand
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"}, "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"},
    "google": {"google.com", "gmail.com", "googleapis.com", "youtube.com"},
    "apple": {"apple.com", "icloud.com"}, "facebook": {"facebook.com", "fb.com"},
    "netflix": {"netflix.com"}, "instagram": {"instagram.com"}, "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"}, "github": {"github.com", "github.io", "githubusercontent.com"},
    "chase": {"chase.com"}, "wellsfargo": {"wellsfargo.com"}, "bankofamerica": {"bankofamerica.com"},
    "hdfcbank": {"hdfcbank.com"}, "icicibank": {"icicibank.com"}, "paytm": {"paytm.com"},
    "whatsapp": {"whatsapp.com"}, "adobe": {"adobe.com"}, "docusign": {"docusign.com", "docusign.net"},
    "coinbase": {"coinbase.com"}, "binance": {"binance.com"}, "fedex": {"fedex.com"}, "usps": {"usps.com"},
    "dhl": {"dhl.com"}, "outlook": {"outlook.com", "office.com", "live.com"},
}
_LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length", "num_dots", "num_hyphens_host",
    "digit_ratio_host", "digit_ratio_url", "num_subdomains", "has_ip_host", "has_at_symbol",
    "has_punycode", "non_ascii_host", "is_https", "nonstandard_port", "is_shortener", "suspicious_tld",
    "keyword_count", "keyword_in_host", "brand_mismatch", "is_typosquat", "host_entropy", "path_entropy",
    "num_params", "double_slash_in_path", "encoded_chars", "exec_extension", "embedded_url_in_query",
    "num_special_chars", "label_len",
]


def levenshtein(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment): a transposition ('paypla') costs 1, not 2."""
    if a == b:
        return 0
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host))  # hex / decimal-encoded IPs


def split_host(host: str):
    """Return (subdomain, label, suffix, registered_domain) without external PSL data."""
    host = host.lower().strip(".")
    if is_ip(host):
        return "", host, "", host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        suffix, rest = ".".join(parts[-2:]), parts[:-2]
    elif len(parts) >= 2:
        suffix, rest = parts[-1], parts[:-1]
    else:
        return "", host, "", host
    label, sub = rest[-1], ".".join(rest[:-1])
    return sub, label, suffix, f"{label}.{suffix}"


def parse_url(url: str):
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    p = urlparse(url)
    return url, p, (p.hostname or "").lower()


def _deleet_variants(s: str):
    base = s.translate(_LEET).replace("vv", "w").replace("rn", "m")
    return {base, base.replace("1", "l"), base.replace("1", "i")}


_CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
                              "і": "i", "ѕ": "s", "ӏ": "l", "ɑ": "a", "ο": "o", "ν": "v"})


def brand_analysis(sub: str, label: str, reg: str, path: str, host: str):
    """Return (brand_mismatch, is_typosquat). A brand token on a domain the brand doesn't own."""
    mismatch = typo = False
    if "xn--" in host:  # decode IDN and fold homoglyphs to ASCII before comparing
        try:
            label = split_host(host.encode().decode("idna"))[1].translate(_CONFUSABLES)
        except UnicodeError:
            pass
    haystack_host = f"{sub}.{label}".lower()
    lpath = path.lower()
    tokens = {label} | {t for t in re.split(r"[-_]", label) if len(t) >= 5}
    for brand, owned in BRANDS.items():
        if reg in owned:
            continue
        if brand in haystack_host or (brand in lpath and len(brand) >= 5):
            mismatch = True
        if len(brand) >= 5:
            for tok in tokens:
                for v in _deleet_variants(tok):
                    d = levenshtein(v, brand)
                    if (0 < d <= (1 if len(brand) < 8 else 2)) or (v == brand and tok != brand):
                        typo = True
                    if brand in v and tok != brand:  # leetspeak combo-squat e.g. paypa1-secure
                        mismatch = mismatch or v != tok
    return mismatch, typo


def extract_features(url: str) -> dict[str, float]:
    url, p, host = parse_url(url)
    sub, label, suffix, reg = split_host(host)
    path, query = unquote(p.path or ""), p.query or ""
    low = url.lower()
    mismatch, typo = brand_analysis(sub, label, reg, path, host)
    kw_total = sum(low.count(k) for k in KEYWORDS)
    f = {
        "url_length": len(url), "host_length": len(host), "path_length": len(path), "query_length": len(query),
        "num_dots": host.count("."), "num_hyphens_host": host.count("-"),
        "digit_ratio_host": sum(c.isdigit() for c in host) / max(1, len(host)),
        "digit_ratio_url": sum(c.isdigit() for c in url) / max(1, len(url)),
        "num_subdomains": len([s for s in sub.split(".") if s]),
        "has_ip_host": float(is_ip(host)), "has_at_symbol": float("@" in p.netloc),
        "has_punycode": float("xn--" in host), "non_ascii_host": float(any(ord(c) > 127 for c in host)),
        "is_https": float(p.scheme == "https"),
        "nonstandard_port": float(p.port not in (None, 80, 443)) if _safe_port(p) else 0.0,
        "is_shortener": float(reg in SHORTENERS), "suspicious_tld": float(suffix.split(".")[-1] in SUSPICIOUS_TLDS),
        "keyword_count": kw_total, "keyword_in_host": float(any(k in host for k in KEYWORDS)),
        "brand_mismatch": float(mismatch), "is_typosquat": float(typo),
        "host_entropy": entropy(host), "path_entropy": entropy(path + query),
        "num_params": len([q for q in query.split("&") if q]), "double_slash_in_path": float("//" in path),
        "encoded_chars": len(re.findall(r"%[0-9a-fA-F]{2}", url)),
        "exec_extension": float(path.lower().endswith(EXEC_EXT)),
        "embedded_url_in_query": float(bool(re.search(r"(https?%3a|https?:)", query.lower()))),
        "num_special_chars": sum(url.count(c) for c in "!$%*;=~#^"), "label_len": len(label),
    }
    return {k: float(f[k]) for k in FEATURE_NAMES}


def _safe_port(p) -> bool:
    try:
        p.port
        return True
    except ValueError:
        return False


def vectorize(url: str) -> list[float]:
    f = extract_features(url)
    return [f[k] for k in FEATURE_NAMES]


# ---------------------------------------------------------------- explainable rules
RULES = [
    ("ip_host", 35, "Host is a raw IP address instead of a domain name", lambda f: f["has_ip_host"]),
    ("at_symbol", 30, "'@' in the authority part hides the real destination host", lambda f: f["has_at_symbol"]),
    ("punycode", 25, "Punycode / non-ASCII host (possible homograph attack)", lambda f: f["has_punycode"] or f["non_ascii_host"]),
    ("brand_mismatch", 35, "Well-known brand name used on a domain the brand does not own", lambda f: f["brand_mismatch"]),
    ("typosquat", 40, "Domain is a look-alike (typo / leetspeak) of a well-known brand", lambda f: f["is_typosquat"]),
    ("suspicious_tld", 15, "TLD frequently abused for phishing", lambda f: f["suspicious_tld"]),
    ("shortener", 10, "URL shortener hides the final destination", lambda f: f["is_shortener"]),
    ("no_https_keywords", 15, "Credential-style keywords over plain HTTP", lambda f: (not f["is_https"]) and f["keyword_count"] >= 1),
    ("deep_subdomains", 15, "Four or more subdomain levels", lambda f: f["num_subdomains"] >= 4),
    ("many_keywords", 15, "Multiple phishing keywords (login/verify/secure/...)", lambda f: f["keyword_count"] >= 3),
    ("long_url", 10, "Unusually long URL", lambda f: f["url_length"] > 100),
    ("hyphen_heavy_host", 15, "Three or more hyphens in host name", lambda f: f["num_hyphens_host"] >= 3),
    ("nonstandard_port", 10, "Non-standard port", lambda f: f["nonstandard_port"]),
    ("encoded_chars", 8, "Heavy percent-encoding (obfuscation)", lambda f: f["encoded_chars"] > 5),
    ("exec_download", 25, "Link points to an executable / installer file", lambda f: f["exec_extension"]),
    ("open_redirect", 10, "Another URL embedded in the query (redirect chain)", lambda f: f["embedded_url_in_query"]),
]


def rule_score(features: dict[str, float]):
    """Return (score 0-100, [(rule_id, weight, description)])."""
    hits = [(rid, w, desc) for rid, w, desc, fn in RULES if fn(features)]
    return min(100, sum(w for _, w, _ in hits)), hits
