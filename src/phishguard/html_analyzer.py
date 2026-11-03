"""Static analysis of a landing page's HTML (no JS execution, no network)."""
from __future__ import annotations

import re
from html.parser import HTMLParser

from .url_features import BRANDS, parse_url, split_host


class _P(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.inputs, self.iframes, self.links = [], [], [], []
        self.meta_refresh = None
        self.text_script = []
        self._in_script = False
        self.onevents = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form": self.forms.append(d)
        elif tag == "input": self.inputs.append(d)
        elif tag == "iframe": self.iframes.append(d)
        elif tag == "a" and d.get("href"): self.links.append(d["href"])
        elif tag == "meta" and (d.get("http-equiv") or "").lower() == "refresh": self.meta_refresh = d.get("content")
        elif tag == "script": self._in_script = True
        for k in d:
            if k.startswith("on"): self.onevents.append((k, d[k] or ""))

    def handle_endtag(self, tag):
        if tag == "script": self._in_script = False

    def handle_data(self, data):
        if self._in_script: self.text_script.append(data)


def analyze_html(html: str, page_url: str = ""):
    """Return (score 0-100, [(id, weight, description)])."""
    p = _P()
    p.feed(html)
    page_reg = split_host(parse_url(page_url)[2])[3] if page_url else ""
    hits = []
    pw = [i for i in p.inputs if (i.get("type") or "").lower() == "password"]
    if pw: hits.append(("password_field", 15, "Page asks for a password"))
    for f in p.forms:
        act = f.get("action") or ""
        if act.startswith("http"):
            reg = split_host(parse_url(act)[2])[3]
            if page_reg and reg != page_reg:
                hits.append(("external_form_action", 40, f"Form posts credentials to a different domain ({reg})"))
            if act.startswith("http://") and pw:
                hits.append(("insecure_form", 15, "Password form submits over plain HTTP"))
        elif act in ("", "#") and pw:
            hits.append(("empty_form_action", 5, "Password form with empty action (JS-handled submit)"))
    for i in p.iframes:
        st = (i.get("style") or "").replace(" ", "").lower()
        if "display:none" in st or i.get("width") in ("0", "1") or i.get("height") in ("0", "1"):
            hits.append(("hidden_iframe", 25, "Hidden iframe (drive-by / tracking)"))
            break
    js = " ".join(p.text_script)
    if re.search(r"eval\s*\(|atob\s*\(|unescape\s*\(|fromCharCode", js):
        hits.append(("obfuscated_js", 20, "Obfuscated JavaScript (eval/atob/unescape)"))
    if re.search(r"contextmenu|event\.button\s*==\s*2", js + " ".join(v for _, v in p.onevents)):
        hits.append(("right_click_disabled", 10, "Right-click disabled to hinder inspection"))
    if any(k == "onmouseover" and "status" in v for k, v in p.onevents):
        hits.append(("status_bar_spoof", 15, "Status-bar spoofing via onmouseover"))
    if p.meta_refresh and "url=" in p.meta_refresh.lower():
        hits.append(("meta_refresh", 10, "Automatic meta-refresh redirect"))
    if p.links and page_reg:
        ext = sum(split_host(parse_url(h)[2])[3] != page_reg for h in p.links if h.startswith("http"))
        if ext / len(p.links) > 0.8 and len(p.links) >= 4:
            hits.append(("external_links", 10, "Most links lead off-site"))
    if pw and page_reg:
        head = html[:4000].lower()
        for brand, owned in BRANDS.items():
            if brand in head and page_reg not in owned:
                hits.append(("brand_on_foreign_domain", 25, f"Login page mentions '{brand}' but is hosted on {page_reg}"))
                break
    return min(100, sum(w for _, w, _ in hits)), hits
