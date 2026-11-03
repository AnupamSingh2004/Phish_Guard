"""RFC-822 e-mail forensics: authentication results, sender spoofing, link/anchor mismatch, attachments."""
from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser

from .url_features import BRANDS, split_host, parse_url

URL_RE = re.compile(r"""https?://[^\s<>"')\]]+""", re.I)
FREEMAIL = {"gmail.com", "outlook.com", "yahoo.com", "proton.me", "mail.com", "hotmail.com", "aol.com"}
URGENCY = ["urgent", "immediately", "within 24 hours", "final notice", "act now", "expires", "suspended",
           "permanently closed", "failure to", "avoid", "verify now", "as soon as possible", "today"]
CRED = ["password", "verify your", "confirm your identity", "social security", "credit card", "bank details",
        "login with", "billing information", "update your information", "card details", "enter your"]
MONEY = ["gift card", "wire transfer", "gift cards", "reimburse", "redelivery fee"]
GENERIC = ["dear customer", "dear user", "dear account holder", "dear client"]
DANGEROUS_EXT = (".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".iso", ".lnk", ".msi")
MACRO_EXT = (".docm", ".xlsm", ".pptm")
ARCHIVE_EXT = (".zip", ".rar", ".7z", ".gz")


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href, self._txt = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._txt = dict(attrs).get("href"), []

    def handle_data(self, data):
        if self._href is not None:
            self._txt.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._txt).strip()))
            self._href = None


@dataclass
class EmailAnalysis:
    subject: str = ""
    from_addr: str = ""
    from_domain: str = ""
    display_name: str = ""
    body_text: str = ""
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    auth: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)    # (id, weight, description)
    flags: dict = field(default_factory=dict)

    @property
    def header_score(self) -> int:
        return min(100, sum(w for _, w, _ in self.findings))


def _auth(msg) -> dict:
    ar = " ".join(str(v) for v in msg.get_all("Authentication-Results", [])).lower()
    out = {}
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{k}=(\w+)", ar)
        out[k] = m.group(1) if m else "missing"
    out["header_present"] = bool(ar)
    return out


def _reg(addr_or_host: str) -> str:
    host = addr_or_host.split("@")[-1].strip("<> ").lower()
    return split_host(host)[3]


def analyze_email(raw: str) -> EmailAnalysis:
    msg = email.message_from_string(raw, policy=policy.default)
    a = EmailAnalysis(subject=str(msg.get("Subject", "")))
    a.display_name, a.from_addr = parseaddr(str(msg.get("From", "")))
    a.from_domain = _reg(a.from_addr) if "@" in a.from_addr else ""
    a.auth = _auth(msg)
    add = lambda i, w, d: a.findings.append((i, w, d))

    text, html_parts = [], []
    for part in msg.walk():
        ct, fn = part.get_content_type(), part.get_filename()
        if fn:
            a.attachments.append(fn)
        elif ct == "text/plain":
            text.append(part.get_content())
        elif ct == "text/html":
            html_parts.append(part.get_content())
    a.body_text = "\n".join(text) or re.sub(r"<[^>]+>", " ", " ".join(html_parts))
    lp = _Links()
    for h in html_parts:
        lp.feed(h)
    raw_urls = URL_RE.findall(a.body_text) + [h for h, _ in lp.links if h and h.startswith("http")]
    a.urls = list(dict.fromkeys(u.rstrip(".,;:!?") for u in raw_urls))

    spf, dkim, dmarc = a.auth["spf"], a.auth["dkim"], a.auth["dmarc"]
    hp = a.auth["header_present"]
    if not hp: add("no_auth_results", 10, "No Authentication-Results header (sender not verified)")
    if spf == "fail": add("spf_fail", 20, "SPF check FAILED - sending server not authorised for the domain")
    elif spf == "softfail": add("spf_softfail", 12, "SPF soft-fail")
    elif spf in ("none", "missing") and hp: add("spf_none", 8, "No SPF record")
    if dkim == "fail": add("dkim_fail", 15, "DKIM signature FAILED")
    elif dkim in ("none", "missing") and hp: add("dkim_none", 6, "Message not DKIM-signed")
    if dmarc == "fail": add("dmarc_fail", 20, "DMARC alignment FAILED")
    elif dmarc in ("none", "missing") and hp: add("dmarc_none", 5, "No DMARC policy")

    reply_to = parseaddr(str(msg.get("Reply-To", "")))[1]
    rpath = parseaddr(str(msg.get("Return-Path", "")))[1]
    if reply_to and _reg(reply_to) != a.from_domain:
        add("reply_to_mismatch", 15, f"Reply-To domain ({_reg(reply_to)}) differs from From domain ({a.from_domain})")
    if rpath and _reg(rpath) != a.from_domain:
        add("return_path_mismatch", 10, f"Return-Path domain ({_reg(rpath)}) differs from From domain")
    dn = a.display_name.lower()
    for brand, owned in BRANDS.items():
        if brand in dn and a.from_domain not in owned:
            add("display_name_spoof", 25, f"Display name impersonates '{brand}' but is sent from {a.from_domain}")
            break
    if re.search(r"\b(ceo|cfo|director|president|manager)\b", dn) and a.from_domain in FREEMAIL:
        add("exec_freemail", 25, "Executive title used with a free-mail address (BEC pattern)")
    if "@" in a.display_name and _reg(a.display_name.split()[-1]) != a.from_domain:
        add("display_name_email", 20, "Display name contains a different e-mail address")

    low = (a.subject + " " + a.body_text).lower()
    u = sum(k in low for k in URGENCY)
    c = sum(k in low for k in CRED)
    if u >= 2: add("urgency", 12, f"{u} urgency / threat phrases")
    if c >= 1: add("credential_request", 15, f"{c} credential / personal-data request phrases")
    if any(k in low for k in MONEY): add("financial_lure", 12, "Gift-card / wire-transfer / fee lure")
    if any(g in low for g in GENERIC): add("generic_greeting", 5, "Generic greeting instead of your name")

    for href, shown in lp.links:
        if shown.lower().startswith("http") and href.startswith("http"):
            if _reg(parse_url(href)[2]) != _reg(parse_url(shown)[2]):
                add("link_text_mismatch", 30, f"Link text shows {_reg(parse_url(shown)[2])} but goes to {_reg(parse_url(href)[2])}")
                a.flags["link_mismatch"] = 1
                break

    for fn in a.attachments:
        f = fn.lower()
        if f.endswith(DANGEROUS_EXT): add("dangerous_attachment", 35, f"Executable/dangerous attachment: {fn}")
        elif f.endswith(MACRO_EXT): add("macro_attachment", 25, f"Macro-enabled Office file: {fn}")
        elif f.endswith((".html", ".htm")): add("html_attachment", 25, f"HTML attachment (credential-harvesting form?): {fn}")
        elif f.endswith(ARCHIVE_EXT): add("archive_attachment", 12, f"Archive attachment: {fn}")
        if f.endswith((".pdf.exe", ".doc.exe", ".pdf.scr")):
            add("double_extension", 15, f"Double extension disguises file type: {fn}")
    a.flags.setdefault("link_mismatch", 0)
    a.flags["attachment_risk"] = int(any(i.endswith("attachment") for i, _, _ in a.findings))
    return a
