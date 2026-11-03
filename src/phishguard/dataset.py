"""Deterministic synthetic data generators (URLs + RFC-822 e-mails).

Why synthetic?  Real phishing feeds (PhishTank / OpenPhish) need network access
and licences, and change daily.  The generators below reproduce the *techniques*
documented in the literature (typosquatting, combosquatting, IP hosts, '@' tricks,
homographs, shorteners, free-hosting abuse, BEC, credential lures ...) and also
inject hard cases (clean-looking phishing, noisy legitimate URLs) so the
evaluation is not trivially 100%.  Swap in real feeds via `load_urls_csv`.
"""
from __future__ import annotations

import hashlib
import random
import string
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import pandas as pd

from .config import DATA_DIR, N_EMAILS, N_URLS, SEED
from .url_features import BRANDS, split_host

LEGIT_DOMAINS = """wikipedia.org github.com stackoverflow.com nytimes.com bbc.co.uk cnn.com reddit.com medium.com
python.org mozilla.org apache.org kernel.org fedoraproject.org ubuntu.com debian.org archlinux.org nasa.gov nih.gov
mit.edu stanford.edu harvard.edu ox.ac.uk cam.ac.uk ieee.org acm.org arxiv.org nature.com sciencedirect.com
springer.com coursera.org edx.org khanacademy.org udemy.com duolingo.com spotify.com soundcloud.com twitch.tv
vimeo.com imdb.com rottentomatoes.com goodreads.com etsy.com ebay.com walmart.com target.com bestbuy.com ikea.com
nike.com adidas.com zara.com hm.com uber.com lyft.com airbnb.com booking.com expedia.com tripadvisor.com
lufthansa.com delta.com united.com irctc.co.in flipkart.com swiggy.com zomato.com myntra.com paytm.com
hdfcbank.com icicibank.com chase.com wellsfargo.com bankofamerica.com paypal.com amazon.com amazon.in
microsoft.com apple.com google.com facebook.com instagram.com linkedin.com dropbox.com adobe.com docusign.com
slack.com zoom.us notion.so figma.com atlassian.com gitlab.com bitbucket.org cloudflare.com digitalocean.com
heroku.com netlify.com vercel.com npmjs.com pypi.org rust-lang.org golang.org nodejs.org docker.com kubernetes.io
mongodb.com postgresql.org mysql.com redis.io elastic.co grafana.com prometheus.io wordpress.org gnu.org""".split()

HOSTING = ["github.io", "netlify.app", "weebly.com", "000webhostapp.com", "blogspot.com", "firebaseapp.com",
           "webflow.io", "pages.dev", "herokuapp.com"]
PHISH_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "icu", "buzz", "cam",
              "com", "net", "info", "online", "site", "live", "org", "co", "me"]
WORDS = ["green", "valley", "bright", "blue", "river", "stone", "happy", "fast", "smart", "prime", "alpha", "delta",
         "urban", "pixel", "cloud", "solar", "metro", "royal", "swift", "maple", "ocean", "peak", "zen", "nova",
         "bakery", "studio", "design", "travel", "clinic", "garage", "books", "foods", "media", "labs", "works",
         "store", "shop", "hub", "tech", "farm", "yoga", "dental", "law", "realty", "cafe"]
KW = ["login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "password", "wallet",
      "suspend", "unlock", "billing", "authenticate", "recover", "validate", "security", "support"]
PATHS = ["wiki/{w}", "docs/en/latest/{w}.html", "articles/{y}/{m}/{w}-{w2}", "products/item-{n}", "search",
         "user/{w}/repos", "blog/{w}-{w2}", "category/{w}", "news/{y}/{w}", "download/release-{n}.tar.gz",
         "watch", "about", "contact", "help/{w}", "pricing", "store/{w}", "careers/{w}-{w2}", "events/{y}"]
LEGIT_AUTH_PATHS = ["login", "signin", "account/settings", "account/security", "password/reset", "billing",
                    "verify-email", "support/contact", "secure/checkout"]


def _rid(rng, n, alphabet=string.ascii_lowercase + string.digits):
    return "".join(rng.choices(alphabet, k=n))


def _legit_url(rng: random.Random) -> str:
    r = rng.random()
    if r < 0.10:                                  # small-business sites, sometimes hyphenated / keyword-ish
        w = [rng.choice(WORDS) for _ in range(rng.choice([2, 2, 3]))]
        sep = "-" if rng.random() < 0.35 else ""
        if rng.random() < 0.06:
            w.append(rng.choice(["secure", "support", "account", "login"]))
        dom = sep.join(w) + "." + rng.choice(["com", "org", "net", "in", "co.uk", "io", "info"])
    elif r < 0.14:
        dom = f"{rng.choice(WORDS)}-{rng.choice(WORDS)}.{rng.choice(HOSTING)}"      # legit free-hosted projects
    else:
        dom = rng.choice(LEGIT_DOMAINS)
    host = dom
    q = rng.random()
    if q < 0.45:
        host = "www." + dom
    elif q < 0.65:
        host = rng.choice(["docs", "blog", "mail", "accounts", "login", "secure", "support", "cdn", "api", "m"]) + "." + dom
    elif q < 0.68:
        host = f"{rng.choice(['eu','us','ap'])}-{rng.randint(1,9)}.{rng.choice(['app','edge'])}.{dom}"
    scheme = "https" if rng.random() < 0.9 else "http"
    port = ":8080" if rng.random() < 0.015 else ""
    t = rng.random()
    if t < 0.08:
        path = rng.choice(LEGIT_AUTH_PATHS)
    elif t < 0.10:
        path = ""
    else:
        path = rng.choice(PATHS).format(w=rng.choice(WORDS), w2=rng.choice(WORDS), y=rng.randint(2015, 2026),
                                       m=rng.randint(1, 12), n=rng.randint(1, 9999))
    url = f"{scheme}://{host}{port}/{path}"
    qr = rng.random()
    if qr < 0.20:
        url += f"?q={rng.choice(WORDS)}&page={rng.randint(1, 20)}"
    elif qr < 0.27:   # long tracking params (high entropy, long) – a classic false-positive source
        url += f"?utm_source={_rid(rng, 6)}&utm_campaign={_rid(rng, 12)}&sid={_rid(rng, 24)}&ref={_rid(rng, 10)}"
    elif qr < 0.29:
        url += f"?redirect=https%3A%2F%2F{rng.choice(LEGIT_DOMAINS)}%2F{rng.choice(WORDS)}"
    elif qr < 0.31:
        url = f"https://{rng.choice(['bit.ly','tinyurl.com','t.co'])}/{_rid(rng, 7, string.ascii_letters + string.digits)}"
    return url


def _mutate_brand(rng, b: str) -> str:
    k = rng.choice(["swap", "replace", "leet", "omit", "dup", "homo"])
    i = rng.randrange(1, len(b) - 1)
    if k == "swap":
        return b[:i] + b[i + 1] + b[i] + b[i + 2:]
    if k == "replace":
        return b[:i] + rng.choice(string.ascii_lowercase) + b[i + 1:]
    if k == "leet":
        m = {"o": "0", "l": "1", "a": "4", "e": "3", "i": "1", "s": "5"}
        pos = [j for j, c in enumerate(b) if c in m]
        j = rng.choice(pos) if pos else i
        return b[:j] + m.get(b[j], "x") + b[j + 1:]
    if k == "omit":
        return b[:i] + b[i + 1:]
    if k == "dup":
        return b[:i] + b[i] + b[i:]
    return b


def _phish_url(rng: random.Random):
    brand = rng.choice([b for b in BRANDS if b != "outlook"])
    tld = rng.choice(PHISH_TLDS)
    kw, kw2 = rng.choice(KW), rng.choice(KW)
    rid = _rid(rng, rng.randint(5, 10))
    tech = rng.choices(
        ["brand_subdomain", "typosquat", "combosquat", "ip_host", "at_symbol", "punycode", "long_obfuscated",
         "shortener", "free_hosting", "deep_subdomain", "hard_clean", "redirect_param", "exec_download"],
        weights=[11, 14, 12, 7, 5, 4, 8, 6, 9, 6, 12, 4, 2])[0]
    sch = "https" if rng.random() < 0.55 else "http"
    if tech == "brand_subdomain":
        u = f"{sch}://{brand}.{rng.choice([kw + '-' + rid, rid, 'com.' + rid])}.{tld}/{kw}"
    elif tech == "typosquat":
        d = _mutate_brand(rng, brand)
        u = f"{sch}://{rng.choice(['', 'www.'])}{d}.{rng.choice(['com', 'net', tld])}/{rng.choice([kw, kw + '.php', 'index.html'])}"
    elif tech == "combosquat":
        u = f"{sch}://{brand}-{kw}.{tld}/{kw2}/{rid}"
    elif tech == "ip_host":
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        u = f"http://{ip}{rng.choice(['', ':8080', ':8888'])}/{brand}/{kw}.php"
    elif tech == "at_symbol":
        u = f"{sch}://{brand}.com@{rid}.{tld}/{kw}"
    elif tech == "punycode":
        label = brand.replace("a", "а", 1) if "a" in brand else brand.replace("o", "о", 1)
        u = f"https://{label}.com/{kw}".encode("utf-8").decode()
        host = label + ".com"
        u = f"https://{host.encode('idna').decode()}/{kw}"
    elif tech == "long_obfuscated":
        u = f"{sch}://{rid}{rng.choice(WORDS)}.{tld}/{kw}/{kw2}.php?id={_rid(rng, 20)}&session={_rid(rng, 32)}&token={_rid(rng, 16)}"
    elif tech == "shortener":
        u = f"{rng.choice(['https', 'http'])}://{rng.choice(['bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy', 'is.gd'])}/{_rid(rng, 7, string.ascii_letters + string.digits)}"
    elif tech == "free_hosting":
        u = f"https://{brand}-{kw}-{rid[:4]}.{rng.choice(HOSTING)}/{kw2}"
    elif tech == "deep_subdomain":
        u = f"{sch}://{kw}.{kw2}.{brand}.{rid}.{tld}/{rid}"
    elif tech == "hard_clean":                       # compromised legit-looking site: nothing lexical gives it away
        dom = rng.choice(WORDS) + rng.choice(WORDS) + "." + rng.choice(["com", "org", "net", "in"])
        u = f"https://www.{dom}/{rng.choice(['wp-content/uploads', 'includes', 'files', 'images'])}/{rng.choice(['index.php', 'doc.html', 'view.php', 'login.php'])}"
    elif tech == "redirect_param":
        dom = rng.choice(WORDS) + rng.choice(WORDS) + ".com"
        u = f"https://{dom}/redirect.php?url=http://{rid}.{tld}/{kw}"
    else:
        u = f"http://{rid}.{tld}/{brand}-update-{rng.randint(1,99)}.exe"
    return u, tech


def generate_urls(n: int = N_URLS, seed: int = SEED) -> pd.DataFrame:
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        if i % 2:
            u, t = _phish_url(rng)
            rows.append((u, 1, t))
        else:
            rows.append((_legit_url(rng), 0, "legit"))
    df = pd.DataFrame(rows, columns=["url", "label", "technique"]).drop_duplicates("url").reset_index(drop=True)
    df["group"] = df.url.map(lambda u: split_host(__import__("urllib.parse").parse.urlparse(u).hostname or "")[3])
    return df


def split_by_group(df: pd.DataFrame, group_col="group", test_frac=0.25):
    """Deterministic group split: a registered domain never appears on both sides (no leakage)."""
    h = df[group_col].map(lambda g: int(hashlib.md5(g.encode()).hexdigest(), 16) % 1000 / 1000)
    return df[h >= test_frac].reset_index(drop=True), df[h < test_frac].reset_index(drop=True)


def load_urls_csv(path) -> pd.DataFrame:
    """Load a real feed: CSV with columns url,label (1=phishing)."""
    df = pd.read_csv(path)
    df["technique"] = df.get("technique", "external")
    df["group"] = df.url.map(lambda u: split_host(__import__("urllib.parse").parse.urlparse(u).hostname or "")[3])
    return df


# ------------------------------------------------------------------------------- e-mail
FREEMAIL = ["gmail.com", "outlook.com", "yahoo.com", "proton.me", "mail.com"]
FIRST = ["Priya", "Rahul", "Anita", "Marcus", "Elena", "Tom", "Sara", "David", "Mei", "Omar", "Julia", "Arjun"]
LAST = ["Sharma", "Patel", "Nguyen", "Miller", "Garcia", "Khan", "Rossi", "Brown", "Singh", "Kim"]

LEGIT_SUBJ = ["Meeting notes – {w} sprint", "Your receipt from {b}", "Weekly newsletter: {w} digest",
              "Lunch on Thursday?", "Q{n} report attached", "Your order has shipped", "Invitation: {w} review",
              "Security notice: new sign-in to your {b} account", "Password reset requested", "Invoice #{n} for {w} services",
              "Re: {w} project timeline", "Your {b} subscription renewal"]
LEGIT_BODY = [
    "Hi {name},\n\nThanks for joining the call today. Notes are in the shared drive. Let me know if I missed anything about {w}.\n\nRegards,\n{sender}",
    "Hello {name},\n\nYour order #{n} has shipped and should arrive on Friday. Track it at {url}.\n\nThanks for shopping with us.",
    "Hi {name},\n\nWe received a request to reset your password. If this was you, use the link below within 24 hours. If you did not request this, ignore this email: {url}\n\n{sender}",
    "Hi team,\n\nAttached is the Q{n} report. Please review {w} figures before Monday. The dashboard is at {url}.\n\nBest,\n{sender}",
    "Hello {name},\n\nWe noticed a new sign-in from a Linux device in your {b} account. If this was you no action is needed. Review activity: {url}\n\nThe {b} team",
    "Hey {name},\n\nAre we still on for lunch Thursday? Also, can you review the {w} pull request when you get a chance: {url}\n\nCheers,\n{sender}",
    "Dear {name},\n\nPlease find invoice #{n} attached for services rendered in {w}. Payment terms are 30 days to the account on file.\n\nKind regards,\n{sender}",
    "Hi {name},\n\nYour subscription renews next week. Manage billing preferences anytime at {url}.\n\nThanks,\n{sender}",
]
LEGIT_URGENT = "Hi {name},\n\nQuick heads-up: the {w} deployment is urgent and needs your approval today. Please verify the checklist at {url} when you can.\n\n{sender}"

PHISH_SUBJ = ["URGENT: Your {b} account has been suspended", "Action required: verify your {b} password",
              "Unusual sign-in activity detected", "Your payment of ${n} failed", "Final notice: account will be closed",
              "You have won a {b} gift card!", "Document shared with you: Invoice_{n}", "Delivery failed – reschedule now",
              "Password expires in 24 hours", "Request", "Are you available?", "Confirm your identity to avoid suspension"]
PHISH_BODY = [
    "Dear Customer,\n\nWe detected suspicious activity on your {b} account. Your account has been suspended. You must verify your password and confirm your identity immediately or it will be permanently closed within 24 hours:\n{url}\n\n{b} Security Team",
    "Dear user,\n\nYour password expires today. Click here to keep your current password and avoid losing access: {url}\nFailure to act immediately will result in account termination.",
    "Congratulations!! You have been selected to receive a ${n} {b} gift card. Claim your prize now before it expires: {url}\nEnter your card details and social security number to confirm.",
    "Hello,\n\nYour payment of ${n} could not be processed. Update your billing information and bank details now to avoid service interruption: {url}\n\nBilling Department",
    "Dear account holder,\n\nA document has been shared with you. Login with your email password to view the secure file: {url}\nThis link will expire.",
    "Your parcel could not be delivered. Pay a small redelivery fee of $1.99 and confirm your address and credit card: {url}",
    "Hi {name},\n\nAre you available? I need a favour urgently and I am in a meeting so cannot take calls. I need you to purchase gift cards for a client and send me the codes. I will reimburse you. Keep this confidential.\n\n{sender}",
    "Hi {name},\n\nPlease process an urgent wire transfer of ${n} to the vendor below today. Do not discuss with anyone, I'm travelling. Send confirmation to my personal email.\n\n{sender}\nCEO",
    "Notice: unusual login attempt blocked. Verify now: {url}",
    "Dear customer, your {b} account will be closed. Update your information: {url}",
]


def _ident(rng):
    return rng.choice(FIRST), rng.choice(LAST)


def _auth_header(rng, status: str, domain: str) -> str:
    if status == "pass":
        r = f"spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc=pass header.from={domain}"
    elif status == "none":
        r = f"spf=none smtp.mailfrom={domain}; dkim=none; dmarc=none header.from={domain}"
    elif status == "partial":
        r = f"spf=pass smtp.mailfrom={domain}; dkim=none; dmarc=none header.from={domain}"
    else:
        r = rng.choice([f"spf=fail smtp.mailfrom={domain}; dkim=fail header.d={domain}; dmarc=fail header.from={domain}",
                        f"spf=softfail smtp.mailfrom={domain}; dkim=none; dmarc=fail header.from={domain}",
                        f"spf=fail smtp.mailfrom={domain}; dkim=none; dmarc=none header.from={domain}"])
    return "mx.recipient.example; " + r


def build_eml(label: int, rng: random.Random):
    """Return (raw_rfc822_text, technique)."""
    first, last = _ident(rng)
    name = rng.choice(FIRST)
    w = rng.choice(WORDS)
    brand = rng.choice([b for b in BRANDS if b != "outlook"])
    n = rng.randint(100, 9999)
    msg = EmailMessage()
    attach = None
    if label == 0:
        kind = "legit"
        b = rng.choice(["github.com", "paypal.com", "amazon.com", "google.com", "linkedin.com", "dropbox.com"])
        corp = rng.random() < 0.5
        sender_dom = rng.choice(LEGIT_DOMAINS) if corp else b
        local = rng.choice(["noreply", "no-reply", "notifications", first.lower(), "info"])
        disp = f"{first} {last}" if local == first.lower() else b.split(".")[0].title()
        link = _legit_url(rng) if rng.random() < 0.9 else f"https://{b}/security"
        body_t = LEGIT_URGENT if rng.random() < 0.06 else rng.choice(LEGIT_BODY)
        subj = rng.choice(LEGIT_SUBJ)
        if rng.random() < 0.15:     # hard negative: genuine but alarming-sounding service notice
            body_t = rng.choice([PHISH_BODY[0], PHISH_BODY[1], PHISH_BODY[3], PHISH_BODY[8], PHISH_BODY[9]])
            subj = rng.choice(PHISH_SUBJ[:5])
        status = rng.choices(["pass", "none", "partial"], [0.90, 0.05, 0.05])[0]
        from_addr = f"{local}@{sender_dom}"
        reply = None
        if "invoice" in subj.lower() or "report" in subj.lower():
            if rng.random() < 0.6:
                attach = (f"{rng.choice(['report','invoice'])}_{n}.pdf", b"%PDF-1.4 fake")
    else:
        kind = rng.choices(["credential", "bec", "lure_attach", "prize"], [0.55, 0.15, 0.15, 0.15])[0]
        url, _t = _phish_url(rng)
        link = url
        b = brand
        subj = rng.choice(PHISH_SUBJ)
        body_t = rng.choice(PHISH_BODY)
        if kind == "bec":
            body_t = PHISH_BODY[6 + rng.randint(0, 1)]
            subj = rng.choice(["Request", "Are you available?", "Urgent task"])
        if kind != "bec" and rng.random() < 0.15:        # hard positive: polite, benign-sounding lure
            body_t = rng.choice(LEGIT_BODY[:2] + LEGIT_BODY[7:])
            subj = rng.choice(LEGIT_SUBJ)
        if rng.random() < 0.07:                          # terse "clean text" phishing – only the link/auth give it away
            body_t = "Hi {name}, please see the document: {url}"
            subj = "Document for you"
        disp_choice = rng.random()
        if kind == "bec" or disp_choice < 0.25:
            disp, from_addr = f"{first} {last} (CEO)", f"{first.lower()}.{last.lower()}@{rng.choice(FREEMAIL)}"
        elif disp_choice < 0.75:
            disp = f"{brand.title()} Security"
            from_addr = f"{rng.choice(['security','support','alert','service'])}@{rng.choice([brand + '-' + rng.choice(KW) + '.' + rng.choice(PHISH_TLDS), _rid(rng, 8) + '.' + rng.choice(PHISH_TLDS)])}"
        else:
            disp, from_addr = f"{brand.title()} Support", f"support@{brand}.com"       # spoofed exact domain
        status = rng.choices(["fail", "none", "partial", "pass"], [0.50, 0.18, 0.14, 0.18])[0]
        if from_addr.split("@")[1] == f"{brand}.com":
            status = rng.choices(["fail", "none"], [0.8, 0.2])[0]
        reply = f"{first.lower()}{rng.randint(1,99)}@{rng.choice(FREEMAIL)}" if rng.random() < 0.55 else None
        if kind == "lure_attach" or rng.random() < 0.06:
            attach = (rng.choice([f"Invoice_{n}.html", f"scan_{n}.zip", f"Statement{n}.pdf.exe", f"payment_{n}.docm", f"doc_{n}.iso"]), b"MZ fake")
    body = body_t.format(name=name, w=w, b=b.split('.')[0].title(), n=n, url=link, sender=f"{first} {last}")
    msg["From"] = f'"{disp}" <{from_addr}>'
    msg["To"] = "user@recipient.example"
    msg["Subject"] = subj.format(w=w, b=b.split('.')[0].title(), n=n)
    msg["Date"] = formatdate(1_700_000_000 + rng.randint(0, 20_000_000))
    msg["Message-ID"] = make_msgid(domain=from_addr.split("@")[1])
    msg["Authentication-Results"] = _auth_header(rng, status, from_addr.split("@")[1])
    if reply:
        msg["Reply-To"] = reply
    if label == 1 and rng.random() < 0.3:
        msg["Return-Path"] = f"<bounce@{_rid(rng, 7)}.{rng.choice(PHISH_TLDS)}>"
    msg.set_content(body)
    if "http" in body and rng.random() < 0.8:
        shown = link
        if label == 1 and rng.random() < 0.45:           # anchor text lies about destination
            shown = f"https://www.{brand}.com/account"
        html_body = body.replace("\n", "<br>").replace(link, f'<a href="{link}">{shown}</a>')
        msg.add_alternative(f"<html><body>{html_body}</body></html>", subtype="html")
    if attach:
        msg.add_attachment(attach[1], maintype="application", subtype="octet-stream", filename=attach[0])
    return msg.as_string(), kind


def generate_emails(n: int = N_EMAILS, seed: int = SEED + 1) -> pd.DataFrame:
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        lab = i % 2
        raw, kind = build_eml(lab, rng)
        rows.append((raw, lab, kind))
    return pd.DataFrame(rows, columns=["raw", "label", "technique"])


def write_all(out_dir=DATA_DIR):
    out_dir.mkdir(parents=True, exist_ok=True)
    u = generate_urls()
    e = generate_emails()
    u.to_csv(out_dir / "urls.csv", index=False)
    e.to_json(out_dir / "emails.jsonl", orient="records", lines=True)
    return u, e
