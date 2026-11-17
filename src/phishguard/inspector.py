"""Interactive / verbose inspection: shows EVERY step of how a verdict was reached.

Used by `python -m phishguard analyze ...` and `python -m phishguard interactive`.
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path

import numpy as np

from .config import BLOCK_AT, ML_WEIGHT, SAMPLES_DIR, WARN_AT
from .email_analyzer import analyze_email
from .html_analyzer import analyze_html
from .url_features import FEATURE_NAMES, RULES, extract_features, parse_url, rule_score, split_host

_TTY = sys.stdout.isatty()


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _TTY else str(s)


def _head(title):
    print("\n" + _c("1;36", "=" * 78))
    print(_c("1;36", f" {title}"))
    print(_c("1;36", "=" * 78))


def _band(action, risk):
    col = {"ALLOW": "1;32", "WARN": "1;33", "BLOCK": "1;31", "QUARANTINE": "1;31"}[action]
    bar = "#" * int(risk / 5)
    return f"risk {risk:5.1f}/100  |{bar:<20}|  " + _c(col, action)


def inspect_url(pg, url: str):
    _head(f"URL ANALYSIS: {url}")
    full, p, host = parse_url(url)
    sub, label, suffix, reg = split_host(host)
    print(_c("1", "\nSTEP 1  Parse the URL"))
    for k, v in [("scheme", p.scheme), ("host", host), ("subdomain", sub or "-"), ("name label", label),
                 ("suffix (TLD)", suffix or "-"), ("REGISTERED DOMAIN", reg), ("path", p.path or "/"), ("query", p.query or "-")]:
        print(f"   {k:<18}{v}")
    print("   -> the registered domain is who REALLY owns the site: " + _c("1", reg))
    st = pg.lists.status(url)
    print(_c("1", "\nSTEP 2  Allow / block lists"))
    print("   " + {"block": _c("31", "domain is on the BLOCKLIST -> risk forced to 100"),
                   "allow": _c("32", "domain is on the ALLOWLIST -> risk capped at 5"), None: "not listed (normal scoring)"}[st])

    f = extract_features(url)
    print(_c("1", "\nSTEP 3  The 30 extracted features  (non-zero values highlighted)"))
    cols = 2
    for i in range(0, len(FEATURE_NAMES), cols):
        line = ""
        for n in FEATURE_NAMES[i:i + cols]:
            v = f[n]
            txt = f"{n:<24}{v:>8.3f}" if v != int(v) else f"{n:<24}{int(v):>8}"
            line += (_c("33", txt) if v else txt) + "     "
        print("   " + line)

    rs, hits = rule_score(f)
    print(_c("1", "\nSTEP 4  Explainable rules fired"))
    if hits:
        for rid, w, desc in hits:
            print(f"   +{w:<3} [{rid}] {desc}")
    else:
        print("   (none fired)")
    print(f"   rule score = min(100, {' + '.join(str(w) for _, w, _ in hits) or '0'}) = {_c('1', rs)}")

    X = np.array([[f[k] for k in FEATURE_NAMES]])
    print(_c("1", "\nSTEP 5  Machine-learning models vote  (P = probability of phishing)"))
    for name, est in pg.url_bundle["members"].items():
        pr = float(est.predict_proba(X)[0, 1])
        print(f"   {name:<14} P = {pr:.4f}  {'#' * int(pr * 30)}")
    pe = float(pg.url_bundle["model"].predict_proba(X)[0, 1])
    print(f"   {'ENSEMBLE':<14} P = {_c('1', f'{pe:.4f}')}   (soft vote, weights 1:2:2)")

    v = pg.scan_url(url, log_it=True)
    print(_c("1", "\nSTEP 6  Hybrid risk score"))
    print(f"   risk = {ML_WEIGHT:.2f} x {pe:.4f} x 100  +  {1 - ML_WEIGHT:.2f} x {rs}  =  {ML_WEIGHT * pe * 100 + (1 - ML_WEIGHT) * rs:.1f}"
          + ("   (then list override applied)" if st else ""))
    print(f"   bands: ALLOW < {WARN_AT} <= WARN < {BLOCK_AT} <= BLOCK")
    print(_c("1", "\nSTEP 7  FINAL VERDICT"))
    print("   " + _band(v["action"], v["risk"]) + f"   [{v['label']}]")
    print(f"   safe (defanged) form: {v['defanged']}")
    for t in v["advice"]:
        print("   * tip: " + t)
    print(f"   scan time: {v['latency_ms']} ms")
    return v


def inspect_email(pg, path: str):
    raw = Path(path).read_text(errors="replace")
    _head(f"E-MAIL ANALYSIS: {path}")
    a = analyze_email(raw)
    print(_c("1", "\nSTEP 1  Parsed headers"))
    print(f"   From      : {a.display_name!r} <{a.from_addr}>  (domain {a.from_domain})")
    print(f"   Subject   : {a.subject}")
    print(f"   Auth      : SPF={a.auth['spf']}  DKIM={a.auth['dkim']}  DMARC={a.auth['dmarc']}")
    print(f"   Attachments: {a.attachments or 'none'}")
    print(_c("1", "\nSTEP 2  Forensic findings (header score)"))
    for i, w, d in a.findings:
        print(f"   +{w:<3} [{i}] {d}")
    if not a.findings:
        print("   (none)")
    print(f"   header score = {_c('1', a.header_score)} / 100")
    print(_c("1", f"\nSTEP 3  Links found in the message ({len(a.urls)})"))
    for u in a.urls:
        r = pg.scan_url(u, log_it=False)
        print(f"   {r['action']:<6} risk {r['risk']:5.1f}  {r['defanged']}")
    v = pg.scan_email(raw)
    print(_c("1", "\nSTEP 4  Signals fed to the stacker (logistic regression)"))
    print(f"   header_score/100  = {a.header_score / 100:.2f}")
    print(f"   text probability  = {v['text_probability']:.4f}   (TF-IDF + logistic regression on subject/body)")
    print(f"   highest link risk = {v['url_max_risk']:.1f}")
    print(f"   link mismatch     = {a.flags['link_mismatch']}   attachment risk = {a.flags['attachment_risk']}   n_urls = {len(a.urls)}")
    print(_c("1", "\nSTEP 5  FINAL VERDICT"))
    print("   " + _band(v["action"], v["risk"]) + f"   [{v['label']}]")
    for t in v["advice"]:
        print("   * tip: " + t)
    if "sanitised_body" in v:
        print(_c("1", "\n   Body delivered to the user (links disabled):"))
        print("   | " + v["sanitised_body"].replace("\n", "\n   | ")[:600])
    return v


def inspect_html(pg, path: str, url: str = ""):
    html = Path(path).read_text(errors="replace")
    _head(f"WEB-PAGE ANALYSIS: {path}  (page address: {url or 'not given'})")
    score, hits = analyze_html(html, url)
    print(_c("1", "\nSTEP 1  Page indicators"))
    for i, w, d in hits:
        print(f"   +{w:<3} [{i}] {d}")
    if not hits:
        print("   (none)")
    print(f"   page score = {_c('1', score)} / 100")
    v = pg.scan_html(html, url)
    print(_c("1", "\nSTEP 2  Combined with the URL risk"))
    print("   " + _band(v["action"], v["risk"]) + f"   [{v['label']}]")
    return v


HELP = """\
Commands (type one per line):
  <url>                    analyse a URL, e.g.  http://paypa1-secure.xyz/login
  url <url>                same as above
  email <file.eml>         analyse an e-mail file
  html <file.html> [url]   analyse a saved web page (optionally with its address)
  batch <file.txt>         scan every URL in a text file (one per line), summary table
  samples                  list the bundled sample files you can try
  stats                    counters for this session
  help                     show this help
  quit                     leave"""


def batch(pg, path: str):
    urls = [l.strip() for l in Path(path).read_text().splitlines() if l.strip() and not l.startswith("#")]
    _head(f"BATCH SCAN: {len(urls)} URLs from {path}")
    print(f"   {'ACTION':<7}{'RISK':>6}   URL / top reasons")
    for u in urls:
        r = pg.scan_url(u, log_it=False)
        col = {"ALLOW": "32", "WARN": "33", "BLOCK": "31"}[r["action"]]
        print(f"   {_c(col, f'{r['action']:<7}')}{r['risk']:>6.1f}   {r['defanged'][:55]}  [{', '.join(x['id'] for x in r['reasons'][:3])}]")


def handle(pg, line: str) -> bool:
    """Process one command line. Returns False when the user wants to quit."""
    line = line.strip()
    if not line:
        return True
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    cmd, args = parts[0].lower(), parts[1:]
    try:
        if cmd in ("quit", "exit", "q"):
            return False
        if cmd == "help":
            print(HELP)
        elif cmd == "samples":
            print("   URL list : samples/urls.txt   (use: batch samples/urls.txt)")
            for f in sorted(SAMPLES_DIR.glob("*.eml")) + sorted(SAMPLES_DIR.glob("*.html")):
                print(f"   {f.suffix[1:]:<5}: samples/{f.name}")
        elif cmd == "stats":
            print("  ", pg.stats)
        elif cmd == "email" and args:
            inspect_email(pg, args[0])
        elif cmd == "html" and args:
            inspect_html(pg, args[0], args[1] if len(args) > 1 else "")
        elif cmd == "batch" and args:
            batch(pg, args[0])
        elif cmd == "url" and args:
            inspect_url(pg, args[0])
        elif cmd in ("email", "html", "batch", "url"):
            print(f"   usage: see 'help' ({cmd} needs an argument)")
        else:
            p = Path(line)
            if p.suffix == ".eml" and p.exists():
                inspect_email(pg, line)
            elif p.suffix in (".html", ".htm") and p.exists():
                inspect_html(pg, line)
            else:
                inspect_url(pg, line)       # anything else is treated as a URL
    except FileNotFoundError as ex:
        print(_c("31", f"   file not found: {ex.filename}"))
    return True


def repl(pg):
    print(_c("1;36", "\nPhishGuard interactive mode") + " - type a URL, or 'help'. Ctrl-D or 'quit' to leave.")
    print("Try:  http://paypa1-secure-login.xyz/verify    |    https://www.github.com/    |    email samples/phishing_paypal.eml")
    while True:
        try:
            line = input(_c("1;32", "\nphishguard> "))
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not handle(pg, line):
            break
    print("Session:", pg.stats, "\nAudit trail: logs/audit.jsonl")
