"""Command line interface:  python -m phishguard <command>"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from .config import ROOT, SAMPLES_DIR
from .logger import get_logger

log = get_logger("phishguard.cli")


def _show(v: dict):
    bar = "#" * int(v["risk"] / 5)
    print(f"\n  {v['type'].upper():5} {v.get('defanged') or v.get('subject') or v['target']}")
    print(f"  risk {v['risk']:5.1f}/100 |{bar:<20}| -> {v['action']} ({v['label']})")
    for r in v["reasons"][:7]:
        print(f"     - [{r['id']}] {r['text']}")
    for t in v.get("advice", [])[:3]:
        print(f"     * tip: {t}")


def cmd_demo(_):
    from .api import start_background
    from .detector import PhishGuard
    from .llm_explain import explain
    pg = PhishGuard(auto_block=False)
    print("\n" + "=" * 78 + "\n 1. URL SCANNING\n" + "=" * 78)
    urls = [l.strip() for l in (SAMPLES_DIR / "urls.txt").read_text().splitlines() if l.strip() and not l.startswith("#")]
    for u in urls:
        _show(pg.scan_url(u))
    print("\n" + "=" * 78 + "\n 2. E-MAIL SCANNING (headers + text + links + attachments)\n" + "=" * 78)
    for f in sorted(SAMPLES_DIR.glob("*.eml")):
        print(f"\n  >> {f.name}")
        v = pg.scan_email(f.read_text())
        _show(v)
        print(f"     auth: {v['auth']}  attachments: {v['attachments']}")
        if "sanitised_body" in v:
            print("     --- sanitised body delivered to user ---")
            print("     " + v["sanitised_body"].replace("\n", "\n     ")[:420])
    print("\n" + "=" * 78 + "\n 3. WEB-PAGE (HTML) ANALYSIS\n" + "=" * 78)
    for f, url in [("fake_login.html", "http://secure-paypal-login.xyz/signin"), ("legit_page.html", "https://www.example-docs.org/")]:
        _show(pg.scan_html((SAMPLES_DIR / f).read_text(), url))
    print("\n" + "=" * 78 + "\n 4. PREVENTION: FEEDBACK LOOP (auto-block after confirmed phishing)\n" + "=" * 78)
    from .prevention import ListStore
    tmp = ListStore(Path("/nonexistent/a"), Path("/nonexistent/b"))
    pg2 = PhishGuard(lists=tmp, url_bundle=pg.url_bundle, email_bundle=pg.email_bundle, audit_log=True)
    u = "http://paypa1-secure.xyz/login"
    pg2.scan_url(u)
    tmp.add_block(u, persist=False)
    r = pg2.scan_url("https://paypa1-secure.xyz/other-page")
    print(f"  after blocklisting: risk={r['risk']} action={r['action']} reason={r['reasons'][0]['text']}")
    print("\n" + "=" * 78 + "\n 5. REST API (live server on an ephemeral port)\n" + "=" * 78)
    srv = start_background(pg)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    def call(path, payload=None):
        req = urllib.request.Request(base + path, data=json.dumps(payload).encode() if payload else None,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    print("  GET  /health          ->", call("/health"))
    v = call("/scan/url", {"url": "http://192.168.4.4:8080/paypal/login.php"})
    print(f"  POST /scan/url        -> action={v['action']} risk={v['risk']} reasons={[r['id'] for r in v['reasons']]}")
    v = call("/scan/email", {"raw": (SAMPLES_DIR / "phishing_bec.eml").read_text()})
    print(f"  POST /scan/email      -> action={v['action']} risk={v['risk']}")
    print("  GET  /stats           ->", call("/stats"))
    srv.shutdown()
    print("\n" + "=" * 78 + "\n 6. EXPLANATION LAYER (Gemini if GEMINI_API_KEY set, otherwise local)\n" + "=" * 78)
    print("  ", explain(pg.scan_url("https://paypal.com.account-verify.top/login", log_it=False)))
    print(f"\nSession stats: {pg.stats}\nAudit trail: {ROOT/'logs'/'audit.jsonl'}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phishguard", description="Phishing detection & prevention toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("train", help="generate data, train models, evaluate, write reports")
    s = sub.add_parser("scan-url"); s.add_argument("url", nargs="+")
    s = sub.add_parser("scan-email"); s.add_argument("file", nargs="+")
    s = sub.add_parser("scan-html"); s.add_argument("file"); s.add_argument("--url", default="")
    s = sub.add_parser("serve"); s.add_argument("--port", type=int, default=8765)
    sub.add_parser("demo", help="run every feature on the bundled samples")
    s = sub.add_parser("analyze", help="verbose step-by-step analysis of URLs / .eml / .html files")
    s.add_argument("targets", nargs="+"); s.add_argument("--url", default="", help="page address when analysing an .html file")
    sub.add_parser("interactive", help="prompt where you type your own URLs / e-mails / pages")
    a = ap.parse_args(argv)

    if a.cmd == "train":
        from .evaluate import run_pipeline
        run_pipeline()
        return 0
    if a.cmd == "demo":
        return cmd_demo(a) or 0
    from .detector import PhishGuard
    pg = PhishGuard()
    if a.cmd == "interactive":
        from .inspector import repl
        repl(pg)
    elif a.cmd == "analyze":
        from .inspector import handle
        for t in a.targets:
            handle(pg, f"html {t} {a.url}" if t.endswith((".html", ".htm")) and a.url else t)
    elif a.cmd == "scan-url":
        for u in a.url:
            _show(pg.scan_url(u))
    elif a.cmd == "scan-email":
        for f in a.file:
            _show(pg.scan_email(Path(f).read_text()))
    elif a.cmd == "scan-html":
        _show(pg.scan_html(Path(a.file).read_text(), a.url))
    elif a.cmd == "serve":
        from .api import make_server
        srv = make_server(pg, port=a.port)
        log.info("PhishGuard API listening on http://127.0.0.1:%d  (POST /scan/url|email|html)", a.port)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log.info("shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
