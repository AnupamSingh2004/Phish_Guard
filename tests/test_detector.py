import json
import unittest
import urllib.request
from pathlib import Path
from _common import *
from phishguard.detector import PhishGuard
from phishguard.prevention import ListStore
from phishguard.api import start_background

NO_LISTS = lambda: ListStore(Path("/nonexistent/a"), Path("/nonexistent/b"))


class TestDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pg = PhishGuard(lists=NO_LISTS(), audit_log=False)

    def test_legit_urls_allowed(self):
        for u in ["https://www.wikipedia.org/wiki/Phishing", "https://accounts.google.com/signin", "https://www.paypal.com/signin",
                  "https://github.com/python/cpython"]:
            self.assertEqual(self.pg.scan_url(u, log_it=False)["action"], "ALLOW", u)

    def test_phishing_urls_blocked(self):
        for u in ["http://paypa1-secure-login.xyz/verify/account", "https://paypal.com.account-verify.top/login",
                  "http://185.220.101.7:8080/chase/login.php", "https://www.paypal.com@evil.top/signin"]:
            r = self.pg.scan_url(u, log_it=False)
            self.assertEqual(r["action"], "BLOCK", (u, r["risk"]))
            self.assertTrue(r["reasons"])

    def test_shortener_warns_not_blocks(self):
        self.assertEqual(self.pg.scan_url("https://bit.ly/3xYz9Qa", log_it=False)["action"], "WARN")

    def test_verdict_schema_and_defang(self):
        r = self.pg.scan_url("http://evil.top/x", log_it=False)
        for k in ["risk", "ml_probability", "rule_score", "label", "action", "reasons", "advice", "defanged", "latency_ms"]:
            self.assertIn(k, r)
        self.assertTrue(0 <= r["risk"] <= 100)
        self.assertNotIn("http://", r["defanged"])
        json.dumps(r)

    def test_blocklist_and_allowlist_override(self):
        d = Path(__import__("tempfile").mkdtemp())
        (d / "a").write_text("trusted.top\n"); (d / "b").write_text("paypal-login.xyz\n")
        pg = PhishGuard(lists=ListStore(d / "a", d / "b"), audit_log=False)
        self.assertEqual(pg.scan_url("https://paypal-login.xyz/", log_it=False)["risk"], 100.0)
        self.assertLessEqual(pg.scan_url("https://trusted.top/x", log_it=False)["risk"], 5.0)

    def test_auto_block_feedback_loop(self):
        d = Path(__import__("tempfile").mkdtemp())
        ls = ListStore(d / "a", d / "b")
        pg = PhishGuard(lists=ls, audit_log=False, auto_block=True)
        pg.scan_url("http://paypa1-secure-login.xyz/verify", log_it=False)
        self.assertIn("paypa1-secure-login.xyz", ls.block)
        self.assertEqual(pg.scan_url("https://paypa1-secure-login.xyz/new", log_it=False)["reasons"][0]["id"], "blocklist")

    def test_emails(self):
        exp = {"legit_github.eml": "ALLOW", "legit_colleague.eml": "ALLOW", "phishing_paypal.eml": "QUARANTINE",
               "phishing_bec.eml": "QUARANTINE", "phishing_attachment.eml": "QUARANTINE"}
        for f, act in exp.items():
            r = self.pg.scan_email((SAMPLES / f).read_text(), log_it=False)
            self.assertEqual(r["action"], act, (f, r["risk"]))

    def test_quarantined_email_is_sanitised(self):
        r = self.pg.scan_email((SAMPLES / "phishing_paypal.eml").read_text(), log_it=False)
        self.assertIn("WARNING", r["sanitised_body"])
        self.assertNotIn("http://paypa1", r["sanitised_body"])
        self.assertNotIn("sanitised_body", self.pg.scan_email((SAMPLES / "legit_github.eml").read_text(), log_it=False))

    def test_html(self):
        r = self.pg.scan_html((SAMPLES / "fake_login.html").read_text(), "http://secure-paypal-login.xyz/signin")
        self.assertEqual(r["action"], "BLOCK")
        r = self.pg.scan_html((SAMPLES / "legit_page.html").read_text(), "https://www.example-docs.org/")
        self.assertEqual(r["action"], "ALLOW")

    def test_robust_to_junk(self):
        for u in ["", "not a url", "http://", "a" * 3000, "javascript:alert(1)", "http://[::1]/"]:
            r = self.pg.scan_url(u, log_it=False)
            self.assertTrue(0 <= r["risk"] <= 100)
        self.pg.scan_email("garbage", log_it=False)


class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = start_background(PhishGuard(lists=NO_LISTS(), audit_log=False))
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def post(self, path, obj, raw=None):
        req = urllib.request.Request(self.base + path, data=raw if raw is not None else json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_health(self):
        with urllib.request.urlopen(self.base + "/health") as r:
            self.assertEqual(json.load(r), {"status": "ok"})

    def test_scan_url(self):
        c, b = self.post("/scan/url", {"url": "http://192.168.4.4/paypal/login.php"})
        self.assertEqual((c, b["action"]), (200, "BLOCK"))

    def test_scan_email(self):
        c, b = self.post("/scan/email", {"raw": (SAMPLES / "phishing_bec.eml").read_text()})
        self.assertEqual((c, b["action"]), (200, "QUARANTINE"))

    def test_scan_html(self):
        c, b = self.post("/scan/html", {"html": "<input type=password>", "url": "http://x.top/"})
        self.assertEqual(c, 200)

    def test_bad_requests(self):
        self.assertEqual(self.post("/scan/url", {})[0], 400)
        self.assertEqual(self.post("/scan/url", None, raw=b"{not json")[0], 400)
        self.assertEqual(self.post("/nope", {})[0], 404)

    def test_stats(self):
        with urllib.request.urlopen(self.base + "/stats") as r:
            self.assertIn("BLOCK", json.load(r))


if __name__ == "__main__":
    unittest.main()
