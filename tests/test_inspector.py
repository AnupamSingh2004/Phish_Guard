import contextlib
import io
import unittest
from pathlib import Path
from _common import *
from phishguard.detector import PhishGuard
from phishguard.inspector import handle
from phishguard.prevention import ListStore


def run(pg, line):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        keep = handle(pg, line)
    return keep, buf.getvalue()


class TestInspector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pg = PhishGuard(lists=ListStore(Path("/nonexistent/a"), Path("/nonexistent/b")), audit_log=False)

    def test_url_shows_every_step(self):
        keep, out = run(self.pg, "http://paypa1-secure-login.xyz/verify")
        self.assertTrue(keep)
        for s in ["STEP 1", "STEP 3", "STEP 4", "STEP 5", "STEP 6", "FINAL VERDICT", "BLOCK", "typosquat", "REGISTERED DOMAIN"]:
            self.assertIn(s, out)

    def test_legit_url_allowed(self):
        self.assertIn("ALLOW", run(self.pg, "https://www.github.com/")[1])

    def test_email_file(self):
        out = run(self.pg, f"email {SAMPLES / 'phishing_paypal.eml'}")[1]
        self.assertIn("QUARANTINE", out)
        self.assertIn("LINK DISABLED", out)

    def test_template_email_runs(self):
        self.assertIn("FINAL VERDICT", run(self.pg, f"email {SAMPLES / 'templates' / 'my_email_template.eml'}")[1])

    def test_html_file(self):
        out = run(self.pg, f"html {SAMPLES / 'fake_login.html'} http://secure-paypal-login.xyz/signin")[1]
        self.assertIn("BLOCK", out)

    def test_batch(self):
        out = run(self.pg, f"batch {SAMPLES / 'urls.txt'}")[1]
        self.assertIn("BATCH SCAN: 13", out)

    def test_commands_and_errors(self):
        self.assertFalse(run(self.pg, "quit")[0])
        self.assertIn("Commands", run(self.pg, "help")[1])
        self.assertIn("file not found", run(self.pg, "email /no/such.eml")[1])
        self.assertTrue(run(self.pg, "")[0])
        self.assertIn("usage", run(self.pg, "email")[1])
        run(self.pg, "not a url at all ###")        # must never crash


if __name__ == "__main__":
    unittest.main()
