import unittest
from _common import *
from phishguard.email_analyzer import analyze_email


def ids(name):
    a = analyze_email((SAMPLES / name).read_text())
    return a, {f[0] for f in a.findings}


class TestEmailAnalyzer(unittest.TestCase):
    def test_phishing_paypal(self):
        a, i = ids("phishing_paypal.eml")
        for k in ["spf_fail", "dmarc_fail", "reply_to_mismatch", "display_name_spoof", "link_text_mismatch", "credential_request"]:
            self.assertIn(k, i)
        self.assertEqual(a.header_score, 100)
        self.assertIn("http://paypa1-secure-login.xyz/verify/account", a.urls)

    def test_trailing_punctuation_stripped(self):
        raw = "From: a@b.com\nSubject: x\n\nsee https://example.com/page."
        self.assertEqual(analyze_email(raw).urls, ["https://example.com/page"])

    def test_bec(self):
        _, i = ids("phishing_bec.eml")
        self.assertIn("exec_freemail", i)
        self.assertIn("financial_lure", i)

    def test_attachment(self):
        a, i = ids("phishing_attachment.eml")
        self.assertIn("dangerous_attachment", i)
        self.assertIn("double_extension", i)
        self.assertEqual(a.attachments, ["Statement4471.pdf.exe"])

    def test_legit_has_no_findings(self):
        for f in ["legit_github.eml", "legit_colleague.eml"]:
            a, i = ids(f)
            self.assertEqual(i, set(), f)
            self.assertEqual(a.auth, {"spf": "pass", "dkim": "pass", "dmarc": "pass", "header_present": True})

    def test_missing_auth_header(self):
        a = analyze_email("From: x@y.com\nSubject: hi\n\nhello")
        self.assertIn("no_auth_results", {f[0] for f in a.findings})

    def test_malformed_email_no_crash(self):
        for raw in ["", "not an email", "From: \n\n", "\x00\x01\x02"]:
            analyze_email(raw)


if __name__ == "__main__":
    unittest.main()
