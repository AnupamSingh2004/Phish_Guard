import unittest
from _common import *
from phishguard.html_analyzer import analyze_html


class TestHtml(unittest.TestCase):
    def test_fake_login(self):
        s, hits = analyze_html((SAMPLES / "fake_login.html").read_text(), "http://secure-paypal-login.xyz/signin")
        i = {h[0] for h in hits}
        for k in ["password_field", "external_form_action", "hidden_iframe", "obfuscated_js", "meta_refresh",
                  "right_click_disabled", "external_links", "brand_on_foreign_domain"]:
            self.assertIn(k, i)
        self.assertEqual(s, 100)

    def test_legit_page(self):
        s, hits = analyze_html((SAMPLES / "legit_page.html").read_text(), "https://www.example-docs.org/")
        self.assertEqual((s, hits), (0, []))

    def test_same_domain_login_is_low(self):
        html = '<form action="https://www.site.com/login"><input type="password"></form>'
        s, hits = analyze_html(html, "https://www.site.com/")
        self.assertNotIn("external_form_action", {h[0] for h in hits})
        self.assertLess(s, 30)

    def test_garbage_html(self):
        analyze_html("<<<>>><form <input", "")
        analyze_html("", "")


if __name__ == "__main__":
    unittest.main()
