import unittest
from _common import *
from phishguard.url_features import extract_features, rule_score, split_host, levenshtein, vectorize, FEATURE_NAMES, entropy


def ids(url):
    return {h[0] for h in rule_score(extract_features(url))[1]}


class TestHostParsing(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(split_host("www.example.com"), ("www", "example", "com", "example.com"))

    def test_multi_part_suffix(self):
        self.assertEqual(split_host("a.b.bbc.co.uk")[3], "bbc.co.uk")

    def test_hosting_suffix(self):
        self.assertEqual(split_host("evil.github.io")[3], "evil.github.io")

    def test_ip(self):
        self.assertEqual(split_host("10.0.0.1")[3], "10.0.0.1")

    def test_levenshtein(self):
        self.assertEqual(levenshtein("kitten", "sitting"), 3)
        self.assertEqual(levenshtein("", "abc"), 3)

    def test_entropy(self):
        self.assertEqual(entropy(""), 0.0)
        self.assertGreater(entropy("a1b2c3d4"), entropy("aaaaaaaa"))


class TestFeatures(unittest.TestCase):
    def test_vector_shape(self):
        self.assertEqual(len(vectorize("https://example.com")), len(FEATURE_NAMES))

    def test_scheme_less_url(self):
        self.assertEqual(extract_features("example.com/login")["is_https"], 0.0)

    def test_malformed_port_does_not_crash(self):
        extract_features("http://example.com:99999999/x")

    def test_garbage_input_does_not_crash(self):
        for u in ["", "   ", "://", "http://", "http:///x", "\x00\x01", "a" * 5000, "http://[::1]/x"]:
            extract_features(u)


class TestRules(unittest.TestCase):
    def test_legit_clean(self):
        for u in ["https://www.paypal.com/signin", "https://accounts.google.com/signin", "https://github.com/a/b",
                  "https://docs.microsoft.com/en-us/", "https://aws.amazonaws.com/s3", "https://login.microsoftonline.com/x"]:
            self.assertEqual(rule_score(extract_features(u))[0], 0, u)

    def test_ip_host(self):
        self.assertIn("ip_host", ids("http://192.168.1.5/login"))

    def test_at_symbol_uses_real_host(self):
        f = extract_features("https://paypal.com@evil.xyz/x")
        self.assertEqual(f["has_at_symbol"], 1.0)
        self.assertEqual(f["brand_mismatch"], 0.0)   # real host is evil.xyz, no brand in it

    def test_typosquat_leet(self):
        self.assertIn("typosquat", ids("http://paypa1.com/login"))

    def test_typosquat_swap(self):
        self.assertIn("typosquat", ids("http://paypla.com/"))

    def test_brand_in_subdomain(self):
        self.assertIn("brand_mismatch", ids("https://paypal.com.verify-now.top/"))

    def test_combosquat(self):
        self.assertIn("brand_mismatch", ids("https://amazon-support.work/"))

    def test_punycode_homoglyph(self):
        host = "раypal.com".encode("idna").decode()   # Cyrillic 'р' and 'а'
        self.assertIn("punycode", ids(f"https://{host}/"))
        self.assertIn("brand_mismatch", ids(f"https://{host}/"))

    def test_exec(self):
        self.assertIn("exec_download", ids("http://a.top/setup.exe"))

    def test_open_redirect(self):
        self.assertIn("open_redirect", ids("https://x.com/r?url=http://evil.top"))

    def test_score_capped(self):
        self.assertLessEqual(rule_score(extract_features("http://1.2.3.4:81/paypal-login@x.top/a.exe?u=http://e.top"))[0], 100)

    def test_official_brand_domain_not_flagged(self):
        self.assertNotIn("brand_mismatch", ids("https://www.amazon.co.uk/orders"))


if __name__ == "__main__":
    unittest.main()
