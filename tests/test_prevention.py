import tempfile
import unittest
from pathlib import Path
from _common import *
from phishguard.prevention import ListStore, PolicyEngine, defang, neutralise_links, tips_for


class TestPrevention(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "a.txt").write_text("# c\ngood.com\n")
        (self.d / "b.txt").write_text("bad.top  # note\n")
        self.ls = ListStore(self.d / "a.txt", self.d / "b.txt")

    def test_lists_match_registered_domain_and_subdomains(self):
        self.assertEqual(self.ls.status("https://www.bad.top/x"), "block")
        self.assertEqual(self.ls.status("https://a.b.good.com/"), "allow")
        self.assertIsNone(self.ls.status("https://other.org"))

    def test_userinfo_trick_cannot_borrow_allowlist(self):
        self.assertEqual(self.ls.status("https://good.com@bad.top/"), "block")
        self.assertIsNone(self.ls.status("https://good.com.evil.org/"))

    def test_add_block_persists_and_dedups(self):
        self.assertTrue(self.ls.add_block("http://new.evil.xyz/a"))
        self.assertFalse(self.ls.add_block("http://new.evil.xyz/b"))
        self.assertIn("evil.xyz", ListStore(self.d / "a.txt", self.d / "b.txt").block)

    def test_missing_files(self):
        ls = ListStore(Path("/nonexistent/1"), Path("/nonexistent/2"))
        self.assertEqual((ls.allow, ls.block), (set(), set()))

    def test_policy_bands(self):
        p = PolicyEngine()
        self.assertEqual(p.decide(0).action, "ALLOW")
        self.assertEqual(p.decide(29.9).action, "ALLOW")
        self.assertEqual(p.decide(30).action, "WARN")
        self.assertEqual(p.decide(50).action, "BLOCK")
        self.assertEqual(p.decide(50, "email").action, "QUARANTINE")

    def test_defang(self):
        self.assertEqual(defang("https://evil.com/a.php"), "hxxps://evil[.]com/a[.]php")

    def test_neutralise(self):
        out = neutralise_links("click http://e.com/x now", {"http://e.com/x"})
        self.assertNotIn("http://e.com", out)
        self.assertIn("LINK DISABLED", out)

    def test_tips(self):
        self.assertTrue(tips_for(["ip_host", "unknown"]))


if __name__ == "__main__":
    unittest.main()
