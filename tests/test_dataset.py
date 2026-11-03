import unittest
from _common import *
from phishguard.dataset import generate_urls, generate_emails, split_by_group


class TestDataset(unittest.TestCase):
    def test_deterministic(self):
        a, b = generate_urls(300, seed=7), generate_urls(300, seed=7)
        self.assertEqual(a.url.tolist(), b.url.tolist())
        self.assertNotEqual(a.url.tolist(), generate_urls(300, seed=8).url.tolist())

    def test_balanced(self):
        self.assertAlmostEqual(generate_urls(1000).label.mean(), 0.5, delta=0.03)

    def test_no_group_leakage(self):
        tr, te = split_by_group(generate_urls(3000))
        self.assertFalse(set(tr.group) & set(te.group))
        self.assertGreater(len(te), 300)

    def test_emails_parse(self):
        from phishguard.email_analyzer import analyze_email
        e = generate_emails(40)
        for raw in e.raw:
            self.assertTrue(analyze_email(raw).from_domain)
        self.assertEqual(e.label.sum(), 20)


if __name__ == "__main__":
    unittest.main()
