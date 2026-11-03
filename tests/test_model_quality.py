"""Quality gates on the metrics produced by `train` (reports/*.json). Fails the build if the models regress."""
import json
import unittest
from _common import *

R = ROOT / "reports"


@unittest.skipUnless((R / "url_metrics.json").exists(), "run `train` first")
class TestQualityGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.u = json.loads((R / "url_metrics.json").read_text())
        cls.e = json.loads((R / "email_metrics.json").read_text())

    def test_url_hybrid_gates(self):
        m = self.u["systems"]["HYBRID (production)"]
        self.assertGreaterEqual(m["roc_auc"], 0.97)
        self.assertGreaterEqual(m["precision"], 0.94)
        self.assertGreaterEqual(m["f1"], 0.85)
        self.assertLessEqual(m["false_positive_rate"], 0.05)

    def test_url_flagged_recall(self):
        self.assertGreaterEqual(self.u["systems"]["HYBRID flagged (WARN+BLOCK)"]["recall"], 0.93)

    def test_hybrid_beats_rules_only(self):
        s = self.u["systems"]
        self.assertGreater(s["HYBRID (production)"]["f1"], s["rules_only"]["f1"] + 0.2)

    def test_email_pipeline_gates(self):
        m = self.e["systems"]["FULL PIPELINE"]
        self.assertGreaterEqual(m["f1"], 0.95)
        self.assertLessEqual(m["false_positive_rate"], 0.02)

    def test_fusion_beats_single_signals(self):
        s = self.e["systems"]
        self.assertGreaterEqual(s["FULL PIPELINE"]["f1"], s["header_rules_only"]["f1"])
        self.assertGreaterEqual(s["FULL PIPELINE"]["f1"], s["text_model_only"]["f1"])

    def test_latency(self):
        self.assertLess(self.u["avg_latency_ms"], 250)

    def test_no_leakage_recorded(self):
        self.assertGreater(self.u["test_size"], 1000)


if __name__ == "__main__":
    unittest.main()
