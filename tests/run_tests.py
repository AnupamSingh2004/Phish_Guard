"""Run the whole suite verbosely; write a log to logs/tests.log and a JSON summary to reports/test_results.json."""
import json
import sys
import time
import unittest
from _common import ROOT

(ROOT / "logs").mkdir(exist_ok=True); (ROOT / "reports").mkdir(exist_ok=True)
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_*.py", top_level_dir=str(ROOT / "tests"))
log = open(ROOT / "logs" / "tests.log", "w")


class Tee:
    def write(self, s): sys.stdout.write(s); log.write(s)
    def flush(self): sys.stdout.flush(); log.flush()


t0 = time.time()
res = unittest.TextTestRunner(stream=Tee(), verbosity=2).run(suite)
summary = {"tests_run": res.testsRun, "failures": len(res.failures), "errors": len(res.errors),
           "skipped": len(res.skipped), "passed": res.testsRun - len(res.failures) - len(res.errors) - len(res.skipped),
           "seconds": round(time.time() - t0, 2)}
(ROOT / "reports" / "test_results.json").write_text(json.dumps(summary, indent=2))
print("SUMMARY", json.dumps(summary))
sys.exit(0 if res.wasSuccessful() else 1)
