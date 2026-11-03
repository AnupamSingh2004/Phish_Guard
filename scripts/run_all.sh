#!/usr/bin/env bash
# PhishGuard - run EVERYTHING: environment check -> data -> train -> evaluate -> tests -> live demo -> report.
# All console output is also saved under outputs/ and logs/.   Usage: ./scripts/run_all.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD/src" PYTHONDONTWRITEBYTECODE=1
mkdir -p logs outputs reports models data
: > logs/phishguard.log; : > logs/audit.jsonl; : > logs/tests.log; : > logs/run_all.log
exec > >(tee -a logs/run_all.log) 2>&1

B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; N=$'\033[0m'
step() { echo; echo "${B}################################################################################"; echo "# STEP $1: $2"; echo "################################################################################${N}"; }
START=$(date +%s)

step 1/6 "Environment check"
echo "date     : $(date -Is)"; echo "host     : $(uname -srm)"; echo "python   : $(python3 --version)"
python3 - <<'PY'
import sklearn, numpy, pandas, joblib
print("sklearn  :", sklearn.__version__, "| numpy:", numpy.__version__, "| pandas:", pandas.__version__)
PY
echo "project  : $PWD"
echo "gemini   : $([ -n "${GEMINI_API_KEY:-}" ] && echo 'GEMINI_API_KEY set (LLM explanations enabled)' || echo 'not set (local explanations; optional feature)')"

step 2/6 "Generate data, train models, evaluate on held-out set"
python3 -m phishguard train 2>&1 | tee outputs/01_train_and_evaluate.txt

step 3/6 "Test suite (unit + integration + API + model-quality gates)"
set +e
python3 tests/run_tests.py 2>&1 | tee outputs/02_tests.txt
TEST_RC=${PIPESTATUS[0]}
set -e

step 4/6 "Live demo: URLs, e-mails, HTML pages, prevention, REST API"
python3 -m phishguard demo 2>&1 | tee outputs/03_demo.txt

step 5/6 "CLI examples"
python3 -m phishguard scan-url "http://paypa1-secure-login.xyz/verify" "https://www.github.com/" 2>&1 | tee outputs/04_cli_scan_url.txt
python3 -m phishguard scan-email samples/phishing_paypal.eml 2>&1 | tee outputs/05_cli_scan_email.txt

step 6/6 "Artifacts"
echo "--- reports/ ---";  ls -1 reports
echo "--- outputs/ ---";  ls -1 outputs
echo "--- logs/ ---";     ls -l logs | tail -n +2
echo "--- audit trail (last 5 of $(wc -l < logs/audit.jsonl) events) ---"; tail -n 5 logs/audit.jsonl | cut -c1-200
echo; cat reports/url_confusion_matrix.txt reports/email_confusion_matrix.txt
echo "--- test summary ---"; cat reports/test_results.json
END=$(date +%s)
echo
if [ "$TEST_RC" -eq 0 ]; then echo "${G}${B}ALL STEPS COMPLETE - ALL TESTS PASSED${N} (total $((END-START))s)"; else echo "${R}${B}TESTS FAILED${N}"; exit 1; fi
