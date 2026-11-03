# PhishGuard — Phishing Detection & Prevention Toolkit

A complete, self-contained system that **detects** phishing in URLs, e-mails and web pages, **explains** every
verdict, and **prevents** harm (block / warn / quarantine, link neutralisation, allow/block lists, a self-updating
feedback loop, audit trail and a REST API). Pure Python; no network access is needed to scan anything.

> **Run everything with one command:** `./scripts/run_all.sh` (≈90 s). It checks the environment, generates data,
> trains and evaluates the models, runs 68 tests, runs a live demo of every feature, and saves all output to
> `logs/` and `outputs/`.

---------------------------------------------------------------------------------------------------------------

## 1. Architecture

```
                         ┌────────────────────────── PhishGuard detector ──────────────────────────┐
  URL ───────────────►   │ url_features (30 lexical/host features) ─► ML ensemble (LR+RF+GB) ┐      │
                         │                              └──► 16 explainable rules ───────────┴► hybrid risk 0-100
  E-mail (.eml) ─────►   │ email_analyzer: SPF/DKIM/DMARC, Reply-To/Return-Path, display-name    │   │
                         │   spoofing, BEC, anchor-vs-href mismatch, attachments ► header score  │   │
                         │ TF-IDF text classifier ► text probability                             │   │
                         │ every embedded link ► URL detector ► max link risk                    │   │
                         │ logistic-regression STACKER fuses all signals ───────────────────────►│   │
  HTML page ─────────►   │ html_analyzer: password forms posting off-site, hidden iframes, eval/atob, … │
                         └───────────────────────────────────┬──────────────────────────────────────┘
                                                             ▼
        Prevention layer:  allow/block lists → policy engine (ALLOW <30 · WARN 30-50 · BLOCK/QUARANTINE ≥50)
        link neutralisation · defanging · warning banner · user-awareness tips · auto-block feedback loop
        · JSON-lines audit log · REST API (/scan/url|email|html, /health, /stats)
```

| Module | Purpose |
|---|---|
| [`url_features.py`](src/phishguard/url_features.py) | Host parsing, Damerau-Levenshtein typosquat detection, leetspeak/homoglyph folding, IP/`@`/punycode/shortener/TLD checks, 16 weighted rules |
| [`email_analyzer.py`](src/phishguard/email_analyzer.py) | RFC-822 forensics: auth results, sender spoofing, BEC, link mismatch, dangerous/double-extension attachments |
| [`html_analyzer.py`](src/phishguard/html_analyzer.py) | Static page analysis (no JS execution) |
| [`models.py`](src/phishguard/models.py) | URL soft-voting ensemble; e-mail text model + stacker trained on **out-of-fold** predictions (no leakage) |
| [`detector.py`](src/phishguard/detector.py) | Orchestrates everything; returns a JSON-serialisable verdict with reasons |
| [`prevention.py`](src/phishguard/prevention.py) | Lists, policy, defang, neutralise, tips, feedback loop |
| [`api.py`](src/phishguard/api.py) | stdlib REST server (size-limited, input-validated, no stack-trace leaks) |
| [`llm_explain.py`](src/phishguard/llm_explain.py) | *Optional* Gemini plain-English explanation (see §7) |
| [`evaluate.py`](src/phishguard/evaluate.py) | Train + evaluate + write reports/SVG charts |
| [`dataset.py`](src/phishguard/dataset.py) | Deterministic URL & e-mail generators (13 URL attack techniques, 4 e-mail families, hard cases) |

## 2. Quick start

```bash
pip install -r requirements.txt          # scikit-learn, numpy, pandas, joblib
./scripts/run_all.sh                     # everything, with logs
# or individually (from this folder):
export PYTHONPATH=src
python3 -m phishguard train              # data + models + reports
python3 tests/run_tests.py               # 68 tests
python3 -m phishguard demo               # live showcase
python3 -m phishguard scan-url "http://paypa1-secure-login.xyz/verify"
python3 -m phishguard scan-email samples/phishing_paypal.eml
python3 -m phishguard scan-html samples/fake_login.html --url http://secure-paypal-login.xyz/signin
python3 -m phishguard serve --port 8765  # REST API
curl -s localhost:8765/scan/url -d '{"url":"http://192.168.4.4/paypal/login.php"}'
```

## 3. Results (from `outputs/01_train_and_evaluate.txt`)

Evaluated on a **held-out test set whose registered domains never appear in training** (checked by an assertion:
`overlapping domains=0`). Threshold: risk ≥ 50 ⇒ phishing.

### URL detection (test n = 2017: 1001 legitimate, 1016 phishing)

| System | Accuracy | Precision | Recall | F1 | ROC-AUC | False-positive rate |
|---|---|---|---|---|---|---|
| Rules only | 0.685 | 1.000 | 0.374 | 0.544 | 0.889 | 0.000 |
| ML only | 0.949 | 0.930 | 0.972 | 0.951 | 0.987 | 0.074 |
| **Hybrid (production, BLOCK only)** | 0.910 | **0.971** | 0.847 | 0.904 | 0.988 | **0.026** |
| Hybrid, WARN+BLOCK flagged | 0.954 | 0.924 | **0.991** | 0.956 | 0.988 | 0.083 |

Confusion matrix (hybrid, BLOCK): TN 975 · FP 26 · FN 156 · TP 860 (`reports/url_confusion_matrix.txt`).
5-fold CV F1 (train): LogReg 0.966, RandomForest 0.992, GradBoost 0.993. Mean latency ≈ 40 ms/URL.

**Design trade-off:** the production policy BLOCKs only when confident (2.6 % FPR — users are rarely blocked
wrongly) and sends uncertain items to WARN, so 99.1 % of phishing is at least flagged. Recall by technique:
100 % blocked for `@`-tricks, IP hosts, brand-subdomains, combosquats, deep subdomains, free-hosting abuse,
obfuscated long URLs, redirects and executables; typosquats 91 % (98 % flagged); homograph/punycode 76 % (87 % flagged).

### E-mail detection (test n = 600, 300 / 300)

| System | Accuracy | Precision | Recall | F1 | AUC | FPR |
|---|---|---|---|---|---|---|
| Header/forensics rules only | 0.942 | 0.962 | 0.920 | 0.940 | 0.988 | 0.037 |
| Text model only | 0.978 | 0.997 | 0.960 | 0.978 | 0.996 | 0.003 |
| **Full pipeline (stacked)** | **0.995** | **1.000** | **0.990** | **0.995** | 1.000 | **0.000** |

Fusing header, text, link and attachment signals beats every single signal (enforced by a test).
Charts: [`reports/url_roc.svg`](reports/url_roc.svg), [`reports/url_feature_importance.svg`](reports/url_feature_importance.svg),
[`reports/email_roc.svg`](reports/email_roc.svg).

## 4. Tests (`outputs/02_tests.txt`, `logs/tests.log`, `reports/test_results.json`)

**68 tests, 68 passed, 0 failed, 0 skipped** (≈2 s):

| File | Covers |
|---|---|
| `test_url_features.py` | host splitting, multi-part suffixes, Levenshtein/entropy, every rule, `@` trick, leetspeak, homoglyph, transposition typos, garbage/malformed input never crashes |
| `test_email_analyzer.py` | SPF/DKIM/DMARC parsing, Reply-To mismatch, display-name spoof, BEC, double extension, link mismatch, malformed mail |
| `test_html_analyzer.py` | fake login page hits 8 indicators; clean page scores 0; same-domain login stays low |
| `test_prevention.py` | list matching (incl. `good.com@bad.top` cannot borrow allowlist trust), persistence, policy bands, defang, neutralise |
| `test_dataset.py` | determinism, balance, **no train/test domain leakage**, generated e-mails parse |
| `test_detector.py` | end-to-end verdicts, schema, overrides, feedback loop, sanitised bodies, **REST API** (200/400/404 paths) |
| `test_model_quality.py` | **quality gates** that fail the build on regression (AUC ≥ 0.97, precision ≥ 0.94, FPR ≤ 5 %, e-mail F1 ≥ 0.95, hybrid ≫ rules, fusion ≥ single signals, latency) |

Two real bugs were found by these tests during development and fixed: transposition typos (`paypla.com`) were
missed by plain Levenshtein (now Damerau), and the HTML brand check mis-fired on domains containing the brand.

## 5. Example output (from `outputs/03_demo.txt`)

```
  URL   hxxps://paypal[.]com[.]account-verify[.]top/login
  risk  88.0/100 |#################   | -> BLOCK (phishing)
     - [brand_mismatch] Well-known brand name used on a domain the brand does not own
     - [suspicious_tld] TLD frequently abused for phishing
     - [many_keywords] Multiple phishing keywords (login/verify/secure/...)
     * tip: Check the registered domain (the part just before the TLD), not the brand name in the subdomain.

  EMAIL Invoice_4471 - payment overdue
  risk  94.6/100 |##################  | -> QUARANTINE (phishing)
     - [spf_softfail] SPF soft-fail        - [dangerous_attachment] Executable/dangerous attachment: Statement4471.pdf.exe
     - [urgency] 2 urgency / threat phrases - [double_extension] Double extension disguises file type
```
Legit samples (`wikipedia.org`, `accounts.google.com`, `paypal.com/signin`, GitHub / colleague e-mails) score 0–6 → **ALLOW**.
The bit.ly sample scores 44.6 → **WARN** (a shortener's destination can't be judged lexically).

## 6. Prevention features

* **Policy actions:** ALLOW · WARN (banner + confirmation) · BLOCK (URL/page) · QUARANTINE (e-mail).
* **Link neutralisation:** risky URLs in quarantined mail are replaced with `[LINK DISABLED: hxxp://evil[.]com]`, plus a warning banner.
* **Defanging** of all indicators in logs/API output so analysts can't click them by accident.
* **Allow/block lists** (`data/allowlist.txt`, `data/blocklist.txt`) matched on the *real* registered domain (userinfo tricks don't bypass).
* **Feedback loop:** with `auto_block=True`, confirmed phishing domains are appended to the blocklist and blocked instantly next time.
* **Audit trail:** every decision → `logs/audit.jsonl` (JSON lines). Human log → `logs/phishguard.log`.
* **User education:** each verdict carries plain-language tips tied to the triggered rules.

## 7. Optional Gemini explanations

`GEMINI_API_KEY=… python3 -m phishguard demo` enables a short natural-language explanation per verdict.
Only the *already computed* verdict (defanged URL + rule names) is sent — never the raw e-mail. **The key is read
from the environment only and is never stored in this repository.** Without a key (or on any network error) a
deterministic local explanation is used, so everything works offline. This layer was verified only in its offline
fallback mode in this build.

## 8. Honest limitations (please read for your evaluation)

* **Data is synthetic.** Real feeds (PhishTank/OpenPhish/Enron) need network access and licences. The generators
  reproduce documented attack techniques and include hard cases, but real-world accuracy will be lower. Plug a real
  feed in with `dataset.load_urls_csv(path)` (`url,label`) and rerun `train`; the quality gates will tell you if it holds up.
* Lexical analysis can't judge **shortened or compromised-but-clean-looking URLs** — these are routed to WARN. A production
  deployment should add redirect expansion, domain age/WHOIS, TLS-certificate and reputation lookups, and sandbox detonation.
* The e-mail text model learned template vocabulary; expect weaker text accuracy on real-world mail (headers/links/attachments carry the rest).
* No JavaScript execution or screenshots/visual-similarity analysis of pages.

## 9. Layout

```
PhishGuard/
├── scripts/run_all.sh        # one-command full run (logs everything)
├── src/phishguard/           # the package (see §1)
├── tests/                    # 68 tests + run_tests.py (writes logs/tests.log)
├── samples/                  # .eml / .html / urls.txt used by tests and demo
├── data/                     # generated datasets, allow/block lists
├── models/                   # trained joblib models
├── reports/                  # metrics JSON, confusion matrices, ROC + importance SVGs, test_results.json
├── docs/                     # PhishGuard_Presentation.pptx (30 slides), PhishGuard_Project_Report.docx (19 pages) + PDF copies
├── outputs/                  # captured console output of every step of run_all.sh
└── logs/                     # run_all.log, phishguard.log, tests.log, audit.jsonl
```
