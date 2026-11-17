#!/usr/bin/env bash
# PhishGuard - try your OWN inputs and see every step of the analysis.
#   ./scripts/try_it.sh                         interactive prompt (type URLs / e-mail / html paths)
#   ./scripts/try_it.sh http://some.site/path   analyse one or more URLs, verbose
#   ./scripts/try_it.sh my_mail.eml             analyse an e-mail file
#   ./scripts/try_it.sh page.html --url http://x.top/login
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD/src" PYTHONDONTWRITEBYTECODE=1
[ -f models/url_model.joblib ] || { echo "No trained models yet - training first (about 60 s)..."; python3 -m phishguard train > /dev/null; }
if [ "$#" -eq 0 ]; then exec python3 -m phishguard interactive; else exec python3 -m phishguard analyze "$@"; fi
