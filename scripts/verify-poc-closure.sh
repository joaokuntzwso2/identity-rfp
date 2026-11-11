#!/usr/bin/env bash
set -euo pipefail
PROJECT='/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc'
cd "$PROJECT"
[[ "$(git rev-parse --show-toplevel)" == "$PROJECT" ]] || { echo 'Wrong Git root';exit 1; }
python -m py_compile demo/poc_closure.py demo/poc_closure_core.py demo/main.py
python -m pytest -q tests/test_poc_closure_core.py tests/test_m3_native_consent.py tests/test_m3_exchange_storytelling.py
if command -v node >/dev/null 2>&1; then node --check demo/static/m3_completion.js; fi
git diff --check
echo 'OFFLINE TESTS COMPLETED. Live WSO2 acceptance still must be executed.'
