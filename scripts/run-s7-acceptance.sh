#!/usr/bin/env bash
set -euo pipefail
PROJECT=/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
cd "$PROJECT"
[[ "$(git rev-parse --show-toplevel)" == "$PROJECT" ]] || { echo 'FATAL: wrong git root' >&2; exit 1; }
DC=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
if [[ -f compose.s7-provider.local.yaml ]]; then
  DC+=(-f compose.s7-provider.local.yaml)
fi
python3 -m py_compile demo/main.py demo/storefront.py demo/s7_acceptance.py demo/s7_assurance.py demo/s7_policy.py
if [[ -x .venv/bin/python ]]; then
  .venv/bin/python -m pytest -q tests/test_s7_acceptance.py
else
  echo 'No .venv Python found: run python3 -m venv .venv; .venv/bin/python -m pip install -r requirements.txt pytest' >&2
  exit 1
fi
"${DC[@]}" build demo store-magalu-web store-magalu-app store-magalupay-web store-magalupay-app
"${DC[@]}" up -d --no-deps demo store-magalu-web store-magalu-app store-magalupay-web store-magalupay-app
for u in http://localhost:8180/m3/section7 http://localhost:8181/healthz http://localhost:8182/healthz http://localhost:8185/healthz http://localhost:8186/healthz; do
  curl -fsS --retry 10 --retry-delay 2 "$u" -o /dev/null && echo "PASS $u"
done
echo 'Dashboard ready: http://localhost:8180/m3/section7'
echo 'Does not restart WSO2/PostgreSQL or perform biometric verification.'
