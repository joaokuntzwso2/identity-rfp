#!/usr/bin/env bash
# Patch/restart ONLY central port-8180 dashboard. Preserve all other services.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env && -f compose.frontends.yaml ]] || { echo 'ERROR: Run from the existing six-storefront project with .env.' >&2; exit 1; }
[[ -f generated/storefront-manifest.json ]] || { echo 'ERROR: Six-storefront provisioning has not completed.' >&2; exit 1; }
command -v docker >/dev/null || { echo 'ERROR: Docker CLI unavailable' >&2; exit 1; }
docker info >/dev/null || { echo 'ERROR: Docker Desktop unavailable' >&2; exit 1; }
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
echo 'Building only the 8180 dashboard; six stores, WSO2 and PostgreSQL are untouched.'
"${compose[@]}" build demo
"${compose[@]}" up -d --no-deps demo
for i in {1..30}; do
  if curl -fsS http://127.0.0.1:8180/healthz >/dev/null 2>&1; then break; fi
  sleep 2
done
if ! curl -fsS http://127.0.0.1:8180/healthz >/dev/null; then
  "${compose[@]}" logs --tail=100 demo
  echo 'ERROR: 8180 dashboard is unhealthy' >&2; exit 1
fi
python3 - <<'PY'
import json,urllib.request
with urllib.request.urlopen('http://127.0.0.1:8180/api/pairwise-evidence',timeout=30) as r:
    result=json.load(r)
assert result['total']==6
assert len(result['storefronts'])==6
assert len(result['checks'])==6
assert result['result'] in ('INCOMPLETE','MISMATCH','OBSERVED_PASS')
print('[PASS] Six-subject evidence API ready')
print('No browser cookies in CLI: subjects remain unavailable until browser login.')
PY
echo '[READY] http://localhost:8180/pairwise'
echo 'Use the SAME browser/profile and hostname localhost for all six storefront logins.'
echo 'No WSO2/DB/storefront containers were rebuilt or restarted.'
