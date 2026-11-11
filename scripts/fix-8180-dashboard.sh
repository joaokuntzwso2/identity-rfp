#!/usr/bin/env bash
# Update ONLY the port-8180 evidence portal. Do not recreate the six storefronts.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo 'ERROR: .env missing; run from existing Magalu CIAM project.' >&2; exit 1; }
[[ -f compose.frontends.yaml ]] || { echo 'ERROR: Six-storefront overlay is missing.' >&2; exit 1; }
[[ -f generated/storefront-manifest.json ]] || { echo 'ERROR: Storefront provisioning manifest is missing.' >&2; exit 1; }
command -v docker >/dev/null || { echo 'ERROR: Docker CLI missing' >&2; exit 1; }
docker info >/dev/null || { echo 'ERROR: Docker Desktop is not running' >&2; exit 1; }
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
name=magalu-ciam73-s7lab
files=(-f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
echo 'Existing storefront containers (read only):'
docker compose -p "$name" "${files[@]}" ps \
  store-magalu-web store-magalu-app store-netshoes-web store-netshoes-app \
  store-magalupay-web store-magalupay-app

echo 'Building ONLY the legacy evaluation dashboard image...'
docker compose -p "$name" "${files[@]}" build demo

echo 'Recreating ONLY the 8180 dashboard container. No database or storefront resets.'
docker compose -p "$name" "${files[@]}" up -d --no-deps demo

success=0
for i in {1..25}; do
  if curl -fsS 'http://127.0.0.1:8180/healthz' >/dev/null 2>&1; then
    success=1; break
  fi
  sleep 2
done
if (( success == 0 )); then
  echo 'ERROR: Evidence dashboard health check failed.' >&2
  docker compose -p "$name" "${files[@]}" logs --tail=100 demo >&2
  exit 1
fi

echo 'Checking session-matrix endpoint...'
python3 - <<'PY'
import json, urllib.request
url = 'http://127.0.0.1:8180/api/storefront-status'
with urllib.request.urlopen(url, timeout=30) as response:
    payload = json.load(response)
assert len(payload['storefronts']) == 6, 'Expected 6 independent storefront statuses'
assert payload['total'] == 6
assert all(x['brand'] in ('magalu','netshoes','magalupay') for x in payload['storefronts'])
print('[PASS] Dashboard returned statuses for all six storefronts')
print('Note: This CLI check has no browser cookies, so it cannot verify your signed-in sessions.')
PY

echo '[READY] http://localhost:8180'
echo 'Use the same browser with localhost on all six storefronts and refresh dashboard.'
echo 'WSO2, PostgreSQL and all six storefront services were left untouched.'
