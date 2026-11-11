#!/usr/bin/env bash
# Patch follow-up: bootstrap correctly handles absent WSO2 root tenants.
# Operates exclusively on the dedicated Magalu PoC Docker Compose project.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env || ! -f compose.isolated.yaml ]]; then
  echo 'ERROR: Isolated Magalu PoC environment not found.' >&2
  exit 2
fi

set -a
source .env
set +a
if [[ "${MAGALU_STACK_MODE:-}" != 'independent-root-tenants-v2' || "${MAGALU_ENV_MODE:-}" != 'isolated' || "${COMPOSE_PROJECT_NAME:-}" != 'magalu-ciam73-s7lab' ]]; then
  echo 'ERROR: Project identity check failed; nothing was changed.' >&2
  exit 2
fi

command -v docker >/dev/null || { echo 'ERROR: Docker is required.' >&2; exit 2; }
command -v curl >/dev/null || { echo 'ERROR: curl is required.' >&2; exit 2; }
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml)
"${compose[@]}" config --quiet

url="https://localhost:${WSO2_HOST_PORT:-9543}/api/server/v1/tenants?limit=1&offset=0"
response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT
if [[ -n "${IS_ADMIN_ACCESS_TOKEN:-}" ]]; then
  auth=(-H "Authorization: Bearer ${IS_ADMIN_ACCESS_TOKEN}")
else
  auth=(-u "${IS_ADMIN_USERNAME:-admin}:${IS_ADMIN_PASSWORD:-admin}")
fi
status="$(curl -ksS --max-time 20 -o "$response_file" -w '%{http_code}' "${auth[@]}" -H 'Accept: application/json' "$url")"
printf 'Tenant LIST API authorization: HTTP %s\n' "$status"
if [[ "$status" != '200' ]]; then
  echo 'ERROR: WSO2 tenant LIST API did not authorize the request; bootstrap was not run.' >&2
  python3 - "$response_file" <<'PY'
import json,sys
try:
    obj=json.load(open(sys.argv[1]))
    print('WSO2 error:',obj.get('code'),obj.get('message'),obj.get('description'))
except Exception:
    print('WSO2 returned a non-JSON error response (check server logs).')
PY
  exit 1
fi

printf '\nBuilding updated bootstrap runner only (WSO2/PostgreSQL unchanged)...\n'
"${compose[@]}" build bootstrap
printf '\nProvisioning root tenants, applications, users, roles and consent fixtures...\n'
"${compose[@]}" --profile tools run --rm bootstrap
printf '\nRunning verification checks...\n'
"${compose[@]}" --profile tools run --rm bootstrap python -m scripts.smoke
printf '\nInspect generated/bootstrap-report.json for exact outcomes.\n'
