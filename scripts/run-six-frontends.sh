#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo 'ERROR: Missing .env; your isolated stack must be configured first.' >&2; exit 1; }
[[ -f generated/manifest.json ]] || { echo 'ERROR: No bootstrapped WSO2 manifest. Run the existing isolated bootstrap first.' >&2; exit 1; }
set -a; source .env; set +a
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
files=(-f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
name=magalu-ciam73-s7lab
command -v docker >/dev/null || { echo 'Docker CLI missing'; exit 1; }
docker info >/dev/null || { echo 'Start Docker Desktop first'; exit 1; }
echo 'Verifying existing isolated WSO2 + databases (NO RECREATION)...'
docker compose -p "$name" "${files[@]}" ps is db identity-db
# The existing DB volume does not rerun docker-entrypoint-initdb.d; apply migration explicitly.
echo 'Applying idempotent request-workflow schema to existing demo PostgreSQL...'
docker compose -p "$name" "${files[@]}" exec -T db \
  psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-ciam}" -d "${POSTGRES_DB:-ciam}" \
  < consent/migrations/004_requests.sql
echo 'Building the updated sector JSON endpoint and bootstrap code...'
docker compose -p "$name" "${files[@]}" build demo bootstrap
docker compose -p "$name" "${files[@]}" up -d --no-deps demo sector
# Must finish API registration before opening storefronts: fail on scope/role/TOTP errors.
echo 'Configuring six tenant-scoped OIDC callback URLs, API resources, roles and ACR-TOTP policies...'
docker compose -p "$name" "${files[@]}" --profile tools run --rm bootstrap \
  python -m bootstrap.storefront_provision
echo 'Starting six independent web/mobile services...'
docker compose -p "$name" "${files[@]}" up -d --build \
  store-magalu-web store-magalu-app store-netshoes-web store-netshoes-app \
  store-magalupay-web store-magalupay-app
for item in 'magalu:web:8181' 'magalu:app:8182' 'netshoes:web:8183' \
            'netshoes:app:8184' 'magalupay:web:8185' 'magalupay:app:8186'; do
  brand="${item%%:*}"; rest="${item#*:}"; channel="${rest%%:*}"; port="${rest##*:}"
  found=0
  for n in {1..20}; do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null; then found=1;break; fi
    sleep 2
  done
  if [[ "$found" -eq 0 ]]; then
    echo "ERROR: $brand $channel storefront not healthy on $port" >&2
    docker compose -p "$name" "${files[@]}" logs --tail=70 "store-$brand-$channel" >&2
    exit 1
  fi
  printf '[READY] %-11s %-6s http://localhost:%s\n' "$brand" "$channel" "$port"
done
echo 'SCOPES + TOTP: Live approval remains unverified until approver enrolls TOTP and completes a successful approval.'
echo 'Provision report: generated/storefront-provision-report.json'
