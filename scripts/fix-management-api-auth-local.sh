#!/usr/bin/env bash
# Isolated development stack only: restore Basic Auth temporarily for WSO2 IS 7.3
# management API bootstrap. Does not remove or recreate database volumes.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env || ! -f compose.isolated.yaml || ! -f docker/wso2/deployment.isolated.template.toml ]]; then
  echo 'ERROR: run this from the magalu-ciam-is73-poc v2 isolated repository.' >&2
  exit 2
fi

# Keep this change strictly on the dedicated Magalu Compose project.
set -a
source .env
set +a
if [[ "${MAGALU_STACK_MODE:-}" != 'independent-root-tenants-v2' || "${MAGALU_ENV_MODE:-}" != 'isolated' ]]; then
  echo 'ERROR: This local compatibility patch is restricted to independent-root-tenants-v2.' >&2
  exit 2
fi
if [[ "${COMPOSE_PROJECT_NAME:-}" != 'magalu-ciam73-s7lab' ]]; then
  echo 'ERROR: Unexpected Compose project. No Docker resources were modified.' >&2
  exit 2
fi
if [[ "${IS_ADMIN_USERNAME:-}" != 'admin' || "${IS_ADMIN_PASSWORD:-}" != 'admin' ]]; then
  echo 'ERROR: Expected local admin/admin credentials. No Docker resources were modified.' >&2
  exit 2
fi
command -v docker >/dev/null || { echo 'ERROR: docker command not found.' >&2; exit 2; }
command -v curl >/dev/null || { echo 'ERROR: curl command not found.' >&2; exit 2; }

export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml)
template=docker/wso2/deployment.isolated.template.toml

# Never duplicate the config block on retries. Restrict to the local template.
if ! grep -Fq '[compatibility_setting.basic_auth.disable_basic_auth]' "$template"; then
  cat >> "$template" <<'TOML'

# TEMPORARY LOCAL PoC COMPATIBILITY ONLY. IS 7.3 update levels disable Basic
# management API authentication by default. Use scoped OAuth2 in production.
[compatibility_setting.basic_auth.disable_basic_auth]
default_value = false
target_value = false
TOML
fi

python3 scripts/prepare-wso2-config.py
if ! grep -Fq 'target_value = false' generated/wso2/deployment.toml; then
  echo 'ERROR: Rendered configuration does not contain the compatibility override.' >&2
  exit 2
fi
"${compose[@]}" config --quiet
printf '\nRestarting only the Magalu WSO2 container (all PostgreSQL volumes preserved)...\n'
"${compose[@]}" up -d --no-deps --force-recreate is

public_url="https://localhost:${WSO2_HOST_PORT:-9543}"
printf 'Waiting for WSO2 OIDC Discovery on %s...\n' "$public_url"
ready=0
for ((attempt=1; attempt<=90; attempt++)); do
  if curl -ksf --max-time 5 "$public_url/oauth2/token/.well-known/openid-configuration" >/dev/null; then
    ready=1
    break
  fi
  sleep 5
done
if (( ready != 1 )); then
  echo 'ERROR: WSO2 did not become ready. Inspect the isolated is container logs.' >&2
  exit 1
fi

# Validate management API access using the documented tenant LIST route.
# A lookup of a missing tenant domain may return 400 (TM-60015) in IS 7.3.
code="$(curl -ksS --max-time 15 -o /dev/null -w '%{http_code}' \
  -u "${IS_ADMIN_USERNAME}:${IS_ADMIN_PASSWORD}" \
  "$public_url/api/server/v1/tenants?limit=1&offset=0")"
printf 'Tenant API authentication preflight: HTTP %s\n' "$code"
case "$code" in
  200) ;;
  *)
    echo 'ERROR: Tenant management API is still unavailable. Bootstrap was NOT started.' >&2
    echo 'Check WSO2 server logs and the rendered deployment.toml; do not reset PostgreSQL.' >&2
    exit 1
    ;;
esac

printf '\nStarting idempotent tenant/application/user/role bootstrap...\n'
"${compose[@]}" --profile tools run --rm bootstrap
printf '\nRunning the PoC smoke checks...\n'
"${compose[@]}" --profile tools run --rm bootstrap python -m scripts.smoke
printf '\nBootstrap finished. Inspect generated/bootstrap-report.json for the individual gates.\n'
