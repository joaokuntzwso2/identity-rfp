#!/usr/bin/env bash
# Recover application creation from WSO2's HTTP 201 with an empty response body.
# Rebuild ONLY bootstrap; never stop/modify WSO2 or PostgreSQL containers.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env || ! -f compose.isolated.yaml || ! -f bootstrap/wso2.py ]]; then
  echo 'ERROR: Expected Magalu isolated PoC files not found.' >&2
  exit 2
fi
set -a
source .env
set +a
if [[ "${MAGALU_STACK_MODE:-}" != 'independent-root-tenants-v2' || \
      "${MAGALU_ENV_MODE:-}" != 'isolated' || \
      "${COMPOSE_PROJECT_NAME:-}" != 'magalu-ciam73-s7lab' ]]; then
  echo 'ERROR: Isolated Magalu Compose project identity check failed. Nothing changed.' >&2
  exit 2
fi
command -v docker >/dev/null || { echo 'ERROR: Docker is required.' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'ERROR: python3 is required.' >&2; exit 2; }
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml)
python3 -m py_compile bootstrap/wso2.py
"${compose[@]}" config --quiet
printf 'Rebuilding ONLY the bootstrap image (WSO2 + PostgreSQL unchanged)...\n'
"${compose[@]}" build bootstrap
printf '\nResuming idempotent bootstrap; existing tenants/users and any apps are reused...\n'
"${compose[@]}" --profile tools run --rm bootstrap
printf '\nRunning live smoke tests...\n'
"${compose[@]}" --profile tools run --rm bootstrap python -m scripts.smoke
printf '\nResults are in generated/bootstrap-report.json\n'
