#!/usr/bin/env bash
# One-time reconciliation of demo SCIM credentials following interrupted bootstrap.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f .env || ! -f compose.isolated.yaml || ! -f generated/manifest.json ]]; then
  echo 'ERROR: Expected an existing, bootstrapped isolated Magalu project.' >&2
  exit 2
fi
set -a
source .env
set +a
if [[ "${MAGALU_STACK_MODE:-}" != 'independent-root-tenants-v2' || \
      "${MAGALU_ENV_MODE:-}" != 'isolated' || \
      "${COMPOSE_PROJECT_NAME:-}" != 'magalu-ciam73-s7lab' ]]; then
  echo 'ERROR: Project identification mismatch; nothing was changed.' >&2
  exit 2
fi
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml)
"${compose[@]}" config --quiet
python3 -m py_compile bootstrap/credential_store.py bootstrap/main.py scripts/repair_user_passwords.py
printf '\nBuilding ONLY the bootstrap runner...\n'
"${compose[@]}" build bootstrap
printf '\nReconciling ONLY the four synthetic demo users in two root tenants...\n'
"${compose[@]}" --profile tools run --rm --no-deps \
    -e MAGALU_STACK_MODE=independent-root-tenants-v2 \
    -e MAGALU_ENV_MODE=isolated \
    bootstrap python -m scripts.repair_user_passwords --apply
printf '\nFinished. WSO2, both databases, all applications and the demo container were not recreated.\n'
printf 'Use the username ana.magalu in Magalu Retail and Netshoes; retry browser login.\n'
