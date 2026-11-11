#!/usr/bin/env bash
# Correct WSO2 IS 7.3.18 application names without restarting IS or PostgreSQL.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env || ! -f compose.isolated.yaml || ! -f bootstrap/app_naming.py ]]; then
  echo 'ERROR: Magalu isolated PoC or application naming patch is missing.' >&2
  exit 2
fi
set -a
source .env
set +a
if [[ "${MAGALU_STACK_MODE:-}" != 'independent-root-tenants-v2' || \
      "${MAGALU_ENV_MODE:-}" != 'isolated' || \
      "${COMPOSE_PROJECT_NAME:-}" != 'magalu-ciam73-s7lab' ]]; then
  echo 'ERROR: Project identity check failed; no containers were changed.' >&2
  exit 2
fi
command -v docker >/dev/null || { echo 'ERROR: Docker is required.' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'ERROR: Python 3 is required.' >&2; exit 2; }
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml)

python3 -m py_compile bootstrap/app_naming.py bootstrap/main.py bootstrap/wso2.py scripts/onboard_brand.py
python3 - <<'PY'
from bootstrap.app_naming import application_name
for parts in (('magalu','web'), ('netshoes','app'), ('magalupay','web'),
              ('seller','web'), ('commerce','m2m','cc'), ('fintech','m2m','jwt'),
              ('magalufresh','web')):
    print('Valid app name:', application_name(*parts))
PY
"${compose[@]}" config --quiet
printf '\nRebuilding ONLY the Magalu bootstrap runner...\n'
"${compose[@]}" build bootstrap
printf '\nReusing existing root tenants and users; provisioning applications...\n'
"${compose[@]}" --profile tools run --rm bootstrap
printf '\nRunning live smoke checks...\n'
"${compose[@]}" --profile tools run --rm bootstrap python -m scripts.smoke
printf '\nBootstrap finished. Inspect generated/bootstrap-report.json for exact results.\n'
