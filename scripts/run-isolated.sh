#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/setup-isolated.sh
set -a; source .env; set +a
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
command -v docker >/dev/null || { echo 'Docker Desktop is required' >&2; exit 1; }
docker info >/dev/null || { echo 'Docker Desktop is not running' >&2; exit 1; }
# Isolate every resource under a project name unique to this PoC.
files=(-f compose.yaml -f compose.isolated.yaml)
name=magalu-ciam73-s7lab
[[ "${1:-}" != '--skip-bootstrap' && "${1:-}" != '' ]] && { echo 'Usage: ./scripts/run-isolated.sh [--skip-bootstrap]'; exit 2; }
./scripts/prepare-updated-image.sh
./scripts/prepare-identity-sql.sh
./scripts/generate-local-tls.sh
python3 scripts/prepare-wso2-config.py
docker compose -p "$name" "${files[@]}" up -d --build identity-db db sector demo is
printf 'WSO2 public endpoint: https://localhost:9543\nDemo portal: http://localhost:8180\n'
if [[ "${1:-}" == '--skip-bootstrap' ]]; then
  exit 0
fi
printf 'Waiting for the independent WSO2 root server on port 9543...\n'
ready=0
for attempt in {1..90}; do
  if curl -ksf https://localhost:9543/oauth2/token/.well-known/openid-configuration >/dev/null; then
    ready=1; break
  fi
  sleep 5
done
if (( ready == 0 )); then
  echo 'WSO2 did not become ready. View logs:' >&2
  echo "docker compose -p $name -f compose.yaml -f compose.isolated.yaml logs --tail=150 is identity-db" >&2
  exit 1
fi
docker compose -p "$name" "${files[@]}" --profile tools run --rm bootstrap
# Smoke test is fail closed; a bootstrap alone is not a Section 7 PASS.
docker compose -p "$name" "${files[@]}" --profile tools run --rm bootstrap python -m scripts.smoke
