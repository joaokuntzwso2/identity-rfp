#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ ! -f requirements.txt || ! -f compose.yaml || ! -f compose.isolated.yaml ]]; then
  echo "ERROR: Run within the Magalu CIAM isolated project (required files not found)." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is unavailable." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker Desktop is not running." >&2
  exit 1
fi

# `SessionMiddleware` imports this package but it is not installed by Starlette itself.
# Keep the version reproducible and preserve any existing dependency edits.
if ! grep -Eq '^[[:space:]]*itsdangerous([[:space:]]*([=<>!~]|$))' requirements.txt; then
  cp -p requirements.txt "requirements.txt.pre-itsdangerous.bak"
  printf '\nitsdangerous==2.2.0\n' >> requirements.txt
  echo 'Added itsdangerous==2.2.0 to requirements.txt (previous file backed up).'
else
  echo 'itsdangerous dependency already declared; no requirements change.'
fi

export HOST_UID="${HOST_UID:-$(id -u)}"
export HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml)

echo 'Rebuilding only the Magalu demo image...'
"${compose[@]}" build demo

echo 'Recreating only the Magalu demo container; other services are untouched...'
"${compose[@]}" up -d --no-deps --force-recreate demo

echo 'Checking the demo HTTP health endpoint on 127.0.0.1:8180...'
for attempt in $(seq 1 30); do
  if health_json=$(curl --silent --show-error --fail --max-time 3 http://127.0.0.1:8180/healthz 2>/dev/null); then
    printf '\nDemo portal is reachable:\n%s\n\n' "$health_json"
    printf 'Open: http://127.0.0.1:8180/\n'
    exit 0
  fi
  sleep 2
done

echo 'ERROR: Demo portal is still not reachable. Latest logs:' >&2
"${compose[@]}" logs --tail=100 demo >&2
exit 1
