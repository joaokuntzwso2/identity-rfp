#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f generated/manifest.json && -f .env ]] || { echo 'Run in bootstrapped Magalu project.' >&2; exit 2; }
[[ -f compose.yaml && -f compose.isolated.yaml && -f compose.frontends.yaml ]] || { echo 'Compose files missing.' >&2; exit 2; }
set -a; source .env; set +a
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
echo '[M3] Building ONLY the bootstrap tool image (not starting bootstrap.main).'
"${compose[@]}" build bootstrap
# No dependencies started, no tenant re-bootstrap, no database migrations.
echo '[M3] Registering and reading back dedicated resource audience on Commerce exchange client.'
"${compose[@]}" run --rm --no-deps --entrypoint python bootstrap \
  -m scripts.m3_register_resource_audience --audience urn:magalu:poc:requests
[[ "$(cat generated/m3-resource-audience.txt)" == 'urn:magalu:poc:requests' ]] || { echo 'Audience readback file missing' >&2;exit 1; }
echo '[OK] WSO2 registration verified; shared resource audience is ready.'
echo '[NEXT] Open http://localhost:8180/m3/exchange and execute the three tests again.'
