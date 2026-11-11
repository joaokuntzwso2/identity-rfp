#!/usr/bin/env bash
# Destroys ONLY the PoC's named Compose project; never uses docker prune.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${1:-}" != '--destroy-magalu-poc-data' ]]; then
  echo 'This permanently deletes ONLY magalu-ciam73-s7lab containers, networks, and DB volumes.' >&2
  echo 'Run: ./scripts/reset-isolated.sh --destroy-magalu-poc-data' >&2
  exit 2
fi
docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml down --volumes --remove-orphans
printf 'PoC project data volumes removed; no other Docker projects touched.\n'
