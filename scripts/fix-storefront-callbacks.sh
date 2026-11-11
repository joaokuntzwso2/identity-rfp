#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo 'ERROR: missing .env' >&2; exit 1; }
[[ -f generated/manifest.json ]] || { echo 'ERROR: missing bootstrap manifest' >&2; exit 1; }
echo 'Using strict single-entry WSO2 callback allowlists (no wildcard callbacks).'
echo 'Existing WSO2, tenant and PostgreSQL containers are preserved.'
exec ./scripts/run-six-frontends.sh
