#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo 'ERROR: .env not found' >&2; exit 1; }
[[ -s generated/manifest.json ]] || { echo 'ERROR: bootstrap manifest not found' >&2; exit 1; }
echo 'Applying WSO2 7.3 APIResources casing and idempotent resource lookup fix.'
echo 'Preserving all WSO2 and PostgreSQL containers, tenant data and existing applications.'
exec ./scripts/run-six-frontends.sh
