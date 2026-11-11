#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { printf 'ERROR: Missing .env\n' >&2; exit 1; }
[[ -s generated/manifest.json ]] || { printf 'ERROR: Missing WSO2 bootstrap manifest\n' >&2; exit 1; }
[[ -s generated/tenant-secrets.json ]] || { printf 'ERROR: Missing tenant secrets\n' >&2; exit 1; }
printf '%s\n' 'Fixing WSO2 7.3.18 login-flow authenticator names in the six-storefront bootstrap.'
printf '%s\n' 'Preserving all existing WSO2/PostgreSQL containers, tenant data, API resources and credentials.'
exec ./scripts/run-six-frontends.sh
