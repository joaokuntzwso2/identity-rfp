#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env && -f generated/manifest.json && -f generated/tenant-secrets.json ]] || {
  echo 'ERROR: Bootstrap credentials and manifest not found; refusing WSO2 update' >&2; exit 2; }
echo 'Updating only M3 evidence app subject type and Commerce exchange read permissions...'
./scripts/provision-m3-oauth-test.sh
echo '[OK] M3 evidence client and exchange client verified through WSO2 APIs.'
echo 'Required next: capture fresh Ana AND Bruno JWTs, then run the exchange workbench.'
