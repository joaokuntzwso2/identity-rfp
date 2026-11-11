#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f generated/manifest.json || ! -f .env ]]; then
  echo 'ERROR: Existing bootstrapped Magalu project (.env and manifest) required.' >&2
  exit 2
fi

if [[ ! -x scripts/provision-m3-oauth-test.sh ]]; then
  echo 'ERROR: Existing M3 OAuth provisioning launcher not found.' >&2
  exit 2
fi

echo 'Updating ONLY the existing M3 OAuth evidence client to issue signed JWT access tokens...'
./scripts/provision-m3-oauth-test.sh

echo
printf '%s\n' \
  '[OK] WSO2 readback confirmed JWT access token configuration for the M3 evidence client.' \
  'Start fresh login flows now; do not reuse earlier callback URLs or authorization codes.' \
  './scripts/m3-local.sh capture-subject --insecure-local' \
  './scripts/m3-local.sh capture-actor --insecure-local' \
  './scripts/m3-local.sh verify --insecure-local'
