#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env && -f generated/manifest.json && -f generated/tenant-secrets.json ]] || {
  echo 'ERROR: Existing complete WSO2 bootstrap and tenant credentials required'; exit 1; }
set -a; source .env; set +a
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
name=magalu-ciam73-s7lab
files=(-f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
echo 'Provisioning one WSO2 OAuth authorization-code client for M3 token evidence (idempotent)...'
docker compose -p "$name" "${files[@]}" build bootstrap
docker compose -p "$name" "${files[@]}" --profile tools run --rm bootstrap \
  python -m scripts.m3_provision_oauth_test_client
echo 'Local private configuration: generated/m3-oauth-test-client.json'
echo 'No passwords or client secrets displayed.'
