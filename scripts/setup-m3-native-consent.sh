#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f compose.yaml ] && [ -f compose.isolated.yaml ] && [ -f compose.frontends.yaml ] || { echo 'Missing Magalu CIAM Compose files' >&2; exit 1; }
[ -d generated ] && [ -f generated/manifest.json ] && [ -f generated/tenant-secrets.json ] || { echo 'Existing bootstrap private config missing' >&2; exit 1; }
DC=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
printf '\n[CHECK] Existing WSO2 and PostgreSQL services\n'
"${DC[@]}" ps is identity-db db
printf '\n[BUILD] Existing bootstrap image only\n'
"${DC[@]}" build bootstrap
printf '\n[RUN] Idempotent native Consent Management v2 provisioning for two root tenants\n'
"${DC[@]}" run --rm bootstrap python -m scripts.m3_native_provision
printf '\n[PASS] Native consent M2M clients and catalog configured (readback verified).\n'
