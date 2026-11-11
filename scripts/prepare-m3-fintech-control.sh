#!/usr/bin/env bash
set -euo pipefail
[[ -f compose.yaml && -f compose.isolated.yaml && -f compose.frontends.yaml ]] || { echo 'Run from the existing project root' >&2; exit 2; }
[[ -f scripts/m3_prepare_fintech_control.py ]] || { echo 'Missing M3 Fintech control script' >&2;exit 2; }
set -a; source .env; set +a
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
echo '[CONFIGURE] ONLY the existing MagaluPay M2M CC test client: JWT access token + dedicated audience.'
"${compose[@]}" build bootstrap
"${compose[@]}" run --rm --no-deps --entrypoint python bootstrap -m scripts.m3_prepare_fintech_control
[[ -f generated/m3-fintech-cc-control-readback.json ]] || { echo 'No WSO2 management readback receipt' >&2;exit 2; }
echo '[OK] Fintech control configured. No tenants, users, stores, volumes, or consent data reset.'
