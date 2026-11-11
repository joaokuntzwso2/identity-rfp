#!/usr/bin/env bash
set -euo pipefail
root="${1:-http://127.0.0.1:8180}"
echo '[CHECK] Guided chapter page…'
curl --fail --silent --show-error "$root/m3/isolation" >/dev/null
echo '[CHECK] Sanitized status endpoint…'
curl --fail --silent --show-error "$root/api/m3/isolation/status" >/dev/null
echo '[CHECK] Protected consent mutation without operator key…'
code="$(curl --silent --show-error -o /dev/null -w '%{http_code}' -X POST "$root/api/m3/isolation/consent/prepare")"
if [[ "$code" != '403' ]]; then echo "[FAIL] Expected 403, received $code" >&2;exit 1;fi
printf '[PASS] Chapter is reachable, status is available, unauthorized mutation rejected (403).\n'
printf '[NOTE] This is a smoke test only. Complete live tenant-isolation acceptance in the UI.\n'
