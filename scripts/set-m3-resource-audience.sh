#!/usr/bin/env bash
set -euo pipefail
# Explicit operator-only resource audience selection, after registering it on WSO2.
if [[ $# -ne 1 ]]; then echo 'Usage: scripts/set-m3-resource-audience.sh <registered-WSO2-audience>' >&2; exit 2; fi
[[ -f generated/manifest.json && -f .env ]] || { echo 'Run from the existing Magalu CIAM project root.' >&2;exit 2; }
value="$1"
if [[ ! "$value" =~ ^[A-Za-z0-9:._/-]{1,160}$ ]]; then
  echo 'Invalid audience format; no changes made.' >&2;exit 2;
fi
umask 077
printf '%s\n' "$value" > generated/m3-resource-audience.txt
chmod 600 generated/m3-resource-audience.txt
echo '[OK] Dedicated resource audience configured for the local dashboard resource API.'
echo '[IMPORTANT] This does NOT register the audience in WSO2. Verify it on the exchange application in the WSO2 Console.'
echo '[NEXT] Enter the identical value in the 8180 workbench Audience field, then execute the three tests.'
