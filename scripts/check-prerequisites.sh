#!/usr/bin/env bash
set -euo pipefail
for cmd in docker curl openssl; do command -v "$cmd" >/dev/null || { echo "Missing $cmd"; exit 1; }; done
: "${IS_PUBLIC_URL:=https://localhost:9443}"
curl -ksSf --max-time 7 "${IS_PUBLIC_URL}/oauth2/token/.well-known/openid-configuration" >/dev/null || \
curl -ksSf --max-time 7 "${IS_PUBLIC_URL}/oauth2/oidcdiscovery/.well-known/openid-configuration" >/dev/null || \
curl -ksSf --max-time 7 "${IS_PUBLIC_URL}/.well-known/openid-configuration" >/dev/null || \
{ echo "OIDC discovery unavailable: check the IS URL and server health"; exit 1; }
echo "OIDC discovery is reachable. Verify subject_types_supported contains pairwise in the final report."
