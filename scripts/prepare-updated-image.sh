#!/usr/bin/env bash
# IMPORTANT: Builds a NEW project image; no container/volume is reused from elsewhere.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
image="${WSO2_IMAGE:-magalu-local/is:7.3.0.18}"
if docker image inspect "$image" >/dev/null 2>&1; then
  echo "Using available software image: $image (containers and DBs will still be NEW)."
  exit 0
fi
if [[ -z "${WSO2_DIST_PATH:-}" ]]; then
  echo 'No WSO2_IMAGE and no WSO2_DIST_PATH. Set the absolute path to your updated 7.3.0.18 ZIP in .env.' >&2
  echo 'Example: WSO2_DIST_PATH=/Users/your-user/Downloads/wso2is-7.3.0.zip' >&2
  exit 2
fi
if [[ ! -e "$WSO2_DIST_PATH" ]]; then
  echo "Missing updated WSO2 distribution: $WSO2_DIST_PATH" >&2
  exit 2
fi
mkdir -p generated/distribution
if [[ -d "$WSO2_DIST_PATH" ]]; then
  [[ "$(basename "$WSO2_DIST_PATH")" == 'wso2is-7.3.0' ]] || {
    echo 'Expected WSO2_DIST_PATH to be the wso2is-7.3.0 directory itself.' >&2; exit 2; }
  (cd "$(dirname "$WSO2_DIST_PATH")" && zip -qr - 'wso2is-7.3.0') > generated/distribution/wso2is-updated.zip
else
  if ! unzip -Z1 "$WSO2_DIST_PATH" | grep -qx 'wso2is-7.3.0/bin/wso2server.sh'; then
    echo 'Not a standard WSO2 IS 7.3.0 distribution archive layout.' >&2; exit 2
  fi
  cp "$WSO2_DIST_PATH" generated/distribution/wso2is-updated.zip
fi
chmod 600 generated/distribution/wso2is-updated.zip
# This check cannot cryptographically prove update level; the operator must select the updated pack.
docker build --file docker/wso2/Dockerfile.from-distribution --tag "$image" .
echo "Built dedicated image $image from supplied updated distribution."
