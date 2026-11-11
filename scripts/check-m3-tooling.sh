#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f scripts/m3_provision_oauth_test_client.py ]] || {
  echo 'ERROR: M3 overlay not installed in this directory' >&2; exit 2;
}
[[ -f bootstrap/wso2.py ]] || {
  echo 'ERROR: WSO2 bootstrap module not found' >&2; exit 2;
}
python3 -m py_compile scripts/m3_provision_oauth_test_client.py scripts/m3_oidc_capture.py scripts/m3_token_exchange_verify.py
python3 - <<'PY'
from pathlib import Path
text=Path('scripts/provision-m3-oauth-test.sh').read_text()
assert 'python -m scripts.m3_provision_oauth_test_client' in text, 'Expected module invocation'
print('[OK] Bootstrap Python module path and M3 script syntax checks')
PY
bash -n scripts/provision-m3-oauth-test.sh scripts/m3-local.sh scripts/check-m3-tooling.sh
printf '%s\n' '[OK] M3 runtime patch installed. WSO2 and PostgreSQL unchanged.'
