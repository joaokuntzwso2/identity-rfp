#!/usr/bin/env bash
# Local, non-destructive M3 OAuth token capture / verification runner.
# No tokens, passwords or secrets are echoed by this script.
set -euo pipefail
cd "$(dirname "$0")/.."

venv=".venv-m3"
py="$venv/bin/python"
requirements=( 'PyJWT[crypto]==2.10.1' 'requests==2.32.3' 'cryptography==44.0.2' )

usage() {
  cat <<'HELP'
Usage:
  ./scripts/m3-local.sh setup
  ./scripts/m3-local.sh capture-subject --insecure-local
  ./scripts/m3-local.sh capture-actor --insecure-local
  ./scripts/m3-local.sh verify --insecure-local [--audience REGISTERED_AUDIENCE]

The subject (ana.magalu) and actor (bruno.seller) capture steps require
an interactive login in a browser. The token files are stored privately in
generated/m3-tokens and are not printed.

Without --audience, the verifier is diagnostic only; it will not report full
RFC 8693 acceptance even if a delegated exchange succeeds.
HELP
}

check_python() {
  [[ -x "$py" ]] || {
    echo "ERROR: Local M3 virtual environment not prepared. Run: ./scripts/m3-local.sh setup" >&2
    exit 2
  }
  "$py" - <<'PY'
import jwt, requests, cryptography
PY
}

command="${1:-help}"
if [[ "$#" -gt 0 ]]; then shift; fi
case "$command" in
  setup)
    if [[ ! -x "$py" ]]; then
      python3 -m venv "$venv"
    fi
    "$py" -m pip install --disable-pip-version-check "${requirements[@]}"
    if ! grep -qxF ".venv-m3/" .gitignore 2>/dev/null; then
      printf "\n.venv-m3/\n" >> .gitignore
    fi
    check_python
    echo '[OK] Isolated M3 Python environment configured (PyJWT, requests, cryptography).'
    echo 'No changes to Docker, WSO2 or PostgreSQL.'
    ;;
  capture-subject|capture-actor)
    check_python
    [[ -f generated/m3-oauth-test-client.json ]] || {
      echo 'ERROR: Missing generated/m3-oauth-test-client.json; provision the test client first.' >&2
      exit 2
    }
    role=subject
    [[ "$command" == capture-actor ]] && role=actor
    "$py" scripts/m3_oidc_capture.py --as-user "$role" "$@"
    ;;
  verify)
    check_python
    for f in generated/m3-oauth-test-client.json generated/m3-tokens/subject.jwt generated/m3-tokens/actor.jwt; do
      [[ -f "$f" ]] || {
        echo "ERROR: Missing $f. Run provisioning and both interactive capture steps first." >&2
        exit 2
      }
    done
    "$py" scripts/m3_token_exchange_verify.py \
      --root commerce \
      --subject-file generated/m3-tokens/subject.jwt \
      --actor-file generated/m3-tokens/actor.jwt \
      "$@"
    ;;
  help|-h|--help) usage ;;
  *) usage >&2; echo "ERROR: Invalid action: $command" >&2; exit 2 ;;
esac
