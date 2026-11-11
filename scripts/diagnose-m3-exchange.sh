#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -x .venv-m3/bin/python ]] || { echo 'Run ./scripts/m3-local.sh setup first' >&2; exit 2; }
for f in generated/manifest.json generated/m3-tokens/subject.jwt generated/m3-tokens/actor.jwt; do
  [[ -r "$f" ]] || { echo "Missing $f. Re-capture with ./scripts/m3-local.sh capture-subject / capture-actor" >&2; exit 2; }
done
.venv-m3/bin/python scripts/m3_exchange_diagnose.py --insecure-local "$@"
