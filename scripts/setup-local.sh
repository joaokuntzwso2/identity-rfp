#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'Deprecated command for the ROOT-TENANT architecture. Use ./scripts/run-isolated.sh' >&2
exec "$(dirname "$0")/run-isolated.sh" "$@"
