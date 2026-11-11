#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m py_compile demo/m3_exchange_engine.py demo/m3_exchange_lab.py
printf '[CHECK] HTML route: '
curl -fsS http://localhost:8180/m3/exchange | grep -q 'Bruno recebe só o acesso necessário' && echo PASS
printf '[CHECK] Status API: '
curl -fsS http://localhost:8180/api/m3/exchange/status | python3 -c '
import json,sys
v=json.load(sys.stdin)
assert v["schema"]=="magalu-rfc8693-workbench-status-v1"
assert v["operator_required"] is True
assert "client_secret" not in json.dumps(v)
assert "access_token" not in json.dumps(v)
print("PASS")'
printf '[CHECK] Unauthorized POST denied: '
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://localhost:8180/api/m3/exchange/run -H 'Content-Type: application/json' -H 'Origin: http://localhost:8180' --data '{}')
[[ "$code" == 403 || "$code" == 503 ]] && echo "PASS (HTTP $code)" || { echo "FAIL (HTTP $code)"; exit 1; }
echo 'Workbench endpoints reachable; diagnostic results still require LIVE token exchange.'
