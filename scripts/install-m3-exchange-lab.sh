#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

[[ -f .env && -f generated/manifest.json ]] || {
  echo 'ERROR: Must run in the existing bootstrapped Magalu project; no changes made.' >&2; exit 2;
}
for file in demo/main.py demo/m3_exchange_lab.py demo/m3_exchange_engine.py \
  demo/templates/m3_exchange_lab.html demo/static/m3_exchange_lab.js \
  demo/static/m3_exchange_lab.css scripts/m3_token_exchange_verify.py; do
  [[ -f "$file" ]] || { echo "ERROR: Missing overlay file: $file" >&2; exit 2; }
done

# Do not clobber previous consent and pairwise hotfixes. Patch only stable hooks.
python3 - <<'PY'
from pathlib import Path
p=Path('demo/main.py')
s=p.read_text()
marker='# M3 RFC8693 operator workbench (token files and secrets stay server-side)'
if marker not in s:
    if 'app=FastAPI(' not in s or "app.mount('/static'" not in s:
        raise SystemExit('ERROR: Unsupported dashboard entrypoint; left untouched')
    p.with_suffix('.py.pre_m3_workbench').write_text(s)
    s += ('\n\n'+marker+'\nfrom demo.m3_exchange_lab import router as _m3_exchange_lab_router\n'
          'app.include_router(_m3_exchange_lab_router)\n')
    p.write_text(s)
    print('[OK] Added M3 Token Exchange workbench to dashboard')
else:
    print('[OK] M3 Token Exchange workbench already registered')

p=Path('demo/templates/base.html')
if p.exists():
    s=p.read_text()
    if '/m3/exchange' not in s:
        anchor='<a href="/m2m">'
        if anchor in s:
            s=s.replace(anchor, '<a href="/m3/exchange" class="{% if request.url.path == \'/m3/exchange\' %}active{% endif %}">⇌ &nbsp; Token Exchange · RFC 8693</a>\n'+anchor,1)
            p.with_suffix('.html.pre_m3_workbench').write_text(p.read_text())
            p.write_text(s)
            print('[OK] Added workbench to central dashboard sidebar')
        else:
            print('[NOTE] Existing dashboard nav differs; workbench remains reachable at /m3/exchange')
PY
python3 -m py_compile demo/main.py demo/m3_exchange_engine.py demo/m3_exchange_lab.py

set -a; source .env; set +a
: "${DEMO_OPERATOR_KEY:?DEMO_OPERATOR_KEY must be configured in .env}"
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
compose=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)

echo 'Rebuilding ONLY dashboard/demo container. No WSO2, PostgreSQL or storefront restarts.'
"${compose[@]}" build demo
"${compose[@]}" up -d --no-deps demo

for i in {1..30}; do
    if curl -fsS http://127.0.0.1:8180/m3/exchange >/dev/null && \
       curl -fsS http://127.0.0.1:8180/api/m3/exchange/status >/dev/null; then
        echo '[READY] http://localhost:8180/m3/exchange'
        echo '[READY] http://localhost:8180/api/m3/exchange/status'
        echo '[SAFE] Raw JWTs and client secrets never appear in browser JSON.'
        echo '[NOTE] WSO2 Token Exchange still requires a live positive result; this installer does not claim acceptance.'
        exit 0
    fi
    sleep 2
done

echo 'ERROR: Workbench not ready. Dashboard logs:' >&2
"${compose[@]}" logs --tail=90 demo >&2
exit 1
