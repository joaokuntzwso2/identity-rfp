#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env && -f generated/manifest.json ]] || { echo 'ERROR: Existing bootstrapped project required'; exit 1; }
for f in demo/main.py demo/templates/base.html demo/m3_consent.py consent/migrations/005_m3_directional_enforcement.sql; do
  [[ -f "$f" ]] || { echo "ERROR: Missing $f; did you extract the overlay in the project root?"; exit 1; }
done
# Integrate new routes only once; preserve all existing hotfixes and environment data.
python3 - <<'PY'
from pathlib import Path
root=Path('demo/main.py')
s=root.read_text()
if 'def storefront_subject_matrix(' not in s or 'def assert_csrf(' not in s or 'def session(' not in s:
    raise SystemExit('ERROR: Current dashboard source lacks required session validation API; no changes applied')
marker='# Customer-owned M3 consent-gated resource server (stable integration hook)'
if marker not in s:
    backup=root.with_suffix('.py.before_m3')
    if not backup.exists(): backup.write_text(s)
    s+='\n\n'+marker+'\nfrom demo.m3_consent import install as _install_m3_consent\n'
    s+='_install_m3_consent(app, DB.dsn, lambda request: storefront_subject_matrix(request.cookies, requests.get), session, assert_csrf)\n'
    root.write_text(s)
p=Path('demo/templates/base.html')
s=p.read_text()
if '/m3/consent' not in s:
    backup=p.with_suffix('.html.before_m3')
    if not backup.exists(): backup.write_text(s)
    anchor='<a href="/m2m">'
    if anchor not in s: raise SystemExit('ERROR: Cannot find dashboard navigation anchor')
    s=s.replace(anchor,'<a href="/m3/consent" class="{% if request.url.path == \'/m3/consent\' %}active{% endif %}">◎ &nbsp; Consentimento · Enforcement</a>\n'+anchor)
    p.write_text(s)
PY
python3 -m py_compile demo/main.py demo/m3_consent.py scripts/m3_token_exchange_verify.py
set -a; source .env; set +a
export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
name=magalu-ciam73-s7lab
files=(-f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
echo 'Applying NEW customer-owned consent migration only (NO WSO2 database edits)...'
docker compose -p "$name" "${files[@]}" exec -T db \
  psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-ciam}" -d "${POSTGRES_DB:-ciam}" \
  < consent/migrations/005_m3_directional_enforcement.sql
echo 'Rebuilding only evidence dashboard on port 8180...'
docker compose -p "$name" "${files[@]}" build demo
docker compose -p "$name" "${files[@]}" up -d --no-deps demo
for i in {1..25}; do
  if curl -fsS http://127.0.0.1:8180/m3/consent >/dev/null; then
    echo '[READY] http://localhost:8180/m3/consent'
    echo 'All functionality requires LIVE browser acceptance; no WSO2 or storefront container was restarted.'
    exit 0
  fi
  sleep 2
done
echo 'ERROR: Consent evaluation route is unavailable. Check logs:' >&2
docker compose -p "$name" "${files[@]}" logs --tail=100 demo >&2
exit 1
