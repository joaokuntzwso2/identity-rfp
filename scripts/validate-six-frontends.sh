#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import json,urllib.request,sys
sites=[('Magalu','Web',8181),('Magalu','Mobile',8182),
       ('Netshoes','Web',8183),('Netshoes','Mobile',8184),
       ('MagaluPay','Web',8185),('MagaluPay','Mobile',8186)]
cookies=set()
for brand,channel,port in sites:
    base=f'http://127.0.0.1:{port}'
    try:
        with urllib.request.urlopen(base+'/healthz',timeout=10) as response:
            obj=json.load(response)
        assert obj['manifest_present'] is True, 'storefront manifest missing'
        assert obj['cookie_name'] not in cookies, 'cookie collision'
        cookies.add(obj['cookie_name'])
        with urllib.request.urlopen(base+'/api/session',timeout=10) as response:
            session=json.load(response)
        assert session['authenticated'] is False, 'unexpected authenticated state from clean probe'
        with urllib.request.urlopen(base+'/',timeout=10) as response:
            assert response.status==200
    except Exception as exc:
        print(f'[FAIL] {brand} {channel} — {exc}')
        sys.exit(1)
    print(f'[PASS] {brand:<10} {channel:<7} {base} | {obj["cookie_name"]}')
print('All six services reachable, independently cookie-namespaced and unauthenticated on clean requests.')
print('This is NOT a substitute for six real browser logins, logout tests or TOTP approval.')
PY
