#!/usr/bin/env bash
# Dedicated stack config. Does not touch other Compose projects or data volumes.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
python3 - <<'PY'
from pathlib import Path
import secrets,re
path=Path('.env')
orig=path.read_text() if path.exists() else Path('.env.example').read_text()
rows=orig.splitlines()
values={}
for line in rows:
    m=re.match(r'^([A-Z][A-Z0-9_]*)=(.*)$',line)
    if m: values[m.group(1)]=m.group(2).strip().strip('"').strip("'")
first=values.get('MAGALU_STACK_MODE') != 'independent-root-tenants-v2'
config={
 'MAGALU_STACK_MODE':'independent-root-tenants-v2',
 'MAGALU_ENV_MODE':'isolated',
 'COMPOSE_PROJECT_NAME':'magalu-ciam73-s7lab',
 'IS_ADMIN_USERNAME':'admin',
 'IS_ADMIN_PASSWORD':'admin',
 'IS_PUBLIC_URL':'https://localhost:9543',
 'IS_INTERNAL_URL':'https://is:9543',
 'DEMO_PUBLIC_URL':'http://localhost:8180',
 'DEMO_HOST_PORT':'8180','WSO2_HOST_PORT':'9543',
 'SECTOR_HOST_PORT':'8543',
 'WSO2_IMAGE':('registry.wso2.com/wso2-is/is:7.3.0.18' if first else values.get('WSO2_IMAGE','registry.wso2.com/wso2-is/is:7.3.0.18')),
 'IS_DB_USER':'wso2',
 'SECTOR_URI_ROOT_TEMPLATE':'https://sector-{brand}',
 'IS_TLS_VERIFY':'false',
}
if first:
    config.update({
      'POSTGRES_PASSWORD':secrets.token_hex(24),
      'IS_DB_PASSWORD':secrets.token_hex(24),
      'DEMO_SESSION_SECRET':secrets.token_hex(32),
      'DEMO_OPERATOR_KEY':secrets.token_hex(32),
      'LDAP_ADMIN_PASSWORD':secrets.token_hex(24),
    })
else:
    for name in ('IS_DB_PASSWORD','DEMO_SESSION_SECRET','DEMO_OPERATOR_KEY'):
        if not values.get(name): config[name]=secrets.token_hex(32)
password=config.get('POSTGRES_PASSWORD',values.get('POSTGRES_PASSWORD'))
if not password: raise SystemExit('Missing consent database password')
config['CONSENT_DB_DSN']=f"postgresql://ciam:{password}@db:5432/ciam"
# Ensure variable references don't expand in the bash source command.
for key,value in config.items():
    if any(c in value for c in '\n\r\'"`$'):
        raise SystemExit('Unsafe environment value: '+key)
    regex=re.compile(r'^'+re.escape(key)+r'=')
    for i,line in enumerate(rows):
        if regex.match(line):
            rows[i]=key+'='+value
            break
    else: rows.append(key+'='+value)
if first and path.exists():
    backup=Path('.env.before-root-tenants-v2')
    if not backup.exists():
        backup.write_text(orig)
        backup.chmod(0o600)
path.write_text('\n'.join(rows)+'\n')
path.chmod(0o600)
print('Configured isolated stack: 2 root tenants, 3 brands, 9543/8180/8543 host ports.')
print('WSO2 super-admin: admin/admin (local development only).')
print('Fresh credentials generated for independent databases.' if first else 'Existing stack secrets preserved.')
PY
