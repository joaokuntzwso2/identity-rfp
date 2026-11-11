"""One-time local-only SCIM password reconciliation for interrupted bootstrap.

Resets *only* synthetic users declared in the two-root-tenant manifest.
No passwords, tokens or owner credentials are printed.
"""
import json
import os
from pathlib import Path
import sys
from urllib.parse import quote

from bootstrap.credential_store import stable_user_passwords
from bootstrap.topology import ROOT_TENANTS
from bootstrap.wso2 import WSO2, WSO2Error


def normalize_scim_username(value: str, domain: str) -> str:
    value = str(value)
    if value.startswith('PRIMARY/'):
        value = value.removeprefix('PRIMARY/')
    if value.endswith('@' + domain):
        value = value[:-(len(domain) + 1)]
    return value


def patch_password_request(password: str) -> dict:
    """SCIM 2 PatchOp updates a core attribute (never use forced-reset flow)."""
    return {
        'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations': [{'op': 'replace', 'value': {'password': password}}],
    }


def reconcile(api, *, user_id: str, username: str, domain: str, password: str):
    path = '/scim2/Users/' + quote(user_id, safe='')
    before, _ = api.call('GET', path, expected=(200,))
    if not isinstance(before, dict) or before.get('id') != user_id:
        raise WSO2Error('SCIM user ID mismatch for ' + domain + '/' + username)
    if normalize_scim_username(before.get('userName', ''), domain) != username:
        raise WSO2Error('SCIM userName mismatch for ' + domain + '/' + username)
    if before.get('active') is False:
        raise WSO2Error('SCIM user is inactive: ' + domain + '/' + username)
    # Tenant-scoped administrator credential + explicit user ID readback
    # ensure no operation can cross the configured root tenant boundary.
    try:
        api.call('PATCH', path, json=patch_password_request(password),
                 headers={'Content-Type': 'application/scim+json'},
                 expected=(200, 204))
    except WSO2Error as exc:
        raise WSO2Error(str(exc).replace(password, '[REDACTED]')) from None
    after, _ = api.call('GET', path, expected=(200,))
    if not isinstance(after, dict) or after.get('id') != user_id or \
       normalize_scim_username(after.get('userName', ''), domain) != username:
        raise WSO2Error('Post-update SCIM readback failed for ' + domain + '/' + username)
    return True


def main():
    if os.getenv('MAGALU_STACK_MODE') != 'independent-root-tenants-v2' or \
       os.getenv('MAGALU_ENV_MODE') != 'isolated':
        raise RuntimeError('Only supported in isolated Magalu root-tenant PoC')
    if '--apply' not in sys.argv:
        raise RuntimeError('Explicit --apply required to update synthetic user passwords')
    path = Path(os.getenv('MANIFEST_FILE', '/project/generated/manifest.json'))
    if not path.exists():
        raise RuntimeError('Completed bootstrap manifest required; do not create new users')
    manifest = json.loads(path.read_text())
    persisted = stable_user_passwords(
        ROOT_TENANTS, path,
        Path(os.getenv('USER_SECRETS_FILE', '/project/generated/user-secrets.json')))
    if manifest.get('schema_version') != 2:
        raise RuntimeError('Unsupported bootstrap manifest schema')
    owner_secrets = json.loads((path.parent / 'tenant-secrets.json').read_text())
    base = os.environ['IS_INTERNAL_URL'].rstrip('/')
    verify = os.getenv('IS_TLS_VERIFY', 'false').lower() == 'true'
    repaired = 0
    for root, spec in ROOT_TENANTS.items():
        domain = spec['domain']
        if manifest['root_tenants'][root]['domain'] != domain:
            raise RuntimeError('Root tenant mismatch: ' + root)
        owner = owner_secrets[root]['owner_password']
        api = WSO2(base + '/t/' + quote(domain, safe=''),
                   spec['owner'] + '@' + domain, owner, verify)
        for username, *_ in spec['people']:
            key = root + ':' + username
            entry = manifest['users'].get(key)
            if not entry or entry['root'] != root or entry['username'] != username or not entry.get('id'):
                raise RuntimeError('Missing or mismatched identity in manifest: ' + key)
            # Do not repair extra users that were onboarded separately.
            reconcile(api, user_id=entry['id'], username=username,
                      domain=domain, password=persisted[key])
            print('[PATCHED] ' + domain + '/' + username + ' (password not displayed)')
            repaired += 1
    print('[OK] ' + str(repaired) + ' synthetic credentials synchronized with persistent manifest')
    print('A SCIM PATCH success is not an interactive-login test. Verify via browser next.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, WSO2Error, OSError, KeyError, ValueError) as exc:
        # Avoid including raw password material from the HTTP request.
        print('[BLOCKED] ' + str(exc)[:250], file=sys.stderr)
        sys.exit(1)
