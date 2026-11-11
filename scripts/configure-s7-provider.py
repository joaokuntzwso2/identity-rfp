#!/usr/bin/env python3
"""Configure the public signing keys of a real independently operated verifier.

This does NOT enroll a biometric provider, execute a check or issue proof; the
trusted integration must implement the signed attestation contract in the runbook.
Never accepts private signing keys or application secrets.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

PROJECT = Path('/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc')


def check_jwks(raw: bytes) -> dict:
    if len(raw) > 65536:
        raise ValueError('JWKS_TOO_LARGE')
    obj = json.loads(raw)
    if not isinstance(obj, dict) or not isinstance(obj.get('keys'), list) or not obj['keys']:
        raise ValueError('JWKS_MISSING_PUBLIC_KEYS')
    seen = set()
    forbidden = {'d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'}
    for k in obj['keys']:
        if not isinstance(k, dict) or k.get('kty') not in ('RSA', 'EC'):
            raise ValueError('ONLY_PUBLIC_RSA_EC_KEYS_SUPPORTED')
        if any(param in k for param in forbidden):
            raise ValueError('PRIVATE_KEY_MATERIAL_REJECTED')
        kid = k.get('kid')
        if not isinstance(kid, str) or not kid or kid in seen:
            raise ValueError('KID_REQUIRED_AND_UNIQUE')
        seen.add(kid)
        if k['kty'] == 'RSA' and not all(x in k for x in ('n', 'e')):
            raise ValueError('INCOMPLETE_RSA_JWK')
        if k['kty'] == 'EC' and not all(x in k for x in ('crv', 'x', 'y')):
            raise ValueError('INCOMPLETE_EC_JWK')
    return obj


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--issuer', required=True, help='HTTPS issuer of external signed verifier attestations')
    ap.add_argument('--audience', default='magalu-ciam-rfp-s7')
    ap.add_argument('--jwks-file', type=Path, required=True, help='public-only JWKS file')
    args = ap.parse_args()
    root = Path.cwd().resolve()
    top = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()).resolve()
    if root != PROJECT or top != PROJECT:
        raise SystemExit('WRONG_GIT_ROOT: only run in Magalu CIAM repository')
    if not args.issuer.startswith('https://') or not args.audience or '\n' in args.issuer:
        raise SystemExit('Verifier issuer must be HTTPS and audience non-empty')
    if not args.jwks_file.is_file():
        raise SystemExit('Provider public JWKS file not found')
    raw = args.jwks_file.read_bytes()
    check_jwks(raw)
    generated = root / 'generated'
    generated.mkdir(exist_ok=True)
    dest = generated / 's7-provider-jwks.json'
    if dest.exists():
        backup=generated/'backups'/('s7-provider-public-jwks-'+str(int(time.time()))+'.json')
        backup.parent.mkdir(exist_ok=True,parents=True)
        shutil.copy2(dest,backup)
        os.chmod(backup,0o600)
    dest.write_bytes(raw)
    os.chmod(dest,0o600)
    # JSON strings are valid YAML double-quoted scalars (no interpolation of host code).
    override=root/'compose.s7-provider.local.yaml'
    override.write_text('services:\n  demo:\n    environment:\n'
        '      S7_PROVIDER_JWKS_FILE: /project/generated/s7-provider-jwks.json\n'
        f'      S7_PROVIDER_ISSUER: {json.dumps(args.issuer)}\n'
        f'      S7_PROVIDER_AUDIENCE: {json.dumps(args.audience)}\n')
    os.chmod(override,0o600)
    ignore=root/'.gitignore'
    entry='/compose.s7-provider.local.yaml'
    lines=ignore.read_text().splitlines() if ignore.exists() else []
    if entry not in lines:
        with ignore.open('a') as f: f.write('\n# Private local Section 7 verification bridge\n'+entry+'\n')
    print('Configured trusted public verifier keys:',len(check_jwks(raw)['keys']))
    print('Local-only Compose override:',override)
    print('No signing private keys, biometric images, tokens, or vendor secrets copied.')
    print('Rerun bash scripts/run-s7-acceptance.sh to restart the dashboard with the override.')
    print('Provider must separately implement verified real N2/N3 assertions as documented.')

if __name__=='__main__':main()
