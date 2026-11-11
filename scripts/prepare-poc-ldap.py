#!/usr/bin/env python3
"""Generate private LDIF fixture, without touching running LDAP volumes.

Does NOT change LDAP/WSo2; previous seeded fixture may already exist.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import json
import secrets
import os
import argparse

ROOT=Path('/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc')

def json_quoted(x):
    return json.dumps(x)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--generate',action='store_true');args=parser.parse_args()
    out=ROOT/'generated'/'poc-ldap'
    f=out/'50-seller.ldif'
    if f.exists():
        print('Existing LDAP fixture preserved:',f)
        return
    if not args.generate:
        print('Run --generate to create a new private fixture. Does not reset LDAP.')
        return
    out.mkdir(parents=True,exist_ok=True)
    password=secrets.token_urlsafe(26)
    # RFC 2307 userPassword; random salt, salted SHA-1 only for legacy LDAP demo fixture.
    # Prefer LDAPS + stronger LDAP password storage in real environments.
    salt=secrets.token_bytes(12)
    import base64
    digest=hashlib.sha1(password.encode()+salt).digest()+salt
    hashed='{SSHA}'+base64.b64encode(digest).decode()
    contents=(
        'dn: ou=people,dc=example,dc=test\nobjectClass: organizationalUnit\nou: people\n\n'
        'dn: uid=ldap.seller,ou=people,dc=example,dc=test\n'
        'objectClass: inetOrgPerson\nobjectClass: posixAccount\nobjectClass: top\n'
        'cn: LDAP Seller\nsn: Seller\nuid: ldap.seller\nuidNumber: 22011\n'
        'gidNumber: 22011\nhomeDirectory: /home/ldap.seller\n'
        f'userPassword: {hashed}\n'
    )
    f.write_text(contents)
    os.chmod(f,0o600)
    pwfile=out/'test-user-password.txt';pwfile.write_text(password+'\n');os.chmod(pwfile,0o600)
    print('Private LDAP fixture generated in:',out)
    print('Password stored ONLY in private test-user-password.txt (never commit).')
    admin=out/'ldap-admin-password.txt'
    admin.write_text(secrets.token_urlsafe(28)+'\n');os.chmod(admin,0o600)
    overlay=out/'compose.poc-ldap.yaml'
    src=str(f)
    overlay.write_text('services:\n  ldap:\n    volumes:\n      - '+json_quoted(src+':/container/service/slapd/assets/config/bootstrap/ldif/custom/50-seller.ldif:ro')+'\n')
    os.chmod(overlay,0o600)
    print('Private Compose seed override:',overlay)
    print('LDAP admin password in private ldap-admin-password.txt')
    print('IMPORTANT: Existing LDAP volumes are not changed. See runbook for WSO2 registration.')

if __name__=='__main__':main()
