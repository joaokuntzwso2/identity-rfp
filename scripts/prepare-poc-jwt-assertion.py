#!/usr/bin/env python3
"""Generate a fresh, private RFC 7523 *test* assertion for a registered issuer.

Does not register the signing public key or trust in WSO2. No WSO2 access.
Use only with a synthetic test subject and a configured authorized lab issuer.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import time
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT=Path('/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc')

def write_private(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    fd=os.open(str(path),flags,0o600)
    try:
        with os.fdopen(fd,'wb') as f: f.write(value)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main():
    a=argparse.ArgumentParser()
    a.add_argument('--root',required=True,choices=['commerce','fintech'])
    a.add_argument('--issuer',required=True,help='The TRUSTED assertion issuer registered in WSO2')
    a.add_argument('--subject',required=True,help='Synthetic subject registered with the issuer')
    a.add_argument('--token-endpoint',required=True,help='Exact WSO2 token endpoint aud')
    args=a.parse_args()
    expected='magalu.demo' if args.root=='commerce' else 'magalupay.demo'
    if not args.issuer.startswith('https://') or expected not in args.token_endpoint or not args.token_endpoint.startswith('https://'):
        a.error('issuer/audience must use HTTPS and the expected WSO2 tenant')
    directory=ROOT/'generated'/'m3-tokens';directory.mkdir(parents=True,exist_ok=True)
    private=directory/('jwt-bearer-'+args.root+'-signer.key')
    public=directory/('jwt-bearer-'+args.root+'-signer-public.pem')
    token=directory/('jwt-bearer-'+args.root+'.jwt')
    if not private.exists():
        k=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        write_private(private,k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        write_private(public,k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    else:
        k=serialization.load_pem_private_key(private.read_bytes(),password=None)
    now=int(time.time());jti=secrets.token_urlsafe(32)
    claims={'iss':args.issuer,'sub':args.subject,'aud':args.token_endpoint,
            'iat':now,'nbf':now-2,'exp':now+120,'jti':jti}
    encoded=jwt.encode(claims,k,algorithm='RS256',headers={'typ':'JWT'})
    if token.exists():token.unlink()
    write_private(token,(encoded+'\n').encode())
    print('Fresh private assertion generated:',token)
    print('Public key (register with trusted issuer / WSO2):',public)
    print('No WSO2 trust registration has been performed.')
    print('Run replay test immediately before assertion expiry (120 seconds).')

if __name__=='__main__':main()
