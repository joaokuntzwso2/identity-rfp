#!/usr/bin/env python3
"""Read-only actor sub vs SCIM ID diagnostic; never prints either identifier."""
import argparse
import json
from pathlib import Path
import requests

try:
    from .m3_token_exchange_verify import read_private, jwk_validate
except ImportError:
    from m3_token_exchange_verify import read_private, jwk_validate


def check(manifest_path, actor_path, discovery, session, tls):
    m=json.loads(Path(manifest_path).read_text())
    expected=m['users']['commerce:bruno.seller']['id']
    if not isinstance(expected,str) or not expected:
        raise ValueError('Actor SCIM ID missing from private manifest')
    token=read_private(actor_path)
    claims=jwk_validate(token,discovery,session,tls)
    actor_sub=claims.get('sub')
    if not isinstance(actor_sub,str):
        raise ValueError('Actor JWT has no valid subject')
    return {'schema':'magalu-m3-actor-identity-probe-v1',
            'jwt_signature_verified':True,
            'registered_scim_id_present':True,
            'actor_sub_equals_scim_id': actor_sub==expected,
            'probable_pairwise_actor_mismatch': actor_sub!=expected,
            'next_action': ('Re-provision only M3 test client with public subject and recapture BOTH JWTs'
                            if actor_sub!=expected else
                            'Actor sub matches manifest SCIM ID; inspect active/locked user and tenant user-store lookup')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--insecure-local',action='store_true')
    p.add_argument('--manifest',default='generated/manifest.json')
    p.add_argument('--actor-file',default='generated/m3-tokens/actor.jwt')
    args=p.parse_args()
    base='https://localhost:9543/t/magalu.demo'
    session=requests.Session()
    verify=not args.insecure_local
    discovery=None
    for path in ('/oauth2/token/.well-known/openid-configuration',
                 '/oauth2/oidcdiscovery/.well-known/openid-configuration',
                 '/.well-known/openid-configuration'):
        try:
            r=session.get(base+path,verify=verify,timeout=10)
            if r.ok and isinstance(r.json(),dict) and 'jwks_uri' in r.json() and 'issuer' in r.json():
                discovery=r.json()
                break
        except (requests.RequestException,ValueError):
            continue
    if discovery is None:
        raise RuntimeError('Could not discover magalu.demo')
    if not discovery['issuer'].startswith('https://localhost:9543/t/magalu.demo/'):
        raise RuntimeError('Unexpected token issuer')
    if not discovery['jwks_uri'].startswith('https://localhost:9543/'):
        raise RuntimeError('Unexpected JWKS origin')
    print(json.dumps(check(args.manifest,args.actor_file,discovery,session,verify),indent=2))

if __name__=='__main__':
    main()
