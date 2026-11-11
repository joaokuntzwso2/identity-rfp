#!/usr/bin/env python3
"""RFC 8693 local acceptance harness. Never logs raw tokens or client secrets.

Requires two JWT access tokens obtained through *authorized* OIDC/OAuth code flows.
Pass them as permission-restricted files, not command-line arguments.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import stat
import sys
from urllib.parse import urlsplit

import jwt
import requests

TOKEN_TYPE='urn:ietf:params:oauth:token-type:jwt'
ACCESS_TYPE='urn:ietf:params:oauth:token-type:access_token'
EXCHANGE='urn:ietf:params:oauth:grant-type:token-exchange'


def read_private(path):
    p=Path(path)
    meta=p.stat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077:
        raise ValueError('Token input must be a regular file with chmod 600 (or stricter)')
    value=p.read_text().strip()
    if value.count('.')!=2 or len(value)<80:
        raise ValueError('Expected one JWT access token (three dot-separated segments)')
    return value


def token_scopes(payload):
    raw=payload.get('scope',payload.get('scp',[]))
    if isinstance(raw,str): return set(raw.split())
    if isinstance(raw,list) and all(isinstance(s,str) for s in raw): return set(raw)
    return set()


def jwk_validate(value,disco,session,verify):
    header=jwt.get_unverified_header(value)
    alg=header.get('alg')
    if alg not in ('RS256','PS256','ES256'):
        raise ValueError('Unsupported JWT signature algorithm')
    jwks_resp=session.get(disco['jwks_uri'],timeout=10,verify=verify)
    jwks_resp.raise_for_status()
    matching=[j for j in jwks_resp.json().get('keys',[]) if j.get('kid')==header.get('kid')]
    if len(matching)!=1:
        raise ValueError('No unique matching WSO2 signing key found')
    key=jwt.PyJWK.from_dict(matching[0],algorithm=alg).key
    claims=jwt.decode(value,key,algorithms=[alg],issuer=disco['issuer'],
                      options={'verify_aud':False,'require':['iss','sub','aud','iat','exp']})
    if not claims.get('aud'): raise ValueError('JWT missing audience')
    return claims


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',choices=['commerce','fintech'],default='commerce')
    p.add_argument('--subject-file',required=True,help='chmod 600 JWT for owner of subject permissions')
    p.add_argument('--actor-file',required=True,help='chmod 600 JWT for distinct acting user')
    p.add_argument('--requested-scope',default='requests:read')
    p.add_argument('--audience',help='Optional configured exchange audience; required for audience-bound acceptance')
    p.add_argument('--base-url',default='https://localhost:9543')
    p.add_argument('--insecure-local',action='store_true',help='Localhost/self-signed PoC ONLY')
    p.add_argument('--manifest',default='generated/manifest.json')
    args=p.parse_args()
    host=urlsplit(args.base_url)
    if args.insecure_local and (host.hostname not in ('localhost','127.0.0.1') or host.scheme!='https'):
        raise SystemExit('--insecure-local is only allowed for https://localhost or 127.0.0.1')
    verify=not args.insecure_local
    m=json.loads(Path(args.manifest).read_text())
    c=m['clients']['m2m:'+args.root+':exchange']
    if not c.get('client_secret'): raise SystemExit('Exchange client secret missing from local manifest')
    root=c['tenant_domain']
    session=requests.Session()
    disco=None
    for path in ('/oauth2/token/.well-known/openid-configuration',
                 '/oauth2/oidcdiscovery/.well-known/openid-configuration',
                 '/.well-known/openid-configuration'):
        try:
            r=session.get(args.base_url.rstrip('/')+'/t/'+root+path,timeout=10,verify=verify)
            if r.ok and r.json().get('issuer') and r.json().get('jwks_uri'):
                disco=r.json();break
        except (requests.RequestException,ValueError): pass
    if not disco: raise SystemExit('Tenant-scoped discovery not available')
    def from_public(url):
        # Strict scheme+authority prevents allowing untrusted discovery destinations.
        base=urlsplit(args.base_url)
        target=urlsplit(url)
        if target.hostname not in (base.hostname,'localhost') or target.scheme!='https':
            raise ValueError('Untrusted endpoint hostname/scheme from discovery')
        return url
    disco['jwks_uri']=from_public(disco['jwks_uri'])
    token_url=from_public(disco['token_endpoint'])
    subject=read_private(args.subject_file)
    actor=read_private(args.actor_file)
    subclaims=jwk_validate(subject,disco,session,verify)
    actorclaims=jwk_validate(actor,disco,session,verify)
    if subclaims['sub']==actorclaims['sub']:
        raise SystemExit('Actor and subject must be distinct WSO2 identities')
    if 'requests:approve' not in token_scopes(actorclaims):
        raise SystemExit('Actor token must carry the expected approver permission')
    owner_scopes=token_scopes(subclaims)
    requested=set(args.requested_scope.split())
    if not requested or not requested<owner_scopes:
        raise SystemExit('Subject token must have a STRICT superset of requested scopes to prove reduction')
    if 'requests:approve' in requested:
        raise SystemExit('Expected a narrowed read-only scope, not an approval scope')

    def exchange(scope):
        payload={'grant_type':EXCHANGE,'subject_token':subject,
                 'subject_token_type':TOKEN_TYPE,'actor_token':actor,
                 'actor_token_type':TOKEN_TYPE,'requested_token_type':ACCESS_TYPE,
                 'scope':scope}
        if args.audience: payload['audience']=args.audience
        r=session.post(token_url,data=payload,auth=(c['client_id'],c['client_secret']),
                       verify=verify,timeout=25)
        try: body=r.json()
        except ValueError: body={}
        value=body.get('access_token')
        return r.status_code,body,value

    outcome={'root':root,'subject_signature_verified':True,'actor_signature_verified':True,
             'subject_actor_distinct':True,'subject_scope_count':len(owner_scopes),
             'requested_scopes':sorted(requested),'audience_bound':bool(args.audience),
             'tests':{}}
    http,reply,token=exchange(' '.join(sorted(requested)))
    good=(http==200 and bool(token) and reply.get('issued_token_type')==ACCESS_TYPE)
    detail={'http':http,'token_issued':bool(token),
            'issued_token_type_valid':reply.get('issued_token_type')==ACCESS_TYPE}
    if good:
        try:
            claim=jwk_validate(token,disco,session,verify)
            scopes=token_scopes(claim)
            actorclaim=claim.get('act')
            detail.update({'signature_verified':True,
                'sub_preserved':claim['sub']==subclaims['sub'],
                'actor_preserved':isinstance(actorclaim,dict) and actorclaim.get('sub')==actorclaims['sub'],
                'scope_restricted':bool(requested <= scopes <= owner_scopes),
                'no_approve_scope':'requests:approve' not in scopes,
                'audience_match':not args.audience or args.audience in ([claim['aud']] if isinstance(claim['aud'],str) else claim['aud'])})
            good=all(detail.get(k,False) for k in ('sub_preserved','actor_preserved','scope_restricted','no_approve_scope','audience_match'))
        except (ValueError,jwt.PyJWTError,KeyError,requests.RequestException) as exc:
            detail.update({'signature_verified':False,'error':type(exc).__name__});good=False
    outcome['tests']['delegated_readonly_exchange']={'pass':good,**detail}
    # Request a privilege that the *subject token* never carried.
    if 'requests:approve' not in owner_scopes:
        http,reply,token=exchange('requests:approve')
        bad_scope=False
        if token:
            try: bad_scope='requests:approve' in token_scopes(jwk_validate(token,disco,session,verify))
            except (ValueError,jwt.PyJWTError,requests.RequestException): bad_scope=True
        outcome['tests']['scope_escalation_rejected']={'pass':not bad_scope,
                'http':http,'forbidden_scope_issued':bad_scope}
    else:
        outcome['tests']['scope_escalation_rejected']={'pass':False,
                'blocked':'Subject has requests:approve; use a read-only subject for negative test'}
    outcome['result']='PASS' if args.audience and all(t.get('pass') for t in outcome['tests'].values()) else 'INCOMPLETE_OR_FAIL'
    print(json.dumps(outcome,indent=2))
    return 0 if outcome['result']=='PASS' else 2


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:
        print(json.dumps({'result':'FAIL','error_type':type(exc).__name__,'message':str(exc)[:160]}))
        sys.exit(1)
