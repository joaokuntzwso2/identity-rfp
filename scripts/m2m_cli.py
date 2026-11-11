"""Real RFC 6749/8693 requests, no artificial token success or assertion replay."""
import argparse
import base64
import json
import os
from pathlib import Path
import sys
import time
import requests
import jwt


def main():
    cli=argparse.ArgumentParser()
    cli.add_argument('flow',choices=['client-credentials','token-exchange','jwt-bearer'])
    cli.add_argument('--subject-token',help='Existing approved subject token; do not reuse expired tokens')
    cli.add_argument('--actor-token',help='Actor token; used for delegation trace')
    cli.add_argument('--assertion',help='Signed assertion from registered trusted token issuer')
    cli.add_argument('--scope',default='',help='Requested narrower scopes (approved by AS)')
    cli.add_argument('--root',default='commerce',choices=['commerce','fintech'],help='Target WSO2 root tenant')
    args=cli.parse_args()
    m=json.loads(Path(os.getenv('MANIFEST_FILE','generated/manifest.json')).read_text())
    key='m2m:'+args.root+':'+{'client-credentials':'cc','token-exchange':'exchange','jwt-bearer':'jwt'}[args.flow]
    c=m['clients'][key]
    if not c.get('client_secret'):
        raise SystemExit('Client secret unavailable. Grant verification cannot continue.')
    token_url=os.getenv('IS_INTERNAL_URL',m['is_internal_url']).rstrip('/')+'/t/'+c['tenant_domain']+'/oauth2/token'
    payload={}
    if args.flow=='client-credentials':
        payload={'grant_type':'client_credentials'}
    elif args.flow=='jwt-bearer':
        if not args.assertion: raise SystemExit('Provide --assertion signed by trusted issuer')
        payload={'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer','assertion':args.assertion}
    elif args.flow=='token-exchange':
        if not args.subject_token: raise SystemExit('Provide --subject-token from a trusted source')
        payload={'grant_type':'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token':args.subject_token,
            'subject_token_type':'urn:ietf:params:oauth:token-type:access_token',
            'requested_token_type':'urn:ietf:params:oauth:token-type:access_token'}
        if args.actor_token:
            payload['actor_token']=args.actor_token
            payload['actor_token_type']='urn:ietf:params:oauth:token-type:access_token'
    if args.scope: payload['scope']=args.scope
    response=requests.post(token_url,auth=(c['client_id'],c['client_secret']),data=payload,
                           verify=os.getenv('IS_TLS_VERIFY','true').lower()=='true',timeout=25)
    try: result=response.json()
    except ValueError: result={'error_description':response.text[:240]}
    access=result.pop('access_token',None)
    result.pop('refresh_token',None)
    print(json.dumps({'flow':args.flow,'http_status':response.status_code,
                      'token_issued':bool(access),'response_without_token':result},indent=2))
    if not response.ok or not access: return 1
    if args.flow=='token-exchange':
        valid_type=result.get('issued_token_type')=='urn:ietf:params:oauth:token-type:access_token'
        print('issued_token_type matches RFC8693:',valid_type)
        if not valid_type: return 2
        try:
            # Observational only; never use unverified payload for an authorization decision.
            parts=access.split('.')
            if len(parts)==3:
                claims=jwt.decode(access,options={'verify_signature':False})
                print('Observational actor claim present:',bool(claims.get('act')))
                if args.actor_token and not claims.get('act'): return 3
        except Exception as exc:
            print('Unable to observe act claim:',str(exc))
            if args.actor_token: return 3
    return 0

if __name__=='__main__': sys.exit(main())
