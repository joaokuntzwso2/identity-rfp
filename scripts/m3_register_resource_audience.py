"""Idempotently register one dedicated RFC 8693 target audience on the Commerce
exchange application. Run as a module *inside the existing bootstrap container*.

Never modifies WSO2 product databases, storefront OIDC apps, or consent data.
Only this existing M2M token-exchange application's idToken.audience is changed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

from bootstrap.wso2 import WSO2
from bootstrap.topology import ROOT_TENANTS

ACCEPTED = frozenset({
    'clientId','clientSecret','grantTypes','callbackURLs','allowedOrigins',
    'publicClient','pkce','accessToken','hybridFlow','refreshToken',
    'subjectToken','idToken','logout','validateRequestObjectSignature',
    'scopeValidators','clientAuthentication','requestObject',
    'pushAuthorizationRequest','subject','isFAPIApplication',
})
DEFAULT = 'urn:magalu:poc:requests'

def _write_private(path:Path, data:object):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp = path.with_name('.'+path.name+'.tmp')
    with tmp.open('w',encoding='utf-8') as fh:
        if isinstance(data,str): fh.write(data+'\n')
        else: json.dump(data,fh,indent=2,ensure_ascii=False); fh.write('\n')
    tmp.chmod(0o600)
    tmp.replace(path)
    path.chmod(0o600)

def _audiences(config:dict)->list[str]:
    token=config.get('idToken') or {}
    if not isinstance(token,dict): raise ValueError('Unexpected OIDC idToken object')
    aud=token.get('audience') or []
    if not isinstance(aud,list) or any(not isinstance(x,str) for x in aud):
        raise ValueError('Unexpected OIDC idToken.audience type; refusing update')
    if len(aud)!=len(set(aud)):
        raise ValueError('Duplicate configured audiences; refusing automatic repair')
    return aud

def _preserved(before:dict,after:dict)->bool:
    fields=('clientId','grantTypes','callbackURLs','publicClient','subject','accessToken')
    return all(before.get(f)==after.get(f) for f in fields)

def register(api, manifest, audience, generated:Path, *, check_only=False):
    client=manifest['clients']['m2m:commerce:exchange']
    if client.get('tenant_domain')!='magalu.demo' or not client.get('app_id') or not client.get('client_id'):
        raise ValueError('Expected Commerce exchange client is missing or inconsistent')
    path='/api/server/v1/applications/'+quote(str(client['app_id']),safe='')+'/inbound-protocols/oidc'
    current,_=api.call('GET',path)
    if not isinstance(current,dict) or current.get('clientId')!=client['client_id']:
        raise ValueError('WSO2 management API returned a different application; no update attempted')
    grants=current.get('grantTypes') or []
    if 'urn:ietf:params:oauth:grant-type:token-exchange' not in grants:
        raise ValueError('Exchange application does not advertise the RFC 8693 grant')
    existing=_audiences(current)
    change_needed=audience not in existing
    if change_needed and check_only:
        return {'result':'BLOCKED','registered':False,'reason':'AUDIENCE_NOT_REGISTERED'}
    backup=None
    if change_needed:
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup=generated/('m3-exchange-oidc-before-audience-'+stamp+'.json')
        _write_private(backup,current)
        patched=dict(current)
        patched['idToken']={**(current.get('idToken') or {}),'audience':existing+[audience]}
        payload={k:v for k,v in patched.items() if k in ACCEPTED and v is not None}
        api.call('PUT',path,json=payload,expected=(200,201,204))
    verified,_=api.call('GET',path)
    if (not isinstance(verified,dict) or verified.get('clientId')!=client['client_id']
        or audience not in _audiences(verified) or not _preserved(current,verified)):
        raise RuntimeError('WSO2 OIDC readback does not verify requested audience or preserved settings')
    receipt={'schema':'magalu-m3-audience-registration-v1',
             'tenant':'magalu.demo','application_id':client['app_id'],
             'client_id':client['client_id'],'audience':audience,
             'oidc_management_api_readback_verified':True,
             'readback_at':datetime.now(timezone.utc).isoformat(),
             'registration_source':'WSO2 application inbound-protocols/oidc',
             'mutation':'ADDED' if change_needed else 'ALREADY_REGISTERED'}
    # Write only after management-API readback. These files are shared with demo
    # via the existing generated volume. No secrets in the JSON receipt.
    _write_private(generated/'m3-resource-audience.txt',audience)
    _write_private(generated/'m3-resource-audience-readback.json',receipt)
    return {'result':'M3_AUDIENCE_REGISTERED_AND_VERIFIED',
            'tenant':'magalu.demo','audience':audience,
            'changed':change_needed,'readback_verified':True,
            'private_backup_created':backup is not None}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audience',default=DEFAULT)
    parser.add_argument('--check-only',action='store_true')
    args=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9:._/-]{1,160}',args.audience):
        raise SystemExit('Invalid audience format')
    generated=Path(os.getenv('MANIFEST_FILE','/project/generated/manifest.json')).parent
    manifest=json.loads((generated/'manifest.json').read_text())
    secrets=json.loads((generated/'tenant-secrets.json').read_text())
    domain=manifest['root_tenants']['commerce']['domain']
    if domain!='magalu.demo': raise SystemExit('Unexpected Commerce tenant')
    owner=ROOT_TENANTS['commerce']['owner']
    api=WSO2(os.getenv('IS_INTERNAL_URL','https://is:9543').rstrip('/')+'/t/'+quote(domain,safe=''),
             f'{owner}@{domain}',secrets['commerce']['owner_password'],
             os.getenv('IS_TLS_VERIFY','false').lower()=='true')
    outcome=register(api,manifest,args.audience,generated,check_only=args.check_only)
    print(json.dumps(outcome,ensure_ascii=False,indent=2))
    if not outcome.get('readback_verified'): raise SystemExit(2)

if __name__=='__main__':main()
