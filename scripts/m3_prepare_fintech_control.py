"""Only configure MagaluPay's existing M2M Client Credentials test application.

Makes its access token a signed JWT and gives it a dedicated lab audience. The
original OIDC settings are backed up privately before any WSO2 PUT.
"""
import json
import os
from pathlib import Path
from datetime import datetime,timezone
from urllib.parse import quote
from bootstrap.wso2 import WSO2
from bootstrap.topology import ROOT_TENANTS

AUD='urn:magalupay:poc:isolation'
ACCEPTED=frozenset({'clientId','clientSecret','grantTypes','callbackURLs','allowedOrigins',
 'publicClient','pkce','accessToken','hybridFlow','refreshToken','subjectToken',
 'idToken','logout','validateRequestObjectSignature','scopeValidators',
 'clientAuthentication','requestObject','pushAuthorizationRequest','subject','isFAPIApplication'})


def private(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name('.'+path.name+'.tmp')
    tmp.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    tmp.chmod(0o600);tmp.replace(path);path.chmod(0o600)


def configure(api,client,generated):
    if client.get('tenant_domain')!='magalupay.demo' or not client.get('app_id') or not client.get('client_id'):
        raise ValueError('Fintech CC app does not match expected root')
    path='/api/server/v1/applications/'+quote(client['app_id'],safe='')+'/inbound-protocols/oidc'
    current,_=api.call('GET',path)
    if current.get('clientId')!=client['client_id'] or 'client_credentials' not in (current.get('grantTypes') or []):
        raise ValueError('WSO2 application does not match Fintech Client Credentials test app')
    access=current.get('accessToken') or {}
    idt=current.get('idToken') or {}
    audience=idt.get('audience') or []
    if not isinstance(access,dict) or not isinstance(idt,dict) or not isinstance(audience,list) or not all(isinstance(a,str) for a in audience):
        raise ValueError('Unexpected WSO2 OAuth configuration: refusing modification')
    modified=access.get('type')!='JWT' or AUD not in audience
    if modified:
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        private(generated/('m3-fintech-cc-oidc-backup-'+stamp+'.json'),current)
        patched=dict(current)
        patched['accessToken']={**access,'type':'JWT'}
        patched['idToken']={**idt,'audience':list(dict.fromkeys(audience+[AUD]))}
        payload={k:v for k,v in patched.items() if k in ACCEPTED and v is not None}
        api.call('PUT',path,json=payload,expected=(200,201,204))
    verify,_=api.call('GET',path)
    if (verify.get('clientId')!=client['client_id'] or
        (verify.get('accessToken') or {}).get('type')!='JWT' or
        AUD not in ((verify.get('idToken') or {}).get('audience') or []) or
        set(verify.get('grantTypes') or []) != set(current.get('grantTypes') or []) or
        verify.get('callbackURLs')!=current.get('callbackURLs')):
        raise RuntimeError('Fintech CC test client readback differs from requested config')
    # The negative test is meaningful only when the destination exchange grant
    # actually exists; verify that application's persisted WSO2 settings too.
    exchange_client=json.loads((generated/'manifest.json').read_text())['clients']['m2m:fintech:exchange']
    exchange_path='/api/server/v1/applications/'+quote(exchange_client['app_id'],safe='')+'/inbound-protocols/oidc'
    exchange_cfg,_=api.call('GET',exchange_path)
    if (exchange_cfg.get('clientId')!=exchange_client['client_id'] or
        'urn:ietf:params:oauth:grant-type:token-exchange' not in (exchange_cfg.get('grantTypes') or [])):
        raise RuntimeError('Fintech exchange application not authorized for RFC 8693: no cross-root conclusion')
    receipt={'schema':'magalu-m3-fintech-control-v1','tenant':'magalupay.demo',
             'application_id':client['app_id'],'client_id':client['client_id'],
             'audience':AUD,'verified':True,'exchange_grant_readback_verified':True,
             'readback_at':datetime.now(timezone.utc).isoformat()}
    private(generated/'m3-fintech-cc-control-readback.json',receipt)
    return {'result':'FINTECH_CONTROL_READY','tenant':'magalupay.demo',
            'audience':AUD,'readback_verified':True,'updated':modified}


def main():
    generated=Path(os.getenv('MANIFEST_FILE','/project/generated/manifest.json')).parent
    manifest=json.loads((generated/'manifest.json').read_text())
    private_secrets=json.loads((generated/'tenant-secrets.json').read_text())
    domain=manifest['root_tenants']['fintech']['domain']
    if domain!='magalupay.demo':raise ValueError('Wrong Fintech tenant in manifest')
    owner=ROOT_TENANTS['fintech']['owner']
    api=WSO2(os.getenv('IS_INTERNAL_URL','https://is:9543').rstrip('/')+'/t/'+quote(domain,safe=''),
             f'{owner}@{domain}',private_secrets['fintech']['owner_password'],
             os.getenv('IS_TLS_VERIFY','false').lower()=='true')
    result=configure(api,manifest['clients']['m2m:fintech:cc'],generated)
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
