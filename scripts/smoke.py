"""Live, fail-closed tenant-root boundary and OAuth token smoke checks.

The smoke report DOES NOT assert B-01 pairwise outcome until real browser sign-ins.
"""
import json
import os
from pathlib import Path
import sys
import requests
from bootstrap.wso2 import WSO2
from bootstrap.topology import ROOT_TENANTS, BRANDS

MANIFEST=Path(os.getenv('MANIFEST_FILE','generated/manifest.json'))
BASE=os.getenv('IS_INTERNAL_URL',os.getenv('IS_PUBLIC_URL','https://is:9543')).rstrip('/')
VERIFY=os.getenv('IS_TLS_VERIFY','false').lower()=='true'


def check(label, ok, detail=''):
    print(('[PASS] ' if ok else '[FAIL] ')+label+((' — '+detail) if detail else ''))
    return bool(ok)


def main():
    failures=0
    if not check('Bootstrap manifest exists',MANIFEST.exists()): return 2
    m=json.loads(MANIFEST.read_text())
    if not check('At least 2 independent WSO2 root tenant domains',
                 len({v['domain'] for v in m.get('root_tenants',{}).values()})>=2): failures+=1
    if not check('Three seeded brands, including two within Commerce root',
        all(k in m.get('brands',{}) for k in BRANDS) and
        m['brands']['magalu']['root']==m['brands']['netshoes']['root'] and
        m['brands']['magalu']['root']!=m['brands']['magalupay']['root']): failures+=1
    for brand in BRANDS:
        web=m['clients'].get(brand+':web',{})
        app=m['clients'].get(brand+':app',{})
        if not check('Separate web and mobile client IDs for '+brand,
                 web.get('client_id') and app.get('client_id') and
                 web['client_id']!=app['client_id'] and
                 web['tenant_domain']==app['tenant_domain']): failures+=1
    for root,t in m['root_tenants'].items():
        try:
            domain=t['domain']
            api=WSO2(BASE+'/t/'+domain,'','',VERIFY)
            d=api.discovery()
            passed=check('Tenant-scoped OIDC discovery: '+domain,
                'pairwise' in d.get('subject_types_supported',[]) and
                d.get('issuer')==t['issuer'])
            failures+=0 if passed else 1
            c=m['clients'].get('m2m:'+root+':cc')
            if not c: continue
            token_url=d['token_endpoint'].replace(m['is_public_url'],BASE)
            r=requests.post(token_url,data={'grant_type':'client_credentials'},
                auth=(c['client_id'],c['client_secret']),verify=VERIFY,timeout=(8,20))
            body=r.json() if 'application/json' in r.headers.get('content-type','') else {}
            passed=check('Actual root-specific M2M token issuance: '+domain,
                r.status_code==200 and bool(body.get('access_token')),
                'HTTP '+str(r.status_code))
            failures+=0 if passed else 1
        except Exception as exc:
            failures+=1
            print('[FAIL] Tenant live API verification:',root,type(exc).__name__,str(exc)[:160])
    report={'result':'SMOKE_PASS' if not failures else 'SMOKE_FAIL',
            'failed_checks':failures,
            'NOT_YET_CERTIFIED':['6-login pairwise evidence','claim minimization',
              'native consent enforcement','transaction step-up',
              'RFC8693 act/privilege reduction','RFC7523 replay protection',
              'two active user stores','seller external IdP federation',
              '1000 RPS 30-minute measured load']}
    output=MANIFEST.parent/'smoke-result.json'
    output.write_text(json.dumps(report,indent=2))
    print('Report:',output)
    return 0 if failures==0 else 1


if __name__=='__main__': sys.exit(main())
