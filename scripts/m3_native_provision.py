"""Idempotent WSO2 Consent Management v2 M2M clients + purpose provisioning.

Execute inside existing project bootstrap container. No SQL writes, tenant reset,
or changes to six OIDC storefronts. Failure never implies success.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import quote

from bootstrap.wso2 import WSO2
from bootstrap.topology import ROOT_TENANTS
from demo.m3_native_service import NativeAPI, write_private, TENANTS

GENERATED = Path(os.getenv('MANIFEST_FILE','/project/generated/manifest.json')).parent
CREDS = GENERATED/'m3-native-clients.json'
CATALOG = GENERATED/'m3-native-catalog.json'
PURPOSE_NAME='MAGALU POC - Magalu to Netshoes Data Sharing v1'
ELEMENT_NAME='MAGALU POC - Synthetic Customer Tier v1'
ALL_SCOPES = {
 'purposes':{'internal_consent_mgt_purpose_view','internal_consent_mgt_purpose_create'},
 'elements':{'internal_consent_mgt_element_view','internal_consent_mgt_element_create'},
 'consents':{'internal_consent_mgt_consent_create','internal_consent_mgt_consent_view','internal_consent_mgt_consent_update'},
}


def scope_names(obj):
    raw=obj.get('authorizedScopes',obj.get('scopes',[])) or []
    if not isinstance(raw,list):raise RuntimeError('Unexpected authorized scope data type')
    return {x if isinstance(x,str) else x.get('name') for x in raw if isinstance(x,(str,dict))}


def resource_entries(api):
    resources=[]
    for offset in range(0,500,100):
        data,_=api.call('GET',f'/api/server/v1/api-resources?limit=100&offset={offset}')
        chunk=data.get('APIResources')
        if not isinstance(chunk,list): raise RuntimeError('WSO2 APIResources field unavailable')
        resources.extend(chunk)
        if len(chunk)<100:break
    return resources


def find_native_resources(api):
    records=resource_entries(api)
    result={}
    for kind in ALL_SCOPES:
        matches=[]
        for r in records:
            identifier=str(r.get('identifier','')).rstrip('/')
            if identifier.endswith('/api/identity/consent-mgt/v2.0/'+kind) and '/o/' not in identifier:
                matches.append(r)
        if len(matches)!=1 or not matches[0].get('id'):
            raise RuntimeError(f'Expected one tenant Consent Management V2 {kind} API resource; found {len(matches)}')
        item=matches[0]
        detail,_=api.call('GET','/api/server/v1/api-resources/'+quote(str(item['id']),safe=''))
        declared={s.get('name') for s in detail.get('scopes',[]) if isinstance(s,dict)}
        if not ALL_SCOPES[kind] <= declared:
            raise RuntimeError(f'Native Consent V2 {kind} resource missing required scopes')
        result[kind]=str(item['id'])
    return result


def authorize(api,app_id,resources):
    route='/api/server/v1/applications/'+quote(app_id,safe='')+'/authorized-apis'
    def current():
        result,_=api.call('GET',route)
        value=result if isinstance(result,list) else result.get('authorizedAPIs',result.get('authorizedApis'))
        if not isinstance(value,list):raise RuntimeError('Invalid WSO2 authorized APIs response')
        return value
    for kind,rid in resources.items():
        existing=next((r for r in current() if r.get('id')==rid),None)
        desired=ALL_SCOPES[kind]
        if not existing:
            api.call('POST',route,json={'id':rid,'policyIdentifier':'RBAC','scopes':sorted(desired)},
                     expected=(200,201))
        else:
            missing=desired-scope_names(existing)
            if missing:
                api.call('PATCH',route+'/'+quote(rid,safe=''),
                    json={'addedScopes':sorted(missing),'removedScopes':[]},expected=(200,204))
        check=next((r for r in current() if r.get('id')==rid),None)
        if not check or not desired <= scope_names(check):
            raise RuntimeError(f'Native {kind} API scope authorization readback failed')


def listings(body,kind):
    if isinstance(body,list):return body
    if not isinstance(body,dict):raise RuntimeError('Unexpected native catalog response')
    for key in (kind,'resources','Resources','items','data'):
        value=body.get(key)
        if isinstance(value,list):return value
    # Empty successful catalog responses may be JSON {} depending on server version.
    if not body:return []
    raise RuntimeError(f'Native {kind} catalog layout is unsupported; inspect OpenAPI definition')


def ensure_named(native,kind,name,payload,create_scope,view_scope):
    data=native.api('GET','/'+kind,scopes={view_scope})
    found=[i for i in listings(data,kind) if isinstance(i,dict) and i.get('name')==name]
    if len(found)>1:raise RuntimeError(f'Duplicate native {kind} with name {name}')
    if found:
        item=found[0]
    else:
        item=native.api('POST','/'+kind,scopes={create_scope},payload=payload,expected=(200,201))
    id_=item.get('id') if isinstance(item,dict) else None
    if not id_:raise RuntimeError(f'Native {kind} did not return an ID')
    # Real API readback avoids credit for a successful POST alone.
    fetched=native.api('GET','/'+kind+'/'+str(id_),scopes={view_scope})
    if not isinstance(fetched,dict) or fetched.get('name')!=name:
        raise RuntimeError(f'Native {kind} readback did not match')
    return str(id_)


def main():
    manifest=json.loads((GENERATED/'manifest.json').read_text())
    secrets=json.loads((GENERATED/'tenant-secrets.json').read_text())
    existing={}
    if CREDS.is_file():
        if CREDS.stat().st_mode&0o077:raise RuntimeError('Insecure existing M3 native credential file')
        existing=json.loads(CREDS.read_text())
    for root,domain in TENANTS.items():
        if manifest['root_tenants'][root]['domain']!=domain:raise RuntimeError('Root manifest mismatch')
        owner=ROOT_TENANTS[root]['owner']
        api=WSO2(os.getenv('IS_INTERNAL_URL','https://is:9543').rstrip('/')+'/t/'+quote(domain,safe=''),
            owner+'@'+domain,secrets[root]['owner_password'],
            os.getenv('IS_TLS_VERIFY','false').lower()=='true')
        app=api.ensure_app('MAGALU CIAM POC - NATIVE CONSENT V2 - '+root.upper(),
                           ['client_credentials'],None,None,kind='m2m')
        prior=existing.get(root)
        secret=(prior or {}).get('client_secret') or app.get('client_secret')
        if not secret or (prior and prior.get('client_id')!=app['client_id']):
            raise RuntimeError('Cannot retrieve native management client secret for '+root)
        resources=find_native_resources(api)
        authorize(api,app['app_id'],resources)
        existing[root]={'tenant':domain,'client_id':app['client_id'],'client_secret':secret}
        write_private(CREDS,existing)
        print(json.dumps({'tenant':domain,'m2m_client_verified':True,'native_resources_authorized':sorted(resources)}))

    commerce=NativeAPI('commerce',existing)
    element=ensure_named(commerce,'elements',ELEMENT_NAME,{
        'name':ELEMENT_NAME,'displayName':'Synthetic customer tier',
        'description':'Lab-only, synthetic data element for Magalu to Netshoes sharing'},
        'internal_consent_mgt_element_create','internal_consent_mgt_element_view')
    purpose=ensure_named(commerce,'purposes',PURPOSE_NAME,{
        'name':PURPOSE_NAME,'description':'Explicit Magalu to Netshoes directional sharing in PoC',
        'type':'MAGALU_POC','version':'v1',
        'elements':[{'id':element,'mandatory':True}]},
        'internal_consent_mgt_purpose_create','internal_consent_mgt_purpose_view')
    write_private(CATALOG,{'root':'commerce','tenant':'magalu.demo',
        'purpose_id':purpose,'element_id':element,'purpose_name':PURPOSE_NAME,
        'service_id':'magalu-ciam-consent-lab'})
    fintech=NativeAPI('fintech',existing)
    fintech_catalog=fintech.catalog()
    # Verify that Commerce's purpose ID is not silently present in the other root.
    if any(isinstance(r,dict) and str(r.get('id'))==purpose for r in listings(fintech_catalog['purposes'],'purposes')):
        raise RuntimeError('A Commerce purpose ID appeared unexpectedly in Fintech native catalog')
    print(json.dumps({'result':'M3_NATIVE_CATALOG_READY',
       'tenant_isolation_checked':True,'commerce_purpose_id_available':True,
       'note':'Live consent grant/revocation and dual-gate acceptance still pending'}))

if __name__=='__main__':main()
