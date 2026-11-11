"""Idempotent second bootstrap stage: six independent callback URLs,
root-local business scopes, app roles and WSO2 TOTP ACR flow.

A partially configured application is never reported as fully verified.
"""
import json
import logging
import os
import re
from pathlib import Path
import sys
import time
from urllib.parse import quote

from bootstrap.wso2 import WSO2
from bootstrap.storefront_ports import FRONTEND_PORTS,callback_uri

LOG=logging.getLogger('storefront-bootstrap')
logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
ACR_TOTP='urn:magalu:aal2:totp'
SCOPE_NAMES=('requests:read','requests:create','requests:approve')
ACR_SCRIPT="""// Magalu CIAM PoC: AAL2 approval requires actual WSO2 TOTP.
// The RP always sends prompt=login. A high ACR selects step 2 (TOTP).
var onLoginRequest = function(context) {
    var acrs = context.requestedAcr || [];
    var high = acrs.indexOf('urn:magalu:aal2:totp') >= 0;
    context.selectedAcr = high ? 'urn:magalu:aal2:totp' : 'urn:magalu:aal1';
    executeStep(1);
    if (high) { executeStep(2); }
};
"""


def secure_write(path,obj):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
    temporary=p.with_suffix('.tmp')
    temporary.write_text(json.dumps(obj,indent=2,ensure_ascii=False,default=str))
    temporary.chmod(0o600);temporary.replace(p);p.chmod(0o600)


def api_resources(api, identifier):
    """Read an EXACT API resource by identifier from a single WSO2 root tenant.

    WSO2 7.3's management response uses case-sensitive ``APIResources``.
    Its list API is cursor-paginated, not offset-paginated; the server's
    documented identifier filter reduces this query to at most one match.
    We fail closed on missing/incomplete listing data instead of issuing a
    duplicate POST (the original cause of HTTP 409 on bootstrap retries).
    """
    if not isinstance(identifier, str) or not identifier:
        raise RuntimeError('API resource identifier is required')
    query=quote('identifier eq '+identifier, safe='')
    path=f'/api/server/v1/api-resources?filter={query}&limit=100'
    data,_=api.call('GET',path,expected=(200,))
    if not isinstance(data,dict):
        raise RuntimeError('WSO2 API resources listing did not return an object')
    # The documented response key is uppercase 'APIResources'. The lower-case
    # spelling is accepted only for a future API variant, never defaulted to [].
    if 'APIResources' in data:
        resources=data['APIResources']
    elif 'apiResources' in data:
        resources=data['apiResources']
    else:
        raise RuntimeError('WSO2 API resource list missing APIResources field; '
                           'refusing to create resource from an ambiguous response')
    if not isinstance(resources,list) or any(not isinstance(v,dict) for v in resources):
        raise RuntimeError('Invalid WSO2 APIResources list')
    count=data.get('totalResults')
    if count is not None and (not isinstance(count,int) or count<0 or count>len(resources)):
        raise RuntimeError('WSO2 filtered API resource list is incomplete; '
                           'refusing to POST without exhaustive readback')
    # A filtered response may vary by server update; never rely on the server
    # filter alone. Require the exact identifier and a unique resource ID.
    matches=[item for item in resources if item.get('identifier')==identifier]
    if len(matches)>1:
        raise RuntimeError('Duplicate WSO2 API resources with identifier '+identifier)
    if matches and not matches[0].get('id'):
        raise RuntimeError('Existing WSO2 API resource has no ID')
    return matches


def ensure_resource(api):
    identifier='urn:magalu:poc:requests'
    expected_name='Magalu POC Requests API'

    def find():
        return api_resources(api,identifier)

    matches=find()
    if matches:
        rid=matches[0]['id']
        LOG.info('Reusing WSO2 API resource %s: %s',identifier,rid)
    else:
        obj={'name':expected_name,'identifier':identifier,
             'description':'RFP Section 7 Create and TOTP-backed Approve',
             'requiresAuthorization':True,
             'scopes':[{'name':n,'displayName':n.replace(':',' / ').title(),
                        'description':'Magalu evaluation scope '+n} for n in SCOPE_NAMES]}
        data,response=api.call('POST','/api/server/v1/api-resources',json=obj,
                               expected=(200,201,409))
        if response.status_code==409:
            # Treat only the documented duplicate-resource conflict as a
            # candidate for reuse. Any other conflict remains fatal.
            if not isinstance(data,dict) or data.get('code')!='API-RESOURCE-60003':
                raise RuntimeError('Unexpected API resource POST conflict; refusing to proceed')
            LOG.info('API resource already created by another run; reconciling %s',identifier)
        elif response.status_code not in (200,201):
            raise RuntimeError('Unexpected API resource creation status')
        matches=find()
        if len(matches)!=1:
            raise RuntimeError('API resource create/conflict did not produce one verified resource')
        rid=matches[0]['id']
    detail,_=api.call('GET',f'/api/server/v1/api-resources/{quote(str(rid),safe="")}',
                      expected=(200,))
    if not isinstance(detail,dict) or detail.get('id')!=rid or detail.get('identifier')!=identifier:
        raise RuntimeError('API resource detailed readback has wrong ID/identifier')
    if detail.get('name')!=expected_name or detail.get('requiresAuthorization') is not True:
        raise RuntimeError('Existing API resource has unexpected name or authorization mode; '
                           'refusing to reuse or modify it')
    scopes=detail.get('scopes')
    if not isinstance(scopes,list):
        raise RuntimeError('API resource detail omitted scopes')
    existing={s.get('name') for s in scopes if isinstance(s,dict)}
    missing=set(SCOPE_NAMES)-existing
    if missing:
        api.call('PUT',f'/api/server/v1/api-resources/{quote(str(rid),safe="")}/scopes',json=[
            {'name':name,'displayName':name,'description':'Evaluation authorization permission'}
            for name in sorted(missing)],expected=(204,200))
        detail,_=api.call('GET',f'/api/server/v1/api-resources/{quote(str(rid),safe="")}',
                          expected=(200,))
    if not isinstance(detail,dict) or detail.get('id')!=rid or detail.get('identifier')!=identifier:
        raise RuntimeError('API resource identifier changed during scope update')
    if not set(SCOPE_NAMES)<=set(s.get('name') for s in detail.get('scopes',[])
                                  if isinstance(s,dict)):
        raise RuntimeError('Missing API scopes after registration')
    return rid


def _registered_callbacks(previous, callback, *, legacy_callback=None):
    """Generate the one-entry WSO2 OAuth callback configuration.

    WSO2 IS 7.3 rejects two callbackURLs elements (HTTP 501). Retain at most
    the known legacy PoC callback and the requested single storefront callback.
    Use an anchored, escaped regexp when two EXACT redirects are needed.
    Refuse unexpected registrations instead of broadening authorization.
    """
    if not isinstance(previous, list) or any(not isinstance(x, str) for x in previous):
        raise RuntimeError('Unexpected WSO2 callbackURLs response shape')
    if not isinstance(callback, str) or not re.fullmatch(
            r'http://localhost:818[1-6]/callback', callback):
        raise RuntimeError('Refusing non-allowlisted storefront callback: '+str(callback))
    legacy_callback=legacy_callback or (
        os.environ.get('DEMO_PUBLIC_URL', 'http://localhost:8180').rstrip('/')
        + '/oidc/callback')
    # Allow only a locally scoped legacy callback configured by this PoC.
    if not re.fullmatch(r'http://localhost:(?:8180|8080)/oidc/callback',
                        legacy_callback):
        raise RuntimeError('Unexpected legacy callback origin; review .env')

    expected_urls=sorted({callback, legacy_callback})
    anchored='regexp=^(?:'+'|'.join(re.escape(x) for x in expected_urls)+')$'
    if previous==[anchored]:
        return [anchored]  # idempotent rerun after successful update
    if any(item.startswith('regexp=') for item in previous):
        raise RuntimeError('Existing callback regex is not the expected exact allowlist; '
                           'manual review required before rewriting redirects')
    if set(previous)-set(expected_urls):
        raise RuntimeError('Unexpected existing OAuth callback(s): '+repr(previous))
    if not previous:
        raise RuntimeError('Existing OAuth client has no registered callback; '
                           'review before modifying')
    if previous==[callback]:
        return [callback]  # standalone storefront client needs no regex
    # Preserve the previously registered original portal callback.
    return [anchored]


def set_callbacks(api,client,callback):
    path=f"/api/server/v1/applications/{client['app_id']}/inbound-protocols/oidc"
    obj,_=api.call('GET',path)
    if not isinstance(obj, dict):
        raise RuntimeError('Unexpected OIDC configuration readback')
    if obj.get('clientId')!=client['client_id']:
        raise RuntimeError('Refusing to update callbacks: WSO2 client ID mismatch')
    previous=obj.get('callbackURLs') or []
    configured=_registered_callbacks(previous,callback)
    accepted={'clientId','clientSecret','grantTypes','callbackURLs','allowedOrigins','publicClient',
              'pkce','accessToken','hybridFlow','refreshToken','subjectToken','idToken',
              'logout','validateRequestObjectSignature','scopeValidators','clientAuthentication',
              'requestObject','pushAuthorizationRequest','subject','isFAPIApplication'}
    if previous!=configured:
        obj['callbackURLs']=configured
        data={k:v for k,v in obj.items() if k in accepted and v is not None}
        api.call('PUT',path,json=data,expected=(200,201,204))
    read,_=api.call('GET',path)
    if not isinstance(read, dict) or read.get('clientId')!=client['client_id']:
        raise RuntimeError('Unexpected client ID after callback update')
    # Readback must match the exact narrowly scoped value we installed.
    if read.get('callbackURLs')!=configured:
        raise RuntimeError('WSO2 callback configuration did not persist exactly; '
                           'stop rather than weakening the redirect allowlist')
    return configured


def _authorized_scopes(entry):
    """API readback uses authorizedScopes, not the POST input field scopes."""
    values = entry.get('authorizedScopes', entry.get('scopes', [])) or []
    return {s if isinstance(s,str) else s.get('name')
            for s in values if isinstance(s,(str,dict))}


def _authorized_resources(data):
    if isinstance(data,list):
        return data
    if isinstance(data,dict):
        for key in ('authorizedAPIs','authorizedApis'):
            value=data.get(key)
            if isinstance(value,list):
                return value
    raise RuntimeError('Unexpected authorized-API listing from WSO2')


def authorize_api(api,app_id,rid):
    route=f'/api/server/v1/applications/{app_id}/authorized-apis'
    records,_=api.call('GET',route)
    collection=_authorized_resources(records)
    existing=next((entry for entry in collection if entry.get('id')==rid),None)
    if not existing:
        api.call('POST',route,json={'id':rid,'policyIdentifier':'RBAC',
                 'scopes':list(SCOPE_NAMES)},expected=(201,200))
    else:
        missing=set(SCOPE_NAMES)-_authorized_scopes(existing)
        if missing:
            api.call('PATCH',route+'/'+rid,json={'addedScopes':sorted(missing),'removedScopes':[]},
                     expected=(200,204))
    check,_=api.call('GET',route)
    resource=next((entry for entry in _authorized_resources(check) if entry.get('id')==rid),None)
    if not resource:
        raise RuntimeError('API authorization missing from application readback')
    if not set(SCOPE_NAMES)<=_authorized_scopes(resource):
        raise RuntimeError('API permissions missing in application readback: '+app_id)


def write_public_manifest(full_manifest, path):
    """Do not mount tenant-admin credentials or seeded user passwords in storefronts."""
    scoped={}
    for key in FRONTEND_PORTS:
        client=full_manifest['clients'][key]
        scoped[key]={k:client[k] for k in (
            'app_id','client_id','tenant_domain','issuer','brand','channel','root')}
        if client['channel']=='web':
            secret=client.get('client_secret')
            if not secret:
                raise RuntimeError('Confidential web client secret missing: '+key)
            scoped[key]['client_secret']=secret
    secure_write(path,{'schema_version':3,'clients':scoped})


def ensure_workflow_role(api,name,app_id,user_id,permissions):
    path='/scim2/v2/Roles'
    data,_=api.call('GET',path+'?count=100')
    matches=[r for r in data.get('Resources',[]) if r.get('displayName')==name and
             (r.get('audience') or {}).get('value')==app_id]
    if len(matches)>1: raise RuntimeError('Duplicate role '+name)
    if matches:
        rid=matches[0]['id']
    else:
        payload={'schemas':['urn:ietf:params:scim:schemas:extension:2.0:Role'],
          'displayName':name,'audience':{'type':'application','value':app_id},
          'users':[{'value':user_id}],
          'permissions':[{'value':p} for p in permissions]}
        result,_=api.call('POST',path,json=payload,headers={
            'Content-Type':'application/scim+json'},expected=(201,))
        rid=result.get('id') if isinstance(result,dict) else None
        if not rid: raise RuntimeError('Role created without id: '+name)
    record,_=api.call('GET',path+'/'+rid)
    members={x.get('value') for x in record.get('users',[])}
    perms={x.get('value') for x in record.get('permissions',[])}
    # Existing roles may have a different grant; do NOT silently say success.
    if user_id not in members or not set(permissions)<=perms:
        raise RuntimeError(f'Role {name} exists but is not bound to intended WSO2 user/scopes; '
                           'inspect SCIM role and reconcile before approval testing')
    return rid


def available_local_authenticators(api):
    """Read server-owned authenticator *names*, not display names.

    WSO2 7.3's authenticator list exposes e.g. name="BasicAuthenticator",
    displayName="basic". Application authenticationSequence needs the actual
    installed name. Do not guess or silently fall back to an inactive method.
    The endpoint is root-tenant scoped via the supplied WSO2 API client.
    """
    data,_=api.call('GET','/api/server/v1/configs/authenticators?type=LOCAL',
                    expected=(200,))
    if isinstance(data,dict) and isinstance(data.get('authenticators'),list):
        entries=data['authenticators']
    elif isinstance(data,list):
        entries=data
    else:
        raise RuntimeError('Local authenticator API returned an unknown response shape; '
                           'cannot safely configure ACR-TOTP')
    if not entries or any(not isinstance(item,dict) for item in entries):
        raise RuntimeError('No usable local authenticators reported by this WSO2 tenant')
    result={}
    for item in entries:
        name=item.get('name')
        if not isinstance(name,str) or not name:
            raise RuntimeError('Local authenticator listing omitted an internal name')
        if item.get('type','LOCAL')!='LOCAL':
            continue
        if item.get('isEnabled') is not True:
            continue
        if name in result:
            raise RuntimeError(f'Duplicate enabled local authenticator: {name}')
        result[name]=item
    return result


def select_password_totp(api):
    """Resolve the actual installed authenticator names for this root tenant."""
    installed=available_local_authenticators(api)
    # These are internal WSO2 authenticator names, not their UI display labels.
    password=next((name for name in ('BasicAuthenticator',)
                   if name in installed), None)
    totp=next((name for name in ('totp','TOTPAuthenticator')
               if name in installed), None)
    if not password or not totp:
        raise RuntimeError('Required WSO2 authenticators unavailable or disabled '
                           f'(BasicAuthenticator={bool(password)}, TOTP={bool(totp)}). '
                           f'Enabled local names: {sorted(installed)}. '
                           'Inspect tenant Login Flow / authenticator enablement.')
    return password,totp


def configure_acr(api,app_id):
    path=f'/api/server/v1/applications/{app_id}'
    detail,_=api.call('GET',path)
    if not isinstance(detail,dict) or str(detail.get('id'))!=str(app_id):
        raise RuntimeError('Application readback ID mismatch before ACR update')
    seq=detail.get('authenticationSequence') or {}
    if not isinstance(seq,dict):
        raise RuntimeError('Unexpected authenticationSequence shape')
    password,totp=select_password_totp(api)
    expected_steps=[{'id':1,'options':[{'idp':'LOCAL','authenticator':password}]},
                    {'id':2,'options':[{'idp':'LOCAL','authenticator':totp}]}]
    # Existing customized login flows might have other authenticators. We never
    # overwrite those without explicit review; this PoC expects its seeded apps.
    old_steps=seq.get('steps') or []
    if seq.get('type')=='USER_DEFINED' and old_steps:
        for step in old_steps:
            for opt in step.get('options',[]):
                name=opt.get('authenticator')
                if opt.get('idp')!='LOCAL' or name not in (password,totp,'basic'):
                    raise RuntimeError('Custom authentication flow contains an unexpected '
                                       'option; refusing to overwrite it')
    patch={'authenticationSequence':{
        **{k:v for k,v in seq.items() if k in ('requestPathAuthenticators',)},
        'type':'USER_DEFINED','steps':expected_steps,'subjectStepId':1,'attributeStepId':1}}
    api.call('PATCH',path,json=patch,expected=(200,204))
    api.call('PUT',path+'/authenticationSequence/script',json={'script':ACR_SCRIPT},
             expected=(200,204))
    read,_=api.call('GET',path)
    effective=read.get('authenticationSequence') or {}
    steps=effective.get('steps') or []
    for sid,name in ((1,password),(2,totp)):
        if not any(step.get('id')==sid and
                   any(opt.get('idp')=='LOCAL' and opt.get('authenticator')==name
                       for opt in step.get('options',[])) for step in steps):
            raise RuntimeError(f'WSO2 login flow step {sid} authenticator {name} '
                               'not persisted after configuration')
    if 'urn:magalu:aal2:totp' not in str(effective.get('script','')):
        # Some versions omit script from main application readback. Do not
        # falsely report script verification just because PUT returned HTTP 200.
        return 'TOTP_STEPS_VERIFIED_SCRIPT_WRITE_OK_READBACK_UNAVAILABLE'
    return 'TOTP_ACR_SCRIPT_AND_STEPS_VERIFIED'


def main():
    base=os.environ.get('IS_INTERNAL_URL','https://is:9543').rstrip('/')
    m_path=Path(os.environ.get('MANIFEST_FILE','/project/generated/manifest.json'))
    secrets_path=Path('/project/generated/tenant-secrets.json')
    m=json.loads(m_path.read_text())
    secrets_db=json.loads(secrets_path.read_text())
    report={'result':'IN_PROGRESS','stages':[],'expected_frontends':6,
            'timestamp':int(time.time()),'manual_tasks':[]}
    output=m_path.parent/'storefront-provision-report.json'
    def stage(label,detail):
        report['stages'].append({'gate':label,'status':'VERIFIED','detail':detail})
        secure_write(output,report)
    try:
        for root,tenant in m['root_tenants'].items():
            if root not in ('commerce','fintech'): continue
            domain=tenant['domain']
            owner='tenantadmin@'+domain
            api=WSO2(base+'/t/'+domain,owner,secrets_db[root]['owner_password'],False)
            rid=ensure_resource(api)
            stage('resource:'+root,rid)
            for key in sorted(k for k in FRONTEND_PORTS if m['clients'][k]['root']==root):
                client=m['clients'][key]
                cb=callback_uri(key)
                set_callbacks(api,client,cb)
                stage('callback:'+key,cb)
                authorize_api(api,client['app_id'],rid)
                stage('api_authorization:'+key,','.join(SCOPE_NAMES))
                creator=m['users'][root+':ana.magalu']['id']
                approver=m['users'][root+':'+('bruno.seller' if root=='commerce' else 'carla.risk')]['id']
                for name,user_id,perms in (
                    ('poc_request_creator',creator,['requests:read','requests:create']),
                    ('poc_request_approver',approver,['requests:read','requests:approve'])):
                    rid_role=ensure_workflow_role(api,name,client['app_id'],user_id,perms)
                    m['roles'][key+':'+name]=rid_role
                    stage('role:'+key+':'+name,rid_role)
                check=configure_acr(api,client['app_id'])
                stage('totp_acr:'+key,check)
        secure_write(m_path,m)
        write_public_manifest(m, m_path.parent/'storefront-manifest.json')
        stage('storefront_manifest','Only six necessary OAuth client records, no seeded user passwords')
        report['manual_tasks']=[
            'Enrol TOTP for the two approvers using their My Account portal (QR seed is not generated by this bootstrap).',
            'Verify ACR and AMR for a real approval; only WSO2-issued totp proof is accepted.',
            'Execute six independent browser logins and logout-then-login tests.']
        report['result']='PROVISIONED_LIVE_LOGIN_PENDING'
        secure_write(output,report)
        print('Six storefront clients updated; scopes and roles provisioned; TOTP policies configured.')
    except Exception as e:
        report['result']='BLOCKED';report['error']=f'{type(e).__name__}: {e}'
        secure_write(output,report)
        raise

if __name__=='__main__':
    try: main()
    except Exception as exc:
        LOG.exception('Storefront bootstrap BLOCKED: %s',exc)
        sys.exit(1)
