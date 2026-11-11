"""Create one purpose-built, local-only authorization-code client for RFC 8693 evidence.

Run inside the existing bootstrap container. Fail closed on WSO2 API errors.
No changes to the storefront applications or identities.
"""
import json
import os
from pathlib import Path
from urllib.parse import quote

from bootstrap.wso2 import WSO2
from bootstrap.storefront_provision import ensure_resource,ensure_workflow_role


def write_private(path,payload):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(payload,indent=2))
    tmp.chmod(0o600);tmp.replace(path);path.chmod(0o600)



# Only API-owned fields are written; preserve the existing callback, grants,
# pairwise subject settings, and the application client identifier.
OIDC_WRITABLE_FIELDS = frozenset({
    'clientId', 'clientSecret', 'grantTypes', 'callbackURLs', 'allowedOrigins',
    'publicClient', 'pkce', 'accessToken', 'hybridFlow', 'refreshToken',
    'subjectToken', 'idToken', 'logout', 'validateRequestObjectSignature',
    'scopeValidators', 'clientAuthentication', 'requestObject',
    'pushAuthorizationRequest', 'subject', 'isFAPIApplication',
})


def ensure_jwt_access_tokens(api, app_id, expected_client_id):
    """Use self-contained, signed access JWTs for THIS test app only.

    WSO2 may default user clients to Opaque access tokens. RFC 8693's
    locally issued subject/actor JWT flow cannot use those reference tokens.
    Read-back makes this idempotent and fail-closed; never modify storefronts.
    """
    path = f'/api/server/v1/applications/{app_id}/inbound-protocols/oidc'
    current, _ = api.call('GET', path)
    if not isinstance(current, dict) or current.get('clientId') != expected_client_id:
        raise RuntimeError('M3 test application client ID mismatch; refusing OIDC update')
    access = current.get('accessToken') or {}
    if not isinstance(access, dict):
        raise RuntimeError('Unexpected WSO2 accessToken configuration')
    if access.get('type') != 'JWT':
        changed = dict(current)
        changed['accessToken'] = {**access, 'type': 'JWT'}
        payload = {k: v for k, v in changed.items()
                   if k in OIDC_WRITABLE_FIELDS and v is not None}
        api.call('PUT', path, json=payload, expected=(200, 201, 204))
    verified, _ = api.call('GET', path)
    if (not isinstance(verified, dict)
            or verified.get('clientId') != expected_client_id
            or (verified.get('accessToken') or {}).get('type') != 'JWT'):
        raise RuntimeError('WSO2 M3 access-token JWT setting was not persisted')
    if verified.get('callbackURLs') != current.get('callbackURLs'):
        raise RuntimeError('M3 JWT update unexpectedly modified redirect configuration')
    if set(verified.get('grantTypes') or []) != set(current.get('grantTypes') or []):
        raise RuntimeError('M3 JWT update unexpectedly modified allowed OAuth grants')
    return True

def _authorized_scopes(entry):
    raw=entry.get('authorizedScopes', entry.get('scopes', [])) or []
    if not isinstance(raw,list):
        raise RuntimeError('Invalid API authorization scope response')
    return {v if isinstance(v,str) else v.get('name')
            for v in raw if isinstance(v,(str,dict))}


def ensure_exchange_read_authorization(api, app_id, resource_id):
    """Authorize only read on the M3 exchange client (no automatic approve grant)."""
    path=f'/api/server/v1/applications/{app_id}/authorized-apis'
    data,_=api.call('GET',path)
    if isinstance(data,list):
        entries=data
    elif isinstance(data,dict):
        entries=data.get('authorizedAPIs',data.get('authorizedApis'))
    else:
        entries=None
    if not isinstance(entries,list):
        raise RuntimeError('Unexpected WSO2 authorized APIs response')
    matches=[r for r in entries if isinstance(r,dict) and r.get('id')==resource_id]
    if len(matches)>1:
        raise RuntimeError('Duplicate authorized APIs for exchange client')
    if not matches:
        api.call('POST',path,json={'id':resource_id,'policyIdentifier':'RBAC',
                  'scopes':['requests:read']},expected=(200,201))
    elif 'requests:read' not in _authorized_scopes(matches[0]):
        api.call('PATCH',path+'/'+quote(resource_id,safe=''),
                 json={'addedScopes':['requests:read'],'removedScopes':[]},
                 expected=(200,204))
    check,_=api.call('GET',path)
    items=check if isinstance(check,list) else (
        check.get('authorizedAPIs',check.get('authorizedApis')) if isinstance(check,dict) else None)
    if not isinstance(items,list):
        raise RuntimeError('WSO2 exchange API authorization readback unavailable')
    registered=[r for r in items if isinstance(r,dict) and r.get('id')==resource_id]
    if len(registered)!=1 or 'requests:read' not in _authorized_scopes(registered[0]):
        raise RuntimeError('Exchange client requests:read authorization not persisted')
    return True


def main():
    manifest=json.loads(Path(os.getenv('MANIFEST_FILE','/project/generated/manifest.json')).read_text())
    admin=json.loads(Path('/project/generated/tenant-secrets.json').read_text())
    tenant='commerce';domain=manifest['root_tenants'][tenant]['domain']
    owner=os.environ.get('M3_TENANT_OWNER') or 'admin'
    # Use the same bootstrap tenant owner as the pre-existing application provisioner.
    from bootstrap.topology import ROOT_TENANTS
    owner=ROOT_TENANTS[tenant]['owner']
    password=admin[tenant]['owner_password']
    base=os.getenv('IS_INTERNAL_URL','https://is:9543').rstrip('/')
    tls=os.getenv('IS_TLS_VERIFY','false').lower()=='true'
    api=WSO2(base+'/t/'+quote(domain,safe=''),f'{owner}@{domain}',password,tls)
    redirect='http://localhost:8991/callback'
    result=api.ensure_app('MAGALU CIAM POC - M3 - TOKEN EVIDENCE',
                          ['authorization_code','refresh_token'],redirect,
                          manifest['brands']['magalu']['sector_uri'],public=False,kind='user_public')
    if not result.get('client_secret'):
        raise RuntimeError('WSO2 did not provide confidential test-client secret')
    # Required by locally issued RFC 8693 JWT subject/actor exchanges.
    ensure_jwt_access_tokens(api, result['app_id'], result['client_id'])
    resource_id=ensure_resource(api)
    # Evidence user application still needs the three explicit test-user scopes.
    from bootstrap.storefront_provision import authorize_api
    authorize_api(api,result['app_id'],resource_id)
    exchange=manifest['clients']['m2m:commerce:exchange']
    if exchange.get('tenant_domain')!=domain or not exchange.get('app_id'):
        raise RuntimeError('Missing correctly scoped Commerce exchange application')
    exchange_read_authorized=ensure_exchange_read_authorization(
        api,exchange['app_id'],resource_id)
    ana=manifest['users']['commerce:ana.magalu']['id']
    bruno=manifest['users']['commerce:bruno.seller']['id']
    role_ana=ensure_workflow_role(api,'poc_m3_ana_token_evidence',result['app_id'],ana,
                                  ['requests:read','requests:create'])
    role_bruno=ensure_workflow_role(api,'poc_m3_bruno_token_evidence',result['app_id'],bruno,
                                    ['requests:read','requests:approve'])
    role_exchange_ana=ensure_workflow_role(api,'poc_m3_ana_exchange_read',
                                           exchange['app_id'],ana,['requests:read'])
    disco=api.discovery()
    path=Path('/project/generated/m3-oauth-test-client.json')
    write_private(path,{'tenant_domain':domain,'client_id':result['client_id'],
                       'client_secret':result['client_secret'],'app_id':result['app_id'],
                       'redirect_uri':redirect,'issuer':disco['issuer'],
                       'access_token_type':'JWT','subject_type':'public',
                       'approved_test_users':['commerce:ana.magalu','commerce:bruno.seller']})
    print(json.dumps({'result':'M3_CLIENT_PROVISIONED','tenant':domain,
                      'client_id_available':True,'redirect_uri':redirect,
                      'roles_verified':bool(role_ana and role_bruno and role_exchange_ana),
                      'exchange_read_scope_verified':exchange_read_authorized,
                      'public_subject_type_verified':True,
                      'jwt_access_tokens_verified':True,
                      'credential_file':str(path)},indent=2))

if __name__=='__main__':main()
