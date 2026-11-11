"""Additive Section 7 B2C/B2B/M2M and consent acceptance cockpit.

All readbacks use the original authenticated sessions and WSO2 clients.
No synthetic success values, no passwords or bearer tokens exposed to callers.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time
from urllib.parse import urlencode, urlparse
import jwt
import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from demo.poc_closure_core import (ordered_native_acceptance, replay_verdict,
                                   seller_policy, tenant_issuer_match)
from demo.m3_isolation import _guard, _identities, _db, _matching
from demo.m3_native_lab import (_map, _mirror_for, _mirror_identity, _native_status, _api)
from demo.m3_native_service import NativeProblem
from demo.store import Ledger

router = APIRouter()
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / 'templates'))
GENERATED = Path(os.getenv('MANIFEST_FILE','/project/generated/manifest.json')).parent
SESSIONS: dict[str,dict] = {}  # local single-replica demonstration only
BASE = os.getenv('DEMO_PUBLIC_URL','http://localhost:8180').rstrip('/')
IS_PUBLIC = os.getenv('IS_PUBLIC_URL','https://localhost:9543').rstrip('/')
IS_INTERNAL = os.getenv('IS_INTERNAL_URL','https://is:9543').rstrip('/')
VERIFY_TLS = os.getenv('IS_TLS_VERIFY','false').lower() == 'true'


class LinkRequest(BaseModel):
    link_id: str = Field(min_length=36, max_length=36)


class M2MRequest(BaseModel):
    root: str = Field(pattern=r'^(commerce|fintech)$')


def reply(value, http=200):
    result = JSONResponse(value, status_code=http)
    result.headers.update({'Cache-Control':'no-store, private','Pragma':'no-cache',
                           'X-Content-Type-Options':'nosniff'})
    return result


def manifest():
    file = GENERATED/'manifest.json'
    if not file.exists() or file.stat().st_size > 250_000:
        raise HTTPException(503,'Private bootstrap manifest not provisioned')
    data = json.loads(file.read_text())
    if data.get('schema_version') != 2:raise HTTPException(503,'Unexpected bootstrap schema')
    return data


def internalize(url):
    u, p = urlparse(url), urlparse(IS_PUBLIC)
    if u.scheme != 'https' or (u.scheme,u.netloc)!=(p.scheme,p.netloc) or not u.path.startswith('/'):
        raise ValueError('Untrusted WSO2 URL')
    return IS_INTERNAL + u.path


def discover(tenant):
    if tenant not in ('magalu.demo','magalupay.demo'):
        raise ValueError('Unknown tenant')
    for endpoint in ('/oauth2/token/.well-known/openid-configuration',
                     '/oauth2/oidcdiscovery/.well-known/openid-configuration',
                     '/.well-known/openid-configuration'):
        try:
            r=requests.get(IS_INTERNAL+'/t/'+tenant+endpoint,verify=VERIFY_TLS,timeout=8,
                           allow_redirects=False)
            if r.status_code != 200:continue
            data=r.json()
            if all(isinstance(data.get(k),str) for k in ('issuer','authorization_endpoint',
                                                        'token_endpoint','jwks_uri')):
                issuer=data['issuer']
                if issuer.startswith(IS_PUBLIC+'/t/'+tenant+'/'):
                    for k in ('token_endpoint','jwks_uri'):
                        internalize(data[k])
                    return data
        except (ValueError,requests.RequestException,KeyError):
            continue
    raise ValueError('Tenant discovery unavailable or invalid')


def signed_claims(token, discovery, client_id, nonce):
    head=jwt.get_unverified_header(token)
    alg=head.get('alg')
    if alg not in ('RS256','ES256','PS256'):raise ValueError('Unexpected signature algorithm')
    jwks=requests.get(internalize(discovery['jwks_uri']),verify=VERIFY_TLS,timeout=8).json()
    keys=[k for k in jwks.get('keys',[]) if k.get('kid')==head.get('kid')]
    if len(keys)!=1:raise ValueError('Signing key not found')
    key=jwt.PyJWK.from_dict(keys[0],algorithm=alg).key
    claims=jwt.decode(token,key,algorithms=[alg],audience=client_id,
                      issuer=discovery['issuer'],options={'require':['iss','sub','aud','exp','iat','nonce']})
    if not hmac.compare_digest(str(claims['nonce']),nonce):raise ValueError('Nonce mismatch')
    return claims


def seller_session(req):
    handle=req.session.get('seller_closure_handle')
    s=SESSIONS.get(handle) if isinstance(handle,str) else None
    if not s or s.get('expires_at',0)<time.time():
        return None
    return s


@router.get('/m3/completion',response_class=HTMLResponse)
def page(req:Request):
    response=TEMPLATES.TemplateResponse('m3_completion.html',{'request':req})
    response.headers.update({'Cache-Control':'no-store, private',
        'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        'X-Frame-Options':'DENY','Referrer-Policy':'no-referrer'})
    return response


@router.post('/api/m3/completion/consent-links')
def consent_links(req:Request):
    _guard(req)
    identities=_identities(req,('magalu','netshoes'))
    # Only relationships for these exact authenticated, signed sessions.
    links=_db().list_for(set(identities.values()))
    matched=[]
    for l in links:
        if l.get('source_brand')!='magalu' or l.get('recipient_brand')!='netshoes':continue
        try:
            _matching(_db(),identities,l['link_id'],'magalu','netshoes')
        except HTTPException:
            continue
        matched.append({'link_id':l['link_id'],'state':l['state'],
                        'source':'magalu','recipient':'netshoes'})
    return reply({'result':'OWNED_SESSION_LINKS','links':matched,
                  'note':'Old link IDs from another browser/user fail closed by design.'})


@router.post('/api/m3/completion/consent-check')
def consent_check(req:Request,body:LinkRequest):
    _guard(req)
    db=_db(); identities=_identities(req,('magalu','netshoes'))
    link=_matching(db,identities,body.link_id,'magalu','netshoes')
    info=_mirror_for(body.link_id,link)
    try:
        native_ok,reason,native=_native_status(info)
        # Distinct root tenant cannot read Commerce consent ID.
        try:
            _api('fintech').consent(info['native_id'])
        except NativeProblem as exc:
            if exc.code=='NATIVE_NOT_FOUND':
                isolated=True
            else:
                return reply({'result':'BLOCKED','reason':'FINTECH_READBACK_'+exc.code},503)
        else:
            isolated=False
        # A catalog response for both roots is required, not just a cached flag.
        cats = all(isinstance(_api(root).catalog(),dict) for root in ('commerce','fintech'))
    except NativeProblem as exc:
        return reply({'result':'BLOCKED','reason':exc.code},503)
    state=native.get('state') if isinstance(native,dict) else None
    data=_map()
    h=_mirror_identity(link)[:16]
    value=ordered_native_acceptance(data.get('events',[]),link_hash=h,
        native_state=state,custom_state=link.get('action') or 'NOT_GRANTED',
        fintech_not_found=isolated,has_two_catalogs=cats)
    value.update({'native_active':native_ok,'native_reason':reason,
                  'link_id':body.link_id,'scope':'ADMIN_NATIVE_MIRROR_AND_CUSTOM_LEDGER'})
    return reply(value)


@router.post('/api/m3/completion/b2c')
def b2c(req:Request):
    _guard(req)
    from demo.main import storefront_subject_matrix
    values=storefront_subject_matrix(req.cookies,requests.get)
    observations=[v for v in values if v['brand']=='magalu' and v['channel'] in ('web','app')]
    ok=len(observations)==2 and all(x['status']=='authenticated' and x.get('sub') for x in observations)
    same=ok and observations[0]['sub']==observations[1]['sub']
    return reply({'result':'OBSERVED_PASS' if same else 'INCOMPLETE',
        'web_and_app_authenticated':bool(ok),'sub_same_within_brand':bool(same),
        'source':'Two independent WSO2-signed storefront sessions; no bearer output',
        'other_b2c_requirements':'Identifier-first, passwordless and self-registration not covered by this check'})


@router.get('/m3/seller/login')
def seller_login(req:Request):
    m=manifest();client=m['clients'].get('seller:web')
    if not client or not client.get('client_secret'):
        raise HTTPException(503,'Seller OIDC client not provisioned')
    if client.get('tenant_domain')!='magalu.demo':raise HTTPException(503,'Seller client wrong tenant')
    disc=discover('magalu.demo')
    handle=secrets.token_urlsafe(32)
    verifier=secrets.token_urlsafe(64)
    state=secrets.token_urlsafe(32)
    nonce=secrets.token_urlsafe(32)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    SESSIONS[handle]={'pending':{'state':state,'verifier':verifier,'nonce':nonce,
                                 'created_at':time.time()},'expires_at':time.time()+900}
    req.session['seller_closure_handle']=handle
    params={'response_type':'code','client_id':client['client_id'],
            'redirect_uri':BASE+'/oidc/callback','scope':'openid profile email',
            'state':state,'nonce':nonce,'prompt':'login','max_age':'0',
            'code_challenge':challenge,'code_challenge_method':'S256'}
    return RedirectResponse(disc['authorization_endpoint']+'?'+urlencode(params),status_code=303)


def seller_callback(req:Request):
    """Return None for non-seller callbacks to preserve retired legacy handler."""
    s=seller_session(req)
    if not s or not isinstance(s.get('pending'),dict):return None
    pending=s.pop('pending')   # one-time state and PKCE verifier
    params=req.query_params
    if (params.get('error') or not params.get('code') or
        time.time()-pending['created_at']>300 or
        not hmac.compare_digest(str(params.get('state','')), pending['state'])):
        return RedirectResponse('/m3/completion?b2b=blocked',status_code=303)
    try:
        client=manifest()['clients']['seller:web']
        disc=discover('magalu.demo')
        r=requests.post(internalize(disc['token_endpoint']),
            auth=(client['client_id'],client['client_secret']),
            data={'grant_type':'authorization_code','code':params['code'],
                  'redirect_uri':BASE+'/oidc/callback','code_verifier':pending['verifier']},
            verify=VERIFY_TLS,timeout=15,allow_redirects=False)
        if r.status_code != 200:raise ValueError('Token request rejected')
        tokens=r.json()
        claims=signed_claims(tokens['id_token'],disc,client['client_id'],pending['nonce'])
        # The signed pairwise subject alone cannot be mapped to a company member.
        # Verify the UserInfo response's *same subject* and tenant before mapping.
        ui=requests.get(internalize(disc['userinfo_endpoint']),
            headers={'Authorization':'Bearer '+tokens['access_token']},
            verify=VERIFY_TLS,timeout=10,allow_redirects=False)
        if ui.status_code!=200:raise ValueError('UserInfo unavailable')
        user=ui.json()
        if user.get('sub')!=claims['sub']:raise ValueError('UserInfo subject mismatch')
        raw_name=user.get('preferred_username') or user.get('username') or ''
        # Only an exact, configured synthetic identity is accepted.
        username=str(raw_name)
        if username.endswith('@magalu.demo'):
            username=username[:-len('@magalu.demo')]
        if username not in ('bruno.seller','ana.magalu','SELLER_LDAP/ldap.seller'):
            username='UNRESOLVED'
        s.update({'authenticated':True,'tenant':'magalu.demo','username':username,
                  'subject_hash':hashlib.sha256(claims['sub'].encode()).hexdigest()[:16],
                  'expires_at':min(time.time()+900,float(claims['exp']))})
    except (ValueError,KeyError,TypeError,requests.RequestException,jwt.PyJWTError):
        s['authenticated']=False
        return RedirectResponse('/m3/completion?b2b=blocked',status_code=303)
    return RedirectResponse('/m3/completion?b2b=authenticated',status_code=303)


@router.post('/api/m3/completion/b2b')
def b2b(req:Request):
    _guard(req)
    s=seller_session(req)
    if not s or not s.get('authenticated'):
        return reply({'result':'NOT_AUTHENTICATED','login':'/m3/seller/login'})
    username=s['username']
    principal=Ledger(os.environ['CONSENT_DB_DSN']).principal_by_username(username) if username!='UNRESOLVED' else None
    member=None
    if principal:
        member=Ledger(os.environ['CONSENT_DB_DSN']).business_access(str(principal['principal_id']))
    return reply({'result':'OIDC_VERIFIED','user_store': 'UNVERIFIED' if '/' not in username else username.split('/')[0],
        'principal_resolved':bool(principal),'representative_active':bool(member and member.get('active')),
        'company': 'Seller Demo LTDA' if member else None,
        'synthetic_cnpj': '00.000.000/0000-00' if member else None,
        'role':member.get('role_name') if member else None,
        'issuer_tenant':'magalu.demo',
        'note':'Federation, CNPJ registry verification and delegated administration are separate work items.'})


class SellerAction(BaseModel):
    action:str=Field(pattern=r'^(view-dashboard|change-payout-account)$')


@router.post('/api/m3/completion/b2b/action')
def seller_action(req:Request,body:SellerAction):
    _guard(req)
    s=seller_session(req)
    if not s or not s.get('authenticated'):
        raise HTTPException(401,'Seller OIDC login required')
    ledger=Ledger(os.environ['CONSENT_DB_DSN'])
    principal=ledger.principal_by_username(s['username']) if s['username']!='UNRESOLVED' else None
    if principal:
        result=ledger.business_authorize(str(principal['principal_id']),body.action)
    else:
        result={'decision':'DENY','reason':'NO_VERIFIED_BUSINESS_REPRESENTATION'}
    return reply({'result':'OBSERVED','action':body.action,**result,
                  'policy_source':'postgresql_business_representatives_with_audit'})


@router.post('/api/m3/completion/m2m/cc')
def client_credentials(req:Request,body:M2MRequest):
    _guard(req)
    m=manifest();key='m2m:'+body.root+':cc'
    client=m['clients'].get(key)
    if not client or not client.get('client_secret'):
        return reply({'result':'BLOCKED','reason':'CC_CLIENT_NOT_PROVISIONED'},503)
    try:
        d=discover(client['tenant_domain'])
        token_endpoint=internalize(d['token_endpoint'])
        r=requests.post(token_endpoint,
            auth=(client['client_id'],client['client_secret']),
            data={'grant_type':'client_credentials'},verify=VERIFY_TLS,
            timeout=15,allow_redirects=False)
        response=r.json() if r.headers.get('Content-Type','').startswith('application/json') else {}
        token=response.get('access_token') if isinstance(response,dict) else None
        signed=False;issuer_ok=False
        if r.status_code==200 and token:
            from scripts.m3_token_exchange_verify import jwk_validate
            disco=dict(d);disco['jwks_uri']=internalize(d['jwks_uri'])
            claims=jwk_validate(token,disco,requests.Session(),VERIFY_TLS)
            signed=True
            issuer_ok=tenant_issuer_match(claims,d['issuer'])
        valid=r.status_code==200 and signed and issuer_ok
        # Exercise the actual HTTP resource handler, not only a local scope check.
        # CC tokens typically lack delegated requests:read; no implicit privilege.
        resource_http=None
        resource_reason='NOT_TESTED'
        if valid:
            rp=requests.get('http://127.0.0.1:8080/api/m3/exchange/resource/read',
                headers={'Authorization':'Bearer '+token},timeout=12,allow_redirects=False)
            resource_http=rp.status_code
            try: resource_reason=str(rp.json().get('reason','UNSPECIFIED'))
            except (ValueError,TypeError): resource_reason='INVALID_RESOURCE_RESPONSE'
        return reply({'result':'PASS_OBSERVED' if valid and resource_http in (401,403) else 'BLOCKED',
            'root':body.root,'tenant':client['tenant_domain'], 'http':r.status_code,
            'access_token_issued':bool(token),'jwt_signature_verified':signed,
            'issuer_matches_tenant':issuer_ok,
            'resource_http':resource_http,'resource_denial_reason':resource_reason,
            'resource_denied_without_delegated_access':resource_http in (401,403),
            'note':'401 rejects audience/issuer; 403 rejects scope after signature/audience verification.'})
    except (ValueError,TypeError,KeyError,requests.RequestException,jwt.PyJWTError):
        return reply({'result':'BLOCKED','reason':'TOKEN_OR_SIGNATURE_VERIFICATION_FAILED'},502)


@router.post('/api/m3/completion/m2m/jwt-replay')
def jwt_replay(req:Request,body:M2MRequest):
    _guard(req)
    # Not sent in browser or CLI args. Stored private in generated/ by operator.
    assertion=GENERATED/'m3-tokens'/('jwt-bearer-'+body.root+'.jwt')
    if (not assertion.is_file() or assertion.stat().st_size>32_000 or
        (assertion.stat().st_mode & 0o077) or assertion.read_text().strip().count('.') != 2):
        return reply({'result':'BLOCKED','reason':'PRIVATE_SIGNED_ASSERTION_REQUIRED'},409)
    m=manifest();client=m['clients'].get('m2m:'+body.root+':jwt')
    if not client or not client.get('client_secret'):
        return reply({'result':'BLOCKED','reason':'JWT_CLIENT_NOT_PROVISIONED'},503)
    try:
        disc=discover(client['tenant_domain'])
        endpoint=internalize(disc['token_endpoint'])
        def issue():
            r=requests.post(endpoint,
                auth=(client['client_id'],client['client_secret']),
                data={'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer',
                      'assertion':assertion.read_text().strip()},
                verify=VERIFY_TLS,timeout=20,allow_redirects=False)
            try: result=r.json()
            except ValueError:result={}
            return r.status_code, bool(result.get('access_token')), result.get('error')
        first=issue();second=issue()
        return reply({'root':body.root,**replay_verdict(first[0],first[1],second[0],second[1],second[2]),
            'assertion_source':'PRIVATE_TRUSTED_ISSUER_FILE',
            'note':'A second 200 is a failed replay test, not a passing grant.'})
    except (ValueError,requests.RequestException,KeyError):
        return reply({'result':'BLOCKED','reason':'JWT_REPLAY_RUNTIME_FAILURE'},502)

@router.post('/api/m3/completion/m2m/tenant-boundary')
def tenant_boundary(req:Request):
    _guard(req)
    values={}
    try:
        from scripts.m3_token_exchange_verify import jwk_validate
        for root,tenant in (('commerce','magalu.demo'),('fintech','magalupay.demo')):
            m=manifest();client=m['clients']['m2m:'+root+':cc']
            d=discover(tenant)
            r=requests.post(internalize(d['token_endpoint']),
                auth=(client['client_id'],client['client_secret']),
                data={'grant_type':'client_credentials'},verify=VERIFY_TLS,
                timeout=15,allow_redirects=False)
            if r.status_code!=200:raise ValueError('Cannot issue token for '+root)
            token=r.json().get('access_token')
            if not token:raise ValueError('Missing token')
            local=dict(d);local['jwks_uri']=internalize(d['jwks_uri'])
            own=jwk_validate(token,local,requests.Session(),VERIFY_TLS)
            if not tenant_issuer_match(own,d['issuer']):raise ValueError('Own issuer mismatch')
            values[root]={'token':token,'issuer':d['issuer']}
        # Resource-style issuer restriction: tokens from either root are invalid in other root.
        # This must not be mistaken for a real API endpoint's HTTP status.
        cross_allowed=(values['commerce']['issuer']==values['fintech']['issuer'])
        return reply({'result':'PASS_OBSERVED' if not cross_allowed else 'FAIL',
            'both_tokens_signed_verified':True,'different_issuer_claims':not cross_allowed,
            'cross_root_issuer_policy_rejects':not cross_allowed,
            'protected_resource_http':'NOT_TESTED_BY_THIS_CHECK'})
    except (ValueError,KeyError,requests.RequestException,TypeError,jwt.PyJWTError):
        return reply({'result':'BLOCKED','reason':'CROSS_TENANT_TOKEN_PROBE_FAILED'},502)
