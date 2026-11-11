"""Professional RFP Section 7 demo portal. Actual WSO2 OIDC; not a mocked login."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

import jwt
import requests
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from demo.policy import assurance_level, pairwise_verdict, step_up_decision
from demo.store import Ledger

PUBLIC=os.getenv('DEMO_PUBLIC_URL','http://localhost:8080').rstrip('/')
IS_PUBLIC=os.getenv('IS_PUBLIC_URL','https://localhost:9443').rstrip('/')
IS_INTERNAL=os.getenv('IS_INTERNAL_URL','https://host.docker.internal:9443').rstrip('/')
VERIFY=os.getenv('IS_TLS_VERIFY','true').lower()=='true'
MANIFEST=Path(os.getenv('MANIFEST_FILE','generated/manifest.json'))
DB=Ledger(os.getenv('CONSENT_DB_DSN','postgresql://ciam:ciam_dev_only@localhost:5432/ciam'))
TEMPLATES=Jinja2Templates(directory=str(Path(__file__).parent/'templates'))
app=FastAPI(title='Magalu Login · CIAM Technical Evaluation',docs_url=None,redoc_url=None)
app.add_middleware(SessionMiddleware,secret_key=os.getenv('DEMO_SESSION_SECRET','DEV_ONLY_REPLACE'),
                   same_site='lax',https_only=False,max_age=60*60*8)
app.mount('/static',StaticFiles(directory=str(Path(__file__).parent/'static')),name='static')
# Single-replica demo: key material remains server-side, session cookie contains only a random handle.
SESSIONS:dict[str,dict]={}

# Fixed, internal-only service map. Never accept service URLs from user input.
# Browser cookies are scoped by hostname (not port), but each storefront uses
# its own independent, signed, uniquely named session cookie.
STOREFRONTS = (
    ('magalu', 'web', 8181), ('magalu', 'app', 8182),
    ('netshoes', 'web', 8183), ('netshoes', 'app', 8184),
    ('magalupay', 'web', 8185), ('magalupay', 'app', 8186),
)
STOREFRONT_COOKIE_PATTERN = re.compile(r'^[A-Za-z0-9._~+/=-]{1,2048}$')


def storefront_session_matrix(cookies, fetch):
    """Read six independently signed sessions, without merging authentication.

    Only each application's own cookie is forwarded to its own internal BFF.
    Returned status has no subjects, granted scopes, tokens, or PII.
    """
    result = []
    for brand, channel, port in STOREFRONTS:
        name = f'magalu_{brand}_{channel}_sid'
        entry = {'brand':brand, 'channel':channel, 'port':port,
                 'authenticated':False, 'available':True}
        value = cookies.get(name, '')
        if value and STOREFRONT_COOKIE_PATTERN.fullmatch(value):
            try:
                # Each BFF independently validates its own cookie and server-side SID.
                r = fetch(f'http://store-{brand}-{channel}:8080/api/session',
                          headers={'Cookie':f'{name}={value}'}, timeout=2.0,
                          allow_redirects=False)
                if r.status_code == 200:
                    response = r.json()
                    if (response.get('brand') == brand and response.get('channel') == channel
                            and response.get('authenticated') is True):
                        entry['authenticated'] = True
                else:
                    entry['available'] = False
            except (requests.RequestException, ValueError, TypeError, AttributeError):
                entry['available'] = False
        if not value or not STOREFRONT_COOKIE_PATTERN.fullmatch(value):
            # No cookie means logged out, but still detect a stopped service.
            try:
                r = fetch(f'http://store-{brand}-{channel}:8080/healthz',
                          timeout=1.5, allow_redirects=False)
                entry['available'] = (r.status_code == 200)
            except requests.RequestException:
                entry['available'] = False
        result.append(entry)
    return result




def storefront_subject_matrix(cookies, fetch):
    """Read opaque subjects from six *authenticated* store BFF sessions.

    Unlike the public session-status overview, this report contains pseudonymous
    subject identifiers. It is private, never persisted or shared across stores.
    Values originate from ID tokens verified by each store at sign-in.
    """
    result = []
    for brand, channel, port in STOREFRONTS:
        tenant = 'magalupay.demo' if brand == 'magalupay' else 'magalu.demo'
        cookie_name = f'magalu_{brand}_{channel}_sid'
        entry = {'brand':brand, 'channel':channel, 'tenant':tenant,
                 'port':port, 'status':'logged_out', 'sub':None}
        value = cookies.get(cookie_name, '')
        if value and STOREFRONT_COOKIE_PATTERN.fullmatch(value):
            try:
                response = fetch(f'http://store-{brand}-{channel}:8080/api/session',
                                 headers={'Cookie':f'{cookie_name}={value}'},
                                 timeout=2.5, allow_redirects=False)
                if response.status_code != 200:
                    entry['status']='unavailable'
                else:
                    data=response.json()
                    if not isinstance(data,dict) or data.get('brand')!=brand or data.get('channel')!=channel:
                        entry['status']='invalid_response'
                    elif data.get('authenticated') is True:
                        subject=data.get('sub')
                        if (data.get('tenant') == tenant and isinstance(subject,str)
                                and 0 < len(subject) <= 255 and subject.isprintable()
                                and not any(c.isspace() for c in subject)):
                            entry['status']='authenticated'
                            entry['sub']=subject
                        else:
                            # Do not report a success from a mismatched tenant or invalid subject.
                            entry['status']='invalid_response'
                    elif data.get('authenticated') is not False:
                        entry['status']='invalid_response'
            except (requests.RequestException, ValueError, TypeError, AttributeError):
                entry['status']='unavailable'
        elif value:
            entry['status']='invalid_cookie'
        else:
            # Report a stopped service distinctly from a logged-out browser.
            try:
                response=fetch(f'http://store-{brand}-{channel}:8080/healthz',
                               timeout=1.5, allow_redirects=False)
                if response.status_code != 200:
                    entry['status']='unavailable'
            except requests.RequestException:
                entry['status']='unavailable'
        result.append(entry)
    return result


def build_pairwise_report(entries):
    """Compare only observed OIDC subjects. Never synthesize missing values."""
    indexed={(e['brand'],e['channel']):e for e in entries}

    def subject(brand, channel):
        item=indexed.get((brand,channel),{})
        return item.get('sub') if item.get('status')=='authenticated' else None

    specs=[]
    for brand in ('magalu','netshoes','magalupay'):
        specs.append({'id':brand+'_continuity','kind':'continuity',
                      'left':(brand,'web'),'right':(brand,'app'),'expected':'equal'})
    for a,b in (('magalu','netshoes'),('magalu','magalupay'),('netshoes','magalupay')):
        # Across brands, use either authenticated channel for each brand.
        ac='web' if subject(a,'web') else 'app'
        bc='web' if subject(b,'web') else 'app'
        specs.append({'id':a+'_'+b+'_separation','kind':'separation',
                      'left':(a,ac),'right':(b,bc),'expected':'different'})

    checks=[]
    for spec in specs:
        a,b=spec['left'],spec['right']
        sa,sb=subject(*a),subject(*b)
        if not sa or not sb:
            status='pending'
        elif (sa==sb)==(spec['expected']=='equal'):
            status='pass'
        else:
            status='fail'
        checks.append({'id':spec['id'],'kind':spec['kind'],
                       'left':{'brand':a[0],'channel':a[1]},
                       'right':{'brand':b[0],'channel':b[1]},
                       'expected':spec['expected'], 'status':status})

    count=sum(e.get('status')=='authenticated' for e in entries)
    failed=any(c['status']=='fail' for c in checks)
    complete=count==6 and all(c['status']=='pass' for c in checks)
    return {'result':'MISMATCH' if failed else 'OBSERVED_PASS' if complete else 'INCOMPLETE',
            'authenticated_count':count, 'total':6,
            'passed_checks':sum(c['status']=='pass' for c in checks),
            'total_checks':6, 'storefronts':entries, 'checks':checks,
            'source':'Authenticated BFF sessions populated from WSO2-signed ID tokens',
            'identity_equivalence':'USER_ATTESTATION_REQUIRED',
            'pairwise_protocol_proof':'DISCOVERY_AND_SECTOR_CONFIG_STILL_REQUIRED',
            'note':'Compare subjects only after authenticating the SAME real test person to all six clients. The observation alone does not prove OIDC pairwise configuration.'}


@app.get('/api/pairwise-evidence')
def pairwise_evidence(request: Request):
    """Browser-scoped, privacy-preserving pairwise evidence (no bearer tokens)."""
    report=build_pairwise_report(storefront_subject_matrix(request.cookies, requests.get))
    response=JSONResponse(report)
    response.headers['Cache-Control']='no-store, private'
    response.headers['Pragma']='no-cache'
    response.headers['X-Content-Type-Options']='nosniff'
    return response


@app.get('/pairwise',response_class=HTMLResponse)
def pairwise_page(request:Request):
    response=TEMPLATES.TemplateResponse('pairwise.html', {
        'request':request, 'brand':None, 'manifest':None,
        'session':{}, 'csrf':''})
    response.headers['Cache-Control']='no-store, private'
    return response


@app.get('/api/storefront-status')
def storefront_status(request: Request):
    """Local browser session matrix for the RFP evidence portal.

    This is NOT an SSO token exchange and does not set any session cookies.
    """
    result = storefront_session_matrix(request.cookies, requests.get)
    response = JSONResponse({'storefronts': result,
       'authenticated_count': sum(e['authenticated'] for e in result),
       'total': len(result)})
    response.headers['Cache-Control'] = 'no-store, private'
    return response


def manifest():
    if not MANIFEST.exists():
        return None
    return json.loads(MANIFEST.read_text())


def session(request: Request):
    sid=request.session.get('sid')
    if not sid or sid not in SESSIONS:
        sid=secrets.token_urlsafe(32)
        request.session['sid']=sid
        SESSIONS[sid]={'csrf':secrets.token_urlsafe(24),'authenticated':{},'started':int(time.time())}
    return SESSIONS[sid]


def page(request,name,**ctx):
    m=manifest()
    context={'request':request,'manifest':m,'session':session(request),
             'csrf':session(request)['csrf'],'brand':ctx.pop('brand',None),**ctx}
    return TEMPLATES.TemplateResponse(name,context)


def internalize(url):
    # Strictly map the configured PUBLIC origin to the INTERNAL container address.
    if url.startswith(IS_PUBLIC+'/'):
        return IS_INTERNAL+url[len(IS_PUBLIC):]
    return url


def discovery(brand=None):
    m=manifest() or {}
    prefix='/t/'+m['brands'][brand]['tenant_domain'] if brand else ''
    for path in ('/oauth2/token/.well-known/openid-configuration',
                 '/oauth2/oidcdiscovery/.well-known/openid-configuration',
                 '/.well-known/openid-configuration'):
        try:
            response=requests.get(IS_INTERNAL+prefix+path,timeout=8,verify=VERIFY)
            if response.ok and 'issuer' in response.json():
                return response.json()
        except (ValueError,requests.RequestException):
            pass
    raise RuntimeError('OIDC discovery cannot be reached from demo container')


def redirect(location):
    return RedirectResponse(location,status_code=303)


def required_brand_session(request,brand):
    sess=session(request)
    if brand not in (manifest() or {}).get('brands',{}):
        raise HTTPException(404,'Unknown brand')
    if not any(v.get('brand')==brand for v in sess.get('authenticated',{}).values()):
        raise HTTPException(403,'Authenticate to this brand first')
    if not sess.get('principal_id'):
        raise HTTPException(403,'Unresolved identity: internal principal mapping missing')
    return sess


def assert_csrf(sess,token):
    if not secrets.compare_digest(sess['csrf'],token):
        raise HTTPException(403,'CSRF validation failed')


def verify_id_token(value,disco,client_id,nonce):
    if not value:
        raise ValueError('WSO2 token response omitted id_token')
    jwks=requests.get(internalize(disco['jwks_uri']),timeout=8,verify=VERIFY).json()
    header=jwt.get_unverified_header(value)
    if header.get('alg') not in ('RS256','PS256','ES256'):
        raise ValueError('Unapproved ID token algorithm')
    selected=next((k for k in jwks.get('keys',[]) if k.get('kid')==header.get('kid')),None)
    if not selected:
        raise ValueError('No matching JWKS kid')
    key=jwt.PyJWK.from_dict(selected,algorithm=header['alg']).key
    claims=jwt.decode(value,key,algorithms=[header['alg']],audience=client_id,
                      issuer=disco['issuer'],options={'require':['sub','iss','aud','exp','iat']})
    if not secrets.compare_digest(str(claims.get('nonce','')),nonce):
        raise ValueError('OIDC nonce mismatch')
    return claims


@app.get('/',response_class=HTMLResponse)
def home(request:Request):
    # The observation dashboard never creates or modifies an auth session.
    return TEMPLATES.TemplateResponse('home.html', {
        'request':request, 'manifest':manifest(), 'brand':None,
        'session':{}, 'csrf':''})


@app.get('/healthz')
def health():
    m=manifest()
    return {'status':'configured' if m else 'needs-bootstrap',
            'manifest_present':bool(m),'identity_issuer':m.get('issuer') if m else None}


@app.get('/sectors/{brand}.json')
def sector(brand:str):
    """OIDC sector JSON: same redirect URLs for both clients of one brand."""
    m=manifest()
    if not m or brand not in m.get('brands',{}):
        raise HTTPException(404)
    from bootstrap.storefront_ports import callback_uri
    return JSONResponse(content=[PUBLIC+'/oidc/callback',
                                 callback_uri(brand+':web'),
                                 callback_uri(brand+':app')])


@app.get('/auth/start/{brand}/{channel}')
def auth_start(brand:str, channel:str):
    """Compatibility entry point; individual storefronts own the OAuth flow.

    Retired 8180 OIDC client to avoid the old preferred_username dependency.
    """
    match = next((port for b,c,port in STOREFRONTS if b==brand and c==channel),None)
    if match is None:
        raise HTTPException(404, 'Independent storefront not found')
    return redirect(f'http://localhost:{match}/login')


@app.get('/oidc/callback',response_class=HTMLResponse)
def callback(request:Request):
    from demo.poc_closure import seller_callback as _poc_seller_callback
    new_response=_poc_seller_callback(request)
    if new_response is not None:
        return new_response
    """Former portal callback is retired: do not correlate users by claims."""
    return page(request,'error.html',problem='Portal legacy substituído',
                details='As seis aplicações independentes gerenciam seu próprio login. Volte ao painel e inicie uma nova autenticação pela aplicação desejada.')


@app.get('/poc/{brand}',response_class=HTMLResponse)
def brand_dashboard(request:Request,brand:str):
    sess=required_brand_session(request,brand)
    observations=DB.bindings(sess['principal_id'])
    att=DB.attributes(sess['principal_id'])
    return page(request,'brand.html',brand=brand,identity_level=assurance_level(att),
                attributes=att,observations=observations,verdict=pairwise_verdict(observations),
                auths=sess['authenticated'])


@app.get('/preferences/{brand}',response_class=HTMLResponse)
def preferences(request:Request,brand:str):
    sess=required_brand_session(request,brand)
    client=brand+':web'
    purposes=DB.active_purposes(brand)
    entries=[]
    for purpose in purposes:
        current=DB.current_consent(sess['principal_id'],client,purpose['purpose_key'])
        entries.append({'purpose':purpose,'current':current})
    return page(request,'preferences.html',brand=brand,entries=entries,
                history=DB.histories(sess['principal_id'],brand))


@app.post('/preferences/{brand}/transition')
def consent_action(request:Request,brand:str,purpose_key:str=Form(),action:str=Form(),
                   csrf:str=Form()):
    sess=required_brand_session(request,brand)
    assert_csrf(sess,csrf)
    if purpose_key not in {p['purpose_key'] for p in DB.active_purposes(brand)}:
        raise HTTPException(404,'Purpose not in this tenant')
    try:
        DB.transition_consent(sess['principal_id'],brand+':web',purpose_key,action,
                              secrets.token_urlsafe(24))
    except ValueError as exc:
        raise HTTPException(400,str(exc)) from exc
    return redirect('/preferences/'+brand)


@app.get('/assurance/{brand}',response_class=HTMLResponse)
def assurance(request:Request,brand:str):
    sess=required_brand_session(request,brand)
    attributes=DB.attributes(sess['principal_id'])
    level=assurance_level(attributes)
    return page(request,'assurance.html',brand=brand,identity_level=level,
                attributes=attributes,policy=step_up_decision(level,80,'fintech-transfer'))


@app.post('/assurance/{brand}/synthetic-event')
def synthetic_event(request:Request,brand:str,attribute:str=Form(),state:str=Form(),csrf:str=Form()):
    sess=required_brand_session(request,brand)
    assert_csrf(sess,csrf)
    if brand!='magalupay':
        raise HTTPException(403,'This special assurance fixture belongs to fintech tenant')
    DB.record_attribute(sess['principal_id'],attribute,state=='VERIFIED')
    return redirect('/assurance/'+brand)


@app.get('/m2m',response_class=HTMLResponse)
def m2m_page(request:Request):
    return page(request,'m2m.html')


@app.post('/m2m/token')
def m2m_token(request:Request,csrf:str=Form()):
    sess=session(request)
    assert_csrf(sess,csrf)
    m=manifest()
    if not m:
        raise HTTPException(503,'Bootstrap missing')
    cc=m['clients']['m2m:commerce:cc']
    if not cc.get('client_secret'):
        raise HTTPException(503,'M2M client secret not retrievable; bootstrap requires read scope')
    d=discovery(cc['brand'])
    r=requests.post(internalize(d['token_endpoint']),data={'grant_type':'client_credentials'},
      auth=(cc['client_id'],cc['client_secret']),timeout=15,verify=VERIFY)
    result=r.json() if r.headers.get('content-type','').startswith('application/json') else {'error':r.text[:200]}
    # Never return a reusable bearer token to the browser or store it in HTML.
    result.pop('access_token',None)
    result.pop('refresh_token',None)
    sess['m2m_result']={'http_status':r.status_code,'response':result}
    return redirect('/m2m')


@app.get('/api/evidence')
def evidence(request:Request):
    """Read-only six-client session evidence; pairwise not inferred from login state."""
    matrix=storefront_session_matrix(request.cookies,requests.get)
    response=JSONResponse({'status':'STOREFRONT_SESSION_MATRIX',
        'pairwise_sub':'NOT_VERIFIED_BY_SESSION_MATRIX',
        'note':'Verify each OIDC sub separately; these sessions are not a shared SSO session.',
        'storefronts':matrix})
    response.headers['Cache-Control']='no-store, private'
    return response


@app.post('/logout-local')
def logout_local(request:Request,csrf:str=Form()):
    sess=session(request)
    assert_csrf(sess,csrf)
    sid=request.session.get('sid')
    if sid: SESSIONS.pop(sid,None)
    request.session.clear()
    return redirect('/')


@app.get('/seller',response_class=HTMLResponse)
def seller_home(request:Request):
    sess=session(request)
    if 'seller:web' not in sess.get('authenticated',{}):
        return redirect('/m3/completion?tab=b2b')
    seller=DB.business_access(sess.get('principal_id'))
    return page(request,'seller.html',brand='magalu',seller=seller,
                auths=sess['authenticated'])


@app.post('/seller/transaction')
def seller_transaction(request:Request,csrf:str=Form()):
    sess=session(request)
    assert_csrf(sess,csrf)
    if 'seller:web' not in sess.get('authenticated',{}) or not sess.get('principal_id'):
        raise HTTPException(403,'B2B login required')
    result=DB.business_authorize(sess['principal_id'],'change-payout-account')
    sess['seller_decision']={**result,
       'limit':'DEMO POLICY ONLY: Real bank change still requires IAL/AAL step-up.'}
    return redirect('/seller')


# Customer-owned M3 consent-gated resource server (stable integration hook)
from demo.m3_consent import install as _install_m3_consent
_install_m3_consent(app, DB.dsn, lambda request: storefront_subject_matrix(request.cookies, requests.get), session, assert_csrf)


# M3 RFC8693 operator workbench (token files and secrets stay server-side)
from demo.m3_exchange_lab import router as _m3_exchange_lab_router
app.include_router(_m3_exchange_lab_router)

# Milestone 3: root-tenant isolation story (independent of consent and RFC8693 pages).
from demo.m3_isolation import router as _m3_isolation_router
app.include_router(_m3_isolation_router)
# Native Consent Management v2 evidence chapter — operator-only, no WSO2 reset.
from demo.m3_native_lab import router as _m3_native_lab_router
app.include_router(_m3_native_lab_router)
# RFP Section 7.2 acceptance cockpit — additive, no API mock.
from demo.s7_acceptance import router as _s7_acceptance_router
app.include_router(_s7_acceptance_router)

# Section 7 additive B2C/B2B/M2M acceptance cockpit.
from demo.poc_closure import router as _poc_closure_router
app.include_router(_poc_closure_router)
