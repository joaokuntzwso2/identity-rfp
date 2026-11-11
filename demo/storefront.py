"""Six isolated brand/channel BFFs using real WSO2 OIDC, scoped business APIs,
and a high-assurance approval redirect. Never performs a simulated OTP check.

Each Docker instance has a unique cookie name, process-local session table,
OAuth client, callback URI and externally published port. Because cookies are
not port-isolated, unique names are essential even for separate processes.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
from urllib.parse import urlencode

import jwt
import requests
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from demo.workflow import Workflow, WorkflowError

BRAND=os.environ.get('STORE_BRAND','magalu')
CHANNEL=os.environ.get('STORE_CHANNEL','web')
if BRAND not in ('magalu','netshoes','magalupay') or CHANNEL not in ('web','app'):
    raise RuntimeError('STORE_BRAND/STORE_CHANNEL must identify exactly one storefront')
CLIENT_KEY=f'{BRAND}:{CHANNEL}'
BASE=os.environ.get('STORE_PUBLIC_URL','http://localhost:8181').rstrip('/')
ISSUER_PUBLIC=os.environ.get('IS_PUBLIC_URL','https://localhost:9543').rstrip('/')
ISSUER_INTERNAL=os.environ.get('IS_INTERNAL_URL','https://is:9543').rstrip('/')
VERIFY=os.environ.get('IS_TLS_VERIFY','false').lower()=='true'
MANIFEST=Path(os.environ.get('MANIFEST_FILE','/project/generated/storefront-manifest.json'))
SESSION_SECRET=os.environ['DEMO_SESSION_SECRET']
ACR_TOTP='urn:magalu:aal2:totp'
SCOPE_READ='requests:read'
SCOPE_CREATE='requests:create'
SCOPE_APPROVE='requests:approve'
COOKIE=f'magalu_{BRAND}_{CHANNEL}_sid'

CATALOG={
 'magalu':{'name':'magalu','caption':'Tudo pra você, do seu jeito.',
  'subject':'Pedido de compra', 'placeholder':'Ex.: compra de notebook para escritório',
  'products':[('Smart TV 55”','R$ 2.799','TVs & Eletrônicos','📺'),
              ('Fone Bluetooth','R$ 289','Tecnologia','🎧'),
              ('Cafeteira Premium','R$ 499','Casa & Cozinha','☕')]},
 'netshoes':{'name':'NETSHOES','caption':'Movimento que transforma.',
  'subject':'Solicitação de troca', 'placeholder':'Ex.: troca de tênis esportivo',
  'products':[('Tênis Performance','R$ 549','Running','👟'),
              ('Jaqueta Sport','R$ 359','Training','🧥'),
              ('Bola Profissional','R$ 219','Futebol','⚽')]},
 'magalupay':{'name':'magalu pay','caption':'Mais controle para suas conquistas.',
  'subject':'Transferência de valores', 'placeholder':'Ex.: transferência para fornecedor',
  'products':[('Saldo disponível','R$ 18.450','Conta digital','◉'),
              ('Cartão virtual','Ativo','Pagamentos','▣'),
              ('Pix & transferências','24/7','Operações','⇄')]},
}

TEMPLATES=Jinja2Templates(directory=str(Path(__file__).parent/'templates'/'storefront'))
app=FastAPI(title=f'{BRAND.title()} {CHANNEL.upper()} – Magalu Login',docs_url=None,redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, session_cookie=COOKIE,
                   max_age=8*3600, https_only=False, same_site='lax')
app.mount('/assets', StaticFiles(directory=str(Path(__file__).parent/'static'/'storefront')), name='assets')
SESSIONS={}
DB=Workflow(os.environ.get('CONSENT_DB_DSN','postgresql://ciam:ciam_dev_only@db:5432/ciam'))


def manifest():
    if not MANIFEST.exists():
        raise HTTPException(503,'Bootstrap WSO2 ainda não foi executado.')
    m=json.loads(MANIFEST.read_text())
    if CLIENT_KEY not in m.get('clients',{}):
        raise HTTPException(503,f'Cliente OIDC {CLIENT_KEY} ausente.')
    return m


def active(request: Request):
    sid=request.session.get('sid')
    if not sid or sid not in SESSIONS:
        sid=secrets.token_urlsafe(32)
        request.session['sid']=sid
        SESSIONS[sid]={'csrf':secrets.token_urlsafe(24),'principal':None,'pending':None}
    return SESSIONS[sid]


def check_csrf(s, value):
    if not secrets.compare_digest(str(s['csrf']),str(value)):
        raise HTTPException(403,'Proteção CSRF rejeitou a requisição.')


def view(request, notice=None, error=None, code=200):
    s=active(request)
    m=manifest()
    client=m['clients'][CLIENT_KEY]
    records=[]
    if s['principal']:
        try:
            records=DB.list_requests(client['tenant_domain'],BRAND)
        except Exception as e:
            error=f'Banco de solicitações não inicializado: {type(e).__name__}'
    return TEMPLATES.TemplateResponse('site.html',{
        'request':request,'site':CATALOG[BRAND],'brand':BRAND,'channel':CHANNEL,
        'client':client,'principal':s['principal'],'csrf':s['csrf'],
        'records':records,'notice':notice,'error':error,'s7_last_failed_tx':s.get('s7_last_failed_tx'),
        'SCOPE_CREATE':SCOPE_CREATE,'SCOPE_APPROVE':SCOPE_APPROVE,'ACR_TOTP':ACR_TOTP,
    }, status_code=code)


def redirect(url):
    return RedirectResponse(url,status_code=303)


def discovery(domain):
    prefix=f'/t/{domain}'
    for path in ('/oauth2/token/.well-known/openid-configuration',
                 '/oauth2/oidcdiscovery/.well-known/openid-configuration',
                 '/.well-known/openid-configuration'):
        try:
            r=requests.get(ISSUER_INTERNAL+prefix+path,timeout=8,verify=VERIFY)
            data=r.json()
            if r.ok and data.get('issuer') and data.get('jwks_uri'):
                return data
        except (ValueError,requests.RequestException):
            pass
    raise HTTPException(503,'OIDC Discovery do root tenant não disponível.')


def internalize(uri):
    if uri.startswith(ISSUER_PUBLIC+'/'):
        return ISSUER_INTERNAL+uri[len(ISSUER_PUBLIC):]
    # Never allow arbitrary origins returned by an untrusted discovery document.
    if uri.startswith(ISSUER_INTERNAL+'/'):
        return uri
    raise RuntimeError('OIDC endpoint origin differs from configured issuer')


def verify_id_token(value, disco, client_id, nonce):
    if not value:
        raise ValueError('ID token ausente.')
    header=jwt.get_unverified_header(value)
    if header.get('alg') not in ('RS256','PS256','ES256'):
        raise ValueError('Algoritmo ID token não permitido.')
    jwks=requests.get(internalize(disco['jwks_uri']),timeout=8,verify=VERIFY).json()
    match=next((k for k in jwks.get('keys',[]) if k.get('kid')==header.get('kid')),None)
    if not match:
        raise ValueError('JWKS: assinatura sem chave correspondente.')
    key=jwt.PyJWK.from_dict(match,algorithm=header['alg']).key
    payload=jwt.decode(value,key,algorithms=[header['alg']],audience=client_id,
                       issuer=disco['issuer'],options={'require':['sub','iss','aud','iat','exp']})
    if not secrets.compare_digest(str(payload.get('nonce','')),nonce):
        raise ValueError('OIDC nonce inválido.')
    return payload


def authorize(s,client,disco,purpose='login',request_id=None):
    verifier=secrets.token_urlsafe(64)
    state=secrets.token_urlsafe(32)
    nonce=secrets.token_urlsafe(32)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    s['pending']={'state':state,'nonce':nonce,'verifier':verifier,'purpose':purpose,
                  'iat':int(time.time()),'request_id':request_id}
    params={'response_type':'code','client_id':client['client_id'],
            'redirect_uri':BASE+'/callback','scope':'openid '+
            ('profile email ' if BRAND == 'magalu' and CHANNEL == 'web' and purpose == 'login' else '') + SCOPE_READ+' '+SCOPE_CREATE+' '+SCOPE_APPROVE,
            'code_challenge':challenge,'code_challenge_method':'S256',
            'state':state,'nonce':nonce,
            # Required for independently operated storefronts sharing an IdP.
            'prompt':('login consent' if BRAND == 'magalu' and CHANNEL == 'web' and purpose == 'login' else 'login'),'max_age':'0'}
    if purpose in ('approval','s7_stepup'):
        params['acr_values']=ACR_TOTP
    # S7-OIDC-ESSENTIAL-AUTH-TIME
    if purpose == 's7_stepup':
        # A fresh authentication needs evidence issued by WSO2 itself.
        # OIDC Core requires auth_time for max_age=0; request it explicitly.
        params['prompt'] = 'login'
        params['max_age'] = '0'
        params['claims'] = json.dumps(
            {'id_token': {'auth_time': {'essential': True}}},
            separators=(',', ':'))
    return redirect(disco['authorization_endpoint']+'?'+urlencode(params))


def principal(request):
    entry=active(request)['principal']
    if not entry:
        raise HTTPException(401,'Faça login nesta aplicação.')
    return entry


def permission(entry,scope):
    if scope not in entry['scopes']:
        raise HTTPException(403,f'WSO2 não concedeu o escopo {scope}. Ação bloqueada.')


@app.get('/healthz')
def health():
    body={'status':'up' if MANIFEST.exists() else 'not-provisioned',
          'brand':BRAND,'channel':CHANNEL,'oidc_client':CLIENT_KEY,
          'manifest_present':MANIFEST.exists(),'cookie_name':COOKIE}
    return JSONResponse(body,status_code=200 if MANIFEST.exists() else 503)


@app.get('/',response_class=HTMLResponse)
def home(request:Request):
    return view(request)


@app.get('/login')
def login(request:Request):
    m=manifest()
    client=m['clients'][CLIENT_KEY]
    return authorize(active(request),client,discovery(client['tenant_domain']))


@app.get('/callback',response_class=HTMLResponse)
def callback(request:Request,code:str='',state:str='',error:str='',error_description:str=''):
    s=active(request)
    if error:
        return view(request,error='WSO2 interrompeu a autenticação: '+str(error),code=403)
    pending=s.pop('pending',None)
    if (not pending or not secrets.compare_digest(str(state),pending['state'])
            or time.time()-pending['iat']>300):
        return view(request,error='Callback OIDC sem estado válido (CSRF/replay).',code=400)
    m=manifest()
    client=m['clients'][CLIENT_KEY]
    disco=discovery(client['tenant_domain'])
    data={'grant_type':'authorization_code','code':code,'client_id':client['client_id'],
          'code_verifier':pending['verifier'],'redirect_uri':BASE+'/callback'}
    auth=(client['client_id'],client['client_secret']) if CHANNEL=='web' and client.get('client_secret') else None
    try:
        response=requests.post(internalize(disco['token_endpoint']),data=data,auth=auth,
                               verify=VERIFY,timeout=15)
        if not response.ok:
            return view(request,error=f'WSO2 token endpoint: HTTP {response.status_code}',code=502)
        tokens=response.json()
        claims=verify_id_token(tokens.get('id_token'),disco,client['client_id'],pending['nonce'])
        scopes=set(str(tokens.get('scope','')).split())
        # These are granted scopes, never the scopes merely requested in authorize().
        display='Cliente autenticado'
        userinfo_keys=[]
        userinfo_observed=False
        userinfo=disco.get('userinfo_endpoint')
        if userinfo and tokens.get('access_token'):
            try:
                result=requests.get(internalize(userinfo),headers={
                    'Authorization':'Bearer '+tokens['access_token']},verify=VERIFY,timeout=8)
                if result.ok:
                    user=result.json()
                    if user.get('sub')==claims['sub']:
                        userinfo_keys=sorted(str(k) for k in user.keys())
                        userinfo_observed=True
                        display=str(user.get('given_name') or user.get('name') or
                                    user.get('preferred_username') or display)[:60]
            except (ValueError,requests.RequestException):
                pass
        # Persist only opaque subjects and granted scopes. Never persist bearer tokens.
        newprincipal={'sub':str(claims['sub']),'issuer':str(claims['iss']),
                      'client_id':client['client_id'],'display':display,
                      'scopes':sorted(scopes),'auth_time':claims.get('auth_time'),
                      'amr':claims.get('amr',[]),'acr':claims.get('acr','')}
        newprincipal.update({
            'id_token_claim_names': sorted(str(k) for k in claims.keys()),
            'userinfo_claim_names': userinfo_keys,
            'userinfo_observed': userinfo_observed,
            'token_fingerprint': hashlib.sha256(tokens['id_token'].encode()).hexdigest()[:20],
            'verified_id_token': True,
        })
        if pending['purpose']=='s7_stepup':
            old=s.get('principal')
            if not old or old['sub']!=newprincipal['sub'] or old['issuer']!=newprincipal['issuer']:
                return view(request,error='Section 7: identidade alterada durante step-up.',code=403)
            # Only OIDC claims from the already signature-verified ID token.
            # Do not accept a UI TOTP challenge as proof when the claims disagree.
            observed_methods=claims.get('amr')
            method_names=observed_methods if isinstance(observed_methods,list) else []
            fresh=claims.get('auth_time')
            failures=[]
            if claims.get('acr')!=ACR_TOTP:
                failures.append('ACR_MISMATCH')
            if 'totp' not in [str(v).lower() for v in method_names if isinstance(v,str)]:
                failures.append('TOTP_AMR_MISSING')
            if not isinstance(fresh,(int,float)):
                failures.append('AUTH_TIME_MISSING')
            elif fresh<pending['iat']-30:
                failures.append('AUTH_TIME_STALE')
            if failures:
                # Preserve only a *failed* transaction pointer for a return link.
                # Do not set s7_stepup_tx: downstream assurance must remain denied.
                s['s7_last_failed_tx']=pending['request_id']
                observed_acr=str(claims.get('acr') or 'MISSING')[:80]
                observed_amr=','.join(str(v)[:35] for v in method_names if isinstance(v,str))[:140] or 'MISSING'
                detail=('Section 7: WSO2 TOTP/AAL2 não comprovado. '
                        + 'Falhas: '+','.join(failures)
                        + '; acr observado='+observed_acr
                        + '; amr observado='+observed_amr
                        + '; auth_time='+('PRESENT' if isinstance(fresh,(int,float)) else 'MISSING')
                        + '. Nenhum token ou segredo foi exibido.')
                return view(request,error=detail,code=403)
            s.pop('s7_last_failed_tx',None)
            s['principal']=newprincipal
            s['s7_stepup_tx']=pending['request_id']
            return redirect('http://localhost:8180/m3/section7?tx='+pending['request_id'])
        if pending['purpose']=='approval':
            old=s.get('principal')
            if not old or old['sub']!=newprincipal['sub'] or old['issuer']!=newprincipal['issuer']:
                return view(request,error='Step-up interrompido: identidade mudou.',code=403)
            if SCOPE_APPROVE not in scopes:
                return view(request,error='WSO2 não concedeu requests:approve.',code=403)
            methods=claims.get('amr',[])
            if not isinstance(methods,list):
                methods=[]
            fresh=claims.get('auth_time')
            if (claims.get('acr')!=ACR_TOTP or 'totp' not in [str(v).lower() for v in methods]
                    or not isinstance(fresh,(int,float)) or fresh<pending['iat']-30):
                return view(request,error='Aprovação bloqueada: é necessário TOTP real, ACR correto e autenticação recente no WSO2.',code=403)
            try:
                DB.approve(pending['request_id'],client['tenant_domain'],BRAND,
                           newprincipal['sub'],newprincipal['issuer'],
                           str(claims['acr']),methods,int(fresh))
            except WorkflowError as exc:
                return view(request,error=str(exc),code=403)
            s['principal']=newprincipal
            return redirect('/?approved=1')
        s['principal']=newprincipal
        return redirect('/?login=1')
    except (requests.RequestException,KeyError,ValueError,TypeError,jwt.InvalidTokenError,RuntimeError) as exc:
        return view(request,error='Validação OIDC não concluída: '+str(exc)[:180],code=403)


@app.post('/logout')
def logout(request:Request,csrf:str=Form()):
    s=active(request)
    check_csrf(s,csrf)
    sid=request.session.get('sid')
    if sid: SESSIONS.pop(sid,None)
    request.session.clear()
    # Relying party logout only: does not terminate other independent apps.
    # Next /login always uses prompt=login/max_age=0 to force credentials.
    return redirect('/?loggedout=1')


@app.post('/requests')
def create_request(request:Request,subject:str=Form(),amount:str=Form(),csrf:str=Form()):
    s=active(request)
    check_csrf(s,csrf)
    p=principal(request)
    permission(p,SCOPE_CREATE)
    client=manifest()['clients'][CLIENT_KEY]
    try:
        DB.request(client['tenant_domain'],BRAND,subject,amount,p['sub'],p['issuer'],p['client_id'])
    except WorkflowError as exc:
        return view(request,error=str(exc),code=400)
    return redirect('/?created=1')


@app.post('/requests/{request_id}/approve')
def approve_start(request:Request,request_id:str,csrf:str=Form()):
    s=active(request)
    check_csrf(s,csrf)
    p=principal(request)
    permission(p,SCOPE_APPROVE)
    client=manifest()['clients'][CLIENT_KEY]
    try:
        item=DB.pending(request_id,client['tenant_domain'],BRAND)
    except WorkflowError as exc:
        raise HTTPException(400,str(exc)) from None
    if not item or item['status']!='PENDING':
        raise HTTPException(404,'Solicitação não encontrada ou já processada.')
    if item['requester_issuer']!=p['issuer'] or item['requested_by_sub']==p['sub']:
        raise HTTPException(403,'Separação de funções ou emissor não validado.')
    return authorize(s,client,discovery(client['tenant_domain']),'approval',request_id)


@app.get('/api/session')
def session_info(request:Request):
    p=active(request)['principal']
    if not p:
        return {'authenticated':False,'brand':BRAND,'channel':CHANNEL}
    return {'authenticated':True,'brand':BRAND,'channel':CHANNEL,
            'tenant':manifest()['clients'][CLIENT_KEY]['tenant_domain'],
            'sub':p['sub'],'scopes':p['scopes'],'acr':p['acr'],'amr':p['amr']}


# RFP S7: never returns tokens or raw user attributes; only live session metadata.
@app.get('/api/s7/evidence')
def s7_evidence(request:Request):
    p=active(request).get('principal')
    if not p or p.get('verified_id_token') is not True:
        return JSONResponse({'authenticated':False},status_code=401)
    return JSONResponse({
        'authenticated':True,'brand':BRAND,'channel':CHANNEL,
        'tenant':manifest()['clients'][CLIENT_KEY]['tenant_domain'],
        'sub':p['sub'],'issuer':p['issuer'],
        'client_id':p['client_id'],'verified_id_token':True,
        'token_fingerprint':p.get('token_fingerprint'),
        'id_token_claim_names':p.get('id_token_claim_names',[]),
        'userinfo_claim_names':p.get('userinfo_claim_names',[]),
        'userinfo_observed':p.get('userinfo_observed',False),
        'acr':p.get('acr'),'amr':p.get('amr',[]),
        'auth_time':p.get('auth_time'),'s7_stepup_tx':active(request).get('s7_stepup_tx')
    },headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'})

@app.get('/s7/stepup')
def s7_stepup(request:Request,tx:str=''):
    import uuid as _uuid
    if BRAND!='magalupay' or CHANNEL!='web':
        raise HTTPException(404,'This challenge is only for MagaluPay Web')
    try:
        if str(_uuid.UUID(tx))!=tx:raise ValueError('invalid tx')
    except ValueError:
        raise HTTPException(400,'Invalid transaction identifier') from None
    s=active(request)
    if not s.get('principal'):
        raise HTTPException(401,'Authenticate in MagaluPay Web before starting the challenge')
    client=manifest()['clients'][CLIENT_KEY]
    return authorize(s,client,discovery(client['tenant_domain']),'s7_stepup',tx)
