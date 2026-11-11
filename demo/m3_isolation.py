"""M3: real, operator-controlled consent & cross-root OAuth isolation evidence.

Mount as a router on the existing 8180 demo. Never exposes bearer material or
client secrets. Mutations are restricted to explicitly requested demo consent
links/grants; all OAuth exchanges are read/test only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit

import jwt
import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from demo.m3_consent import ConsentDb, verified_subject
from demo.m3_exchange_engine import _discovery, _urls, filtered_error, readiness
from demo.m3_resource_api import resource_audience_config
from scripts.m3_token_exchange_verify import (ACCESS_TYPE, EXCHANGE, TOKEN_TYPE,
                                                jwk_validate, read_private, token_scopes)

router = APIRouter()
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent/'templates'))
GENERATED = Path(os.getenv('MANIFEST_FILE','generated/manifest.json')).parent
CONSENT_REPORT = GENERATED/'m3-isolation-consent-evidence.json'
TOKEN_REPORT = GENERATED/'m3-isolation-token-evidence.json'
PAY_READBACK = GENERATED/'m3-fintech-cc-control-readback.json'
PAY_AUDIENCE = 'urn:magalupay:poc:isolation'
LOCK = threading.Lock()
BRANDS = {'magalu':'magalu.demo','netshoes':'magalu.demo','magalupay':'magalupay.demo'}
CONSENT_DESTS = {'netshoes','magalupay','reverse'}
ALLOWED_ERROR = {'invalid_scope','invalid_grant','invalid_request','unauthorized_client','access_denied','invalid_target'}


class LinkInput(BaseModel):
    link_id: str = Field(min_length=36,max_length=36)


class ConfirmInput(LinkInput):
    acknowledged: bool = False


class TestInput(BaseModel):
    link_id: str = Field(min_length=36,max_length=36)
    reverse_link_id: str = Field(min_length=36,max_length=36)


def _reply(data,code=200):
    result=JSONResponse(data,status_code=code)
    result.headers.update({'Cache-Control':'private, no-store','Pragma':'no-cache',
                           'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'})
    return result


def _guard(req):
    expected=os.getenv('DEMO_OPERATOR_KEY','')
    origin=os.getenv('DEMO_PUBLIC_URL','http://localhost:8180').rstrip('/')
    if not expected or len(expected)<24 or expected.startswith('CHANGE_'):
        raise HTTPException(503,'Lab operator key is not configured')
    if not origin.startswith(('http://localhost:','http://127.0.0.1:')):
        raise HTTPException(403,'Local-only operator actions')
    if req.headers.get('origin')!=origin or not hmac.compare_digest(req.headers.get('x-ciam-lab-key',''),expected):
        raise HTTPException(403,'Same-origin operator authorization required')


def _sessions(req):
    # Reuse existing independent, signed storefront sessions and tenant checks.
    from demo.main import storefront_subject_matrix
    return storefront_subject_matrix(req.cookies,requests.get)


def _identities(req,required=()):
    rows=_sessions(req)
    found={}
    for brand in BRANDS:
        try: found[brand]=verified_subject(rows,brand)
        except HTTPException: pass
    for brand in required:
        if brand not in found:
            raise HTTPException(409,f'Authenticate to {brand} in this localhost browser first')
    return found


def _db():
    dsn=os.getenv('CONSENT_DB_DSN')
    if not dsn:raise HTTPException(503,'Consent database is unavailable')
    return ConsentDb(dsn)


def _matching(db,identities,link_id,source,recipient):
    """Never allow operator-selected link identifiers to cross identity boundaries."""
    with db.tx() as conn: link=db.get(link_id,conn)
    source_tenant,source_sub=identities[source]
    recipient_tenant,recipient_sub=identities[recipient]
    if not (link['source_tenant']==source_tenant and
            link['source_brand']==source and
            hmac.compare_digest(link['source_sub'],source_sub) and
            link['recipient_tenant']==recipient_tenant and
            link['recipient_brand']==recipient and
            hmac.compare_digest(link['recipient_sub'],recipient_sub)):
        raise HTTPException(403,'Consent link does not belong to these authenticated sessions')
    return link


def _session_tag(identities):
    key=os.getenv('DEMO_OPERATOR_KEY','').encode()
    src='|'.join(f'{k}:{identities[k][0]}:{identities[k][1]}' for k in sorted(identities))
    return hmac.new(key,src.encode(),hashlib.sha256).hexdigest()[:20]


def _read(path):
    try:
        p=Path(path)
        if not p.is_file() or p.stat().st_size>32_000 or p.stat().st_mode&0o077:
            return None
        return json.loads(p.read_text())
    except (OSError,ValueError,TypeError):return None


def _fresh(report,seconds=3600):
    """Do not present yesterday's report as a current live status."""
    if not isinstance(report,dict):return None
    try:
        stamp=datetime.fromisoformat(report['timestamp'])
        age=(datetime.now(timezone.utc)-stamp).total_seconds()
        return report if 0<=age<=seconds else None
    except (ValueError,TypeError,KeyError):return None


def _write(path,data):
    import tempfile
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.m3-isolation-',suffix='.json',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as out:
            json.dump(data,out,indent=2,ensure_ascii=False);out.write('\n')
        os.chmod(tmp,0o600)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def _safe_summary(resp):
    try: body=resp.json()
    except ValueError:body={}
    if not isinstance(body,dict):body={}
    return {'http':resp.status_code,
            'decision':body.get('decision') if body.get('decision') in ('ALLOW','DENY') else None,
            'reason':body.get('reason') if body.get('reason') in (
                'ACTIVE_DIRECTIONAL_CONSENT','WRONG_RECIPIENT_OR_TENANT',
                'CONSENT_NOT_GRANTED_OR_REVOKED','MISSING_BEARER_TOKEN',
                'INVALID_ACCESS_TOKEN','INVALID_AUDIENCE','VERIFIED_TENANT_JWT') else None,
            'signature_verified':body.get('signature_verified') is True,
            'issuer_verified':body.get('issuer_verified') is True,
            'audience_verified':body.get('audience_verified') is True}


def _local_resource_call(req,path,payload,token=None):
    # Fixed 127.0.0.1 destination and route (no browser-controlled URLs).
    url='http://127.0.0.1:8080'+path
    headers={'Origin':os.getenv('DEMO_PUBLIC_URL','http://localhost:8180').rstrip('/'),
             'X-CIAM-Lab-Key':req.headers.get('x-ciam-lab-key','')}
    if token:headers['Authorization']='Bearer '+token
    else:
        # Local self-call only; original user cookie is forwarded to our own BFF.
        cookie=req.headers.get('cookie','')
        if len(cookie)>8192:raise HTTPException(400,'Browser cookie header too large')
        headers['Cookie']=cookie
    response=requests.post(url,json=payload,headers=headers,timeout=30,allow_redirects=False)
    return _safe_summary(response)


@router.get('/m3/isolation',response_class=HTMLResponse)
def page(req:Request):
    r=TEMPLATES.TemplateResponse('m3_isolation.html',{'request':req})
    r.headers.update({'Cache-Control':'private, no-store','X-Frame-Options':'DENY',
      'Referrer-Policy':'no-referrer',
      'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"})
    return r


@router.get('/api/m3/isolation/status')
def status(req:Request):
    identities=_identities(req)
    links=[]
    if 'magalu' in identities and 'netshoes' in identities:
        try:
            for l in _db().list_for(set(identities.values())):
                if l['source_brand'] in ('magalu','netshoes') and l['recipient_brand'] in ('magalu','netshoes'):
                    links.append({'link_id':l['link_id'],'source':l['source_brand'],
                                  'recipient':l['recipient_brand'],'state':l['state']})
        except Exception:
            # Show dependency failure as unverified, never as a PASS.
            links=[]
    subject=readiness(GENERATED/'m3-tokens'/'subject.jwt',GENERATED/'m3-tokens'/'actor.jwt')
    consent=_read(CONSENT_REPORT)
    if consent and consent.get('session_tag')!=_session_tag(identities):consent=None
    # Never show prior consent acceptance when the current grant is active again.
    if consent and consent.get('result')=='PASS':
        current=next((l for l in links if l['link_id']==consent.get('link_id')),None)
        if not current or current['state']!='REVOKED':consent=None
    pay_config=_read(PAY_READBACK)
    return _reply({'schema':'magalu-isolation-status-v1',
                   'sessions':{b:b in identities for b in BRANDS},
                   'links':links,'token_readiness':subject,
                   'consent_report':consent,
                   'token_report':_fresh(_read(TOKEN_REPORT)),
                   'fintech_control_ready':bool(pay_config and pay_config.get('verified') is True and pay_config.get('exchange_grant_readback_verified') is True),
                   'notice':'Records come from the current browser sessions and live WSO2 probes; no synthetic test outcomes.'})


@router.post('/api/m3/isolation/consent/prepare')
def prepare(req:Request):
    _guard(req)
    identities=_identities(req,('magalu','netshoes','magalupay'))
    db=_db()
    forward=db.link(('magalu',*identities['magalu']),('netshoes',*identities['netshoes']))
    reverse=db.link(('netshoes',*identities['netshoes']),('magalu',*identities['magalu']))
    return _reply({'result':'PREPARED','forward_link_id':forward,'reverse_link_id':reverse,
                   'notice':'Only link records were created. No consent has been granted.'})


@router.post('/api/m3/isolation/consent/grant')
def grant(req:Request,body:ConfirmInput):
    _guard(req)
    identities=_identities(req,('magalu','netshoes'))
    if not body.acknowledged:raise HTTPException(409,'Explicit customer consent confirmation required')
    db=_db();link=_matching(db,identities,body.link_id,'magalu','netshoes')
    event=db.change(str(link['link_id']),*identities['magalu'],'GRANTED',secrets.token_urlsafe(32))
    return _reply({'result':'GRANTED','event_id':event,
                   'note':'Explicit directional grant. No MagaluPay or reverse grant was created.'})


@router.post('/api/m3/isolation/consent/revoke')
def revoke(req:Request,body:ConfirmInput):
    _guard(req)
    identities=_identities(req,('magalu','netshoes'))
    if not body.acknowledged:raise HTTPException(409,'Explicit revocation confirmation required')
    db=_db();link=_matching(db,identities,body.link_id,'magalu','netshoes')
    event=db.change(str(link['link_id']),*identities['magalu'],'REVOKED',secrets.token_urlsafe(32))
    return _reply({'result':'REVOKED','event_id':event})


@router.post('/api/m3/isolation/resource/fintech-issuer')
def fintech_issuer_resource(req:Request):
    """Synthetic Pay resource: strict issuer and audience allowlist, no side effects."""
    _guard(req)
    raw=req.headers.get('Authorization','')
    if not raw.startswith('Bearer ') or raw.count(' ')!=1 or len(raw)>20060:
        return _reply({'decision':'DENY','reason':'MISSING_BEARER_TOKEN'},401)
    try:
        s=requests.Session()
        public,internal=_urls(os.getenv('IS_PUBLIC_URL','https://localhost:9543'),
                              os.getenv('IS_INTERNAL_URL','https://is:9543'),'magalupay.demo')
        disco,_,validation=_discovery(s,public,internal,'magalupay.demo',
                           os.getenv('IS_TLS_VERIFY','false').lower()=='true')
        claims=jwk_validate(raw[7:],validation,s,os.getenv('IS_TLS_VERIFY','false').lower()=='true')
        cc=json.loads((GENERATED/'manifest.json').read_text())['clients']['m2m:fintech:cc']
        # For the local tenant-issuer probe only, accept either of WSO2's
        # known Pay token-endpoint or dedicated client-ID audiences. This is
        # NOT a substitute for a registered resource-specific API audience.
        proof=_read(PAY_READBACK)
        if not proof or proof.get('verified') is not True or proof.get('exchange_grant_readback_verified') is not True or proof.get('tenant')!='magalupay.demo' or proof.get('client_id')!=cc['client_id'] or proof.get('audience')!=PAY_AUDIENCE:
            return _reply({'decision':'BLOCKED','reason':'RESOURCE_AUDIENCE_CONFIG_UNAVAILABLE'},503)
        if PAY_AUDIENCE not in _aud_set(claims):
            return _reply({'decision':'DENY','reason':'INVALID_AUDIENCE',
                           'signature_verified':True,'issuer_verified':True,
                           'audience_verified':False},401)
        return _reply({'decision':'ALLOW','reason':'VERIFIED_TENANT_JWT',
                       'signature_verified':True,'issuer_verified':True,
                       'audience_verified':True,'audience_mode':'DEDICATED_FINTECH_RESOURCE'},200)
    except (ValueError,KeyError,TypeError,OSError,jwt.PyJWTError,requests.RequestException):
        return _reply({'decision':'DENY','reason':'INVALID_ACCESS_TOKEN',
                       'signature_verified':False,'issuer_verified':False,
                       'audience_verified':False},401)



@router.post('/api/m3/isolation/resource/{recipient}')
def isolated_resource(req:Request,recipient:str,body:LinkInput):
    _guard(req)
    if recipient not in CONSENT_DESTS:raise HTTPException(404,'Resource not found')
    ids=_identities(req,('magalu','netshoes','magalupay'))
    source,expected=(('netshoes','magalu') if recipient=='reverse' else ('magalu','netshoes'))
    db=_db();_matching(db,ids,body.link_id,source,expected)
    actual_brand={'netshoes':'netshoes','magalupay':'magalupay','reverse':'magalu'}[recipient]
    identity=ids[actual_brand]
    protected,reason=db.shared_profile(body.link_id,*identity)
    code=200 if protected else 403
    return _reply({'decision':'ALLOW' if protected else 'DENY',
                   'reason':reason,'resource':'SYNTHETIC_PROFILE_ONLY',
                   'tenant_verified':True},code)


@router.post('/api/m3/isolation/consent/run')
def consent_run(req:Request,body:TestInput):
    _guard(req)
    identities=_identities(req,('magalu','netshoes','magalupay'))
    db=_db();forward=_matching(db,identities,body.link_id,'magalu','netshoes')
    _matching(db,identities,body.reverse_link_id,'netshoes','magalu')
    phase=forward.get('action') or 'NOT_GRANTED'
    if phase not in ('GRANTED','REVOKED'):
        return _reply({'result':'BLOCKED','detail':'First grant consent explicitly, then test.'},409)
    with LOCK:
        net=_local_resource_call(req,'/api/m3/isolation/resource/netshoes',{'link_id':body.link_id})
        pay=_local_resource_call(req,'/api/m3/isolation/resource/magalupay',{'link_id':body.link_id})
        rev=_local_resource_call(req,'/api/m3/isolation/resource/reverse',{'link_id':body.reverse_link_id})
        expected_net=200 if phase=='GRANTED' else 403
        checks={'authorized_or_revoked':net['http']==expected_net and
                net['reason']==('ACTIVE_DIRECTIONAL_CONSENT' if phase=='GRANTED' else 'CONSENT_NOT_GRANTED_OR_REVOKED'),
                'magalupay_not_inherited':pay['http']==403 and pay['reason']=='WRONG_RECIPIENT_OR_TENANT',
                'reverse_not_inherited':rev['http']==403 and rev['reason']=='CONSENT_NOT_GRANTED_OR_REVOKED'}
        run={'phase':phase,'at':datetime.now(timezone.utc).isoformat(),
             'tests':{'netshoes':net,'magalupay':pay,'reverse':rev},
             'checks':checks,'result':'PASS' if all(checks.values()) else 'FAIL'}
        old=_read(CONSENT_REPORT) or {}
        same=(old.get('link_id')==body.link_id and
              old.get('session_tag')==_session_tag(identities))
        history=(old.get('phases') or {}) if same else {}
        history[phase]=run
        result=('PASS' if all(p in history and history[p]['result']=='PASS'
                              for p in ('GRANTED','REVOKED')) else 'INCOMPLETE')
        audit=db.audit(body.link_id,set(identities.values()))
        report={'schema':'magalu-m3-cross-root-consent-v1',
                'timestamp':datetime.now(timezone.utc).isoformat(),
                'link_id':body.link_id,'session_tag':_session_tag(identities),
                'phases':history,'audit':audit,'result':result,
                'scope':'Customer-owned consent, not native WSO2 Consent Management v2'}
        _write(CONSENT_REPORT,report)
        return _reply(report)


def _aud_set(claims):
    aud=claims.get('aud')
    return {aud} if isinstance(aud,str) else set(aud) if isinstance(aud,list) and all(isinstance(x,str) for x in aud) else set()


def _oauth_summary(response):
    try:body=response.json()
    except ValueError:body={}
    if not isinstance(body,dict):body={}
    code=(body.get('error') if body.get('error') in ALLOWED_ERROR else 'unavailable')
    token=body.get('access_token')
    return {'http':response.status_code, 'token_issued':isinstance(token,str) and bool(token),
            'oauth_error_code':code if response.status_code!=200 else None},token,body


def _live_tokens(public,internal,verify,session):
    manifest=json.loads((GENERATED/'manifest.json').read_text())
    clients=manifest['clients']
    cc=clients['m2m:fintech:cc']
    commerce=clients['m2m:commerce:exchange']
    fintech=clients['m2m:fintech:exchange']
    if not (cc.get('tenant_domain')=='magalupay.demo' and
            commerce.get('tenant_domain')=='magalu.demo' and
            fintech.get('tenant_domain')=='magalupay.demo'):
        raise ValueError('Manifest exchange client root binding invalid')
    if not all(x.get('client_id') and x.get('client_secret') for x in (cc,commerce,fintech)):
        raise ValueError('Local test clients need real WSO2 credentials')
    commerce_d,commerce_ep,commerce_j=_discovery(session,public,internal,'magalu.demo',verify)
    pay_d,pay_ep,pay_j=_discovery(session,public,internal,'magalupay.demo',verify)
    if commerce_d['issuer']==pay_d['issuer']:
        raise ValueError('Distinct root tenants must have distinct issuers')
    ana=read_private(GENERATED/'m3-tokens/subject.jwt')
    bruno=read_private(GENERATED/'m3-tokens/actor.jwt')
    ac=jwk_validate(ana,commerce_j,session,verify)
    bc=jwk_validate(bruno,commerce_j,session,verify)
    if ac['sub']==bc['sub'] or 'requests:read' not in token_scopes(ac):
        raise ValueError('Commerce test identities or scopes are invalid')
    if min(ac['exp'],bc['exp'])-datetime.now(timezone.utc).timestamp()<90:
        raise ValueError('Recapture Ana and Bruno JWTs: less than 90 seconds remain')
    return locals()


def _exchange(session,endpoint,client,subject,actor=None,audience=None):
    data={'grant_type':EXCHANGE,'subject_token':subject,
          'subject_token_type':TOKEN_TYPE,'requested_token_type':ACCESS_TYPE}
    if actor is not None:
        data.update(actor_token=actor,actor_token_type=TOKEN_TYPE)
    if audience is not None:data.update(audience=audience,scope='requests:read')
    response=session.post(endpoint,data=data,
                          auth=(client['client_id'],client['client_secret']),
                          verify=os.getenv('IS_TLS_VERIFY','false').lower()=='true',timeout=25)
    return _oauth_summary(response)


@router.post('/api/m3/isolation/token/run')
def token_run(req:Request):
    _guard(req)
    if not LOCK.acquire(blocking=False):
        return _reply({'result':'BUSY','detail':'Another isolation test is running'},409)
    try:
        verify=os.getenv('IS_TLS_VERIFY','false').lower()=='true'
        s=requests.Session()
        public,internal=_urls(os.getenv('IS_PUBLIC_URL','https://localhost:9543'),
                              os.getenv('IS_INTERNAL_URL','https://is:9543'),'magalu.demo')
        ctx=_live_tokens(public,internal,verify,s)
        ac,bc=ctx['ac'],ctx['bc']
        ana,bruno=ctx['ana'],ctx['bruno']
        cc,com,pay=ctx['cc'],ctx['commerce'],ctx['fintech']
        pay_proof=_read(PAY_READBACK)
        if not pay_proof or pay_proof.get('verified') is not True or pay_proof.get('exchange_grant_readback_verified') is not True or pay_proof.get('tenant')!='magalupay.demo' or pay_proof.get('client_id')!=cc['client_id'] or pay_proof.get('audience')!=PAY_AUDIENCE:
            return _reply({'result':'BLOCKED','detail':'Run scripts/prepare-m3-fintech-control.sh first'},409)
        # CONTROL 1: same-tenant delegated RFC8693 flow must succeed FIRST.
        target=resource_audience_config()
        if target['mode']!='DEDICATED_RESOURCE' or not target['management_api_readback_verified']:
            return _reply({'result':'BLOCKED','detail':'First register and verify the Commerce resource audience'},409)
        outcome,issued,reply=_exchange(s,ctx['commerce_ep'],com,ana,bruno,target['value'])
        baseline=False
        try:
            if outcome['http']==200 and issued and reply.get('issued_token_type')==ACCESS_TYPE:
                dec=jwk_validate(issued,ctx['commerce_j'],s,verify)
                baseline=(dec['sub']==ac['sub'] and
                          isinstance(dec.get('act'),dict) and dec['act'].get('sub')==bc['sub'] and
                          token_scopes(dec)=={'requests:read'} and target['value'] in _aud_set(dec))
        except (ValueError,KeyError,TypeError,jwt.PyJWTError,requests.RequestException):
            baseline=False
        control_commerce={'http':outcome['http'],'jwt_verified':baseline,
                          'actor_preserved':baseline,'audience_verified':baseline,
                          'result':'PASS' if baseline else 'BLOCKED'}
        # CONTROL 2: prove MagaluPay's own OAuth endpoint and signing path work.
        ccresp=s.post(ctx['pay_ep'],data={'grant_type':'client_credentials'},
                      auth=(cc['client_id'],cc['client_secret']),verify=verify,timeout=25)
        ccout,cctoken,ccbody=_oauth_summary(ccresp)
        fintech_verified=False
        if ccout['http']==200 and cctoken:
            try:
                ccclaims=jwk_validate(cctoken,ctx['pay_j'],s,verify)
                fintech_verified=(ccclaims['iss']==ctx['pay_d']['issuer'] and
                                  PAY_AUDIENCE in _aud_set(ccclaims))
            except (ValueError,KeyError,TypeError,jwt.PyJWTError,requests.RequestException):pass
        control_pay={'http':ccout['http'],'jwt_verified':fintech_verified,
                     'result':'PASS' if fintech_verified else 'BLOCKED'}
        pay_positive={'http':None};commerce_negative={'http':None}
        if fintech_verified:
            pay_positive=_local_resource_call(req,'/api/m3/isolation/resource/fintech-issuer',{},cctoken)
            commerce_negative=_local_resource_call(req,'/api/m3/isolation/resource/fintech-issuer',{},ana)
        positive_api=(pay_positive.get('http')==200 and pay_positive.get('decision')=='ALLOW' and
                      pay_positive.get('issuer_verified') and pay_positive.get('audience_verified'))
        negative_api=(commerce_negative.get('http')==401 and commerce_negative.get('decision')=='DENY'
                      and commerce_negative.get('signature_verified') is False)
        # CROSS-ROOT NEGATIVES: only run if both controls are healthy; otherwise
        # error responses can be unrelated to trust isolation.
        cross_subject={'http':None,'token_issued':False,'result':'BLOCKED'}
        cross_actor={'http':None,'token_issued':False,'result':'BLOCKED'}
        if baseline and fintech_verified and positive_api and negative_api:
            sub_out,_,_=_exchange(s,ctx['pay_ep'],pay,ana)
            act_out,_,_=_exchange(s,ctx['pay_ep'],pay,ana,bruno)
            for src,raw in ((cross_subject,sub_out),(cross_actor,act_out)):
                src.update(raw)
                # Any HTTP 200 or token issuance is NOT accepted as safe isolation.
                src['result']=('PASS' if 400<=raw['http']<500 and
                               not raw['token_issued'] and
                               raw.get('oauth_error_code') in ('invalid_grant','invalid_request','access_denied')
                               else 'FAIL')
        checks={'commerce_positive_control':baseline,
                'fintech_positive_control':fintech_verified and positive_api,
                'fintech_resource_rejects_commerce_issuer':negative_api,
                'cross_root_subject_exchange_rejected':cross_subject['result']=='PASS',
                'cross_root_actor_exchange_rejected':cross_actor['result']=='PASS'}
        report={'schema':'magalu-m3-cross-root-tokens-v1',
                'timestamp':datetime.now(timezone.utc).isoformat(),
                'root_tenants':['magalu.demo','magalupay.demo'],
                'fintech_resource_audience':PAY_AUDIENCE,
                'checks':checks,
                'controls':{'commerce_delegation':control_commerce,
                            'magalupay_token_issuance':control_pay,
                            'magalupay_resource_with_own_token':pay_positive,
                            'magalupay_resource_with_commerce_token':commerce_negative},
                'cross_root_exchanges':{'subject_only':cross_subject,'subject_and_actor':cross_actor},
                'result':'PASS' if all(checks.values()) else 'BLOCKED' if not baseline or not fintech_verified
                    else 'FAIL',
                'notes':['Root-specific WSO2 endpoints and actual credentials used; no tokens/secrets exported.',
                         'Fintech resource is an isolated synthetic issuer/audience probe, not a business API.',
                         'No automatic trusted issuer or federation relationship is provisioned.']}
        _write(TOKEN_REPORT,report)
        return _reply(report)
    except (OSError,ValueError,TypeError,KeyError,jwt.PyJWTError,requests.RequestException) as e:
        # No exception messages: WSO2/HTTP may embed bearer secrets.
        return _reply({'result':'BLOCKED','error_type':type(e).__name__,
                       'detail':'Missing, expired or incompatible tokens; inspect local server logs without bearer values.'},409)
    finally:
        LOCK.release()


@router.get('/api/m3/isolation/evidence')
def evidence(req:Request):
    # Evidence excludes tokens, client secrets and exact user identifiers.
    identities=_identities(req)
    consent=_read(CONSENT_REPORT)
    if consent and consent.get('session_tag')!=_session_tag(identities):consent=None
    tok=_fresh(_read(TOKEN_REPORT))
    if consent and consent.get('result')=='PASS':
        try:
            links=_db().list_for(set(identities.values()))
            current=next((l for l in links if l.get('link_id')==consent.get('link_id')),None)
            if not current or current.get('state')!='REVOKED':consent=None
        except Exception:consent=None
    complete=consent and consent.get('result')=='PASS' and tok and tok.get('result')=='PASS'
    report={'schema':'magalu-m3-isolation-acceptance-v1',
            'exported_at':datetime.now(timezone.utc).isoformat(),
            'result':'PASS' if complete else 'INCOMPLETE',
            'cross_root_consent':consent,
            'cross_root_token_exchange':tok,
            'limitation':'Does not certify WSO2-native Consent Management v2 synchronization or cross-tenant federation.'}
    r=_reply(report)
    r.headers['Content-Disposition']='attachment; filename="magalu-m3-tenant-isolation-evidence.json"'
    return r
