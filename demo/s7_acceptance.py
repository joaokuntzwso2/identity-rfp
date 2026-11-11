"""Section 7.2 acceptance cockpit. Only real WSO2 BFF sessions and native API readbacks.

Every operator API uses the existing local-only, same-origin DEMO_OPERATOR_KEY guard.
Never returns tokens, secrets, biometrics, personal attributes, or full subjects.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import os, secrets, uuid
import requests
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from demo.m3_isolation import _guard
from demo.s7_policy import claims_result,compare_four,derived_identity_level,safe_hash
from demo.s7_assurance import (start,retrieve,record_aal2,verify_provider_assertion,
                               decision,verify_n2_assertion,VerificationRejected,NotConfigured)

router=APIRouter()
TEMPLATES=Jinja2Templates(directory=str(Path(__file__).parent/'templates'))
STORES={('magalu','web'):8181,('magalu','app'):8182,
        ('netshoes','web'):8183,('netshoes','app'):8184,
        ('magalupay','web'):8185,('magalupay','app'):8186}

class PairwiseProof(BaseModel):
    same_person_attested:bool=False
class ConsentProof(BaseModel):
    link_id:str=Field(pattern=r'^[0-9a-fA-F-]{36}$')
class TransactionStart(BaseModel):
    risk_score:int=Field(ge=0,le=100)
    unknown_device:bool=False
    operation:str='fintech-transfer'
class TransactionRef(BaseModel):
    tx:str=Field(pattern=r'^[0-9a-fA-F-]{36}$')
class IdentityAssertion(TransactionRef):
    signed_provider_jwt:str=Field(min_length=50,max_length=12000)

def _reply(data,status=200):
    r=JSONResponse(data,status_code=status)
    r.headers.update({'Cache-Control':'no-store, private','Pragma':'no-cache',
                     'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'})
    return r

def _evidence(req:Request,brand:str,channel:str):
    port=STORES[(brand,channel)]
    cookie=f'magalu_{brand}_{channel}_sid'
    val=req.cookies.get(cookie,'')
    if not val or len(val)>2048 or any(x in val for x in '\n\r;'):
        return None
    try:
        r=requests.get(f'http://store-{brand}-{channel}:8080/api/s7/evidence',
                       headers={'Cookie':f'{cookie}={val}'},timeout=3,allow_redirects=False)
        if r.status_code!=200:return None
        data=r.json()
        if (data.get('brand')!=brand or data.get('channel')!=channel or
            data.get('tenant')!=('magalupay.demo' if brand=='magalupay' else 'magalu.demo') or
            data.get('verified_id_token') is not True):return None
        return data
    except (requests.RequestException,ValueError,AttributeError):
        return None

@router.get('/m3/section7',response_class=HTMLResponse)
def page(req:Request):
    r=TEMPLATES.TemplateResponse('m3_section7.html',{'request':req})
    r.headers.update({'Cache-Control':'no-store, private',
                      'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'",
                      'X-Frame-Options':'DENY'})
    return r

@router.post('/api/m3/s7/pairwise')
def pairwise(req:Request,body:PairwiseProof):
    _guard(req)
    from demo.main import storefront_subject_matrix
    rows=storefront_subject_matrix(req.cookies,requests.get)
    return _reply(compare_four(rows,operator_same_person=body.same_person_attested))

@router.post('/api/m3/s7/claims')
def claims(req:Request):
    _guard(req)
    rows=[]
    for brand,channel in (('magalu','web'),('magalu','app')):
        item=_evidence(req,brand,channel)
        if not item:
            rows.append({'client':f'{brand}:{channel}','result':'INCOMPLETE',
                         'reason':'FRESH_VERIFIED_OIDC_SESSION_REQUIRED'})
            continue
        outcome=claims_result(f'{brand}:{channel}',
                              item.get('id_token_claim_names',[]),
                              item.get('userinfo_claim_names',[]))
        outcome['verified_id_token']=True
        outcome['userinfo_observed']=item.get('userinfo_observed') is True
        outcome['token_fingerprint']=item.get('token_fingerprint')
        outcome['subject_fingerprint']=safe_hash(item.get('sub',''))
        if not outcome['userinfo_observed']:outcome['result']='INCOMPLETE'
        rows.append(outcome)
    if any(r['result']=='FAIL' for r in rows):status='FAIL'
    elif len(rows)==2 and all(r['result']=='PASS' for r in rows) and \
            rows[0].get('subject_fingerprint')==rows[1].get('subject_fingerprint'):
        web=rows[0]; app=rows[1]
        # A pair of empty responses is not evidence of client-specific disclosure.
        observed_web=set(web.get('id_token_pii',[])) | set(web.get('userinfo_pii',[]))
        observed_app=set(app.get('id_token_pii',[])) | set(app.get('userinfo_pii',[]))
        status='PASS_OBSERVED' if observed_web and observed_web != observed_app else 'INCOMPLETE'
    else:status='INCOMPLETE'
    return _reply({'result':status,'clients':rows,
       'expected_different_allowlists':True,
       'native_disclosure_observation': 'OBSERVED_FROM_VERIFIED_ID_TOKEN_AND_USERINFO',
       'wso2_native_claim_allowlists_verified':False,
       'next':'Configure each WSO2 app User Attributes/Scopes, then compare fresh ID token and UserInfo payloads.'})

@router.post('/api/m3/s7/consent')
def consent(req:Request,body:ConsentProof):
    _guard(req)
    from demo.m3_native_lab import _check_link,_mirror_for,_native_status,_mirror_identity,_map,_api
    from demo.m3_native_service import NativeProblem
    _,_,link=_check_link(req,body.link_id)
    info=_mirror_for(body.link_id,link)
    try:
        native_ok,native_reason,_=_native_status(info)
        try:
            _api('fintech').consent(info['native_id'])
            fintech='CROSS_TENANT_RECORD_ACCESSIBLE'
        except NativeProblem as e:
            fintech='NOT_FOUND' if e.code=='NATIVE_NOT_FOUND' else 'BLOCKED_'+e.code
    except NativeProblem as e:
        return _reply({'result':'BLOCKED','reason':e.code},503)
    events=_map()['events']
    own=[{'event':e['stage'],'at':e.get('at'),'reason':e.get('reason') or e.get('native_reason'),
          'custom_revoked':e.get('custom_revoked') if e.get('stage')=='RECONCILE' else None}
         for e in events if e.get('link_hash')==_mirror_identity(link)[:16]]
    seen={item['event'] for item in own}
    has_allow=any(e.get('event')=='ALLOW' and e.get('reason')=='BOTH_CONSENTS_ACTIVE' for e in own)
    has_native_revoke='NATIVE_REVOKED' in seen
    has_native_denial=any(e.get('event')=='DENY' and e.get('reason')=='NATIVE_REVOKED' for e in own)
    has_reconcile=any(e.get('event')=='RECONCILE' and e.get('custom_revoked') is True for e in own)
    full=(has_allow and has_native_revoke and has_native_denial and has_reconcile and
          native_reason=='NATIVE_REVOKED' and link.get('action')=='REVOKED' and fintech=='NOT_FOUND')
    return _reply({'result':'PASS_OBSERVED' if full else 'INCOMPLETE',
       'native_active':native_ok,'native_reason':native_reason,
       'custom_state':link.get('action') or 'NOT_GRANTED',
       'fintech_native_record_readback':fintech,
       'tenant_boundary':{'source_root':'magalu.demo','other_root':'magalupay.demo'},
       'allowed_observed':has_allow,'native_revoke_readback_event':has_native_revoke,
       'denial_due_to_native_revoke':has_native_denial,'reconcile_event':has_reconcile,
       'audit_events':own[-24:],
       'scope':'CUSTOM_DIRECTIONAL_LEDGER_PLUS_NATIVE_ADMIN_MIRROR',
       'limitation':'Self-service application consent in My Account is a separate flow.'})

def _pay(req):
    result=_evidence(req,'magalupay','web')
    if not result:raise HTTPException(409,'Log into MagaluPay Web first (8185), then reload')
    return result

def _check_tx(req,tx):
    pay=_pay(req)
    try:row=retrieve(tx,pay['issuer'],pay['sub'])
    except VerificationRejected as e:raise HTTPException(409,str(e)) from None
    return pay,row

@router.post('/api/m3/s7/transaction/start')
def transaction_start(req:Request,body:TransactionStart):
    _guard(req)
    if body.operation!='fintech-transfer':raise HTTPException(400,'Unsupported operation')
    pay=_pay(req)
    if body.risk_score < 65 and not body.unknown_device:
        raise HTTPException(409,'Risk policy did not trigger step-up; choose risk score >=65 or unknown device. Low-risk authorization requires separate N2 acceptance.')
    tx=str(uuid.uuid4());nonce=secrets.token_urlsafe(36)
    start(tx,pay['issuer'],pay['sub'],nonce,body.risk_score,body.unknown_device)
    return _reply({'result':'CHALLENGE','tx':tx,'preserved_operation':body.operation,
        'risk_score':body.risk_score,'unknown_device':body.unknown_device,
        'required_authentication':'WSO2_FRESH_TOTP_AAL2',
        'required_identity':'EXTERNAL_FACE_LIVENESS_N3',
        'aal2_start_url':'http://localhost:8185/s7/stepup?tx='+tx,
        'identity_verification_provider':'CONFIGURE_EXTERNAL_PROVIDER',
        'provider_nonce_for_trusted_bridge':nonce,
        'subject_ref_for_trusted_bridge':safe_hash(pay['issuer']+'|'+pay['sub']),
        'notice':'Bridge must bind the vendor session to this WSO2-authenticated customer. Never send raw biometric data to this lab.'})

@router.post('/api/m3/s7/transaction/aal2')
def transaction_aal2(req:Request,body:TransactionRef):
    _guard(req)
    pay,_=_check_tx(req,body.tx)
    try:result=record_aal2(body.tx,pay['issuer'],pay['sub'],pay)
    except VerificationRejected as e:raise HTTPException(409,str(e)) from None
    return _reply(result)

@router.post('/api/m3/s7/transaction/n2')
def n2(req:Request,body:IdentityAssertion):
    _guard(req)
    pay,_=_check_tx(req,body.tx)
    try:r=verify_n2_assertion(body.tx,pay['issuer'],pay['sub'],body.signed_provider_jwt)
    except NotConfigured as e:raise HTTPException(503,str(e)) from None
    except VerificationRejected as e:raise HTTPException(409,str(e)) from None
    return _reply(r)

@router.post('/api/m3/s7/transaction/provider')
def provider(req:Request,body:IdentityAssertion):
    _guard(req)
    pay,_=_check_tx(req,body.tx)
    try:r=verify_provider_assertion(body.tx,pay['issuer'],pay['sub'],body.signed_provider_jwt)
    except NotConfigured as e:raise HTTPException(503,str(e)) from None
    except VerificationRejected as e:raise HTTPException(409,str(e)) from None
    return _reply(r)

@router.post('/api/m3/s7/transaction/decision')
def transaction_decision(req:Request,body:TransactionRef):
    _guard(req)
    pay,_=_check_tx(req,body.tx)
    return _reply(decision(body.tx,pay['issuer'],pay['sub']))
