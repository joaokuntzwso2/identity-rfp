"""Native Consent & Compliance lab. Every protected read checks BOTH live stores.

WSO2 CM v2 is the native record, PostgreSQL is the directional business grant.
This operator-only PoC never assumes the two models are automatically synced.
"""
from __future__ import annotations

from datetime import datetime,timezone
from pathlib import Path
import hashlib
import json
import os
import secrets
import threading
import uuid

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from demo.m3_native_service import (NativeAPI, NativeProblem, TENANTS, SERVICE_ID,
                                     allowed_native_consent, dual_decision, private_json, write_private)
from demo.m3_isolation import _guard, _identities, _db, _matching
from demo.m3_exchange_engine import _discovery
from scripts.m3_token_exchange_verify import jwk_validate, read_private

router=APIRouter()
TEMPLATES=Jinja2Templates(directory=str(Path(__file__).parent/'templates'))
GEN=Path(os.getenv('MANIFEST_FILE','/project/generated/manifest.json')).parent
MAP=GEN/'m3-native-consent-links.json'
EVIDENCE=GEN/'m3-native-consent-evidence.json'
LOCK=threading.RLock()


class LinkInput(BaseModel):
    link_id:str=Field(min_length=36,max_length=36)

class ExplicitGrant(LinkInput):
    confirmed:bool=False
    subject_attestation:bool=False

class ConfirmRevoke(LinkInput):
    confirmed:bool=False


def _now():return datetime.now(timezone.utc).isoformat()


def _reply(value,http=200):
    resp=JSONResponse(value,status_code=http)
    resp.headers.update({'Cache-Control':'private, no-store','Pragma':'no-cache',
                         'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'})
    return resp


def _api(root='commerce'):
    return NativeAPI(root,private_json(GEN/'m3-native-clients.json'))


def _catalog():
    raw=private_json(GEN/'m3-native-catalog.json')
    if raw.get('tenant')!='magalu.demo' or not raw.get('purpose_id') or not raw.get('element_id'):
        raise NativeProblem('NATIVE_CATALOG_UNVERIFIED')
    return raw


def _map():
    if not MAP.is_file():return {'schema':'magalu-m3-native-mirror-v1','links':{},'events':[]}
    result=private_json(MAP)
    if result.get('schema')!='magalu-m3-native-mirror-v1':raise NativeProblem('NATIVE_MIRROR_INVALID')
    return result


def _check_link(req,link_id):
    identities=_identities(req,('magalu','netshoes'))
    db=_db()
    link=_matching(db,identities,link_id,'magalu','netshoes')
    return db,identities,link


def _principal_public_subject():
    """Captured, signature-verified Ana SCIM identity — NEVER a pairwise BFF sub."""
    manifest=json.loads((GEN/'manifest.json').read_text())
    # The manifest has passwords; access only known SCIM identifier, never expose manifest to browser.
    subject_id=manifest['users']['commerce:ana.magalu']['id']
    if not isinstance(subject_id,str) or len(subject_id)>128:raise NativeProblem('SCIM_ID_INVALID')
    verify=os.getenv('IS_TLS_VERIFY','false').lower()=='true'
    public=os.getenv('IS_PUBLIC_URL','https://localhost:9543')
    internal=os.getenv('IS_INTERNAL_URL','https://is:9543')
    session=requests.Session()
    disco,_,verification_disco=_discovery(session,public,internal,'magalu.demo',verify)
    value=read_private(GEN/'m3-tokens'/'subject.jwt')
    signed=jwk_validate(value,verification_disco,session,verify)
    if signed.get('sub')!=subject_id:
        raise NativeProblem('CAPTURED_ANA_SUBJECT_NOT_SCIM_ID',409)
    return subject_id


def _mirror_identity(link):
    return hashlib.sha256((str(link['link_id'])+'|'+link['source_tenant']+'|'+link['source_sub']).encode()).hexdigest()


def _mirror_for(link_id,link):
    info=_map()['links'].get(str(link_id))
    if not info or info.get('tenant')!='magalu.demo' or info.get('link_binding')!=_mirror_identity(link):
        raise NativeProblem('NO_VERIFIED_NATIVE_MIRROR',403)
    return info


def _native_status(info):
    native=_api('commerce')
    try:
        value=native.consent(info['native_id'])
    except NativeProblem as exc:
        if exc.code=='NATIVE_NOT_FOUND':
            return False,'NATIVE_NOT_FOUND',{}
        raise
    ok,reason=allowed_native_consent(value,subject_id=info['subject_id'],
         purpose_id=info['purpose_id'],service_id=SERVICE_ID)
    if not ok and isinstance(value,dict) and str(value.get('state','')).upper()=='REVOKED':
        reason='NATIVE_REVOKED'
    return ok,reason,value


def _event(stage,fields):
    with LOCK:
        d=_map()
        d['events'].append({'stage':stage,'at':_now(),**fields})
        d['events']=d['events'][-120:]
        write_private(MAP,d)


def _record_report(report):
    write_private(EVIDENCE,{'schema':'magalu-m3-native-acceptance-v1',
         'reported_at':_now(),**report})


@router.get('/m3/native-consent',response_class=HTMLResponse)
def page(req:Request):
    resp=TEMPLATES.TemplateResponse('m3_native_consent.html',{'request':req})
    resp.headers.update({'Cache-Control':'no-store, private','X-Frame-Options':'DENY',
         'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'"})
    return resp


@router.get('/api/m3/native/status')
def status(req:Request):
    identities=_identities(req)
    links=[]
    if 'magalu' in identities and 'netshoes' in identities:
        for item in _db().list_for(set(identities.values())):
            if (item['source_brand'],item['recipient_brand'])==('magalu','netshoes'):
                links.append({'link_id':item['link_id'],'state':item['state']})
    result={'schema':'magalu-m3-native-status-v1',
        'sessions':{b:b in identities for b in ('magalu','netshoes','magalupay')},
        'links':links,'native_configured':(GEN/'m3-native-clients.json').exists() and
                                      (GEN/'m3-native-catalog.json').exists(),
        'native_mirror_exists':bool(_map()['links']),
        'result':'PENDING_LIVE_VERIFICATION'}
    return _reply(result)


@router.post('/api/m3/native/preflight')
def preflight(req:Request):
    _guard(req)
    result={}
    for root in TENANTS:
        try:
            cat=_api(root).catalog()
            result[root]={'http':200,'native_v2_catalog_reachable':True,
                          'response_type_valid':all(isinstance(v,(list,dict)) for v in cat.values())}
        except NativeProblem as exc:
            result[root]={'native_v2_catalog_reachable':False,'error':exc.code}
    catalog_ok=False
    try:catalog_ok=bool(_catalog().get('purpose_id'))
    except NativeProblem:pass
    value={'schema':'magalu-m3-native-preflight-v1',
           'tenants':result,'registered_purpose_readback':catalog_ok,
           'result':'PASS' if all(r.get('native_v2_catalog_reachable') for r in result.values()) and catalog_ok else 'BLOCKED'}
    if value['result']=='PASS':_event('PREFLIGHT_VERIFIED',{'both_tenants':True})
    _record_report({'preflight':value,'result':'INCOMPLETE'})
    return _reply(value)


@router.post('/api/m3/native/mirror-grant')
def mirror_grant(req:Request,body:ExplicitGrant):
    _guard(req)
    if not body.confirmed or not body.subject_attestation:
        raise HTTPException(409,'Explicit user consent and synthetic-user subject attestation required')
    db,identities,link=_check_link(req,body.link_id)
    if link.get('action')!='GRANTED':
        raise HTTPException(403,'The directional customer-owned consent must be GRANTED first')
    subject_id=_principal_public_subject()
    cat=_catalog()
    with LOCK:
        existing=_map()['links'].get(body.link_id)
        if existing:
            ok,reason,_=_native_status(existing)
            if not ok:raise HTTPException(409,'Existing native record is not ACTIVE: '+reason+'; do not silently recreate it')
            return _reply({'result':'NATIVE_CONSENT_ALREADY_PRESENT','native_readback':True,
                           'subject_binding':'PUBLIC_SCIM_ID_VERIFIED_WITH_JWT'})
        cid=_api('commerce').create(subject_id,cat['purpose_id'],cat['element_id'],body.link_id)
        entry={'native_id':cid,'tenant':'magalu.demo','subject_id':subject_id,
               'purpose_id':cat['purpose_id'],'link_binding':_mirror_identity(link),'created_at':_now(),
               'origin':'ADMIN_API_MIRROR_OF_EXPLICIT_CUSTOM_GRANT'}
        # Save even when readback fails so retry cannot create duplicate native records.
        state=_map();state['links'][body.link_id]=entry
        state['events'].append({'stage':'NATIVE_CREATED','at':_now(),
                                'link_hash':entry['link_binding'][:16]})
        write_private(MAP,state)
        ok,reason,_=_native_status(entry)
        if not ok:
            raise HTTPException(409,'WSO2 native consent failed readback: '+reason)
    return _reply({'result':'NATIVE_CONSENT_CREATED_AND_READBACK_VERIFIED',
                   'native_active':True,'origin':'ADMIN_API_MIRROR','purpose_verified':True})


@router.post('/api/m3/native/protected-read')
def protected_read(req:Request,body:LinkInput):
    _guard(req)
    db,identities,link=_check_link(req,body.link_id)
    try:
        info=_mirror_for(body.link_id,link)
        native_ok,native_reason,_=_native_status(info)
    except NativeProblem as exc:
        _event('DENY',{'reason':exc.code,'link_hash':_mirror_identity(link)[:16]})
        return _reply({'http':503,'decision':'DENY','reason':exc.code,
                       'native_verified':False,'custom_verified':False},503)
    permitted,reason=dual_decision(link.get('action'),native_ok,native_reason)
    if not permitted:
        _event('DENY',{'reason':reason,'link_hash':_mirror_identity(link)[:16]})
        return _reply({'http':403,'decision':'DENY','reason':reason,
            'native_verified':True,'custom_verified':True},403)
    recipient_tenant,recipient_sub=identities['netshoes']
    data,custom_reason=db.shared_profile(body.link_id,recipient_tenant,recipient_sub)
    if data is None:
        _event('DENY',{'reason':custom_reason,'link_hash':_mirror_identity(link)[:16]})
        return _reply({'http':403,'decision':'DENY','reason':custom_reason},403)
    _event('ALLOW',{'reason':'BOTH_CONSENTS_ACTIVE','link_hash':_mirror_identity(link)[:16]})
    return _reply({'http':200,'decision':'ALLOW','reason':'BOTH_CONSENTS_ACTIVE',
          'native_verified':True,'custom_verified':True,
          'protected_profile':data})


@router.post('/api/m3/native/reconcile')
def reconcile(req:Request,body:LinkInput):
    _guard(req)
    db,identities,link=_check_link(req,body.link_id)
    info=_mirror_for(body.link_id,link)
    native_ok,reason,_=_native_status(info)
    before=link.get('action') or 'NOT_GRANTED'
    changed=False
    if not native_ok and before=='GRANTED':
        source_tenant,source_sub=identities['magalu']
        db.change(body.link_id,source_tenant,source_sub,'REVOKED',
            'native-reconcile-'+str(uuid.uuid4()))
        changed=True
    _event('RECONCILE',{'native_reason':reason,'custom_revoked':changed,
                         'link_hash':_mirror_identity(link)[:16]})
    result={'result':'RECONCILED' if not native_ok else 'IN_SYNC_IF_CUSTOM_ACTIVE',
        'native_active':native_ok,'native_reason':reason,
        'custom_before':before,'custom_revoked':changed,
        'never_restores_permission_automatically':True}
    _record_report({'reconciliation':result,'result':'INCOMPLETE'})
    return _reply(result)


@router.post('/api/m3/native/native-revoke')
def native_revoke(req:Request,body:ConfirmRevoke):
    _guard(req)
    if not body.confirmed:raise HTTPException(409,'Native revoke requires explicit confirmation')
    _,_,link=_check_link(req,body.link_id)
    info=_mirror_for(body.link_id,link)
    try:_api('commerce').revoke(info['native_id'])
    except NativeProblem as exc:
        return _reply({'result':'BLOCKED','reason':exc.code,
                       'notice':'Verify the exact WSO2 7.3.0.18 native revoke API contract before further action.'},409)
    ok,reason,_=_native_status(info)
    if ok or reason != 'NATIVE_REVOKED':
        return _reply({'result':'BLOCKED','reason':reason,
                       'notice':'Native revocation not independently verified as state REVOKED.'},409)
    _event('NATIVE_REVOKED',{'native_reason':reason,'link_hash':_mirror_identity(link)[:16]})
    return _reply({'result':'NATIVE_NO_LONGER_ACTIVE','readback_confirmed':True,
                   'native_reason':reason,'notice':'Confirm whether this is native REVOKED or record deletion.'})


@router.post('/api/m3/native/acceptance')
def acceptance(req:Request,body:LinkInput):
    _guard(req)
    _,_,link=_check_link(req,body.link_id)
    info=_mirror_for(body.link_id,link)
    ok,reason,_=_native_status(info)
    history=_map()['events']
    h=_mirror_identity(link)[:16]
    matching=[e for e in history if e.get('link_hash')==h]
    allowed=any(e.get('stage')=='ALLOW' and e.get('reason')=='BOTH_CONSENTS_ACTIVE' for e in matching)
    denied=any(e.get('stage')=='DENY' and e.get('reason') == 'NATIVE_REVOKED' for e in matching)
    native_revoke=any(e.get('stage')=='NATIVE_REVOKED' for e in matching)
    reconciled=any(e.get('stage')=='RECONCILE' and e.get('custom_revoked') for e in matching)
    preflight_ok=any(e.get('stage')=='PREFLIGHT_VERIFIED' and e.get('both_tenants') for e in history)
    consent_states=[e.get('stage') for e in matching]
    full=(allowed and denied and native_revoke and reconciled and preflight_ok and
          link.get('action')=='REVOKED' and not ok and reason=='NATIVE_REVOKED')
    result={'schema':'magalu-m3-native-acceptance-v1','tenant':'magalu.demo',
        'native_api_readback':True,'native_active_now':ok,'native_reason':reason,
        'custom_consent_state':link.get('action') or 'NOT_GRANTED',
        'native_admin_mirror_created':'NATIVE_CREATED' in consent_states,
        'dual_gate_allowed_observed':allowed,'post_native_revoke_denied_observed':denied,
        'native_revoke_readback_observed':native_revoke,
        'custom_revocation_reconciled':reconciled and link.get('action')=='REVOKED',
        'both_root_native_api_preflight_verified':preflight_ok,
        'result':'PASS' if full else 'INCOMPLETE',
        'scope':'ADMIN_API_NATIVE_MIRROR_PLUS_CUSTOM_RESOURCE_GATE',
        'limitations':['Not proof of end-user self-service consent on an OIDC application',
                       'No event-webhook synchronization; resource checks native on each call',
                       'Business user identity matched by operator attestation plus signed public-sub JWT']}
    _record_report(result)
    return _reply(result)


@router.post('/api/m3/native/evidence')
def evidence(req:Request):
    _guard(req)
    try:value=private_json(EVIDENCE)
    except NativeProblem:value={'result':'NOT_RUN'}
    return _reply(value)
