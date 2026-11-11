"""Operator-controlled, read-only RFC 8693 demonstration routes for port 8180.

Secrets and JWTs remain on the server. Only preconfigured local WSO2 is contacted.
"""
from __future__ import annotations

import hmac
import json
import os
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from demo.m3_exchange_engine import readiness, run_diagnostic
from demo.m3_resource_api import router as resource_router, resource_audience_config

router=APIRouter()
router.include_router(resource_router)
TEMPLATES=Jinja2Templates(directory=str(Path(__file__).parent/'templates'))
GENERATED=Path(os.getenv('MANIFEST_FILE','generated/manifest.json')).parent
SUBJECT=GENERATED/'m3-tokens'/'subject.jwt'
ACTOR=GENERATED/'m3-tokens'/'actor.jwt'
REPORT=GENERATED/'m3-exchange-lab-report.json'
LOCK=threading.Lock()


class RunRequest(BaseModel):
    audience: str | None = Field(default=None,max_length=160)


def _respond(data,status=200):
    r=JSONResponse(data,status_code=status)
    r.headers['Cache-Control']='no-store, private'
    r.headers['Pragma']='no-cache'
    r.headers['X-Content-Type-Options']='nosniff'
    return r


def _latest():
    if REPORT.exists():
        try:
            if REPORT.stat().st_size > 48_000:
                return None
            data=json.loads(REPORT.read_text())
            if data.get('schema')=='magalu-rfc8693-story-v1':
                return data
        except (OSError,ValueError,TypeError):
            pass
    return None


def _operator_check(request: Request):
    key=os.getenv('DEMO_OPERATOR_KEY','')
    if not key or key.startswith('CHANGE_') or len(key)<24:
        raise HTTPException(503,'Local operator key is not configured')
    supplied=request.headers.get('x-ciam-lab-key','')
    if not hmac.compare_digest(key,supplied):
        raise HTTPException(403,'Operator authorization required')
    # Require an actual same-origin browser invocation as well as operator authentication.
    public=os.getenv('DEMO_PUBLIC_URL','http://localhost:8180').rstrip('/')
    origin=request.headers.get('origin','')
    if origin != public or not public.startswith(('http://localhost:','http://127.0.0.1:')):
        raise HTTPException(403,'Same-origin local lab browser required')


@router.get('/m3/exchange',response_class=HTMLResponse)
def exchange_page(request:Request):
    response=TEMPLATES.TemplateResponse('m3_exchange_lab.html',{'request':request})
    response.headers['Cache-Control']='no-store, private'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Content-Security-Policy']=("default-src 'self'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    return response


@router.get('/api/m3/exchange/status')
def exchange_status():
    try:
        cfg=resource_audience_config()
        audience_mode=cfg['mode']
        resource_audience={
            'value':cfg['value'] if cfg['mode']=='DEDICATED_RESOURCE' else None,
            'mode':cfg['mode'],
            'readback_verified':cfg['management_api_readback_verified'],
            'readback_at':cfg.get('readback_at')}
    except (ValueError,KeyError,OSError,TypeError):
        audience_mode='NOT_CONFIGURED'
        resource_audience={'value':None,'mode':'NOT_CONFIGURED','readback_verified':False}
    return _respond({'schema':'magalu-rfc8693-workbench-status-v1',
                     'resource_audience_mode':audience_mode,
                     'resource_audience':resource_audience,
                     'report_has_resource_http_evidence':bool(isinstance(_latest(),dict) and
                        isinstance(_latest().get('resource_api'),dict)),
                     'capture':readiness(SUBJECT,ACTOR),
                     'report':_latest(),
                     'operator_required':True,
                     'technical_note':'Success requires a real signed delegated JWT and scope restriction.'})


@router.post('/api/m3/exchange/run')
def exchange_run(request:Request,body:RunRequest):
    _operator_check(request)
    if not LOCK.acquire(blocking=False):
        return _respond({'error':'ALREADY_RUNNING','detail':'A Token Exchange diagnostic is already running.'},409)
    try:
        if not readiness(SUBJECT,ACTOR)['can_attempt']:
            return _respond({'error':'INPUT_TOKENS_NOT_READY',
                'detail':'Capture fresh Ana and Bruno JWTs on the Mac before running.'},409)
        # Registered audience is a server-side policy, not an editable browser
        # assertion. Mismatches are rejected instead of silently using fallback.
        try:
            cfg=resource_audience_config()
        except (ValueError,KeyError,OSError,TypeError):
            return _respond({'error':'AUDIENCE_NOT_REGISTERED',
                'detail':'Register the audience through WSO2 and verify API readback first.'},409)
        requested=body.audience.strip() if body.audience else None
        if cfg['mode']=='DEDICATED_RESOURCE':
            if requested and requested!=cfg['value']:
                return _respond({'error':'AUDIENCE_MISMATCH',
                    'detail':'Browser audience differs from registered WSO2 resource audience.'},409)
            audience=cfg['value']
        else:
            audience=requested
        try:
            report=run_diagnostic(
                manifest_file=GENERATED/'manifest.json',
                subject_file=SUBJECT,actor_file=ACTOR,
                public_base=os.getenv('IS_PUBLIC_URL','https://localhost:9543'),
                internal_base=os.getenv('IS_INTERNAL_URL','https://is:9543'),
                audience=audience,
                registered_audience_verified=cfg['management_api_readback_verified'],
                verify_tls=os.getenv('IS_TLS_VERIFY','false').lower()=='true')
        except Exception as exc:
            # Never include exception messages: HTTP exceptions can embed bearer tokens.
            return _respond({'error':'DIAGNOSTIC_BLOCKED',
              'error_type':type(exc).__name__,
              'detail':'The diagnostic could not complete; inspect secure WSO2/server logs and token readiness.'},502)
        if not isinstance(report.get('resource_api'),dict) or not all(
            isinstance(report['resource_api'].get(k),dict)
            for k in ('read','approval_check')):
            return _respond({'error':'RESOURCE_API_EVIDENCE_MISSING',
                'detail':'The current runtime did not produce protected-resource HTTP evidence.'},502)
        REPORT.parent.mkdir(parents=True,exist_ok=True)
        import tempfile
        fd,tmp=tempfile.mkstemp(dir=REPORT.parent,prefix='.m3-exchange-',suffix='.json')
        try:
            with os.fdopen(fd,'w') as f:
                json.dump(report,f,indent=2,ensure_ascii=False)
                f.write('\n')
            os.replace(tmp,REPORT)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
        REPORT.chmod(0o600)
        return _respond(report)
    finally:
        LOCK.release()


@router.get('/api/m3/exchange/evidence')
def exchange_evidence():
    report=_latest()
    if not report:
        raise HTTPException(404,'No RFC 8693 diagnostic evidence has been captured yet')
    response=_respond(report)
    response.headers['Content-Disposition']='attachment; filename="magalu-rfc8693-sanitized-evidence.json"'
    return response
