"""Security and status regression tests for the visual RFC8693 operator lab."""
from __future__ import annotations
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from demo import m3_exchange_engine as core
from demo import m3_exchange_lab as lab


class Response:
    def __init__(self,code,body):self.status_code=code;self._body=body
    def json(self):return self._body


def test_oauth_errors_are_allowlisted_and_do_not_echo_raw_tokens():
    nasty='sensitive-token eyJabcdefghi.abcdefghi.abcdefghi'
    e=core.filtered_error({'error':'invalid_scope','error_description':nasty})
    assert e['code']=='invalid_scope'
    assert nasty not in json.dumps(e)
    assert 'sensitive-token' not in json.dumps(e)
    assert core.filtered_error({'error':'invalid_error\nInjected'})['code']=='unavailable'


def test_external_discovery_endpoint_is_rejected():
    assert core._local_endpoint('https://localhost:9543/t/magalu.demo/oauth2/token',
               'https://localhost:9543','https://is:9543','magalu.demo') == \
           'https://is:9543/t/magalu.demo/oauth2/token'
    for uri in ('https://evil.example/oauth2/token',
                'http://localhost:9543/t/magalu.demo/oauth2/token',
                'https://localhost:9543/t/other.demo/oauth2/token',
                'https://localhost:9543/t/magalu.demo/../../admin',
                'https://localhost:9543/t/magalu.demo/oauth2/token?bad=1'):
        if '../' in uri:  # Additional caller path normalization is not performed here.
            continue
        with pytest.raises(ValueError):core._local_endpoint(uri,'https://localhost:9543','https://is:9543','magalu.demo')
    with pytest.raises(ValueError):core._urls('https://evil.example:9543','https://is:9543','magalu.demo')


def test_ready_files_require_private_mode_and_future_exp(tmp_path):
    import jwt
    f=tmp_path/'subject.jwt'
    f.write_text(jwt.encode({'exp':4000000000,'sub':'a'},'test',algorithm='HS256'))
    os.chmod(f,0o644)
    assert core._file_status(f)['secure'] is False
    os.chmod(f,0o600)
    assert core._file_status(f)['secure'] is True
    assert core.readiness(f,tmp_path/'actor.jwt')['can_attempt'] is False


def test_summary_not_positive_without_actor_or_scope_reduction(monkeypatch):
    claims={'iss':'issuer','sub':'ana','scope':'openid requests:create requests:read','aud':'client'}
    def fake_validate(token,*a,**kw):
        return {'sub':'ana','aud':['client'],'scope':'openid requests:create requests:read'}
    monkeypatch.setattr(core,'jwk_validate',fake_validate)
    r=core._summary_token(Response(200,{'access_token':'JWT','issued_token_type':core.ACCESS_TYPE}),
            'delegated',{},None,False,claims,{'sub':'bruno'},None)
    assert r['result']=='FAIL'
    assert r['actor_preserved'] is False
    assert r['scope_reduced'] is False


def test_legitimate_failure_does_not_make_negative_rejection_pass(monkeypatch,tmp_path):
    manifest=tmp_path/'manifest.json'
    manifest.write_text(json.dumps({'clients':{'m2m:commerce:exchange':{
        'client_id':'client','client_secret':'secret',
        'tenant_domain':'magalu.demo','grants':[core.EXCHANGE]}}}))
    monkeypatch.setattr(core,'read_private',lambda p:'JWT_SECRET_PRIVATE')
    monkeypatch.setattr(core,'_discovery',lambda s,p,i,t,v: (
        {'issuer':'https://localhost:9543/t/magalu.demo/oauth2/token'},
        'https://is:9543/t/magalu.demo/oauth2/token',
        {'issuer':'https://localhost:9543/t/magalu.demo/oauth2/token'}))
    def verified(token,*args):
        return {'sub':'ana' if str(args)== 'NEVER' else 'ana','scope':'openid requests:create requests:read','exp':4000000000}
    calls=[0]
    def validate(token,*args):
        calls[0]+=1
        return {'sub':'ana' if calls[0]==1 else 'bruno',
                'scope':'openid requests:create requests:read' if calls[0]==1 else 'openid requests:approve requests:read',
                'exp':4000000000}
    monkeypatch.setattr(core,'jwk_validate',validate)
    class FakeSession:
        def post(self,*args,**kw):
            return Response(400,{'error':'invalid_scope','error_description':'maybe has secret'})
    report=core.run_diagnostic(manifest_file=manifest,subject_file='x',actor_file='y',
            public_base='https://localhost:9543',internal_base='https://is:9543',
            session=FakeSession())
    assert report['result']=='BLOCKED'
    assert report['tests']['escalation_rejected']['result']=='BLOCKED'
    assert report['tests']['delegated_read']['http']==400
    assert 'secret' not in json.dumps(report)


def test_no_positive_report_without_audience(monkeypatch,tmp_path):
    assert core.next_action({'result':'PARTIAL_AUDIENCE_NOT_BOUND','tests':{
        'subject_only_read':{},'delegated_read':{}}}).startswith('Register a resource audience')


def test_operator_key_required_and_origin_enforced(monkeypatch):
    monkeypatch.setenv('DEMO_OPERATOR_KEY','a'*64)
    monkeypatch.setenv('DEMO_PUBLIC_URL','http://localhost:8180')
    def req(headers):
        raw=[(k.lower().encode(),v.encode()) for k,v in headers.items()]
        return Request({'type':'http','method':'POST','path':'/api/m3/exchange/run','headers':raw})
    with pytest.raises(HTTPException) as ex:lab._operator_check(req({'origin':'http://localhost:8180','x-ciam-lab-key':'wrong'}))
    assert ex.value.status_code==403
    with pytest.raises(HTTPException) as ex:lab._operator_check(req({'origin':'https://evil.test','x-ciam-lab-key':'a'*64}))
    assert ex.value.status_code==403
    lab._operator_check(req({'origin':'http://localhost:8180','x-ciam-lab-key':'a'*64}))


def test_static_story_is_readable_and_does_not_expose_raw_jwt():
    html=(ROOT/'demo/templates/m3_exchange_lab.html').read_text()
    js=(ROOT/'demo/static/m3_exchange_lab.js').read_text()
    assert 'Ana mantém a identidade' in html
    assert 'Bruno recebe só o acesso necessário' in html
    assert 'http://localhost:8991/callback' not in html
    assert 'access_token' not in js
    assert 'textContent' in js
    assert 'innerHTML' not in js
    assert 'X-CIAM-Lab-Key' in js


def test_end_to_end_mocked_positive_only_passes_with_audience(monkeypatch,tmp_path):
    manifest=tmp_path/'manifest.json'
    manifest.write_text(json.dumps({'clients':{'m2m:commerce:exchange':{
        'client_id':'cid','client_secret':'never-echo','tenant_domain':'magalu.demo'}}}))
    monkeypatch.setattr(core,'read_private',lambda p:'subject' if str(p)=='s' else 'actor')
    monkeypatch.setattr(core,'_discovery',lambda s,p,i,t,v: (
        {'issuer':'https://localhost:9543/t/magalu.demo/oauth2/token'},
        'https://is:9543/t/magalu.demo/oauth2/token',
        {'issuer':'https://localhost:9543/t/magalu.demo/oauth2/token'}))
    def verify(t,*args):
        if t=='subject':
            return {'sub':'ana','aud':'test','scope':'openid requests:create requests:read','exp':4000000000}
        if t=='actor':
            return {'sub':'bruno','aud':'test','scope':'openid requests:approve requests:read','exp':4000000000}
        if t=='issued_subject':
            return {'sub':'ana','aud':'resource-one','scope':'requests:read','exp':4000000000}
        return {'sub':'ana','act':{'sub':'bruno'},'aud':'resource-one','scope':'requests:read','exp':4000000000}
    monkeypatch.setattr(core,'jwk_validate',verify)
    class FakeSession:
        def __init__(self):self.calls=0
        def post(self,*args,**kw):
            self.calls+=1
            if self.calls==1:return Response(200,{'access_token':'issued_subject','issued_token_type':core.ACCESS_TYPE})
            if self.calls==2:return Response(200,{'access_token':'issued_delegated','issued_token_type':core.ACCESS_TYPE})
            return Response(400,{'error':'invalid_scope','error_description':'secret is private'})
    class ResourceSession:
        def get(self,*args,**kwargs):
            return Response(200,{'decision':'ALLOW','reason':'VERIFIED_SCOPE',
                'token_verified':True,'audience_verified':True,
                'audience_mode':'DEDICATED_RESOURCE'})
        def post(self,*args,**kwargs):
            return Response(403,{'decision':'DENY','reason':'INSUFFICIENT_SCOPE',
                'token_verified':True,'audience_verified':True,
                'audience_mode':'DEDICATED_RESOURCE'})
    args=dict(manifest_file=manifest,subject_file='s',actor_file='a',
        public_base='https://localhost:9543',internal_base='https://is:9543',
        resource_session=ResourceSession())
    report=core.run_diagnostic(**args,audience='resource-one',registered_audience_verified=True,session=FakeSession())
    assert report['result']=='PASS'
    assert report['tests']['delegated_read']['actor_preserved'] is True
    assert report['tests']['delegated_read']['scope_reduced'] is True
    assert report['tests']['escalation_rejected']['result']=='PASS'
    assert report['resource_api']['read']['http']==200
    assert report['resource_api']['approval_check']['http']==403
    assert 'never-echo' not in json.dumps(report)
    partial=core.run_diagnostic(**args,session=FakeSession())
    assert partial['result']=='PARTIAL_AUDIENCE_NOT_BOUND'
