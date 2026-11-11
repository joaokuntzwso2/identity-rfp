"""Act 03 security: true JWT authentication, scoped resource API, safe evidence."""
import json
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
# Project dependencies (scripts/ module) are provided by the staged repository.
from demo import m3_resource_api as resource
from demo import m3_exchange_engine as exchange

ISSUER='https://localhost:9543/t/magalu.demo/oauth2/token'
AUDIENCE='urn:magalu:poc:requests'


class Resp:
    def __init__(self,code,body):self.status_code=code;self.body=body
    def json(self):return self.body
    def raise_for_status(self):
        if self.status_code>=400: raise ValueError('HTTP error')


@pytest.fixture
def signing():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk['kid']='test-2026'
    def encode(*,scopes='requests:read',aud=AUDIENCE,sub='ana',act='bruno',exp=None):
        payload={'iss':ISSUER,'sub':sub,'aud':aud,'iat':int(time.time())-5,
                 'exp':exp or int(time.time())+3600,'scope':scopes}
        if act is not None:payload['act']={'sub':act}
        return jwt.encode(payload,key,algorithm='RS256',headers={'kid':'test-2026'})
    return encode,{'keys':[jwk]}


def test_protected_resource_rechecks_jwt_and_denies_approval(monkeypatch,signing):
    encode,jwks=signing
    def discovery(session,public,internal,tenant,verify):
        return ({'issuer':ISSUER},'https://is:9543/t/magalu.demo/oauth2/token',
                {'issuer':ISSUER,'jwks_uri':'https://is:9543/oauth2/jwks'})
    monkeypatch.setattr(resource,'_discovery',discovery)
    class JWKS:
        def get(self,url,**kw):return Resp(200,jwks)
    token=encode()
    code,allow=resource.authorization_decision(token,'requests:read',audience=AUDIENCE,
        public_base='https://localhost:9543',internal_base='https://is:9543',session=JWKS())
    assert (code,allow['decision'],allow['token_verified'],allow['audience_verified'])==(200,'ALLOW',True,True)
    code,denied=resource.authorization_decision(token,'requests:approve',audience=AUDIENCE,
        public_base='https://localhost:9543',internal_base='https://is:9543',session=JWKS())
    assert code==403 and denied['reason']=='INSUFFICIENT_SCOPE' and denied['token_verified']
    empty=encode(scopes='')
    code,denied=resource.authorization_decision(empty,'requests:approve',audience=AUDIENCE,
        public_base='https://localhost:9543',internal_base='https://is:9543',session=JWKS())
    assert code==403 and denied['reason']=='INSUFFICIENT_SCOPE' and denied['audience_verified']
    wrong=encode(aud='urn:other:resource')
    code,denied=resource.authorization_decision(wrong,'requests:read',audience=AUDIENCE,
        public_base='https://localhost:9543',internal_base='https://is:9543',session=JWKS())
    assert code==401 and denied['reason']=='INVALID_AUDIENCE'
    expired=encode(exp=int(time.time())-30)
    code,denied=resource.authorization_decision(expired,'requests:read',audience=AUDIENCE,
        public_base='https://localhost:9543',internal_base='https://is:9543',session=JWKS())
    assert code==401 and not denied['token_verified']
    forged=token[:-4]+'AAAA'
    code,denied=resource.authorization_decision(forged,'requests:read',audience=AUDIENCE,
        public_base='https://localhost:9543',internal_base='https://is:9543',session=JWKS())
    assert code==401 and not denied['token_verified']


def test_fallback_audience_never_claims_dedicated_api(tmp_path):
    path=tmp_path/'manifest.json'
    path.write_text(json.dumps({'clients':{'m2m:commerce:exchange':{
      'tenant_domain':'magalu.demo','client_id':'exchange-client-001','app_id':'app-exchange-001'}}}))
    v=resource.resource_audience_config(path,tmp_path/'not-there')
    assert v['value']=='exchange-client-001' and v['mode']=='EXCHANGE_CLIENT_FALLBACK'
    assert v['management_api_readback_verified'] is False
    cfg=tmp_path/'resource-audience.txt';cfg.write_text(AUDIENCE)
    with pytest.raises(ValueError,match='readback'):
        resource.resource_audience_config(path,cfg)
    cfg.write_text('')
    with pytest.raises(ValueError):resource.resource_audience_config(path,cfg)


def test_probe_never_reports_401_as_approval_denial():
    class Resource:
        def post(self,*a,**kw):return Resp(401,{'decision':'DENY','reason':'INVALID_AUDIENCE',
            'token_verified':False,'audience_verified':False})
    r=exchange._resource_probe(Resource(),resource_base='http://127.0.0.1:8080',
       path='/api/m3/exchange/resource/approve-check',method='POST',access_token='jwt-private')
    assert r['http']==401 and r['token_verified'] is False
    with pytest.raises(ValueError):exchange._resource_probe(Resource(),resource_base='http://external:8080',
       path='/api/m3/exchange/resource/approve-check',method='POST',access_token='jwt-private')


def test_full_negative_scope_issuance_and_actual_api_probe(monkeypatch,tmp_path):
    manifest=tmp_path/'manifest.json'
    manifest.write_text(json.dumps({'clients':{'m2m:commerce:exchange':{
        'client_id':'exchange-client','client_secret':'top-secret-not-for-browser',
        'tenant_domain':'magalu.demo'}}}))
    monkeypatch.setattr(exchange,'read_private',lambda p:'private-sub' if str(p)=='sub' else 'private-actor')
    monkeypatch.setattr(exchange,'_discovery',lambda *a: (
      {'issuer':ISSUER},'https://is:9543/t/magalu.demo/oauth2/token',
      {'issuer':ISSUER,'jwks_uri':'https://is:9543/oauth2/jwks'}))
    claims={
      'private-sub':{'sub':'ana','scope':'openid requests:create requests:read','exp':time.time()+3600},
      'private-actor':{'sub':'bruno','scope':'openid requests:approve requests:read','exp':time.time()+3600},
      'out-basic':{'sub':'ana','scope':'requests:read','aud':'exchange-client'},
      'out-delegated':{'sub':'ana','act':{'sub':'bruno'},'scope':'requests:read','aud':'exchange-client'},
      'out-escalation':{'sub':'ana','act':{'sub':'bruno'},'scope':'','aud':'exchange-client'},
    }
    monkeypatch.setattr(exchange,'jwk_validate',lambda token,*a: claims[token])
    class TokenServer:
        index=0
        def post(self,url,**kw):
            self.index+=1
            assert kw['auth']==('exchange-client','top-secret-not-for-browser')
            assert kw['data']['grant_type']==exchange.EXCHANGE
            name=['out-basic','out-delegated','out-escalation'][self.index-1]
            return Resp(200,{'access_token':name,'issued_token_type':exchange.ACCESS_TYPE})
    class ResourceServer:
        def get(self,url,**kw):
            assert url.endswith('/resource/read')
            assert kw['headers']['Authorization']=='Bearer out-delegated'
            return Resp(200,{'decision':'ALLOW','reason':'VERIFIED_SCOPE',
                            'token_verified':True,'audience_verified':True,
                            'audience_mode':'EXCHANGE_CLIENT_FALLBACK'})
        def post(self,url,**kw):
            assert url.endswith('/resource/approve-check')
            assert kw['headers']['Authorization']=='Bearer out-escalation'
            return Resp(403,{'decision':'DENY','reason':'INSUFFICIENT_SCOPE',
                             'token_verified':True,'audience_verified':True,
                             'audience_mode':'EXCHANGE_CLIENT_FALLBACK'})
    report=exchange.run_diagnostic(manifest_file=manifest,subject_file='sub',actor_file='actor',
        public_base='https://localhost:9543',internal_base='https://is:9543',
        session=TokenServer(),resource_session=ResourceServer())
    assert report['tests']['subject_only_read']['result']=='PASS'
    assert report['tests']['delegated_read']['result']=='PASS'
    negative=report['tests']['escalation_rejected']
    assert negative['result']=='PASS'
    assert negative['http']==200 and negative['scope_issued']==[]
    assert negative['issued_token_type_valid'] and negative['signature_verified']
    assert negative['subject_preserved'] and negative['actor_preserved']
    assert negative['resource_api_read_allowed'] and negative['resource_api_approval_denied']
    assert report['result']=='PARTIAL_AUDIENCE_NOT_BOUND'
    assert 'top-secret-not-for-browser' not in json.dumps(report)
    assert 'out-escalation' not in json.dumps(report)


def test_no_false_pass_if_approval_api_returns_401(monkeypatch,tmp_path):
    class ResourceServer:
        def get(self,*a,**kw):return Resp(200,{'decision':'ALLOW','reason':'VERIFIED_SCOPE',
            'token_verified':True,'audience_verified':True,'audience_mode':'DEDICATED_RESOURCE'})
        def post(self,*a,**kw):return Resp(401,{'decision':'DENY','reason':'INVALID_AUDIENCE',
            'token_verified':False,'audience_verified':False,'audience_mode':'DEDICATED_RESOURCE'})
    # Check gate logic from reference implementation by constraining real probe response.
    r=exchange._resource_probe(ResourceServer(),resource_base='http://127.0.0.1:8080',
       path='/api/m3/exchange/resource/approve-check',method='POST',access_token='anything')
    assert not (r['http']==403 and r['reason']=='INSUFFICIENT_SCOPE' and r['token_verified'])


def test_visual_act03_has_actual_http_portal_evidence():
    base=Path(__file__).resolve().parents[1]/'demo'
    html=(base/'templates/m3_exchange_lab.html').read_text()
    js=(base/'static/m3_exchange_lab.js').read_text()
    assert 'resource-read-http' in html and 'resource-approve-http' in html
    assert 'resourceProof' in js and 'resource_api' in js
    assert 'textContent' in js and 'innerHTML' not in js
    assert 'access_token' not in js and 'client_secret' not in js
