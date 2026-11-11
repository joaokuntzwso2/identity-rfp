"""Offline regression tests; do not call WSO2 or modify PostgreSQL."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
from unittest.mock import Mock, MagicMock

if importlib.util.find_spec('psycopg') is None:
    psycopg=types.ModuleType('psycopg');rows=types.ModuleType('psycopg.rows')
    rows.dict_row=object()
    psycopg.rows=rows
    sys.modules['psycopg']=psycopg
    sys.modules['psycopg.rows']=rows

import pytest
from fastapi import FastAPI,HTTPException
from fastapi.testclient import TestClient
from demo import m3_isolation as iso
from scripts import m3_prepare_fintech_control as prep


@pytest.fixture
def identities():
    return {'magalu':('magalu.demo','ana-sub'),
            'netshoes':('magalu.demo','netshoes-sub'),
            'magalupay':('magalupay.demo','pay-sub')}


def test_tenants_are_distinct_and_brand_bound():
    assert iso.BRANDS['magalu']==iso.BRANDS['netshoes']
    assert iso.BRANDS['netshoes']!=iso.BRANDS['magalupay']
    assert iso.PAY_AUDIENCE.startswith('urn:magalupay:')


def test_no_insecure_get_can_grant_or_revoke():
    app=FastAPI();app.include_router(iso.router)
    paths=[r.path for r in app.routes if 'consent' in getattr(r,'path','')]
    for path in paths:
        if path.endswith(('/grant','/revoke','/prepare')):
            methods=next(r.methods for r in app.routes if r.path==path)
            assert 'POST' in methods and 'GET' not in methods


def test_no_operator_secret_denied(monkeypatch):
    monkeypatch.setenv('DEMO_OPERATOR_KEY','a'*32)
    monkeypatch.setenv('DEMO_PUBLIC_URL','http://localhost:8180')
    app=FastAPI();app.include_router(iso.router)
    c=TestClient(app)
    r=c.post('/api/m3/isolation/consent/prepare')
    assert r.status_code==403
    r=c.post('/api/m3/isolation/consent/prepare',headers={'Origin':'http://localhost:8180'})
    assert r.status_code==403
    r=c.post('/api/m3/isolation/consent/prepare',headers={'Origin':'http://evil.local', 'X-CIAM-Lab-Key':'a'*32})
    assert r.status_code==403


def test_missing_operator_key_returns_503(monkeypatch):
    monkeypatch.delenv('DEMO_OPERATOR_KEY',raising=False)
    app=FastAPI();app.include_router(iso.router)
    assert TestClient(app).post('/api/m3/isolation/consent/prepare').status_code==503


def test_link_rejects_wrong_tenant(identities):
    db=MagicMock()
    db.tx.return_value.__enter__.return_value=object()
    link={'source_tenant':'magalu.demo','source_brand':'magalu','source_sub':'ana-sub',
          'recipient_tenant':'magalu.demo','recipient_brand':'netshoes','recipient_sub':'netshoes-sub'}
    db.get.return_value=link
    assert iso._matching(db,identities,'00000000-0000-0000-0000-000000000000','magalu','netshoes')==link
    bad=link|{'recipient_tenant':'magalupay.demo'}
    db.get.return_value=bad
    with pytest.raises(HTTPException) as e:
        iso._matching(db,identities,'00000000-0000-0000-0000-000000000000','magalu','netshoes')
    assert e.value.status_code==403


def test_link_rejects_subject_mismatch(identities):
    db=MagicMock()
    db.tx.return_value.__enter__.return_value=object()
    db.get.return_value={'source_tenant':'magalu.demo','source_brand':'magalu','source_sub':'other-user',
          'recipient_tenant':'magalu.demo','recipient_brand':'netshoes','recipient_sub':'netshoes-sub'}
    with pytest.raises(HTTPException):
        iso._matching(db,identities,'00000000-0000-0000-0000-000000000000','magalu','netshoes')


def test_session_evidence_uses_hmac_not_raw_sub(monkeypatch,identities):
    monkeypatch.setenv('DEMO_OPERATOR_KEY','z'*32)
    x=iso._session_tag(identities)
    assert len(x)==20
    assert 'ana-sub' not in x
    assert x!=iso._session_tag(identities|{'magalupay':('magalupay.demo','different')})


def test_empty_audience_rejected():
    assert iso._aud_set({'aud':None})==set()
    assert iso._aud_set({'aud':'urn:x'})=={'urn:x'}
    assert iso._aud_set({'aud':['urn:x','urn:y']})=={'urn:x','urn:y'}
    assert iso._aud_set({'aud':[23]})==set()


def test_oauth_error_discloses_only_safe_code():
    response=Mock(status_code=400)
    response.json.return_value={'error':'invalid_grant','error_description':'SECRET credentials abc'}
    public,token,body=iso._oauth_summary(response)
    assert public['oauth_error_code']=='invalid_grant'
    assert 'SECRET' not in json.dumps(public)
    assert token is None


def test_unknown_oauth_error_not_echoed():
    response=Mock(status_code=400)
    response.json.return_value={'error':'TOKENS SHOULD NOT BE LOGGED'}
    public,_,_=iso._oauth_summary(response)
    assert public['oauth_error_code']=='unavailable'


def test_private_report_roundtrip(tmp_path):
    p=tmp_path/'report.json'
    iso._write(p,{'result':'PASS'})
    assert p.stat().st_mode&0o077==0
    assert iso._read(p)=={'result':'PASS'}
    p.chmod(0o644)
    assert iso._read(p) is None


def test_fintech_cc_readback_idempotent(tmp_path):
    cc={'app_id':'123','client_id':'client-pay','tenant_domain':'magalupay.demo'}
    exchange={'app_id':'456','client_id':'exchange-pay','tenant_domain':'magalupay.demo'}
    (tmp_path/'manifest.json').write_text(json.dumps({'clients':{'m2m:fintech:exchange':exchange}}))
    cc_current={'clientId':'client-pay','grantTypes':['client_credentials'],'accessToken':{'type':'JWT'},
                'idToken':{'audience':[prep.AUD]},'callbackURLs':[]}
    exch={'clientId':'exchange-pay','grantTypes':['urn:ietf:params:oauth:grant-type:token-exchange']}
    api=Mock()
    api.call.side_effect=[(cc_current,None),(cc_current,None),(exch,None)]
    result=prep.configure(api,cc,tmp_path)
    assert result['readback_verified'] is True
    assert result['updated'] is False
    assert (tmp_path/'m3-fintech-cc-control-readback.json').exists()
    assert api.call.call_count==3


def test_fintech_cc_wont_accept_wrong_tenant(tmp_path):
    with pytest.raises(ValueError):
        prep.configure(Mock(),{'app_id':'x','client_id':'y','tenant_domain':'magalu.demo'},tmp_path)


def test_fintech_cc_must_verify_exchange_grant(tmp_path):
    (tmp_path/'manifest.json').write_text(json.dumps({'clients':{'m2m:fintech:exchange':{'app_id':'xx','client_id':'ex'}}}))
    current={'clientId':'pay','grantTypes':['client_credentials'],'accessToken':{'type':'JWT'},
             'idToken':{'audience':[prep.AUD]},'callbackURLs':[]}
    api=Mock()
    api.call.side_effect=[(current,None),(current,None),({'clientId':'ex','grantTypes':[]},None)]
    with pytest.raises(RuntimeError):
        prep.configure(api,{'app_id':'cc','client_id':'pay','tenant_domain':'magalupay.demo'},tmp_path)
    assert not (tmp_path/'m3-fintech-cc-control-readback.json').exists()


def test_stale_token_report_never_shown_as_current():
    assert iso._fresh({'timestamp':'2020-01-01T00:00:00+00:00','result':'PASS'}) is None
    assert iso._fresh({'timestamp':'malformed','result':'PASS'}) is None
    assert iso._fresh({'result':'PASS'}) is None
