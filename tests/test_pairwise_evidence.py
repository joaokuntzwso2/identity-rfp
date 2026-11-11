"""Isolated backend tests: no live WSO2, no database, no bearer tokens."""
import ast
import re
from pathlib import Path
from types import SimpleNamespace

import requests

ROOT=Path(__file__).parents[1]
MAIN=ROOT/'demo/main.py'


def helpers():
    tree=ast.parse(MAIN.read_text())
    take=[]
    functions={'storefront_subject_matrix','build_pairwise_report'}
    for n in tree.body:
        if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('STOREFRONTS','STOREFRONT_COOKIE_PATTERN') for t in n.targets):
            take.append(n)
        if isinstance(n,ast.FunctionDef) and n.name in functions:
            take.append(n)
    assert len(take)==4
    scope={'re':re,'requests':requests}
    exec(compile(ast.Module(body=take,type_ignores=[]),str(MAIN),'exec'),scope)
    return scope['storefront_subject_matrix'], scope['build_pairwise_report']


def res(body=None,status=200):
    return SimpleNamespace(status_code=status,json=lambda:body)


def all_entries(subs):
    return [
        {'brand':brand,'channel':channel,'tenant':'magalupay.demo' if brand=='magalupay' else 'magalu.demo',
         'port':port,'status':'authenticated' if (brand,channel) in subs else 'logged_out',
         'sub':subs.get((brand,channel))}
        for brand,channel,port in [('magalu','web',8181),('magalu','app',8182),('netshoes','web',8183),('netshoes','app',8184),('magalupay','web',8185),('magalupay','app',8186)]
    ]


def test_all_six_observed_pass():
    _, build=helpers()
    vals={(b,c):s for b,s in [('magalu','A'),('netshoes','B'),('magalupay','C')] for c in ('web','app')}
    report=build(all_entries(vals))
    assert report['result']=='OBSERVED_PASS'
    assert report['passed_checks']==6 and report['authenticated_count']==6
    assert all(x['status']=='pass' for x in report['checks'])
    assert report['identity_equivalence']=='USER_ATTESTATION_REQUIRED'
    assert report['pairwise_protocol_proof']=='DISCOVERY_AND_SECTOR_CONFIG_STILL_REQUIRED'


def test_partial_four_observations_do_not_fake_success():
    _, build=helpers()
    report=build(all_entries({('magalu','web'):'A',('magalu','app'):'A',('netshoes','web'):'B',('magalupay','web'):'C'}))
    assert report['result']=='INCOMPLETE'
    assert report['authenticated_count']==4
    assert report['passed_checks']==4
    assert {x['id'] for x in report['checks'] if x['status']=='pending'}=={'netshoes_continuity','magalupay_continuity'}


def test_same_brand_mismatch_is_fail():
    _, build=helpers()
    report=build(all_entries({('magalu','web'):'A',('magalu','app'):'wrong'}))
    assert report['result']=='MISMATCH'
    assert report['checks'][0]['status']=='fail'


def test_cross_brand_same_sub_is_fail():
    _, build=helpers()
    vals={(b,c):s for b,s in [('magalu','A'),('netshoes','A'),('magalupay','C')] for c in ('web','app')}
    report=build(all_entries(vals))
    assert report['result']=='MISMATCH'
    assert next(x for x in report['checks'] if x['id']=='magalu_netshoes_separation')['status']=='fail'


def test_fallback_uses_mobile_when_web_logged_out():
    _, build=helpers()
    report=build(all_entries({('magalu','app'):'A',('netshoes','app'):'B'}))
    separation=next(x for x in report['checks'] if x['id']=='magalu_netshoes_separation')
    assert separation['left']['channel']=='app' and separation['right']['channel']=='app'
    assert separation['status']=='pass'
    assert report['result']=='INCOMPLETE'


def test_no_cookies_health_only_and_no_fake_sub():
    read,_=helpers()
    called=[]
    def fetch(url,**kwargs):
        called.append((url,kwargs))
        assert url.endswith('/healthz')
        assert 'headers' not in kwargs
        return res({'status':'up'})
    entries=read({},fetch)
    assert len(entries)==6 and len(called)==6
    assert all(x['status']=='logged_out' and x['sub'] is None for x in entries)


def test_authenticated_cookie_returns_real_exact_subject():
    read,_=helpers()
    subject='f519f701-39ae-390b-bad2-ee09f8ed9bcd'
    def fetch(url,**kwargs):
        if url.endswith('/api/session'):
            assert url=='http://store-magalu-web:8080/api/session'
            assert kwargs['headers']=={'Cookie':'magalu_magalu_web_sid=abc.valid.sign'}
            return res({'authenticated':True,'brand':'magalu','channel':'web','tenant':'magalu.demo','sub':subject})
        return res({'status':'up'})
    out=read({'magalu_magalu_web_sid':'abc.valid.sign'},fetch)
    assert out[0]['sub']==subject and out[0]['status']=='authenticated'
    assert all(x['sub'] is None for x in out[1:])


def test_tenant_mismatch_fails_closed_and_does_not_return_sub():
    read,_=helpers()
    def fetch(url,**kwargs):
        if url.endswith('/api/session'):
            return res({'authenticated':True,'brand':'magalu','channel':'web','tenant':'magalupay.demo','sub':'wrong'})
        return res({'status':'up'})
    out=read({'magalu_magalu_web_sid':'abc.valid.sign'},fetch)
    assert out[0]['status']=='invalid_response' and out[0]['sub'] is None


def test_mismatched_brand_or_missing_sub_fails_closed():
    read,_=helpers()
    for response in ({'authenticated':True,'brand':'netshoes','channel':'web','tenant':'magalu.demo','sub':'a'},
                     {'authenticated':True,'brand':'magalu','channel':'web','tenant':'magalu.demo'}):
        def fetch(url,**kwargs):
            if url.endswith('/api/session'):return res(response)
            return res({'status':'up'})
        out=read({'magalu_magalu_web_sid':'abc.valid.sign'},fetch)
        assert out[0]['status']=='invalid_response' and out[0]['sub'] is None


def test_corrupt_cookie_never_forwarded():
    read,_=helpers()
    def fetch(url,**kwargs):
        assert 'Cookie' not in kwargs.get('headers',{})
        return res({'status':'up'})
    out=read({'magalu_magalu_web_sid':'bad\r\nX-Leak: yes'},fetch)
    assert out[0]['status']=='invalid_cookie'


def test_backend_error_is_unavailable_not_logged_out():
    read,_=helpers()
    def fetch(url,**kwargs):
        if url.endswith('/api/session'):raise requests.Timeout()
        return res({'status':'up'})
    out=read({'magalu_magalu_web_sid':'abc.valid.sign'},fetch)
    assert out[0]['status']=='unavailable' and out[0]['sub'] is None


def test_page_renders_six_cards_and_all_six_comparisons():
    from jinja2 import Environment,FileSystemLoader
    env=Environment(loader=FileSystemLoader(str(ROOT/'demo/templates')))
    rendered=env.get_template('pairwise.html').render(brand=None,manifest=None,session={},csrf='',request={'url':{'path':'/pairwise'}})
    assert rendered.count('data-pw-key=')==6
    assert rendered.count('data-pw-check=')==6
    assert 'api/pairwise-evidence' in rendered
    assert 'http://localhost:8181' in rendered and 'http://localhost:8186' in rendered
    assert 'user["password"]' not in rendered


def test_home_and_sidebar_link_to_pairwise_evidence():
    assert 'href="/pairwise"' in (ROOT/'demo/templates/home.html').read_text()
    assert 'href="/pairwise"' in (ROOT/'demo/templates/base.html').read_text()
    text=MAIN.read_text()
    assert "@app.get('/api/pairwise-evidence')" in text
    assert "@app.get('/pairwise'" in text
    api=text.split("@app.get('/api/pairwise-evidence')",1)[1].split("@app.get('/pairwise'",1)[0]
    assert "'Cache-Control'" in api and "'no-store, private'" in api
    assert 'access_token' not in api and 'client_secret' not in api


def test_example_user_observation_four_sessions_consistent_but_incomplete():
    _, build=helpers()
    vals={('magalu','web'):'f519f701-39ae-390b-bad2-ee09f8ed9bcd',
          ('magalu','app'):'f519f701-39ae-390b-bad2-ee09f8ed9bcd',
          ('netshoes','web'):'268803de-7e56-3c65-9ff2-008520d3b54c',
          ('magalupay','web'):'69451670-ec46-33dc-9b11-9e0466e43a10'}
    report=build(all_entries(vals))
    assert report['authenticated_count']==4
    assert report['passed_checks']==4
    assert report['result']=='INCOMPLETE'
