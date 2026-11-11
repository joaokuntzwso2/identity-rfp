"""Smoke contract tests for the read-only 8180 dashboard.

Pure-source extraction permits testing without installing application database
packages or opening a PostgreSQL connection in the packaging environment.
"""
import ast
from pathlib import Path
from types import SimpleNamespace
import re
import requests

ROOT=Path(__file__).parents[1]
MAIN=ROOT/'demo/main.py'


def matrix():
    tree=ast.parse(MAIN.read_text())
    selected=[]
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('STOREFRONTS','STOREFRONT_COOKIE_PATTERN') for t in node.targets):
            selected.append(node)
        if isinstance(node,ast.FunctionDef) and node.name=='storefront_session_matrix':
            selected.append(node)
    namespace={'re':re,'requests':requests}
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(MAIN),'exec'),namespace)
    return namespace['storefront_session_matrix']


def fake_response(body, status=200):
    return SimpleNamespace(status_code=status,json=lambda:body)


def test_six_no_cookies_show_logged_out_and_check_health_only():
    calls=[]
    def fetch(url,**kwargs):
        calls.append((url,kwargs))
        assert url.endswith('/healthz')
        assert 'Cookie' not in kwargs.get('headers',{})
        return fake_response({'status':'up'})
    result=matrix()({},fetch)
    assert len(result)==6
    assert all(x['available'] and not x['authenticated'] for x in result)
    assert len(calls)==6


def test_only_matching_cookie_forwarded_to_matching_storefront():
    calls=[]
    def fetch(url,**kwargs):
        calls.append((url,kwargs))
        if url.endswith('/api/session'):
            assert url.startswith('http://store-magalu-web:8080/')
            assert kwargs['headers']=={'Cookie':'magalu_magalu_web_sid=valid.signed.cookie'}
            return fake_response({'authenticated':True,'brand':'magalu','channel':'web','sub':'sensitive'})
        return fake_response({'status':'up'})
    result=matrix()({'magalu_magalu_web_sid':'valid.signed.cookie',
        'session':'another-legacy-cookie'},fetch)
    assert result[0]['authenticated'] is True
    assert sum(x['authenticated'] for x in result)==1
    assert len(calls)==6
    assert 'sub' not in result[0]


def test_mismatched_response_not_authenticated():
    def fetch(url,**kwargs):
        if url.endswith('/api/session'):
            return fake_response({'authenticated':True,'brand':'netshoes','channel':'app'})
        return fake_response({'status':'up'})
    result=matrix()({'magalu_magalu_web_sid':'a.b.c'},fetch)
    assert result[0]['available'] and not result[0]['authenticated']


def test_backend_unavailable_is_not_a_pass():
    def fetch(url,**kwargs):
        if 'store-magalu-web' in url:
            raise requests.Timeout('timeout')
        return fake_response({'status':'up'})
    result=matrix()({'magalu_magalu_web_sid':'a.b.c'},fetch)
    assert result[0]['available'] is False
    assert result[0]['authenticated'] is False


def test_invalid_cookie_never_forwarded():
    calls=[]
    def fetch(url,**kwargs):
        calls.append(url)
        return fake_response({'status':'up'})
    result=matrix()({'magalu_magalu_web_sid':'bad\r\nInjected: yes'},fetch)
    assert result[0]['authenticated'] is False
    assert calls[0].endswith('/healthz')


def test_legacy_8180_login_only_redirects_to_independent_storefronts():
    source=MAIN.read_text()
    block=source.split("@app.get('/auth/start/{brand}/{channel}')",1)[1].split("@app.get('/oidc/callback'",1)[0]
    assert '/login' in block and 'redirect(' in block
    assert 'claims.get(' not in block
    callback=source.split("@app.get('/oidc/callback'",1)[1].split("@app.get('/poc/{brand}'",1)[0]
    assert 'Trusted user mapping claim not released' not in callback


def test_dashboard_has_six_independent_cards_and_no_legacy_login_links():
    from jinja2 import Environment,FileSystemLoader
    env=Environment(loader=FileSystemLoader(str(ROOT/'demo/templates')))
    rendered=env.get_template('home.html').render(brand=None,manifest={},session={},csrf='test',
        request={'url':{'path':'/'}})
    assert rendered.count('data-session-key=')==6
    assert '/auth/start/' not in rendered
    assert 'api/storefront-status' in rendered
    assert 'preferred_username' not in rendered


def test_two_sessions_are_independent_and_logout_only_changes_one_card():
    cookies={'magalu_magalu_web_sid':'one.signed.cookie',
             'magalu_netshoes_web_sid':'two.signed.cookie'}
    def fetch(url,**kwargs):
        if url.endswith('/api/session'):
            name=url.split('/')[2].split(':')[0]
            brand='netshoes' if name == 'store-netshoes-web' else 'magalu'
            assert kwargs['headers']['Cookie'].startswith('magalu_'+brand+'_web_sid=')
            return fake_response({'authenticated':True,'brand':brand,'channel':'web'})
        return fake_response({'status':'up'})
    both=matrix()(cookies,fetch)
    assert sum(x['authenticated'] for x in both)==2
    cookies.pop('magalu_magalu_web_sid')
    after_logout=matrix()(cookies,fetch)
    assert sum(x['authenticated'] for x in after_logout)==1
    assert after_logout[0]['authenticated'] is False
    assert after_logout[2]['authenticated'] is True


def test_home_does_not_create_a_seventh_session():
    src=MAIN.read_text()
    code=src.split("@app.get('/',response_class=HTMLResponse)",1)[1].split("@app.get('/healthz')",1)[0]
    assert 'session(request)' not in code
    assert 'TemplateResponse' in code
