#!/usr/bin/env python3
"""Locally obtain real user access JWTs by Authorization Code + PKCE.

Uses a one-use 127.0.0.1 HTTP callback on port 8991, and never prints tokens.
The browser authenticates with WSO2, including prompt=login/max_age=0.
"""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import os
from pathlib import Path
import secrets
import sys
import time
from urllib.parse import parse_qs,urlencode,urlsplit
import webbrowser

import jwt
import requests
from m3_token_exchange_verify import jwk_validate,token_scopes


def local(url):
    parsed=urlsplit(url)
    if parsed.scheme!='https' or parsed.hostname not in ('localhost','127.0.0.1'):
        raise ValueError('Only local HTTPS WSO2 for demo token capture')
    return url



def require_jwt(value, token_label):
    """Classify token format without logging the credential value."""
    if not isinstance(value, str) or value.count('.') != 2 or not all(value.split('.')):
        if token_label == 'access_token':
            raise RuntimeError('WSO2 returned a non-JWT (likely OPAQUE) access token. '
                               'Re-run ./scripts/provision-m3-oauth-test.sh to set '
                               'Access Token type JWT on the dedicated M3 test client; '
                               'then start a fresh browser login.')
        raise RuntimeError(f'WSO2 returned a non-JWT {token_label}; cannot verify OIDC login')
    return value

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--as-user',choices=['subject','actor'],required=True)
    parser.add_argument('--client-file',default='generated/m3-oauth-test-client.json')
    parser.add_argument('--base-url',default='https://localhost:9543')
    parser.add_argument('--insecure-local',action='store_true')
    parser.add_argument('--open-browser',action='store_true',default=True)
    args=parser.parse_args()
    cfg=json.loads(Path(args.client_file).read_text())
    redirect=cfg['redirect_uri']
    assert redirect=='http://localhost:8991/callback', 'Unexpected redirect URI'
    if args.insecure_local:local(args.base_url)
    verify=not args.insecure_local
    url=args.base_url.rstrip('/')+'/t/'+cfg['tenant_domain']
    session=requests.Session()
    disco=None
    for path in ('/oauth2/token/.well-known/openid-configuration',
                 '/oauth2/oidcdiscovery/.well-known/openid-configuration',
                 '/.well-known/openid-configuration'):
        try:
            r=session.get(url+path,verify=verify,timeout=10)
            if r.ok and r.json().get('issuer') and r.json().get('jwks_uri'):
                disco=r.json();break
        except (ValueError,requests.RequestException):pass
    if not disco:raise RuntimeError('No valid WSO2 tenant discovery')
    for name in ('authorization_endpoint','token_endpoint','jwks_uri'):
        disco[name]=local(disco[name])
    state=secrets.token_urlsafe(32)
    nonce=secrets.token_urlsafe(32)
    verifier=secrets.token_urlsafe(64)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    scopes=('openid requests:read requests:create' if args.as_user=='subject'
            else 'openid requests:read requests:approve')
    params={'response_type':'code','client_id':cfg['client_id'],'redirect_uri':redirect,
            'scope':scopes,'code_challenge_method':'S256','code_challenge':challenge,
            'state':state,'nonce':nonce,'prompt':'login','max_age':'0'}
    authorization=disco['authorization_endpoint']+'?'+urlencode(params)
    holder={}
    class Callback(BaseHTTPRequestHandler):
        def log_message(self,*items):pass
        def do_GET(self):
            parsed=urlsplit(self.path)
            if parsed.path!='/callback':
                self.send_error(404);return
            q=parse_qs(parsed.query)
            received=q.get('state',[''])[0]
            if not secrets.compare_digest(state,received):
                holder['error']='State mismatch or CSRF';status=400
            elif 'error' in q:
                holder['error']='WSO2 authorization failed: '+q['error'][0][:80];status=400
            else:
                holder['code']=q.get('code',[''])[0];status=200
            self.send_response(status)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Cache-Control','no-store')
            self.send_header('Referrer-Policy','no-referrer')
            self.end_headers()
            self.wfile.write(b'<html><body><h2>Magalu local OAuth verification completed.</h2><p>You may close this tab and return to the terminal.</p></body></html>')
    httpd=HTTPServer(('127.0.0.1',8991),Callback)
    httpd.timeout=120
    print(f'Open WSO2 login in browser, authenticate as {"ana.magalu" if args.as_user=="subject" else "bruno.seller"}.')
    print('Local one-time callback: http://localhost:8991/callback')
    webbrowser.open(authorization)
    # Single-use, time-bounded callback; do not leave the listener running indefinitely.
    httpd.handle_request();httpd.server_close()
    if holder.get('error'):raise RuntimeError(holder['error'])
    if not holder.get('code'):raise RuntimeError('No authorization code callback received')
    payload={'grant_type':'authorization_code','code':holder['code'],
             'redirect_uri':redirect,'client_id':cfg['client_id'],'code_verifier':verifier}
    r=session.post(disco['token_endpoint'],auth=(cfg['client_id'],cfg['client_secret']),
                   data=payload,verify=verify,timeout=20)
    if not r.ok:raise RuntimeError(f'Token endpoint rejected code: HTTP {r.status_code}')
    tok=r.json()
    access=tok.get('access_token')
    idtoken=tok.get('id_token')
    if not access or not idtoken:raise RuntimeError('No access token or ID token returned')
    # A successful OIDC login does not imply a JWT access token: WSO2 supports
    # opaque reference access tokens per application. Validate ID token first.
    require_jwt(idtoken, 'id_token')
    idclaims=jwk_validate(idtoken,disco,session,verify)
    if cfg['client_id'] not in ([idclaims['aud']] if isinstance(idclaims['aud'],str) else idclaims['aud']):
        raise RuntimeError('OIDC ID token audience mismatch')
    if not secrets.compare_digest(str(idclaims.get('nonce','')),nonce):
        raise RuntimeError('OIDC nonce invalid')
    require_jwt(access, 'access_token')
    claims=jwk_validate(access,disco,session,verify)
    needed={'requests:read','requests:create'} if args.as_user=='subject' else {'requests:read','requests:approve'}
    if not needed<=token_scopes(claims):
        raise RuntimeError('WSO2 did not grant required test scopes; verify app-scoped roles')
    output=Path('generated/m3-tokens')
    output.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=output/(args.as_user+'.jwt')
    temp=path.with_suffix('.tmp');temp.write_text(access);temp.chmod(0o600)
    temp.replace(path);path.chmod(0o600)
    print('JWT verified and stored locally:',path)
    print('No token displayed; remove generated/m3-tokens after testing.')

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:
        print('ERROR:',type(exc).__name__,str(exc)[:180],file=sys.stderr)
        sys.exit(1)
