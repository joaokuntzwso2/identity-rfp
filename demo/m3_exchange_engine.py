"""RFC 8693 evidence engine for the local Magalu lab.

Only local, configured WSO2 hosts can be contacted. JWTs and client secrets are
never included in results or errors. This module never modifies server state.
"""
from __future__ import annotations

import json
import os
import re
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import jwt
import requests

from scripts.m3_token_exchange_verify import (ACCESS_TYPE, EXCHANGE, TOKEN_TYPE,
                                                jwk_validate, read_private, token_scopes)

LOCAL_HOSTS = {'localhost', '127.0.0.1', 'is'}
ALLOWED_ERROR_CODES = {'invalid_scope', 'invalid_grant', 'invalid_request',
                       'unauthorized_client', 'access_denied', 'invalid_target'}
REDUCIBLE_SCOPES = {'requests:create', 'requests:read', 'requests:approve'}


def filtered_error(body):
    """Protocol error only; no attacker-controlled description is echoed verbatim."""
    if not isinstance(body, dict):
        return {'code': 'non_json_response', 'summary': 'WSO2 response was not JSON'}
    code = body.get('error')
    if not isinstance(code, str) or not re.fullmatch(r'[a-z_]{3,60}', code):
        code = 'unavailable'
    summary = {
        'invalid_scope': 'Requested scope is not authorized for this client, token or resource.',
        'invalid_grant': 'WSO2 could not accept the presented grant or token context.',
        'invalid_request': 'WSO2 rejected a parameter or token-exchange request format.',
        'unauthorized_client': 'The exchange application is not authorized for this grant.',
        'access_denied': 'The delegated operation was denied by policy.',
        'invalid_target': 'The requested audience is not registered for the exchange client.',
    }.get(code, 'Consult WSO2 logs for details; response content was withheld for safety.')
    return {'code': code, 'summary': summary}


def _file_status(path):
    p = Path(path)
    if not p.exists():
        return {'present': False, 'secure': False, 'looks_jwt': False,
                'remaining_seconds_unverified': None}
    try:
        meta = p.stat()
        secure = stat.S_ISREG(meta.st_mode) and meta.st_mode & 0o077 == 0 and meta.st_size <= 32768
        if not secure:
            return {'present': True, 'secure': False, 'looks_jwt': False,
                    'remaining_seconds_unverified': None}
        value = p.read_text().strip()
        looks_jwt = value.count('.') == 2
        remaining = None
        if looks_jwt:
            try:
                unverified = jwt.decode(value, options={'verify_signature': False, 'verify_exp': False,
                                                        'verify_aud': False, 'verify_iss': False})
                if isinstance(unverified.get('exp'), (int, float)):
                    remaining = max(0, int(unverified['exp'] - time.time()))
            except jwt.PyJWTError:
                looks_jwt = False
        return {'present': True, 'secure': secure, 'looks_jwt': looks_jwt,
                'remaining_seconds_unverified': remaining}
    except (OSError, ValueError, UnicodeDecodeError):
        return {'present': True, 'secure': False, 'looks_jwt': False,
                'remaining_seconds_unverified': None}


def readiness(subject_file, actor_file):
    # The time estimates are UNVERIFIED hints. Signature verification occurs on run.
    a = _file_status(subject_file)
    b = _file_status(actor_file)
    return {'subject': a, 'actor': b,
            'can_attempt': all(v['secure'] and v['looks_jwt'] and
                               (v['remaining_seconds_unverified'] is not None and
                                v['remaining_seconds_unverified'] > 30)
                               for v in (a, b)),
            'warning': 'File existence and expiry estimates are not JWT signature validation.'}


def _urls(public_base, internal_base, tenant):
    public = urlsplit(public_base.rstrip('/'))
    internal = urlsplit(internal_base.rstrip('/'))
    if (public.scheme != 'https' or public.hostname not in {'localhost','127.0.0.1'} or
        internal.scheme != 'https' or internal.hostname not in LOCAL_HOSTS or
        public.username or internal.username or public.query or internal.query or
        public.fragment or internal.fragment or public.path not in ('', '/') or
        internal.path not in ('', '/')):
        raise ValueError('Only configured local HTTPS WSO2 endpoints are permitted')
    if not re.fullmatch(r'[a-zA-Z0-9.-]{1,120}', tenant):
        raise ValueError('Invalid configured tenant domain')
    return public_base.rstrip('/'), internal_base.rstrip('/')


def _local_endpoint(uri, public_base, internal_base, tenant):
    # Exactly the official issuer authority and tenant context; no server-side URL injection.
    u=urlsplit(uri)
    pb=urlsplit(public_base)
    if (u.scheme != 'https' or (u.scheme,u.netloc)!=(pb.scheme,pb.netloc) or
        not (u.path.startswith('/t/'+tenant+'/') or u.path.startswith('/oauth2/')) or
        u.username or u.password or u.fragment or u.query or '..' in u.path.split('/')):
        raise ValueError('WSO2 discovery returned an unexpected endpoint')
    return internal_base.rstrip('/')+u.path


def _discovery(session, public, internal, tenant, verify):
    for path in ('/oauth2/token/.well-known/openid-configuration',
                 '/oauth2/oidcdiscovery/.well-known/openid-configuration',
                 '/.well-known/openid-configuration'):
        try:
            r=session.get(f'{internal}/t/{tenant}{path}',timeout=10,verify=verify)
            if not r.ok: continue
            d=r.json()
            if not isinstance(d,dict) or not all(k in d for k in ('issuer','token_endpoint','jwks_uri')):
                continue
            # Keep issuer intact for cryptographic JWT verification.
            if not isinstance(d['issuer'],str) or not (
                d['issuer'].startswith(public+'/t/'+tenant+'/') or
                d['issuer'] == public+'/oauth2/token'):
                continue
            token_uri=_local_endpoint(d['token_endpoint'],public,internal,tenant)
            jwks_uri=_local_endpoint(d['jwks_uri'],public,internal,tenant)
            return d, token_uri, {**d,'jwks_uri':jwks_uri}
        except (requests.RequestException,ValueError,TypeError,KeyError):
            continue
    raise ValueError('Tenant OIDC discovery unavailable or returned untrusted endpoint URLs')


def _summary_token(response, mode, disco, session, verify, subject_claims, actor_claims, audience):
    out={'http': response.status_code, 'token_issued': False, 'issued_token_type_valid': False,
         'signature_verified':False, 'subject_preserved':False, 'actor_preserved':None,
         'scope_reduced':False, 'audience_match':None,
         'scope_issued':[], 'scope_requested':'requests:read', 'result':'BLOCKED'}
    try: body=response.json()
    except (ValueError,requests.RequestException): body={}
    if response.status_code != 200:
        out['oauth_error']=filtered_error(body)
        return out
    token=body.get('access_token') if isinstance(body,dict) else None
    if not isinstance(token,str) or not token:
        out['oauth_error']={'code':'missing_token','summary':'HTTP 200 response had no access token.'}
        return out
    out['token_issued']=True
    out['issued_token_type_valid']=body.get('issued_token_type')==ACCESS_TYPE
    try:
        claim=jwk_validate(token,disco,session,verify)
        issued=token_scopes(claim)
        original=token_scopes(subject_claims)
        business=issued & REDUCIBLE_SCOPES
        out['signature_verified']=True
        out['subject_preserved']=claim['sub']==subject_claims['sub']
        out['actor_preserved']=(isinstance(claim.get('act'),dict) and
                                claim['act'].get('sub')==actor_claims['sub']) if actor_claims else None
        out['scope_issued']=sorted(issued)
        out['scope_reduced']=(bool(issued < original) and
                               'requests:read' in issued and
                               business=={'requests:read'})
        if audience:
            aud=claim.get('aud')
            out['audience_match']=([aud] if isinstance(aud,str) else aud if isinstance(aud,list) else []) == [audience]
        gates=[out['issued_token_type_valid'],out['signature_verified'],out['subject_preserved'],out['scope_reduced']]
        if actor_claims is not None: gates.append(out['actor_preserved'])
        if audience: gates.append(out['audience_match'])
        out['result']='PASS' if all(gates) else 'FAIL'
    except (jwt.PyJWTError,requests.RequestException,ValueError,KeyError,TypeError) as exc:
        out['validation_error_type']=type(exc).__name__
        out['result']='FAIL'
    return out


def _resource_probe(resource_session, *, resource_base, path, method, access_token):
    """Real HTTP invocation of the protected API; never return the bearer token."""
    if resource_base != 'http://127.0.0.1:8080':
        raise ValueError('Resource probe may only contact the local dashboard service')
    url=resource_base+path
    try:
        headers={'Authorization':'Bearer '+access_token}
        if method=='GET':
            response=resource_session.get(url,headers=headers,timeout=18,allow_redirects=False)
        elif method=='POST':
            response=resource_session.post(url,headers=headers,timeout=18,allow_redirects=False)
        else:
            raise ValueError('Unsupported resource probe method')
        try: body=response.json()
        except ValueError: body={}
        if not isinstance(body,dict): body={}
        allowed={'ALLOW','DENY','BLOCKED'}
        reasons={'VERIFIED_SCOPE','INSUFFICIENT_SCOPE','INVALID_AUDIENCE',
                 'INVALID_ACCESS_TOKEN','MISSING_BEARER_TOKEN','RESOURCE_AUDIENCE_CONFIG_UNAVAILABLE'}
        return {'http':response.status_code,
                'decision':body.get('decision') if body.get('decision') in allowed else 'UNKNOWN',
                'reason':body.get('reason') if body.get('reason') in reasons else 'UNVERIFIED_RESPONSE',
                'token_verified':body.get('token_verified') is True,
                'audience_verified':body.get('audience_verified') is True,
                'audience_mode':body.get('audience_mode') if body.get('audience_mode') in
                   ('DEDICATED_RESOURCE','EXCHANGE_CLIENT_FALLBACK') else 'NOT_VERIFIED'}
    except requests.RequestException:
        return {'http':None,'decision':'BLOCKED','reason':'RESOURCE_API_UNAVAILABLE',
                'token_verified':False,'audience_verified':False,'audience_mode':'NOT_VERIFIED'}


def run_diagnostic(*, manifest_file, subject_file, actor_file,
                   public_base, internal_base, audience=None, verify_tls=False,
                   session=None, resource_session=None, resource_base='http://127.0.0.1:8080',
                   registered_audience_verified=False):
    """Execute 3 real requests; output is SAFE for the operator browser.

    The negative test passes only when the legitimate delegated exchange works.
    """
    public,internal=_urls(public_base,internal_base,'magalu.demo')
    if audience is not None:
        if not isinstance(audience,str) or not re.fullmatch(r'[a-zA-Z0-9:./_-]{1,160}',audience):
            raise ValueError('Invalid audience; use a configured resource audience only')
    s=session if session is not None else requests.Session()
    manifest=json.loads(Path(manifest_file).read_text())
    client=manifest['clients']['m2m:commerce:exchange']
    tenant=client['tenant_domain']
    if tenant!='magalu.demo' or not client.get('client_id') or not client.get('client_secret'):
        raise ValueError('Commerce exchange application is missing or misconfigured')
    public,internal=_urls(public,internal,tenant)
    disco,token_url,validation_disco=_discovery(s,public,internal,tenant,verify_tls)
    subject=read_private(subject_file)
    actor=read_private(actor_file)
    subject_claims=jwk_validate(subject,validation_disco,s,verify_tls)
    actor_claims=jwk_validate(actor,validation_disco,s,verify_tls)
    original=token_scopes(subject_claims)
    actor_scopes=token_scopes(actor_claims)
    if subject_claims['sub']==actor_claims['sub']:
        raise ValueError('Ana and Bruno must be distinct WSO2 identities')
    if 'requests:read' not in original or 'requests:approve' in original:
        raise ValueError('Ana must have requests:read and must not have requests:approve')
    if 'requests:approve' not in actor_scopes:
        raise ValueError('Bruno actor token lacks requests:approve')
    if subject_claims['exp']<=time.time() or actor_claims['exp']<=time.time():
        raise ValueError('Input JWT expired; capture fresh tokens')
    report={'schema':'magalu-rfc8693-story-v1',
            'timestamp':datetime.now(timezone.utc).isoformat(),
            'tenant':tenant,
            'result':'INCOMPLETE',
            'input_evidence':{'subject_signature_verified':True,'actor_signature_verified':True,
              'subject_actor_distinct':True,
              'subject_id_prefix':subject_claims['sub'][:12],
              'actor_id_prefix':actor_claims['sub'][:12],
              'issuer':disco['issuer'],
              'subject_scopes':sorted(original), 'actor_scopes':sorted(actor_scopes),
              'subject_exp_remaining':int(subject_claims['exp']-time.time()),
              'actor_exp_remaining':int(actor_claims['exp']-time.time())},
            'audience':{'requested':audience,'registered_in_client':('VERIFIED_BY_MANAGEMENT_API_READBACK'
                            if registered_audience_verified else 'NOT_VERIFIED'),
                        'bound':False,'acceptance_required':True},
            'tests':{}}
    def call(scope,with_actor):
        data={'grant_type':EXCHANGE,'subject_token':subject,
              'subject_token_type':TOKEN_TYPE,
              'requested_token_type':ACCESS_TYPE,
              'scope':scope}
        if with_actor:
            data.update(actor_token=actor,actor_token_type=TOKEN_TYPE)
        if audience: data['audience']=audience
        response=s.post(token_url,data=data,auth=(client['client_id'],client['client_secret']),
                        verify=verify_tls,timeout=25,allow_redirects=False)
        return response
    try:
        a=call('requests:read',False)
        report['tests']['subject_only_read']=_summary_token(
            a,'subject',validation_disco,s,verify_tls,subject_claims,None,audience)
        b=call('requests:read',True)
        report['tests']['delegated_read']=_summary_token(
            b,'delegated',validation_disco,s,verify_tls,subject_claims,actor_claims,audience)
        # Retain the actual issued tokens in memory only, exclusively for the
        # protected resource API calls. Never persist or return these values.
        try:
            delegated_body=b.json() if b.status_code==200 else {}
        except ValueError:
            delegated_body={}
        delegated_token=delegated_body.get('access_token') if isinstance(delegated_body,dict) else None
        c=call('requests:approve',True)
        try: body=c.json()
        except ValueError: body={}
        negative={'http':c.status_code,'token_issued':False,
                  'issued_token_type_valid':False,'signature_verified':False,
                  'subject_preserved':False,'actor_preserved':False,
                  'scope_issued':[], 'scope_subset_of_original':False,
                  'forbidden_scope_issued':None,'result':'BLOCKED',
                  'oauth_error':filtered_error(body) if c.status_code!=200 else None}
        negative_token=body.get('access_token') if isinstance(body,dict) else None
        if c.status_code==200 and isinstance(negative_token,str) and negative_token:
            negative['token_issued']=True
            negative['issued_token_type_valid']=body.get('issued_token_type')==ACCESS_TYPE
            try:
                claims=jwk_validate(negative_token,validation_disco,s,verify_tls)
                issued=token_scopes(claims)
                negative.update({'signature_verified':True,
                    'subject_preserved':claims.get('sub')==subject_claims['sub'],
                    'actor_preserved':isinstance(claims.get('act'),dict) and
                                      claims['act'].get('sub')==actor_claims['sub'],
                    'scope_issued':sorted(issued),
                    'scope_subset_of_original':issued <= original,
                    'forbidden_scope_issued':'requests:approve' in issued})
                if audience:
                    aud=claims.get('aud')
                    negative['audience_match']=([aud] if isinstance(aud,str)
                                                       else aud if isinstance(aud,list) else []) == [audience]
                gates=[negative['issued_token_type_valid'],negative['signature_verified'],
                       negative['subject_preserved'],negative['actor_preserved'],
                       negative['scope_subset_of_original'],
                       negative['forbidden_scope_issued'] is False]
                if audience: gates.append(negative.get('audience_match') is True)
                negative['result']='PASS_TOKEN_POLICY' if all(gates) else 'FAIL'
            except (jwt.PyJWTError,ValueError,KeyError,TypeError,requests.RequestException):
                negative['result']='FAIL'
                negative['validation_error_type']='JWT_VERIFICATION_FAILED'
        elif c.status_code in (400,401,403):
            # Only a specific scope or policy denial proves privilege protection.
            error=negative.get('oauth_error') or {}
            if error.get('code') in ('invalid_scope','access_denied'):
                negative['result']='PASS_TOKEN_POLICY'
        elif c.status_code==200:
            negative['result']='FAIL'  # A 200 response without an access token is ambiguous.

        # No simulated resource API status. Call the real API through HTTP,
        # passing JWTs only via loopback Authorization header.  The service
        # revalidates WSO2 signature, issuer, time claims and trusted audience.
        rs=resource_session or requests.Session()
        read_probe={'http':None,'decision':'BLOCKED','reason':'NO_VALID_DELEGATED_TOKEN',
                    'token_verified':False,'audience_verified':False,'audience_mode':'NOT_VERIFIED'}
        approve_probe={'http':None,'decision':'BLOCKED','reason':'NO_VERIFIED_TEST_TOKEN',
                       'token_verified':False,'audience_verified':False,'audience_mode':'NOT_VERIFIED'}
        if isinstance(delegated_token,str) and report['tests']['delegated_read']['result']=='PASS':
            read_probe=_resource_probe(rs,resource_base=resource_base,
              path='/api/m3/exchange/resource/read',method='GET',access_token=delegated_token)
        # Prefer the actual returned escalation token. If WSO2 refuses to issue
        # one for a valid scope/policy reason, use the verified read-only token
        # to demonstrate that the protected approval endpoint denies it.
        candidate=None
        if negative['result']=='PASS_TOKEN_POLICY':
            if isinstance(negative_token,str) and negative['signature_verified']:
                candidate=negative_token
            elif isinstance(delegated_token,str) and report['tests']['delegated_read']['result']=='PASS':
                candidate=delegated_token
        if candidate:
            approve_probe=_resource_probe(rs,resource_base=resource_base,
              path='/api/m3/exchange/resource/approve-check',method='POST',access_token=candidate)
        report['resource_api']={'read':read_probe,'approval_check':approve_probe,
            'notes':'The approval endpoint is an authorization probe only: it does not change workflow data.'}
        read_allowed=read_probe['http']==200 and read_probe['decision']=='ALLOW' and \
                     read_probe['reason']=='VERIFIED_SCOPE' and read_probe['token_verified'] and \
                     read_probe['audience_verified']
        approve_denied=approve_probe['http']==403 and approve_probe['decision']=='DENY' and \
                       approve_probe['reason']=='INSUFFICIENT_SCOPE' and approve_probe['token_verified'] and \
                       approve_probe['audience_verified']
        negative['resource_api_read_allowed']=read_allowed
        negative['resource_api_approval_denied']=approve_denied
        if negative['result']=='PASS_TOKEN_POLICY':
            negative['result']='PASS' if (read_allowed and approve_denied and
                   report['tests']['delegated_read']['result']=='PASS') else 'BLOCKED'
        report['tests']['escalation_rejected']=negative
        report['audience']['bound']=bool(audience and report['tests']['delegated_read']['audience_match'] and
                                         read_probe['audience_verified'])
        report['audience']['resource_mode']=read_probe['audience_mode']
        # A successful exchange is additional runtime proof, but it cannot
        # replace a trusted management API configuration readback.
        if audience and report['audience']['bound'] and not registered_audience_verified:
            report['audience']['registered_in_client']='INFERRED_FROM_SUCCESSFUL_ISSUANCE_NOT_READBACK'
        positive=report['delegated_baseline_pass']=report['tests']['delegated_read']['result']=='PASS' and read_allowed
        negative_pass=negative['result']=='PASS'
        if negative['result']=='FAIL' or report['tests']['delegated_read']['result']=='FAIL':
            report['result']='FAIL'
        elif (positive and negative_pass and report['audience']['bound'] and
             read_probe['audience_mode']=='DEDICATED_RESOURCE' and registered_audience_verified):
            report['result']='PASS'
        elif positive and negative_pass:
            report['result']='PARTIAL_AUDIENCE_NOT_BOUND'
        else:
            report['result']='BLOCKED'
        report['narrative']=(
            'WSO2 issued a cryptographically verified delegated, read-only token.' if positive else
            'The legitimate delegated exchange has not succeeded; a rejected escalation is not a security pass.')
        report['next_action']=next_action(report)
        return report
    finally:
        # Only in-memory request bodies contained secrets; never persist or echo them.
        pass


def next_action(report):
    for key in ('subject_only_read','delegated_read'):
        r=report['tests'][key]
        error=r.get('oauth_error',{}).get('code')
        if error=='invalid_scope':
            return 'Verify exchange-client authorized API-resource scopes and subject token permissions in magalu.demo.'
        if error=='unauthorized_client':
            return 'Verify RFC 8693 Token Exchange is enabled for the requesting M2M client.'
        if error=='invalid_target':
            return 'Register the target audience on the requesting application, then rerun with that exact value.'
        if error in ('invalid_grant','invalid_request'):
            return 'Inspect token-exchange trust, subject/actor type, issuer and WSO2 OAuth logs (no tokens).'
    if report['result']=='PARTIAL_AUDIENCE_NOT_BOUND':
        return 'Register a resource audience in WSO2, write generated/m3-resource-audience.txt and rerun with that audience. Acts 01–03 passed with the local resource client-ID fallback only.'
    if report['result']=='PASS':
        return 'Export sanitized evidence and attach it to the RFP 7.2 Token Exchange acceptance record.'
    if report.get('resource_api',{}).get('read',{}).get('reason')=='INVALID_AUDIENCE':
        return 'Protected resource rejected the token audience. Configure the dedicated audience in WSO2 and generated/m3-resource-audience.txt.'
    return 'Inspect each token and protected resource decision; a 401 invalid token is NOT a 403 scope denial.'
