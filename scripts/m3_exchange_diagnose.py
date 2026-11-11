#!/usr/bin/env python3
"""Local, non-destructive RFC8693 diagnosis. Never prints tokens or secrets.

Runs three scoped token-exchange requests against local WSO2, and reports
sanitized OAuth error metadata and signed-token verification outcomes.
No management API or database writes are performed.
"""
from __future__ import annotations
import argparse
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests
from m3_token_exchange_verify import (
    ACCESS_TYPE, EXCHANGE, TOKEN_TYPE, jwk_validate, read_private, token_scopes
)


def sanitize_description(value: object) -> str | None:
    """Only show short, aggressively redacted OAuth diagnostics."""
    if not isinstance(value, str) or not value.strip():
        return None
    # A description is diagnostic, never trusted or logged verbatim.
    value = value.replace('\n', ' ').replace('\r', ' ')
    value = re.sub(r'\beyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+){1,2}\b', '[JWT]', value)
    value = re.sub(r'(?i)\b(?:client_secret|password|subject_token|actor_token|access_token|authorization)\s*[=:]\s*\S+', '[REDACTED_FIELD]', value)
    value = re.sub(r'https?://\S+', '[URL]', value)
    value = re.sub(r'\b[A-Za-z0-9_+/-]{33,}={0,2}\b', '[REDACTED_VALUE]', value)
    return value[:240]


def oauth_error(body: object) -> dict:
    if not isinstance(body, dict):
        return {'error': 'non_json_response'}
    code = body.get('error')
    # Error codes are short protocol identifiers; arbitrary strings are not propagated.
    if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_\-]{0,63}', code):
        code = 'error_code_unavailable'
    result = {'error': code}
    desc = sanitize_description(body.get('error_description') or body.get('message'))
    if desc:
        result['description'] = desc
    return result


def describe_response(response, disco, session, verify, sub_claims, actor_claims=None, audience=None):
    result = {'http': response.status_code, 'token_issued': False}
    try:
        body = response.json()
    except (ValueError, requests.RequestException):
        body = {}
    if response.status_code != 200:
        result.update(oauth_error(body))
        return result
    if not isinstance(body, dict) or not isinstance(body.get('access_token'), str):
        result['error'] = 'successful_response_missing_token'
        return result
    result['token_issued'] = True
    result['issued_token_type_valid'] = body.get('issued_token_type') == ACCESS_TYPE
    try:
        claims = jwk_validate(body['access_token'], disco, session, verify)
        scope = token_scopes(claims)
        result.update(signature_verified=True,
                      subject_preserved=(claims['sub'] == sub_claims['sub']),
                      scopes=sorted(scope),
                      scope_subset_of_original=scope <= token_scopes(sub_claims),
                      actor_preserved=(isinstance(claims.get('act'), dict) and
                                       claims['act'].get('sub') == actor_claims['sub']) if actor_claims else None,
                      audience_match=audience in (([claims['aud']] if isinstance(claims['aud'], str) else claims['aud'])) if audience else None)
    except Exception as exc:
        result.update(signature_verified=False, validation_error_type=type(exc).__name__)
    return result


def tenant_discovery(session, base, tenant, verify):
    for path in ('/oauth2/token/.well-known/openid-configuration',
                 '/oauth2/oidcdiscovery/.well-known/openid-configuration',
                 '/.well-known/openid-configuration'):
        try:
            r = session.get(f'{base}/t/{tenant}{path}', timeout=12, verify=verify)
            if r.ok and isinstance(r.json(), dict) and all(k in r.json() for k in ('issuer', 'token_endpoint', 'jwks_uri')):
                result = r.json()
                for field in ('issuer', 'token_endpoint', 'jwks_uri'):
                    u = urlsplit(result[field])
                    if u.scheme != 'https' or u.hostname not in ('localhost', '127.0.0.1'):
                        raise ValueError('Discovery returned a non-local endpoint: '+field)
                return result
        except (requests.RequestException, ValueError):
            continue
    raise RuntimeError('No valid tenant-scoped localhost discovery')


def diagnose(args):
    base = args.base_url.rstrip('/')
    url = urlsplit(base)
    if url.scheme != 'https' or url.hostname not in ('localhost', '127.0.0.1'):
        raise ValueError('This diagnostic only permits local WSO2 over HTTPS')
    m = json.loads(Path(args.manifest).read_text())
    c = m['clients'][f'm2m:{args.root}:exchange']
    tenant = c['tenant_domain']
    if not c.get('client_secret') or not c.get('client_id'):
        raise ValueError('No exchange-client credentials in private manifest')
    verify = not args.insecure_local
    s = requests.Session()
    disco = tenant_discovery(s, base, tenant, verify)
    subject = read_private(args.subject_file)
    actor = read_private(args.actor_file)
    subclaims = jwk_validate(subject, disco, s, verify)
    actclaims = jwk_validate(actor, disco, s, verify)
    if subclaims['sub'] == actclaims['sub']:
        raise ValueError('Actor and subject must be different identities')
    remaining = min(int(subclaims['exp'] - time.time()), int(actclaims['exp'] - time.time()))
    if remaining <= 0:
        raise ValueError('Subject or actor JWT expired; capture fresh tokens')
    report = {'schema': 'magalu-m3-exchange-diagnostic-v1',
              'result': 'DIAGNOSTIC_ONLY',
              'tenant': tenant,
              'subject_signature_verified': True,
              'actor_signature_verified': True,
              'subject_actor_distinct': True,
              'minimum_token_lifetime_seconds': remaining,
              'subject_scopes': sorted(token_scopes(subclaims)),
              'actor_scopes': sorted(token_scopes(actclaims)),
              'exchange_client_grant_in_manifest': EXCHANGE in c.get('grants', []),
              'exchange_client_api_scope_authorization': 'NOT_VERIFIED',
              'audience_bound': bool(args.audience),
              'tests': {}}

    def send(label, scope, delegate):
        params = {'grant_type': EXCHANGE,
                  'subject_token': subject,
                  'subject_token_type': TOKEN_TYPE,
                  'requested_token_type': ACCESS_TYPE,
                  'scope': scope}
        if delegate:
            params.update(actor_token=actor, actor_token_type=TOKEN_TYPE)
        if args.audience:
            params['audience'] = args.audience
        r = s.post(disco['token_endpoint'], data=params,
                   auth=(c['client_id'], c['client_secret']),
                   verify=verify, timeout=30)
        report['tests'][label] = describe_response(r, disco, s, verify, subclaims,
                                                    actclaims if delegate else None, args.audience)
    send('subject_only_read', 'requests:read', False)
    send('delegated_read', 'requests:read', True)
    send('delegated_forbidden_approve', 'requests:approve', True)
    report['notes'] = [
        'HTTP 400 is not automatically a PASS for the forbidden-scope test.',
        'The exchange client API-resource scope authorization must be checked separately.',
        'Token endpoint errors are redacted; this is not acceptance evidence.'
    ]
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + '\n')
    out.chmod(0o600)
    print(json.dumps(report, indent=2))
    print(f'Private diagnostic written: {out}')
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', default='commerce', choices=('commerce', 'fintech'))
    p.add_argument('--subject-file', default='generated/m3-tokens/subject.jwt')
    p.add_argument('--actor-file', default='generated/m3-tokens/actor.jwt')
    p.add_argument('--manifest', default='generated/manifest.json')
    p.add_argument('--base-url', default='https://localhost:9543')
    p.add_argument('--audience')
    p.add_argument('--insecure-local', action='store_true')
    p.add_argument('--output', default='generated/m3-exchange-diagnostic.json')
    args = p.parse_args()
    try:
        return diagnose(args)
    except Exception as exc:
        print(json.dumps({'result':'DIAGNOSTIC_FAILED','error_type':type(exc).__name__,
                          'description':sanitize_description(str(exc))}))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
