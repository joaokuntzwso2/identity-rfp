"""Real, isolated JWT-protected synthetic resource endpoints for M3 Act 03.

These endpoints NEVER modify request workflow state. They demonstrate the same
cryptographic authentication and scope gates a real resource API must apply.

All access tokens are accepted solely via Authorization: Bearer, verified against
WSO2 tenant JWKS + issuer + expiration + explicit registered audience. Data and
errors never contain raw JWT material. Lab audience defaults to the exchange
client ID ONLY as a development demonstrator; dedicated API audience requires
an operator-configured local file.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jwt
import requests
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from demo.m3_exchange_engine import _discovery, _urls
from scripts.m3_token_exchange_verify import jwk_validate, token_scopes

router = APIRouter()
MANIFEST = Path('generated/manifest.json')
DEDICATED_AUDIENCE_FILE = Path('generated/m3-resource-audience.txt')
READBACK_FILE = Path('generated/m3-resource-audience-readback.json')


def resource_audience_config(manifest_file: Path = MANIFEST,
                             audience_file: Path = DEDICATED_AUDIENCE_FILE,
                             readback_file: Path = READBACK_FILE) -> dict[str, Any]:
    """Fail closed unless the dedicated audience has WSO2 API readback evidence.

    The local receipt is evidence of a successful management API read at
    registration time, not a substitute for live token/API audience checks.
    """
    manifest = json.loads(manifest_file.read_text())
    client = manifest['clients']['m2m:commerce:exchange']
    if client.get('tenant_domain') != 'magalu.demo' or not client.get('client_id') or not client.get('app_id'):
        raise ValueError('Exchange client audience unavailable')
    if audience_file.is_file():
        value = audience_file.read_text().strip()
        if not value or len(value) > 160 or any(ord(c) <= 32 for c in value):
            raise ValueError('Invalid dedicated resource audience configuration')
        if not readback_file.is_file():
            raise ValueError('Dedicated audience requires WSO2 management API readback evidence')
        proof=json.loads(readback_file.read_text())
        if (not isinstance(proof, dict) or
            proof.get('schema')!='magalu-m3-audience-registration-v1' or
            proof.get('oidc_management_api_readback_verified') is not True or
            proof.get('tenant') != 'magalu.demo' or
            proof.get('application_id') != client['app_id'] or
            proof.get('client_id') != client['client_id'] or
            proof.get('audience') != value):
            raise ValueError('Audience evidence does not match the active WSO2 exchange application')
        return {'value':value,'mode':'DEDICATED_RESOURCE',
                'management_api_readback_verified':True,
                'readback_at':proof.get('readback_at')}
    return {'value':client['client_id'],'mode':'EXCHANGE_CLIENT_FALLBACK',
            'management_api_readback_verified':False}


def authorization_decision(token: str, required_scope: str, *, audience: str,
                           public_base: str, internal_base: str,
                           session: requests.Session | None = None,
                           verify_tls: bool = False) -> tuple[int, dict[str, Any]]:
    """Fail closed. A 403 means *authenticated* JWT with insufficient scope.

    A bad signature, issuer, expiration, or audience returns 401 (not a fake
    authorization denial). Only a verified, appropriately addressed token can
    reach the business scope gate.
    """
    result = {'decision': 'DENY', 'reason': 'INVALID_ACCESS_TOKEN',
              'token_verified': False, 'audience_verified': False,
              'required_scope': required_scope}
    if not isinstance(token, str) or len(token) < 80 or len(token) > 20000 or token.count('.') != 2:
        return 401, result
    try:
        public, internal = _urls(public_base, internal_base, 'magalu.demo')
        s = session or requests.Session()
        _, _, discovery = _discovery(s, public, internal, 'magalu.demo', verify_tls)
        claims = jwk_validate(token, discovery, s, verify_tls)
        aud = claims.get('aud')
        aud_set = {aud} if isinstance(aud, str) else set(aud) if isinstance(aud, list) and all(isinstance(a, str) for a in aud) else set()
        if audience not in aud_set:
            result['reason'] = 'INVALID_AUDIENCE'
            return 401, result
        # Signature + tenant issuer + exp/nbf/iat are checked by jwk_validate.
        result['token_verified'] = True
        result['audience_verified'] = True
        scopes = token_scopes(claims)
        if required_scope not in scopes:
            result['reason'] = 'INSUFFICIENT_SCOPE'
            return 403, result
        return 200, {'decision': 'ALLOW', 'reason': 'VERIFIED_SCOPE',
                     'token_verified': True, 'audience_verified': True,
                     'required_scope': required_scope,
                     'resource': {'id': 'demo-request-001', 'synthetic': True}}
    except (KeyError, TypeError, ValueError, OSError, jwt.PyJWTError,
            requests.RequestException):
        return 401, result


def _api_response(payload: dict[str, Any], status_code: int):
    r = JSONResponse(payload, status_code=status_code)
    r.headers['Cache-Control'] = 'no-store, private'
    r.headers['Pragma'] = 'no-cache'
    r.headers['X-Content-Type-Options'] = 'nosniff'
    return r


def _authorize(request: Request, permission: str):
    import os
    try:
        cfg = resource_audience_config()
    except (OSError, ValueError, KeyError, TypeError):
        return _api_response({'decision': 'BLOCKED', 'reason': 'RESOURCE_AUDIENCE_CONFIG_UNAVAILABLE'}, 503)
    auth = request.headers.get('authorization', '')
    if not auth.startswith('Bearer ') or auth.count(' ') != 1:
        return _api_response({'decision': 'DENY', 'reason': 'MISSING_BEARER_TOKEN',
                              'token_verified': False, 'audience_verified': False}, 401)
    code, decision = authorization_decision(
        auth[7:], permission, audience=cfg['value'],
        public_base=os.getenv('IS_PUBLIC_URL', 'https://localhost:9543'),
        internal_base=os.getenv('IS_INTERNAL_URL', 'https://is:9543'),
        verify_tls=os.getenv('IS_TLS_VERIFY', 'false').lower() == 'true')
    # Add the audience mode, never the raw audience or token.
    decision['audience_mode'] = cfg['mode']
    if code == 200:
        decision['effect'] = 'READ_SYNTHETIC_DATA' if permission == 'requests:read' else 'AUTHORIZATION_CHECK_ONLY_NO_MUTATION'
    return _api_response(decision, code)


@router.get('/api/m3/exchange/resource/read')
def m3_protected_read(request: Request):
    return _authorize(request, 'requests:read')


@router.post('/api/m3/exchange/resource/approve-check')
def m3_protected_approve_check(request: Request):
    """Authorization probe only. No approval transaction or database writes."""
    return _authorize(request, 'requests:approve')
