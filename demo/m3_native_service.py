"""WSO2 Consent Management v2 connector and fail-closed dual-consent policy.

Operator lab only: native records are never confused with application-session
consent. M2M secrets and WSO2 responses stay on the backend. No user-supplied URL.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid

import requests

TENANTS = {'commerce': 'magalu.demo', 'fintech': 'magalupay.demo'}
REQUIRED_SCOPES = frozenset({'internal_consent_mgt_consent_create',
    'internal_consent_mgt_consent_view','internal_consent_mgt_consent_update',
    'internal_consent_mgt_purpose_view', 'internal_consent_mgt_element_view'})
ACTIVE = {'ACTIVE'}
LOCK = threading.RLock()
SERVICE_ID = 'magalu-ciam-consent-lab'


class NativeProblem(Exception):
    def __init__(self, code, http=503):
        self.code, self.http = code, http
        super().__init__(code)


def private_json(path: Path):
    if not path.is_file() or path.stat().st_size > 128_000 or (path.stat().st_mode & 0o077):
        raise NativeProblem('PRIVATE_CONFIG_MISSING_OR_INSECURE')
    try:
        obj = json.loads(path.read_text())
    except (ValueError, UnicodeDecodeError):
        raise NativeProblem('PRIVATE_CONFIG_INVALID') from None
    if not isinstance(obj, dict):
        raise NativeProblem('PRIVATE_CONFIG_INVALID')
    return obj


def write_private(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.m3-native-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.write('\n')
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def allowed_native_consent(record, *, subject_id, purpose_id, service_id, now=None):
    """Only a matching ACTIVE native record authorizes the custom lab resource."""
    if not isinstance(record, dict): return False, 'NATIVE_RECORD_INVALID'
    if str(record.get('subjectId','')) != str(subject_id): return False, 'NATIVE_SUBJECT_MISMATCH'
    if record.get('serviceId') != service_id: return False, 'NATIVE_SERVICE_MISMATCH'
    if str(record.get('state','')).upper() not in ACTIVE: return False, 'NATIVE_NOT_ACTIVE'
    selected = record.get('purposes')
    if not isinstance(selected, list) or not any(isinstance(p,dict) and str(p.get('id')) == str(purpose_id)
            for p in selected):
        return False, 'NATIVE_PURPOSE_MISMATCH'
    deadline = record.get('expiryTime')
    if isinstance(deadline, (int, float)) and deadline <= int((now or time.time())*1000):
        return False, 'NATIVE_EXPIRED'
    return True, 'NATIVE_ACTIVE_MATCHED'


def dual_decision(custom_state, native_ok, native_reason):
    if custom_state != 'GRANTED': return False, 'CUSTOM_CONSENT_NOT_ACTIVE'
    if not native_ok: return False, native_reason
    return True, 'BOTH_CONSENTS_ACTIVE'


class NativeAPI:
    def __init__(self, root, credentials, http=None):
        if root not in TENANTS: raise NativeProblem('UNKNOWN_TENANT', 400)
        values = credentials.get(root)
        if not isinstance(values, dict) or values.get('tenant') != TENANTS[root]:
            raise NativeProblem('TENANT_CREDENTIAL_MISMATCH')
        self.root, self.tenant, self.credentials = root, TENANTS[root], values
        self.http = http or requests.Session()
        self.base = os.getenv('IS_INTERNAL_URL', 'https://is:9543').rstrip('/')
        if self.base != 'https://is:9543' and self.base != 'https://host.docker.internal:9543':
            raise NativeProblem('UNTRUSTED_WSO2_ENDPOINT')
        self.verify = os.getenv('IS_TLS_VERIFY','false').lower() == 'true'

    def token(self, scopes):
        scopes = set(scopes)
        if not scopes or not scopes <= REQUIRED_SCOPES|{'internal_consent_mgt_purpose_create','internal_consent_mgt_element_create'}:
            raise NativeProblem('FORBIDDEN_MANAGEMENT_SCOPE', 400)
        try:
            r = self.http.post(f'{self.base}/t/{self.tenant}/oauth2/token',
                auth=(self.credentials['client_id'],self.credentials['client_secret']),
                data={'grant_type':'client_credentials','scope':' '.join(sorted(scopes))},
                verify=self.verify, timeout=12, allow_redirects=False)
            body = r.json()
            if r.status_code != 200 or not isinstance(body,dict) or not body.get('access_token'):
                raise NativeProblem('MANAGEMENT_TOKEN_REJECTED')
            issued = set(str(body.get('scope','')).split())
            if not scopes <= issued: raise NativeProblem('MANAGEMENT_SCOPE_NOT_GRANTED')
            return body['access_token']
        except (requests.RequestException, ValueError, KeyError):
            raise NativeProblem('MANAGEMENT_TOKEN_UNAVAILABLE') from None

    def api(self, method, part, *, scopes, payload=None, expected=(200,)):
        if not re.fullmatch(r'/(?:purposes|elements|consents)(?:/[0-9a-fA-F-]{36})?', part):
            raise NativeProblem('UNSUPPORTED_NATIVE_PATH',400)
        bearer = self.token(scopes)
        try:
            r = self.http.request(method,
                f'{self.base}/t/{self.tenant}/api/identity/consent-mgt/v2.0{part}',
                headers={'Authorization':'Bearer '+bearer,'Accept':'application/json'},
                json=payload, verify=self.verify, timeout=15, allow_redirects=False)
        except requests.RequestException:
            raise NativeProblem('NATIVE_API_UNAVAILABLE') from None
        if r.status_code not in expected:
            mapping = {401:'NATIVE_UNAUTHORIZED',403:'NATIVE_SCOPE_DENIED',404:'NATIVE_NOT_FOUND',
                       405:'NATIVE_METHOD_NOT_SUPPORTED',409:'NATIVE_CONFLICT',500:'NATIVE_SERVER_ERROR'}
            raise NativeProblem(mapping.get(r.status_code,'NATIVE_API_HTTP_'+str(r.status_code)),
                503 if r.status_code >= 500 else 409)
        if r.status_code == 204 or not r.content:
            return {}
        try:
            body = r.json()
            if not isinstance(body,(dict,list)):
                raise ValueError('invalid native JSON')
            return body
        except (ValueError, TypeError):
            raise NativeProblem('NATIVE_RESPONSE_INVALID') from None

    def catalog(self):
        return {'purposes':self.api('GET','/purposes',scopes={'internal_consent_mgt_purpose_view'}),
                'elements':self.api('GET','/elements',scopes={'internal_consent_mgt_element_view'})}

    def create(self, subject_id, purpose_id, element_id, link_id):
        # The administrator explicitly mirrors a user-authorized, existing demo grant.
        payload = {'subjectId':subject_id,'serviceId':SERVICE_ID,
           'purposes':[{'id':purpose_id,'elements':[{'id':element_id}]}],
           'language':'en','state':'ACTIVE',
           'expiryTime':int(time.time()*1000)+24*60*60*1000,
           'authorizations':[],
           'properties':{'sourceBrand':'magalu','recipientBrand':'netshoes',
                         'demoLinkHash':hashlib.sha256(link_id.encode()).hexdigest()}}
        result = self.api('POST','/consents',scopes={'internal_consent_mgt_consent_create'},
                         payload=payload,expected=(200,201))
        cid = result.get('id') if isinstance(result,dict) else None
        if not isinstance(cid,str) or not re.fullmatch(r'[0-9a-fA-F-]{36}',cid):
            raise NativeProblem('NATIVE_CREATE_ID_MISSING')
        return cid

    def consent(self, cid):
        if not isinstance(cid,str) or not re.fullmatch(r'[0-9a-fA-F-]{36}', cid):
            raise NativeProblem('INVALID_CONSENT_ID',400)
        return self.api('GET','/consents/'+cid, scopes={'internal_consent_mgt_consent_view'})

    def revoke(self,cid):
        # Version-dependent operation: verify HTTP method on live WSO2 7.3.0.18.
        # An unsupported method is explicitly BLOCKED; never fake a revocation.
        return self.api('DELETE','/consents/'+cid,
            scopes={'internal_consent_mgt_consent_update'},expected=(200,204))
