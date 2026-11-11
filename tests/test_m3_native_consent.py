"""Offline regressions: security classification, native scope controls, route surface."""
from pathlib import Path
import importlib
import inspect
import json
from unittest.mock import Mock

import pytest

from demo.m3_native_service import (NativeAPI, NativeProblem, allowed_native_consent,
                                    dual_decision, write_private, private_json, SERVICE_ID)

SUB='b2ac36a9-0520-4bfd-87ce-112233445566'
PURPOSE='7be00462-142c-4c12-8d4f-1234567890ab'


def active():return {'subjectId':SUB,'serviceId':SERVICE_ID,'state':'ACTIVE',
    'purposes':[{'id':PURPOSE,'elements':[{'id':'a'}]}],
    'expiryTime':9_999_999_999_000}


@pytest.mark.parametrize('patch,reason',[({'subjectId':'wrong'},'NATIVE_SUBJECT_MISMATCH'),
    ({'serviceId':'wrong'},'NATIVE_SERVICE_MISMATCH'),
    ({'state':'REVOKED'},'NATIVE_NOT_ACTIVE'),
    ({'state':'PENDING'},'NATIVE_NOT_ACTIVE'),
    ({'purposes':[]},'NATIVE_PURPOSE_MISMATCH'),
    ({'expiryTime':1000},'NATIVE_EXPIRED')])
def test_reject_modified_native_consent(patch,reason):
    assert allowed_native_consent({**active(),**patch},subject_id=SUB,purpose_id=PURPOSE,
                                 service_id=SERVICE_ID)[1]==reason


def test_active_consent_allowed():
    assert allowed_native_consent(active(),subject_id=SUB,purpose_id=PURPOSE,service_id=SERVICE_ID)==(True,'NATIVE_ACTIVE_MATCHED')


@pytest.mark.parametrize('custom,native,reason,expected',[('GRANTED',True,'NATIVE_ACTIVE_MATCHED',True),
   ('REVOKED',True,'NATIVE_ACTIVE_MATCHED',False),
   ('GRANTED',False,'NATIVE_REVOKED',False),
   ('GRANTED',False,'NATIVE_API_UNAVAILABLE',False),
   ('NOT_GRANTED',True,'NATIVE_ACTIVE_MATCHED',False)])
def test_dual_gate_fail_closed(custom,native,reason,expected):
    actual,_=dual_decision(custom,native,reason)
    assert actual is expected


def client(credentials=None,http=None):
    return NativeAPI('commerce', credentials or {'commerce':{'tenant':'magalu.demo',
        'client_id':'private','client_secret':'private'}},http=http)


def test_native_client_rejects_cross_root_credentials():
    with pytest.raises(NativeProblem):client({'commerce':{'tenant':'magalupay.demo'}})


def test_native_client_does_not_allow_arbitrary_management_scope():
    with pytest.raises(NativeProblem) as exc:client().token({'internal_user_mgt_update'})
    assert exc.value.code=='FORBIDDEN_MANAGEMENT_SCOPE'


def test_native_client_rejects_path_injection():
    with pytest.raises(NativeProblem) as exc:client().api('GET','/consents/../secrets',scopes={'internal_consent_mgt_consent_view'})
    assert exc.value.code=='UNSUPPORTED_NATIVE_PATH'


def test_native_token_scope_must_be_granted():
    h=Mock();h.post.return_value.status_code=200;h.post.return_value.json.return_value={
      'access_token':'SECRET','scope':'internal_consent_mgt_purpose_view'}
    with pytest.raises(NativeProblem) as exc:
        client(http=h).token({'internal_consent_mgt_consent_view'})
    assert exc.value.code=='MANAGEMENT_SCOPE_NOT_GRANTED'


def test_native_api_no_raw_error_body():
    h=Mock();h.post.return_value.status_code=200;h.post.return_value.json.return_value={
      'access_token':'SECRET','scope':'internal_consent_mgt_consent_view'}
    h.request.return_value.status_code=403;h.request.return_value.text='REAL PRIVATE TOKEN HERE'
    with pytest.raises(NativeProblem) as exc:
        client(http=h).api('GET','/consents/'+PURPOSE,scopes={'internal_consent_mgt_consent_view'})
    assert exc.value.code=='NATIVE_SCOPE_DENIED'
    assert 'REAL PRIVATE' not in str(exc.value)


def test_native_record_read_from_expected_tenant_only():
    h=Mock();h.post.return_value.status_code=200;h.post.return_value.json.return_value={
      'access_token':'SECRET','scope':'internal_consent_mgt_consent_view'}
    h.request.return_value.status_code=200;h.request.return_value.content=b'{}';h.request.return_value.json.return_value=active()
    c=client(http=h); c.consent(PURPOSE)
    args,kwargs=h.request.call_args
    assert '/t/magalu.demo/api/identity/consent-mgt/v2.0/consents/' in args[1]
    assert 'SECRET' in kwargs['headers']['Authorization']


def test_private_config_rejects_world_access(tmp_path):
    file=tmp_path/'native.json';write_private(file,{'demo':'private'})
    assert private_json(file)=={'demo':'private'}
    file.chmod(0o644)
    with pytest.raises(NativeProblem):private_json(file)


def test_api_source_uses_no_native_record_cache():
    source=Path(inspect.getfile(NativeAPI)).read_text()
    assert 'def consent(self, cid)' in source
    assert "self.api('GET','/consents/'+cid" in source


def test_html_contains_full_story_and_unverified_caveat():
    p=Path(__file__).resolve().parents[1]/'demo/templates/m3_native_consent.html'
    html=p.read_text()
    for needle in ('/m3/consent','Native','CONSENT','Revogação','ADMIN_API_MIRROR','DEMO_OPERATOR_KEY'):
        assert needle.lower() in html.lower()


def test_native_revoke_cannot_be_claimed_without_state_revoke():
    src=(Path(__file__).resolve().parents[1]/'demo/m3_native_lab.py').read_text()
    assert "reason != 'NATIVE_REVOKED'" in src
    assert "reason=='NATIVE_REVOKED'" in src


def test_acceptance_requires_two_root_preflight_and_reconciliation():
    src=(Path(__file__).resolve().parents[1]/'demo/m3_native_lab.py').read_text()
    assert 'preflight_ok and' in src
    assert 'reconciled and preflight_ok' in src
    assert "link.get('action')=='REVOKED'" in src


def test_no_plaintext_secrets_in_frontend():
    page=(Path(__file__).resolve().parents[1]/'demo/static/m3_native_consent.js').read_text()
    assert 'access_token' not in page
    assert 'client_secret' not in page
    assert "sessionStorage" not in page
    assert "localStorage" not in page
