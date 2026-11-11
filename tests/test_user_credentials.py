import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from bootstrap.credential_store import stable_user_passwords
from bootstrap.topology import ROOT_TENANTS
from scripts.repair_user_passwords import normalize_scim_username, patch_password_request, reconcile
from bootstrap.wso2 import WSO2Error


def test_passwords_persist_before_manifest_exists():
    with TemporaryDirectory() as root:
        path = Path(root)
        manifest = path / 'manifest.json'
        store = path / 'user-secrets.json'
        first = stable_user_passwords(ROOT_TENANTS, manifest, store)
        assert len(first) == 4
        assert store.exists() and store.stat().st_mode & 0o777 == 0o600
        second = stable_user_passwords(ROOT_TENANTS, manifest, store)
        assert second == first


def test_completed_manifest_is_source_for_migration():
    with TemporaryDirectory() as root:
        path = Path(root)
        users = {}
        for key in ('commerce:ana.magalu', 'commerce:bruno.seller',
                    'fintech:ana.magalu', 'fintech:carla.risk'):
            root_name, username = key.split(':', 1)
            users[key] = {'root': root_name, 'username': username, 'password': key + '_passphrase_123'}
        manifest = path / 'manifest.json'
        manifest.write_text(json.dumps({'users': users}))
        result = stable_user_passwords(ROOT_TENANTS, manifest, path / 'user-secrets.json')
        assert all(result[key] == users[key]['password'] for key in users)


def test_manifest_entry_wrong_tenant_is_rejected():
    with TemporaryDirectory() as root:
        path = Path(root)
        manifest = path / 'manifest.json'
        manifest.write_text(json.dumps({'users': {'commerce:ana.magalu':
             {'root': 'fintech', 'username': 'ana.magalu', 'password': 'long-valid-password'}}}))
        with pytest.raises(ValueError, match='Manifest identity mismatch'):
            stable_user_passwords(ROOT_TENANTS, manifest, path / 'user-secrets.json')


def test_tenant_and_store_credentials_are_separate():
    with TemporaryDirectory() as root:
        path = Path(root)
        secrets = stable_user_passwords(ROOT_TENANTS, path / 'manifest.json', path / 'user-secrets.json')
        assert secrets['commerce:ana.magalu'] != secrets['fintech:ana.magalu']


def test_patch_request_has_scim_schema_and_password():
    payload = patch_password_request('secure-test-pass')
    assert payload['schemas'] == ['urn:ietf:params:scim:api:messages:2.0:PatchOp']
    assert payload['Operations'] == [{'op': 'replace', 'value': {'password': 'secure-test-pass'}}]


class FakeAPI:
    def __init__(self, user_name='ana.magalu', user_id='user-123', status=204):
        self.name = user_name
        self.user_id = user_id
        self.status = status
        self.calls = []

    def call(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if method == 'GET':
            return {'id': self.user_id, 'userName': self.name, 'active': True}, None
        if method == 'PATCH':
            assert kwargs['expected'] == (200, 204)
            assert 'password' in kwargs['json']['Operations'][0]['value']
            return None, None
        raise AssertionError('Wrong method')


def test_patch_works_on_verified_root_user():
    fake = FakeAPI('PRIMARY/ana.magalu@magalu.demo')
    assert reconcile(fake, user_id='user-123', username='ana.magalu',
                     domain='magalu.demo', password='secret-password')
    assert [call[0] for call in fake.calls] == ['GET', 'PATCH', 'GET']


def test_patch_rejects_username_mismatch_before_update():
    fake = FakeAPI('another.user')
    with pytest.raises(WSO2Error, match='userName mismatch'):
        reconcile(fake, user_id='user-123', username='ana.magalu',
                  domain='magalu.demo', password='secret-password')
    assert [call[0] for call in fake.calls] == ['GET']


def test_patch_rejects_wrong_user_id_before_update():
    fake = FakeAPI('ana.magalu', user_id='another-id')
    with pytest.raises(WSO2Error, match='user ID mismatch'):
        reconcile(fake, user_id='user-123', username='ana.magalu',
                  domain='magalu.demo', password='secret-password')
    assert [call[0] for call in fake.calls] == ['GET']


def test_password_not_printed():
    import inspect
    from scripts import repair_user_passwords
    source = inspect.getsource(repair_user_passwords.main)
    assert 'print(password)' not in source


def test_normalize_domain_qualified_username():
    assert normalize_scim_username('PRIMARY/ana.magalu@magalu.demo', 'magalu.demo') == 'ana.magalu'
