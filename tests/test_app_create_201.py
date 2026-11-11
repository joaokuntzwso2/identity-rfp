"""Regression coverage for WSO2 IS 7.3.18 app POST returning HTTP 201 without JSON.

All tests simulate API responses. They do not claim live WSO2 verification.
"""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from bootstrap.wso2 import WSO2, WSO2Error


NAME = 'MAGALU CIAM POC - MAGALU - WEB'
APP_ID = 'aba7f53b-713c-4c3e-9196-b00a67c415a0'


class StubWSO2(WSO2):
    def __init__(self, *, body=None, location='', listing_after_post=True,
                 mismatched_detail=False):
        # No network or secrets in unit tests.
        self.body = body
        self.location = location
        self.listing_after_post = listing_after_post
        self.mismatched_detail = mismatched_detail
        self.created = False
        self.post_count = 0
        self.oidc = {'clientId': 'client-100', 'clientSecret': 'mock-not-real',
                     'grantTypes': ['authorization_code'], 'pkce': {'mandatory': False}}
        self.application_list_reads = 0

    def applications(self):
        self.application_list_reads += 1
        if self.created and self.listing_after_post:
            return [{'id': APP_ID, 'name': NAME}]
        return []

    def call(self, method, path, *, expected=(200,), **kwargs):
        if method == 'POST' and path == '/api/server/v1/applications':
            self.post_count += 1
            self.created = True
            return self.body, SimpleNamespace(headers={'Location': self.location})
        if method == 'GET' and path == f'/api/server/v1/applications/{APP_ID}':
            return {'id': APP_ID, 'name': 'wrong' if self.mismatched_detail else NAME}, None
        if path == f'/api/server/v1/applications/{APP_ID}/inbound-protocols/oidc':
            if method == 'GET':
                return deepcopy(self.oidc), None
            if method == 'PUT':
                self.oidc.update(kwargs['json'])
                return {}, None
        raise AssertionError(f'unexpected API operation: {method} {path}')


def create(api):
    return api.ensure_app(NAME, ['authorization_code', 'refresh_token'],
                          'http://localhost:8180/oidc/callback',
                          'https://sector-magalu.local.test:8543/sectors/magalu.json')


def test_201_no_body_no_location_uses_exact_name_readback():
    api = StubWSO2(body=None)
    result = create(api)
    assert result['app_id'] == APP_ID
    assert api.post_count == 1
    assert api.oidc['subject']['subjectType'] == 'pairwise'
    assert api.oidc['pkce']['mandatory'] is True
    # Rerun must reuse and not POST again.
    assert create(api)['app_id'] == APP_ID
    assert api.post_count == 1


def test_201_body_with_id_and_readback():
    api = StubWSO2(body={'id': APP_ID})
    assert create(api)['app_id'] == APP_ID


def test_201_location_only_and_readback():
    api = StubWSO2(body=None, location=f'/t/magalu.demo/api/server/v1/applications/{APP_ID}')
    assert create(api)['app_id'] == APP_ID


def test_201_location_without_immediate_collection_visibility_uses_detail():
    api = StubWSO2(body=None,
                   location=f'https://id.example/t/magalu.demo/api/server/v1/applications/{APP_ID}',
                   listing_after_post=False)
    assert create(api)['app_id'] == APP_ID


def test_201_unverifiable_application_fails_closed():
    api = StubWSO2(body=None, listing_after_post=False)
    with pytest.raises(WSO2Error, match='HTTP 201 but application was not found'):
        create(api)
    assert api.post_count == 1


def test_201_detail_name_mismatch_fails_closed():
    api = StubWSO2(body=None,
                   location=f'/api/server/v1/applications/{APP_ID}',
                   listing_after_post=False, mismatched_detail=True)
    with pytest.raises(WSO2Error, match='name readback mismatch'):
        create(api)


def test_201_invalid_body_type_fails_cleanly():
    api = StubWSO2(body=['unexpected'])
    with pytest.raises(WSO2Error, match='unexpected JSON type'):
        create(api)


def test_201_body_id_mismatch_location_fails_cleanly():
    api = StubWSO2(body={'id': 'another-id'},
                   location=f'/api/server/v1/applications/{APP_ID}')
    with pytest.raises(WSO2Error, match='conflicts with Location'):
        create(api)


def test_201_body_id_mismatch_listing_fails_cleanly():
    api = StubWSO2(body={'id': 'another-id'})
    with pytest.raises(WSO2Error, match='readback mismatch'):
        create(api)


def test_duplicate_application_names_fails_closed():
    api = StubWSO2()
    api.applications = lambda: [{'id': APP_ID, 'name': NAME},
                                {'id': 'other-id', 'name': NAME}]
    with pytest.raises(WSO2Error, match='Duplicate WSO2 application name'):
        create(api)
