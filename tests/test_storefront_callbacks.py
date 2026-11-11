"""Regression coverage for WSO2 7.3 one-entry callback regex limitation."""
import os
from unittest.mock import patch
import re
import unittest

from bootstrap.storefront_provision import _registered_callbacks, set_callbacks

LEGACY='http://localhost:8180/oidc/callback'

class MockWSO2:
    def __init__(self, callback_urls, cid='abc'):
        self.record={'clientId':cid,'clientSecret':'local','grantTypes':['authorization_code'],
                     'callbackURLs':list(callback_urls)}
        self.writes=[]
    def call(self, method, path, **kwargs):
        if method=='GET':return self.record.copy(),object()
        if method=='PUT':
            self.record=kwargs['json'].copy()
            self.writes.append(kwargs['json'])
            if len(self.record['callbackURLs'])!=1:
                raise AssertionError('WSO2 rejects multiple callback entries')
            return None,object()
        raise AssertionError(method)

class TestWSO2StorefrontCallbacks(unittest.TestCase):
    def test_one_anchored_regex_for_each_of_the_six_clients(self):
        for port in range(8181,8187):
            cb=f'http://localhost:{port}/callback'
            value=_registered_callbacks([LEGACY],cb)[0]
            self.assertTrue(value.startswith('regexp=^(?:'))
            expr=value[len('regexp='):]
            for allowed in (LEGACY,cb):self.assertIsNotNone(re.fullmatch(expr,allowed))
            for forbidden in ('https://attacker.test/callback',
                              f'http://localhost:{port}/callback/extra',
                              f'http://localhost:{port+1}/callback',
                              f'http://localhost:{port}/callback?next=http://evil.test'):
                if forbidden != cb:self.assertIsNone(re.fullmatch(expr,forbidden))
            self.assertEqual(len(_registered_callbacks([LEGACY],cb)),1)
    def test_idempotent(self):
        cb='http://localhost:8181/callback'
        first=_registered_callbacks([LEGACY],cb)
        self.assertEqual(_registered_callbacks(first,cb),first)
        api=MockWSO2([LEGACY])
        client={'app_id':'id-1','client_id':'abc'}
        set_callbacks(api,client,cb)
        self.assertEqual(len(api.writes),1)
        set_callbacks(api,client,cb)
        self.assertEqual(len(api.writes),1)
    def test_guard_unexpected_pattern_and_callback(self):
        with self.assertRaisesRegex(RuntimeError,'not the expected'):
            _registered_callbacks(['regexp=.*'],'http://localhost:8181/callback')
        with self.assertRaisesRegex(RuntimeError,'Unexpected existing'):
            _registered_callbacks(['https://unrelated.example/cb'],'http://localhost:8181/callback')
        with self.assertRaisesRegex(RuntimeError,'non-allowlisted'):
            _registered_callbacks([LEGACY],'http://evil.test/callback')
        with self.assertRaisesRegex(RuntimeError,'no registered callback'):
            _registered_callbacks([],'http://localhost:8181/callback')
    def test_exact_client_id_required_before_put(self):
        api=MockWSO2([LEGACY],cid='different')
        with self.assertRaisesRegex(RuntimeError,'client ID mismatch'):
            set_callbacks(api,{'app_id':'xyz','client_id':'abc'},'http://localhost:8181/callback')
        self.assertFalse(api.writes)
    def test_one_exact_redirect_needs_no_regex(self):
        url='http://localhost:8182/callback'
        self.assertEqual(_registered_callbacks([url],url),[url])
    def test_wrong_legacy_origin_fails_closed(self):
        with patch.dict(os.environ, {'DEMO_PUBLIC_URL':'https://unrelated.test'}):
            with self.assertRaisesRegex(RuntimeError,'Unexpected legacy callback origin'):
                _registered_callbacks([LEGACY],'http://localhost:8183/callback')

if __name__=='__main__':unittest.main()
