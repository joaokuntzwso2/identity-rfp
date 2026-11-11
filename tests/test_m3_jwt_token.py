"""Targeted regression tests for WSO2 M3 JWT-access-token setup."""
import copy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2] / 'm3_runtime_sim'
# In package form the patch files live in a project that already has bootstrap.
# For local tests, prefer the assembled baseline available in this container.
if not ROOT.exists():
    ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

from m3_provision_oauth_test_client import ensure_jwt_access_tokens
from m3_oidc_capture import require_jwt


class MockAPI:
    def __init__(self, initial, apply_changes=True):
        self.config=copy.deepcopy(initial)
        self.puts=[]
        self.apply_changes=apply_changes
    def call(self, method, path, **kw):
        if method=='GET':
            return copy.deepcopy(self.config), None
        if method=='PUT':
            self.puts.append((path,copy.deepcopy(kw['json'])))
            if self.apply_changes:
                self.config=copy.deepcopy(kw['json'])
            return None, None
        raise AssertionError('Unexpected method')


def starting_config():
    return {'clientId':'m3-client','clientSecret':'secret-not-printed',
            'grantTypes':['authorization_code','refresh_token'],
            'callbackURLs':['http://localhost:8991/callback'],
            'subject':{'subjectType':'pairwise','sectorIdentifierUri':'https://sector.magalu.test/sector.json'},
            'pkce':{'mandatory':True,'supportPlainTransformAlgorithm':False},
            'accessToken':{'type':'Opaque','userAccessTokenExpiryInSeconds':3600}}


class TestM3JWT(unittest.TestCase):
    def test_first_run_changes_only_access_type(self):
        orig=starting_config(); api=MockAPI(orig)
        self.assertTrue(ensure_jwt_access_tokens(api,'safe-id','m3-client'))
        self.assertEqual(len(api.puts),1)
        self.assertEqual(api.config['accessToken']['type'],'JWT')
        self.assertEqual(api.config['pkce'],orig['pkce'])
        self.assertEqual(api.config['subject'],orig['subject'])
        self.assertEqual(api.config['grantTypes'],orig['grantTypes'])
        self.assertEqual(api.config['callbackURLs'],orig['callbackURLs'])
        self.assertEqual(api.config['clientSecret'],orig['clientSecret'])
    def test_rerun_is_idempotent(self):
        api=MockAPI(starting_config())
        ensure_jwt_access_tokens(api,'safe-id','m3-client')
        ensure_jwt_access_tokens(api,'safe-id','m3-client')
        self.assertEqual(len(api.puts),1)
    def test_reject_unexpected_client(self):
        api=MockAPI(starting_config())
        with self.assertRaisesRegex(RuntimeError,'client ID mismatch'):
            ensure_jwt_access_tokens(api,'safe-id','different-client')
        self.assertEqual(api.puts,[])
    def test_fail_if_readback_does_not_persist(self):
        api=MockAPI(starting_config(),apply_changes=False)
        with self.assertRaisesRegex(RuntimeError,'not persisted'):
            ensure_jwt_access_tokens(api,'safe-id','m3-client')
    def test_opaque_token_explains_problem_without_leaking(self):
        with self.assertRaisesRegex(RuntimeError,'OPAQUE') as caught:
            require_jwt('secret-opaque-token','access_token')
        self.assertNotIn('secret-opaque-token',str(caught.exception))
    def test_id_token_invalid_format(self):
        with self.assertRaisesRegex(RuntimeError,'non-JWT id_token'):
            require_jwt('not-a-jwt','id_token')
    def test_three_segments_accepted_at_format_gate(self):
        self.assertEqual(require_jwt('a.b.c','access_token'),'a.b.c')

if __name__=='__main__':unittest.main()
