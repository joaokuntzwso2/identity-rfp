import unittest
from bootstrap.wso2 import WSO2, WSO2Error
from scripts.m3_provision_oauth_test_client import ensure_exchange_read_authorization
from scripts.m3_actor_identity_probe import check
from unittest.mock import patch
import tempfile, json
from pathlib import Path


class TestM3ActorFix(unittest.TestCase):
    def make_api(self):
        s={'clientId':'id','grantTypes':['authorization_code','refresh_token'],
           'callbackURLs':['http://localhost:8991/callback'], 'publicClient':False,
           'pkce':{'mandatory':True},'subject':{'subjectType':'pairwise','sectorIdentifierUri':'https://x'},
           'accessToken':{'type':'JWT'}}
        class Fake:
            def application_id(self,name):return 'evidence-app'
            def call(self,method,path,**kwargs):
                if method=='GET':return dict(s),None
                if method=='PUT':
                    s.update(kwargs['json'])
                    return {},None
                raise RuntimeError(method)
        return Fake(), s

    def test_public_evidence_client_config(self):
        api, config=self.make_api()
        WSO2.ensure_app(api,'MAGALU CIAM POC - M3 - TOKEN EVIDENCE',
                        ['authorization_code','refresh_token'],
                        'http://localhost:8991/callback','https://sector-magalu',
                        kind='user_public')
        self.assertEqual(config['subject']['subjectType'],'public')
        self.assertNotIn('sectorIdentifierUri',config['subject'])
        self.assertTrue(config['pkce']['mandatory'])
        self.assertEqual(config['accessToken']['type'],'JWT')
        self.assertEqual(config['callbackURLs'],['http://localhost:8991/callback'])

    def test_public_client_readback_fails_closed(self):
        api,_=self.make_api()
        def bad(method,path,**kwargs):
            if method=='GET':
                return {'clientId':'id','grantTypes':['authorization_code','refresh_token'],
                        'pkce':{'mandatory':True},'subject':{'subjectType':'pairwise'}},None
            return {},None
        api.call=bad
        with self.assertRaises(WSO2Error):
            WSO2.ensure_app(api,'MAGALU CIAM POC - M3 - TOKEN EVIDENCE',
                            ['authorization_code','refresh_token'],
                            'http://localhost:8991/callback','sector',kind='user_public')

    def test_pairwise_still_pairwise(self):
        api,config=self.make_api()
        WSO2.ensure_app(api,'MAGALU CIAM POC - Magalu Web',
                        ['authorization_code','refresh_token'],
                        'http://localhost:8991/callback','https://sector-magalu',kind='user')
        self.assertEqual(config['subject']['subjectType'],'pairwise')
        self.assertEqual(config['subject']['sectorIdentifierUri'],'https://sector-magalu')

    def test_exchange_api_scopes_read_only(self):
        state=[]
        class API:
            def call(self,method,path,**kwargs):
                if method=='GET':return state.copy(),None
                if method=='POST':
                    state.append({'id':'resource','authorizedScopes':kwargs['json']['scopes']})
                    return {},None
                raise RuntimeError(method)
        self.assertTrue(ensure_exchange_read_authorization(API(),'exchange','resource'))
        self.assertEqual(state[0]['authorizedScopes'],['requests:read'])

    def test_exchange_api_readback_fails_if_missing(self):
        class API:
            def call(self,method,path,**kwargs):return [],None
        with self.assertRaises(RuntimeError):
            ensure_exchange_read_authorization(API(),'exchange','resource')

    def test_probe_reports_boolean_not_sub(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'manifest.json'
            p.write_text(json.dumps({'users':{'commerce:bruno.seller':{'id':'scim-user-id'}}}))
            with patch('scripts.m3_actor_identity_probe.read_private',return_value='test-secret-token'),\
                 patch('scripts.m3_actor_identity_probe.jwk_validate',return_value={'sub':'pairwise-id'}):
                r=check(p,'ignored',{},None,False)
            self.assertFalse(r['actor_sub_equals_scim_id'])
            self.assertTrue(r['jwt_signature_verified'])
            self.assertNotIn('pairwise-id',json.dumps(r))
            self.assertNotIn('scim-user-id',json.dumps(r))


if __name__=='__main__':unittest.main()
