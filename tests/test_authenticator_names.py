"""ACR/TOTP app patch must use enabled WSO2 internal authenticator names."""
import copy
import unittest
from types import SimpleNamespace
from bootstrap.storefront_provision import (
    available_local_authenticators, select_password_totp, configure_acr)

APPID='aabbccdd-0011-2233-4455-66778899aabb'

class MockAPI:
    def __init__(self, *, listing=None, seq=None):
        self.calls=[]
        self.seq=copy.deepcopy(seq if seq is not None else {'type':'DEFAULT','steps':[]})
        self.script=''
        self.listing=listing if listing is not None else [
            {'name':'BasicAuthenticator','displayName':'basic','type':'LOCAL','isEnabled':True},
            {'name':'totp','displayName':'TOTP','type':'LOCAL','isEnabled':True},
            {'name':'EmailOTPAuthenticator','type':'LOCAL','isEnabled':False},
        ]
    def call(self,method,path,**kwargs):
        self.calls.append((method,path,kwargs))
        if method=='GET' and path=='/api/server/v1/configs/authenticators?type=LOCAL':
            return copy.deepcopy(self.listing),SimpleNamespace(status_code=200)
        if method=='GET' and path==f'/api/server/v1/applications/{APPID}':
            return {'id':APPID,'authenticationSequence':{**copy.deepcopy(self.seq),'script':self.script}},SimpleNamespace(status_code=200)
        if method=='PATCH' and path==f'/api/server/v1/applications/{APPID}':
            self.seq=copy.deepcopy(kwargs['json']['authenticationSequence'])
            return None,SimpleNamespace(status_code=204)
        if method=='PUT' and path==f'/api/server/v1/applications/{APPID}/authenticationSequence/script':
            self.script=kwargs['json']['script']
            return None,SimpleNamespace(status_code=200)
        raise AssertionError(f'Unexpected API call {method} {path}')

class AuthenticatorNameTests(unittest.TestCase):
    def test_uses_internal_names_not_display_names(self):
        api=MockAPI()
        self.assertEqual(select_password_totp(api),('BasicAuthenticator','totp'))
        self.assertEqual(configure_acr(api,APPID),'TOTP_ACR_SCRIPT_AND_STEPS_VERIFIED')
        steps=api.seq['steps']
        self.assertEqual(steps[0]['options'][0]['authenticator'],'BasicAuthenticator')
        self.assertEqual(steps[1]['options'][0]['authenticator'],'totp')
        self.assertNotIn('basic',repr(steps))

    def test_safe_idempotent_rerun(self):
        api=MockAPI()
        configure_acr(api,APPID)
        configure_acr(api,APPID)
        self.assertEqual(len([x for x in api.calls if x[0]=='PATCH']),2)

    def test_disabled_totp_stops_without_mutation(self):
        api=MockAPI(listing=[
            {'name':'BasicAuthenticator','displayName':'basic','type':'LOCAL','isEnabled':True},
            {'name':'totp','type':'LOCAL','isEnabled':False}])
        with self.assertRaisesRegex(RuntimeError,'unavailable or disabled'):
            configure_acr(api,APPID)
        self.assertFalse(any(op in ('PATCH','PUT') for op,*_ in api.calls))

    def test_missing_password_stops_without_mutation(self):
        api=MockAPI(listing=[{'name':'totp','type':'LOCAL','isEnabled':True},
                             {'name':'basic','displayName':'basic','type':'LOCAL','isEnabled':True}])
        with self.assertRaisesRegex(RuntimeError,'BasicAuthenticator=False'):
            configure_acr(api,APPID)
        self.assertFalse(any(op in ('PATCH','PUT') for op,*_ in api.calls))

    def test_unsupported_shape_stops(self):
        api=MockAPI(listing={'items':[]})
        with self.assertRaisesRegex(RuntimeError,'unknown response shape'):
            available_local_authenticators(api)

    def test_disabled_password_stops(self):
        api=MockAPI(listing=[{'name':'BasicAuthenticator','type':'LOCAL','isEnabled':False},
                             {'name':'totp','type':'LOCAL','isEnabled':True}])
        with self.assertRaisesRegex(RuntimeError,'unavailable or disabled'):
            select_password_totp(api)

    def test_existing_unexpected_custom_sequence_not_overwritten(self):
        api=MockAPI(seq={'type':'USER_DEFINED','steps':[
            {'id':1,'options':[{'idp':'LOCAL','authenticator':'FIDOAuthenticator'}]}]})
        with self.assertRaisesRegex(RuntimeError,'unexpected'):
            configure_acr(api,APPID)
        self.assertFalse(any(op in ('PATCH','PUT') for op,*_ in api.calls))

    def test_no_inaccurate_success_when_readback_is_wrong(self):
        class Bad(MockAPI):
            def call(self,method,path,**kwargs):
                if method=='GET' and path==f'/api/server/v1/applications/{APPID}':
                    data,response=super().call(method,path,**kwargs)
                    if self.script: data['authenticationSequence']['steps']=[]
                    return data,response
                return super().call(method,path,**kwargs)
        with self.assertRaisesRegex(RuntimeError,'not persisted'):
            configure_acr(Bad(),APPID)

if __name__=='__main__': unittest.main()
