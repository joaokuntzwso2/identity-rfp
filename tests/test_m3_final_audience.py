import json
from pathlib import Path
import pytest
from demo.m3_resource_api import resource_audience_config
from scripts.m3_register_resource_audience import register

AUD='urn:magalu:poc:requests'


def sample():
    return {'clients':{'m2m:commerce:exchange':{
        'app_id':'exchange-app-id','client_id':'exchange-client-id',
        'tenant_domain':'magalu.demo'}}}

class FakeWSO2:
    def __init__(self):
        self.config={
            'clientId':'exchange-client-id',
            'grantTypes':['client_credentials','urn:ietf:params:oauth:grant-type:token-exchange'],
            'callbackURLs':[], 'publicClient':False,
            'accessToken':{'type':'JWT','userAccessTokenExpiryInSeconds':3600},
            'idToken':{'expiryInSeconds':3600,'audience':['some-existing-audience']},
        }
        self.puts=[]
    def call(self, method, path, **kwargs):
        assert '/applications/exchange-app-id/inbound-protocols/oidc' in path
        if method=='GET':return json.loads(json.dumps(self.config)), None
        if method=='PUT':
            self.puts.append(kwargs['json'])
            self.config.update(kwargs['json'])
            return {},None
        raise AssertionError(method)

def test_registration_preserves_existing_app_config_and_verifies_readback(tmp_path):
    api=FakeWSO2()
    out=register(api,sample(),AUD,tmp_path)
    assert out['result']=='M3_AUDIENCE_REGISTERED_AND_VERIFIED'
    assert len(api.puts)==1
    assert api.config['idToken']['audience']==['some-existing-audience',AUD]
    assert api.config['accessToken']['type']=='JWT'
    assert (tmp_path/'m3-resource-audience.txt').read_text().strip()==AUD
    receipt=json.loads((tmp_path/'m3-resource-audience-readback.json').read_text())
    assert receipt['oidc_management_api_readback_verified'] is True
    assert receipt['client_id']=='exchange-client-id'
    assert 'secret' not in json.dumps(receipt).lower()
    assert len(list(tmp_path.glob('m3-exchange-oidc-before-audience-*.json')))==1
    out=register(api,sample(),AUD,tmp_path)
    assert out['changed'] is False
    assert len(api.puts)==1

def test_check_only_missing_audience_does_not_change_or_attest(tmp_path):
    api=FakeWSO2()
    out=register(api,sample(),AUD,tmp_path,check_only=True)
    assert out['result']=='BLOCKED'
    assert not api.puts
    assert not (tmp_path/'m3-resource-audience.txt').exists()

def test_registration_refuses_wrong_application_identity(tmp_path):
    api=FakeWSO2();api.config['clientId']='other-client'
    with pytest.raises(ValueError,match='different application'):
        register(api,sample(),AUD,tmp_path)
    assert not api.puts

def test_resource_requires_receipt_and_matching_exchange_client(tmp_path):
    api=FakeWSO2();register(api,sample(),AUD,tmp_path)
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps(sample()))
    result=resource_audience_config(manifest,tmp_path/'m3-resource-audience.txt',
                                    tmp_path/'m3-resource-audience-readback.json')
    assert result['value']==AUD
    assert result['mode']=='DEDICATED_RESOURCE'
    assert result['management_api_readback_verified'] is True
    (tmp_path/'m3-resource-audience-readback.json').unlink()
    with pytest.raises(ValueError,match='readback'):
        resource_audience_config(manifest,tmp_path/'m3-resource-audience.txt',
                                 tmp_path/'m3-resource-audience-readback.json')

def test_resource_refuses_tampered_readback(tmp_path):
    api=FakeWSO2();register(api,sample(),AUD,tmp_path)
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps(sample()))
    receipt_path=tmp_path/'m3-resource-audience-readback.json'
    payload=json.loads(receipt_path.read_text());payload['client_id']='foreign-client'
    receipt_path.write_text(json.dumps(payload))
    with pytest.raises(ValueError,match='does not match'):
        resource_audience_config(manifest,tmp_path/'m3-resource-audience.txt',receipt_path)
