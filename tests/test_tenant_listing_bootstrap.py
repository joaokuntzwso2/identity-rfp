"""Contract tests for root-tenant creation avoiding WSO2 TM-60015."""
import json
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import pytest
from requests import Response
from bootstrap.wso2 import WSO2, WSO2Error


def response(status, payload):
    r=Response()
    r.status_code=status
    r._content=json.dumps(payload).encode()
    r.url='https://is:9543/api/server/v1/tenants'
    return r


class TenantServer:
    def __init__(self, tenants=None):
        self.tenants=list(tenants or [])
        self.calls=[]
        self.error=None

    def request(self, method, url, **kwargs):
        self.calls.append((method,url,kwargs))
        if self.error:
            return response(self.error, {'code':'TEST-ERROR','message':'bad request'})
        path=urlsplit(url).path
        if method=='GET' and path=='/api/server/v1/tenants':
            query=parse_qs(urlsplit(url).query)
            offset=int(query['offset'][0])
            limit=int(query['limit'][0])
            return response(200, {'totalResults':len(self.tenants),
                                  'tenants':self.tenants[offset:offset+limit]})
        if method=='POST' and path=='/api/server/v1/tenants':
            body=kwargs['json']
            self.tenants.append({'id':'tenant-'+str(len(self.tenants)+1),
                                 'domain':body['domain'],'name':body['name']})
            return response(201, {'id':self.tenants[-1]['id']})
        raise AssertionError('Unexpected API path: '+method+' '+url)


def client(server):
    api=WSO2('https://is:9543','admin','admin',False)
    api.session.request=server.request
    return api


def test_missing_domain_creates_root_tenant_and_verifies():
    server=TenantServer()
    api=client(server)
    assert api.ensure_root_tenant('magalu.demo','Magalu Commerce','tenantadmin','safepass')=='tenant-1'
    assert len(server.tenants)==1
    assert len([c for c in server.calls if c[0]=='POST'])==1
    assert all('/tenants/domain/' not in c[1] for c in server.calls)
    assert server.calls[1][2]['json']['owners'][0]['provisioningMethod']=='inline-password'


def test_repeated_bootstrap_does_not_create_duplicate_root_tenant():
    server=TenantServer()
    api=client(server)
    first=api.ensure_root_tenant('magalu.demo','Magalu Commerce','tenantadmin','safepass')
    second=api.ensure_root_tenant('magalu.demo','Magalu Commerce','tenantadmin','safepass')
    assert first==second
    assert len([c for c in server.calls if c[0]=='POST'])==1


def test_tenant_list_paginated_before_matching_target():
    existing=[{'id':str(i),'domain':f'tenant{i}.demo'} for i in range(100)]
    existing.append({'id':'existing-101','domain':'magalupay.demo'})
    server=TenantServer(existing)
    api=client(server)
    assert api.ensure_root_tenant('magalupay.demo','MagaluPay','tenantadmin','safepass')=='existing-101'
    assert not any(method=='POST' for method,_,_ in server.calls)
    assert len(server.calls)==2


def test_unexpected_400_is_not_silently_accepted():
    server=TenantServer()
    server.error=400
    with pytest.raises(WSO2Error,match='HTTP 400'):
        client(server).ensure_root_tenant('magalu.demo','Magalu Commerce','tenantadmin','pass')


def test_patch_does_not_recreate_is_or_reset_databases():
    script=(Path(__file__).resolve().parents[1]/'scripts/fix-tenant-list-bootstrap.sh').read_text()
    assert 'tenants?limit=1&offset=0' in script
    assert 'build bootstrap' in script
    for prohibited in ('--force-recreate', 'down -v', 'docker system prune','up -d'):
        assert prohibited not in script
