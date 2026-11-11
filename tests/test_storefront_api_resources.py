"""WSO2 7.3 APIResources casing and safe create-or-reuse regression tests."""
import unittest
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from bootstrap.storefront_provision import api_resources, ensure_resource, SCOPE_NAMES

IDENT='urn:magalu:poc:requests'
RESOURCE_ID='resource-existing-1'


class ResourceAPI:
    def __init__(self, *, exists=True, missing=(), clash=False, shape='APIResources', name='Magalu POC Requests API'):
        self.exists=exists
        self.missing=set(missing)
        self.clash=clash
        self.shape=shape
        self.name=name
        self.calls=[]
        self.auth=True
        self.force_bad_detail=False

    def call(self, method, path, **kw):
        self.calls.append((method,path,kw))
        if method=='GET' and path.startswith('/api/server/v1/api-resources?'):
            query=parse_qs(urlsplit(path).query)
            if query.get('filter')!=[f'identifier eq {IDENT}']:
                raise AssertionError('Missing exact filter: '+str(query))
            items=([{'id':RESOURCE_ID,'name':self.name,'identifier':IDENT}]
                   if self.exists else [])
            if self.shape=='missing':
                return {'totalResults':len(items)},SimpleNamespace(status_code=200)
            if self.shape=='incomplete':
                return {'APIResources':items,'totalResults':len(items)+1},SimpleNamespace(status_code=200)
            return {self.shape:items,'totalResults':len(items)},SimpleNamespace(status_code=200)
        if method=='POST' and path=='/api/server/v1/api-resources':
            if self.exists or self.clash:
                self.exists=True
                return {'code':'API-RESOURCE-60003'},SimpleNamespace(status_code=409)
            self.exists=True
            return None,SimpleNamespace(status_code=201)
        if method=='GET' and path.startswith('/api/server/v1/api-resources/'):
            return {'id': 'unexpected' if self.force_bad_detail else RESOURCE_ID,
                    'identifier':IDENT,'name':self.name,
                    'requiresAuthorization':self.auth,
                    'scopes':[{'name':name} for name in SCOPE_NAMES if name not in self.missing]},SimpleNamespace(status_code=200)
        if method=='PUT' and path.endswith('/scopes'):
            provided={s['name'] for s in kw['json']}
            self.missing-=provided
            return None,SimpleNamespace(status_code=204)
        raise AssertionError(f'Unexpected call {method} {path}')


class TestApiResourceRecovery(unittest.TestCase):
    def test_existing_resource_is_reused_not_posted(self):
        api=ResourceAPI(exists=True)
        self.assertEqual(ensure_resource(api),RESOURCE_ID)
        self.assertNotIn('POST',[c[0] for c in api.calls])

    def test_empty_response_creates_then_verifies(self):
        api=ResourceAPI(exists=False)
        self.assertEqual(ensure_resource(api),RESOURCE_ID)
        self.assertEqual(sum(m=='POST' for m,*_ in api.calls),1)
        self.assertEqual(ensure_resource(api),RESOURCE_ID)
        self.assertEqual(sum(m=='POST' for m,*_ in api.calls),1)

    def test_conflict_only_reused_after_exact_lookup_and_detail(self):
        api=ResourceAPI(exists=False,clash=True)
        self.assertEqual(ensure_resource(api),RESOURCE_ID)

    def test_only_missing_scopes_added(self):
        api=ResourceAPI(missing={'requests:approve','requests:create'})
        self.assertEqual(ensure_resource(api),RESOURCE_ID)
        writes=[c[2]['json'] for c in api.calls if c[0]=='PUT']
        self.assertEqual([{r['name'] for r in write} for write in writes],
                         [{'requests:create','requests:approve'}])
        ensure_resource(api)
        self.assertEqual(len([c for c in api.calls if c[0]=='PUT']),1)

    def test_real_wso2_response_case_is_required_and_no_silent_miss(self):
        api=ResourceAPI(shape='APIResources')
        self.assertEqual(len(api_resources(api,IDENT)),1)
        bad=ResourceAPI(shape='missing')
        with self.assertRaisesRegex(RuntimeError,'missing APIResources'):
            ensure_resource(bad)
        self.assertFalse(any(x[0]=='POST' for x in bad.calls))

    def test_alt_case_accepted_but_not_assumed(self):
        api=ResourceAPI(shape='apiResources')
        self.assertEqual(len(api_resources(api,IDENT)),1)

    def test_incomplete_filtered_readback_does_not_create(self):
        api=ResourceAPI(exists=False,shape='incomplete')
        with self.assertRaisesRegex(RuntimeError,'incomplete'):
            ensure_resource(api)
        self.assertFalse(any(x[0]=='POST' for x in api.calls))

    def test_unexpected_resource_name_and_auth_mode_block(self):
        for overrides in ({'name':'Something else'}, {'exists':True}):
            if 'name' in overrides:
                api=ResourceAPI(**overrides)
            else:
                api=ResourceAPI(**overrides); api.auth=False
            with self.assertRaisesRegex(RuntimeError,'unexpected name or authorization'):
                ensure_resource(api)
            self.assertFalse(any(x[0] in ('POST','PUT') for x in api.calls))

    def test_wrong_detail_id_rejected(self):
        api=ResourceAPI()
        api.force_bad_detail=True
        with self.assertRaisesRegex(RuntimeError,'wrong ID/identifier'):
            ensure_resource(api)

    def test_list_duplicate_exact_identifier_rejected(self):
        class Duplicates(ResourceAPI):
            def call(self,method,path,**kw):
                if method=='GET' and '?' in path:
                    return {'APIResources':[{'id':'a','identifier':IDENT},{'id':'b','identifier':IDENT}],
                            'totalResults':2},SimpleNamespace(status_code=200)
                return super().call(method,path,**kw)
        with self.assertRaisesRegex(RuntimeError,'Duplicate'):
            ensure_resource(Duplicates())

if __name__=='__main__':
    unittest.main()
