from pathlib import Path
import ast
import json
import re
import unittest
import yaml

ROOT=Path(__file__).parents[1]

class TestSixStorefronts(unittest.TestCase):
    def test_six_unique_ports_and_separate_containers(self):
        conf=yaml.safe_load((ROOT/'compose.frontends.yaml').read_text())
        self.assertEqual(len(conf['services']),6)
        self.assertTrue(all('user' in service for service in conf['services'].values()))
        self.assertTrue(all(service['volumes']==['./generated/storefront-manifest.json:/project/generated/storefront-manifest.json:ro'] for service in conf['services'].values()))
        ports=[item['ports'][0] for item in conf['services'].values()]
        self.assertEqual(len(set(ports)),6)
        self.assertEqual({int(x.split(':')[1]) for x in ports},set(range(8181,8187)))

    def test_separate_oauth_clients_and_cookie_names(self):
        p=(ROOT/'demo/storefront.py').read_text()
        self.assertIn("CLIENT_KEY=f'{BRAND}:{CHANNEL}'",p)
        self.assertIn("COOKIE=f'magalu_{BRAND}_{CHANNEL}_sid'",p)
        self.assertIn('session_cookie=COOKIE',p)
        self.assertIn("'prompt':'login'",p)
        self.assertIn("'max_age':'0'",p)
        self.assertIn("request.session.clear()",p)

    def test_approval_requires_wso2_evidence(self):
        code=(ROOT/'demo/storefront.py').read_text()
        for token in ("'acr_values'", "'totp'", "claims.get('auth_time')",
                      "claims.get('acr')!=ACR_TOTP", "SCOPE_APPROVE not in scopes",
                      "old['sub']!=newprincipal['sub']"):
            self.assertIn(token,code)
        self.assertNotIn('pyotp.TOTP',code)

    def test_database_is_tenant_and_brand_scoped(self):
        sql=(ROOT/'consent/migrations/004_requests.sql').read_text()
        self.assertIn('tenant_domain TEXT NOT NULL',sql)
        self.assertIn('brand TEXT NOT NULL',sql)
        self.assertIn('CHECK (approved_by_sub IS NULL OR approved_by_sub <> requested_by_sub)',sql)
        self.assertIn('CREATE TRIGGER prevent_history_changes',sql)
        source=(ROOT/'demo/workflow.py').read_text()
        self.assertIn('FOR UPDATE',source)
        self.assertIn('tenant_domain=%s AND brand=%s',source)
        self.assertIn("target['requested_by_sub']==actor_sub",source)

    def test_bootstrap_configures_real_wso2(self):
        code=(ROOT/'bootstrap/storefront_provision.py').read_text()
        for path in ('/api/server/v1/api-resources', '/authorized-apis', '/scim2/v2/Roles',
                     '/authenticationSequence/script', 'totp', "'USER_DEFINED'",'read'):
            self.assertIn(path,code)
        self.assertIn("report['result']='BLOCKED'",code)

    def test_authorized_api_readback_and_minimal_manifest(self):
        from bootstrap.storefront_provision import _authorized_scopes, _authorized_resources, write_public_manifest
        self.assertEqual(_authorized_scopes({'authorizedScopes':[{'name':'requests:create'},{'name':'requests:read'}]}),
                         {'requests:create','requests:read'})
        self.assertEqual(len(_authorized_resources([{'id':'123'}])),1)
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            from bootstrap.storefront_ports import FRONTEND_PORTS
            m={'users':{'commerce:ana.magalu':{'password':'SUPER-SECRET'}},
               'clients':{key:{'app_id':key,'client_id':key,'tenant_domain':'magalu.demo',
                   'issuer':'https://idp.example','brand':key.split(':')[0],
                   'channel':key.split(':')[1],'root':'commerce',
                   'client_secret':'SECRET' if key.endswith('web') else None}
                for key in FRONTEND_PORTS}}
            output=Path(temp)/'storefront-manifest.json'
            write_public_manifest(m,output)
            result=json.loads(output.read_text())
            self.assertNotIn('users',result)
            self.assertNotIn('SUPER-SECRET',output.read_text())
            self.assertEqual(len(result['clients']),6)

    def test_templates_parse(self):
        from jinja2 import Environment, FileSystemLoader
        templates=ROOT/'demo/templates/storefront'
        env=Environment(loader=FileSystemLoader(templates))
        for f in templates.glob('*.html'):env.get_template(f.name)

    def test_python_parse(self):
        for f in [ROOT/'demo/storefront.py',ROOT/'demo/workflow.py',
                  ROOT/'bootstrap/storefront_provision.py']:
            ast.parse(f.read_text(),filename=str(f))

if __name__=='__main__': unittest.main()
