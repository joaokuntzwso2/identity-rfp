"""Idempotent two-ROOT-TENANT WSO2 7.3 bootstrap. Fail-closed API verification.

Provisions: root tenants, root-scoped users, roles, two channels per brand,
B2B seller client, M2M clients, and separate directional consent seed data.
Never provisions child organizations or writes WSO2-owned tables directly.
"""
import json
import logging
import os
from pathlib import Path
import secrets
import sys
from urllib.parse import quote

from bootstrap.topology import ROOT_TENANTS, BRANDS, PURPOSES
from bootstrap.credential_store import stable_user_passwords
from bootstrap.app_naming import application_name
from bootstrap.wso2 import WSO2, WSO2Error
from demo.store import Ledger

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
LOG=logging.getLogger('root-tenant-bootstrap')


def required(name, default=None):
    value=os.getenv(name, default)
    if not value:
        raise RuntimeError('Required environment value missing: '+name)
    return value


def secure_json(path, data):
    path.parent.mkdir(exist_ok=True,parents=True)
    tmp=path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2))
    tmp.chmod(0o600)
    tmp.replace(path)
    path.chmod(0o600)


def persistent_secrets():
    """Keep owner credentials stable even if a later provisioning API fails."""
    path=Path(required('TENANT_SECRETS_FILE','/project/generated/tenant-secrets.json'))
    secrets_dict=json.loads(path.read_text()) if path.exists() else {}
    for key in ROOT_TENANTS:
        secrets_dict.setdefault(key,{'owner_password':secrets.token_urlsafe(32)})
    secure_json(path,secrets_dict)
    return secrets_dict


def main():
    internal=required('IS_INTERNAL_URL','https://is:9543').rstrip('/')
    public=required('IS_PUBLIC_URL','https://localhost:9543').rstrip('/')
    demo=required('DEMO_PUBLIC_URL','http://localhost:8180').rstrip('/')
    tls=os.getenv('IS_TLS_VERIFY','false').lower()=='true'
    manifest_path=Path(required('MANIFEST_FILE','/project/generated/manifest.json'))
    old=json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    owner_secrets=persistent_secrets()
    user_passwords=stable_user_passwords(
        ROOT_TENANTS, manifest_path,
        Path(required('USER_SECRETS_FILE','/project/generated/user-secrets.json')))
    superapi=WSO2(internal, required('IS_ADMIN_USERNAME','admin'),
                 required('IS_ADMIN_PASSWORD','admin'),tls,
                 os.getenv('IS_ADMIN_ACCESS_TOKEN',''))
    report={'topology':'two-independent-root-tenants-three-brands',
            'stages':[], 'result':'IN_PROGRESS','live_server_verified':False}

    def gate(label, detail):
        report['stages'].append({'gate':label,'status':'VERIFIED','detail':detail})
        secure_json(manifest_path.parent/'bootstrap-report.json',report)

    try:
        # Get root tenants, not organizations. There must be no call to /o/api/server/v1/organizations.
        tenants={}
        tenant_apis={}
        for root, spec in ROOT_TENANTS.items():
            domain=spec['domain']
            tid=superapi.ensure_root_tenant(domain,spec['name'],spec['owner'],
                                            owner_secrets[root]['owner_password'])
            api=WSO2(internal+'/t/'+quote(domain,safe=''),
                    f"{spec['owner']}@{domain}",owner_secrets[root]['owner_password'],tls)
            disco=api.discovery()
            if 'pairwise' not in disco.get('subject_types_supported',[]):
                raise WSO2Error(domain+' discovery does not advertise pairwise subjects')
            tenants[root]={'id':tid,'domain':domain,'name':spec['name'],
                           'issuer':disco['issuer'],
                           'discovery_url':disco.get('issuer')}
            tenant_apis[root]=api
            gate('root_tenant:'+root,domain)

        # Distinct SCIM identities in each ROOT tenant, not a shared SCIM account.
        users={}
        for root,spec in ROOT_TENANTS.items():
            api=tenant_apis[root]
            for username,person_key,given,email in spec['people']:
                key=root+':'+username
                password=user_passwords[key]  # persisted BEFORE first SCIM create
                uid=api.ensure_user(username,email,password,given)
                users[key]={'id':uid,'username':username,'root':root,
                            'person_key':person_key,'password':password}
                gate('user:'+key,'SCIM user created/located within '+spec['domain'])

        brands={}
        clients={}
        for brand, spec in BRANDS.items():
            root=spec['root']
            api=tenant_apis[root]
            b={**spec,'tenant_domain':ROOT_TENANTS[root]['domain']}
            b['sector_uri']=required('SECTOR_URI_ROOT_TEMPLATE','https://sector-{brand}').format(
                brand=brand).rstrip('/')+'/sectors/'+brand+'.json'
            brands[brand]=b
            for channel in ('web','app'):
                key=f'{brand}:{channel}'
                redirect=demo+'/oidc/callback'
                result=api.ensure_app(
                    application_name(brand, channel),
                    ['authorization_code','refresh_token'],redirect,b['sector_uri'],
                    public=(channel=='app'))
                result.update(brand=brand,root=root,tenant_domain=b['tenant_domain'],
                              channel=channel,kind='user',
                              claim_profile='profile' if channel=='web' else 'minimum',
                              scopes='openid profile email' if channel=='web' else 'openid profile',
                              issuer=tenants[root]['issuer'])
                clients[key]=result
                gate('oidc_app:'+key,'pairwise sector '+b['sector_uri'])

        seller=tenant_apis['commerce'].ensure_app(
            application_name('seller', 'web'), ['authorization_code','refresh_token'],
            demo+'/oidc/callback',brands['magalu']['sector_uri'])
        seller.update(brand='magalu',root='commerce',tenant_domain=ROOT_TENANTS['commerce']['domain'],
                      channel='web',kind='user',claim_profile='profile',
                      scopes='openid profile email',issuer=tenants['commerce']['issuer'])
        clients['seller:web']=seller
        gate('oidc_app:seller:web','B2B seller app in commerce root')

        # M2M is tenant-scoped too; no shared machine credentials across root boundaries.
        m2m_grants={
            'cc':['client_credentials'],
            'jwt':['urn:ietf:params:oauth:grant-type:jwt-bearer'],
            'exchange':['client_credentials','urn:ietf:params:oauth:grant-type:token-exchange'],
        }
        for root,api in tenant_apis.items():
            for suffix,grants in m2m_grants.items():
                key=f'm2m:{root}:{suffix}'
                result=api.ensure_app(application_name(root, 'm2m', suffix),
                                      grants,None,None,kind='m2m')
                result.update(root=root,tenant_domain=ROOT_TENANTS[root]['domain'],
                              brand=ROOT_TENANTS[root]['brands'][0],kind='m2m',
                              channel='backend',claim_profile='m2m',scopes='',
                              issuer=tenants[root]['issuer'])
                if suffix=='cc' and not result.get('client_secret'):
                    raise WSO2Error('M2M client_credentials secret not readable in '+root)
                clients[key]=result
                gate('m2m:'+root+':'+suffix,','.join(grants))

        roles={}
        for root,spec in ROOT_TENANTS.items():
            api=tenant_apis[root]
            buyer_username=spec['people'][0][0]
            buyer_id=users[root+':'+buyer_username]['id']
            first_app=clients[spec['brands'][0]+':web']['app_id']
            role_key=root+':customer'
            roles[role_key]=api.ensure_application_role('poc_customer',first_app,[buyer_id])
            gate('role:'+role_key,'application-scoped role; member '+buyer_username)
        roles['commerce:seller_admin']=tenant_apis['commerce'].ensure_application_role(
            'poc_seller_admin',seller['app_id'],[users['commerce:bruno.seller']['id']])
        gate('role:commerce:seller_admin','seller app scoped role + synthetic representative')

        manifest={'schema_version':2, 'issuer':tenants['commerce']['issuer'],
                  'is_public_url':public,'is_internal_url':internal,
                  'root_tenants':tenants,'brands':brands,'clients':clients,
                  'users':users,'roles':roles,'purposes':PURPOSES,
                  'update_level_expected':os.getenv('IS_EXPECTED_UPDATE_LEVEL','18'),
                  'notice':'Contains development secrets; do not publish or commit.'}
        # Preserve additional independently onboarded root tenants across reruns.
        for section in ('root_tenants','brands','clients','users','roles','purposes'):
            for key,value in old.get(section,{}).items():
                manifest[section].setdefault(key,value)
        ledger=Ledger(required('CONSENT_DB_DSN'))
        ledger.seed(manifest)
        # Default-denied synthetic consent history. User-granted consent is never
        # silently created by bootstrap; real grants require a user-action event.
        from uuid import uuid5, NAMESPACE_URL
        ana=str(uuid5(NAMESPACE_URL,'magalu-ciam-synthetic-person:ana'))
        for purpose_key, purpose in manifest['purposes'].items():
            source_brand=purpose['source']
            client_key=source_brand+':web'
            if client_key in manifest['clients']:
                ledger.transition_consent(ana,client_key,purpose_key,'REVOKED',
                    'baseline-deny:'+purpose_key,'synthetic-demo')
        ledger.seed_business()
        gate('consent_ledger','three brands, seven isolated purposes, private cross-root identity vault')
        secure_json(manifest_path,manifest)
        report['live_server_verified']=True
        report['result']='BOOTSTRAP_VERIFIED'
        report['manual_acceptance_outstanding']=[
            'interactive-pairwise-six-logins','client-claims-minimization',
            'native-consent-enforcement','acr-step-up','rfc8693-actor-token',
            'rfc7523-jti-replay','multi-userstore','b2b-federation',
            'm2m-1000rps-30min']
        secure_json(manifest_path.parent/'bootstrap-report.json',report)
        print('BOOTSTRAP VERIFIED: 2 root tenants, 3 brands, 6 channel apps, 1 seller app, '
              '6 M2M apps, 4 scoped synthetic users, 3 app roles, 7 consent purposes.')
        print('This does not certify the outstanding Section 7 functional/performance tests.')
    except Exception as exc:
        report['result']='BLOCKED'
        report['failure_type']=type(exc).__name__
        report['failure_detail']=str(exc)[:400]
        secure_json(manifest_path.parent/'bootstrap-report.json',report)
        raise


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        LOG.exception('BOOTSTRAP BLOCKED; see generated/bootstrap-report.json: %s',exc)
        sys.exit(1)
