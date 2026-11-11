"""RFP 7.2 #7: provision a NEW root tenant, not an organization.

This is a fail-closed, deliberate live test. The baseline stays intact.
"""
import json
import os
from pathlib import Path
import secrets
from bootstrap.wso2 import WSO2
from bootstrap.app_naming import application_name
from demo.store import Ledger


def save(path,data):
    tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data,indent=2,ensure_ascii=False))
    tmp.chmod(0o600)
    tmp.replace(path)
    path.chmod(0o600)


def main():
    mp=Path(os.getenv('MANIFEST_FILE','generated/manifest.json'))
    m=json.loads(mp.read_text())
    sp=mp.parent/'tenant-secrets.json'
    owner_secrets=json.loads(sp.read_text())
    name='magalufresh'
    root='fresh'
    domain='magalufresh.demo'
    if name in m['brands']:
        print('Already provisioned: third root tenant',domain)
        return
    tls=os.getenv('IS_TLS_VERIFY','false').lower()=='true'
    base=os.getenv('IS_INTERNAL_URL',m['is_internal_url']).rstrip('/')
    public=os.getenv('DEMO_PUBLIC_URL','http://localhost:8180').rstrip('/')
    superapi=WSO2(base,os.getenv('IS_ADMIN_USERNAME','admin'),
                  os.getenv('IS_ADMIN_PASSWORD','admin'),tls)
    owner_secrets[root]={'owner_password':secrets.token_urlsafe(32)}
    save(sp,owner_secrets)
    tid=superapi.ensure_root_tenant(domain,'Magalu Fresh Delivery','tenantadmin',
                                   owner_secrets[root]['owner_password'])
    api=WSO2(base+'/t/'+domain,'tenantadmin@'+domain,
             owner_secrets[root]['owner_password'],tls)
    d=api.discovery()
    if 'pairwise' not in d.get('subject_types_supported',[]):
        raise RuntimeError('Third root lacks pairwise support')
    fresh_user_password=secrets.token_urlsafe(24)+'aB7!'
    uid=api.ensure_user('ana.magalu','ana.fresh@example.test',fresh_user_password,'Ana')
    sector='https://sector-magalufresh/sectors/magalufresh.json'
    added={}
    for channel in ('web','app'):
        key=name+':'+channel
        cl=api.ensure_app(application_name('magalufresh', channel),
            ['authorization_code','refresh_token'],public+'/oidc/callback',sector,
            public=(channel=='app'))
        cl.update(brand=name,root=root,tenant_domain=domain,channel=channel,
                  kind='user',claim_profile='profile' if channel=='web' else 'minimum',
                  scopes='openid profile email' if channel=='web' else 'openid profile',issuer=d['issuer'])
        added[key]=cl
    role=api.ensure_application_role('poc_customer',added[name+':web']['app_id'],[uid])
    # Update manifest only AFTER all WSO2 API operations succeed.
    m['root_tenants'][root]={'id':tid,'domain':domain,'name':'Magalu Fresh Delivery',
                             'issuer':d['issuer']}
    m['brands'][name]={'name':'Magalu Fresh · Delivery','root':root,'color':'#1cb29f',
                       'tenant_domain':domain,'sector_uri':sector}
    m['clients'].update(added)
    m['users']['fresh:ana.magalu']={'id':uid,'root':root,'username':'ana.magalu',
                                   'person_key':'ana','password':fresh_user_password}
    m['roles']['fresh:customer']=role
    m['purposes']['fresh-profile']={
       'source':name,'target':None,'scope':'profile:basic',
       'title':'Magalu Fresh', 'text':'Perfil mínimo no novo root tenant.',
       'icon':'shield-check','visibility':'private','required':True}
    Ledger(os.getenv('CONSENT_DB_DSN')).seed(m)
    save(mp,m)
    print('CREATED: third independent ROOT tenant, two OIDC apps, synthetic user, role, consent purpose.')
    print('Existing two root tenants and six baseline app identifiers retained in manifest.')
    print('Live user login, policy difference and unaffected request rates still require evidence.')


if __name__=='__main__': main()
