"""Idempotent, fail-closed WSO2 IS 7.3 REST API adapter.

No direct writes to WSO2 product database. API failures are *not* treated as success.
"""
import logging
from urllib.parse import quote, urlsplit
import re
import requests
from requests.auth import HTTPBasicAuth
from bootstrap.app_naming import check_application_name

LOG = logging.getLogger(__name__)


class WSO2Error(RuntimeError):
    pass


class WSO2:
    def __init__(self, url: str, username: str, password: str, verify: bool, bearer: str = ''):
        self.base=url.rstrip('/')
        self.session=requests.Session()
        self.session.verify=verify
        if not verify:
            requests.packages.urllib3.disable_warnings()
        if bearer:
            self.session.headers['Authorization']='Bearer '+bearer
        else:
            self.session.auth=HTTPBasicAuth(username,password)
        self.session.headers.update({'Accept':'application/json','Content-Type':'application/json'})

    def call(self, method, path, *, expected=(200,), **kwargs):
        try:
            r=self.session.request(method,self.base+path,timeout=(8,35),**kwargs)
        except requests.RequestException as exc:
            raise WSO2Error(f'{method} {path}: transport failure: {exc}') from exc
        if r.status_code not in expected:
            excerpt=(r.text or '')[:800]
            raise WSO2Error(f'{method} {path}: HTTP {r.status_code}; {excerpt}. '
                            'Check API auth scopes and IS update level.')
        if r.status_code==204 or not r.content:
            return None, r
        try:
            return r.json(), r
        except ValueError:
            return {}, r

    def discovery(self):
        paths=['/oauth2/token/.well-known/openid-configuration',
               '/oauth2/oidcdiscovery/.well-known/openid-configuration',
               '/.well-known/openid-configuration']
        for path in paths:
            try:
                data,_=self.call('GET',path)
                if data.get('issuer') and data.get('jwks_uri'):
                    return data
            except WSO2Error:
                continue
        raise WSO2Error('No valid WSO2 OIDC discovery document found')

    def ensure_user(self, username: str, email: str, password: str, given_name: str):
        # Use SCIM2 as the supported WSO2 provisioner; idempotent by exact userName.
        filt=quote(f'userName eq "{username}"',safe='')
        data,_=self.call('GET',f'/scim2/Users?filter={filt}',expected=(200,))
        for user in data.get('Resources',[]):
            if user.get('userName','').casefold()==username.casefold():
                LOG.info('User exists: %s',username)
                return user['id']
        payload={'schemas':['urn:ietf:params:scim:schemas:core:2.0:User'],
                 'userName':username,'password':password,'name':{'givenName':given_name},
                 'emails':[{'value':email,'primary':True}], 'active':True}
        data,_=self.call('POST','/scim2/Users',json=payload,expected=(201,))
        if not data.get('id'):
            raise WSO2Error('SCIM create returned no id for '+username)
        LOG.info('Created SCIM user %s',username)
        return data['id']

    def applications(self):
        apps=[]
        for offset in range(0,300,100):
            data,_=self.call('GET',f'/api/server/v1/applications?limit=100&offset={offset}')
            chunk=data.get('applications',[])
            apps.extend(chunk)
            if len(chunk)<100:
                break
        return apps

    def application_id(self, name):
        """Find an exact application name in the CURRENT root tenant only.

        Refuse ambiguity rather than accidentally binding a client to the wrong app.
        """
        matches=[a for a in self.applications() if a.get('name')==name]
        if len(matches)>1:
            raise WSO2Error('Duplicate WSO2 application name in current tenant: '+name)
        if not matches:
            return None
        app_id=matches[0].get('id')
        if not app_id:
            raise WSO2Error('Application list omitted ID for '+name)
        return app_id

    @staticmethod
    def _created_application_id(data, response):
        """Handle WSO2's 201 responses with a JSON body, Location, or neither.

        Only syntactically valid API resource URLs are considered. The ID must
        still be verified against a tenant-scoped GET or application-list readback.
        """
        if data is not None and not isinstance(data, dict):
            raise WSO2Error('Application create returned unexpected JSON type')
        body_id=(data or {}).get('id')
        location=(response.headers.get('Location') or '').strip()
        location_id=None
        if location:
            url_path=urlsplit(location).path.rstrip('/')
            match=re.search(r'/api/server/v1/applications/([a-zA-Z0-9._-]+)$',url_path)
            if match:
                location_id=match.group(1)
        if body_id and location_id and str(body_id)!=location_id:
            raise WSO2Error('Application create ID conflicts with Location header')
        return str(body_id or location_id) if (body_id or location_id) else None

    def ensure_app(self,name,grant_types,redirect,sector,public=False,kind='user'):
        check_application_name(name)  # fail before reaching the management API
        app_id=self.application_id(name)
        if not app_id:
            # Create once; a 201 response can have NO JSON body. Never POST
            # again just because the returned data is null/empty.
            data,response=self.call('POST','/api/server/v1/applications',json={
                'name':name,'description':'Magalu CIAM Section 7 proof-of-concept',
                'inboundProtocolConfiguration':{'oidc':{'grantTypes':grant_types,
                    'callbackURLs':[redirect] if redirect else [], 'publicClient':public}}},
                expected=(201,))
            response_id=self._created_application_id(data,response)
            # Authoritative tenant-scoped readback is preferable to trusting
            # headers; it also recovers from 201 with NO body AND NO Location.
            listed_id=self.application_id(name)
            if listed_id:
                if response_id and str(listed_id)!=str(response_id):
                    raise WSO2Error('Created application ID readback mismatch: '+name)
                app_id=listed_id
            elif response_id:
                detail,_=self.call('GET',f'/api/server/v1/applications/{quote(response_id,safe="")}',
                                   expected=(200,))
                if not isinstance(detail,dict) or detail.get('name')!=name:
                    raise WSO2Error('Created application name readback mismatch: '+name)
                app_id=response_id
            if not app_id:
                raise WSO2Error('WSO2 returned HTTP 201 but application was not found by '
                                'exact name and no usable ID/Location was returned: '+name)
            LOG.info('Created and verified application %s: %s',name,app_id)
        else:
            LOG.info('Application exists: %s',name)
        # Preserve any version-specific defaults returned by this WSO2 release.
        path=f'/api/server/v1/applications/{app_id}/inbound-protocols/oidc'
        config,_=self.call('GET',path)
        if not config.get('clientId'):
            raise WSO2Error(f'Application {name} lacks OIDC clientId')
        config['grantTypes']=grant_types
        config['callbackURLs']=[redirect] if redirect else []
        config['publicClient']=public
        if kind in ('user','user_public'):
            config['pkce']={'mandatory':True,'supportPlainTransformAlgorithm':False}
            config['subject']=({'subjectType':'public'} if kind=='user_public'
                               else {'subjectType':'pairwise','sectorIdentifierUri':sector})
            config['refreshToken']={'expiryInSeconds':60*60*24*30,
                                    'renewRefreshToken':True}
        if kind=='m2m':
            config['accessToken']={**config.get('accessToken',{}), 'type':'JWT',
                                   'applicationAccessTokenExpiryInSeconds':7200}
        # PUT may reject server-computed properties in different versions. Restrict to accepted keys.
        accepted={'clientId','clientSecret','grantTypes','callbackURLs','allowedOrigins','publicClient',
                  'pkce','accessToken','hybridFlow','refreshToken','subjectToken','idToken',
                  'logout','validateRequestObjectSignature','scopeValidators','clientAuthentication',
                  'requestObject','pushAuthorizationRequest','subject','isFAPIApplication'}
        payload={k:v for k,v in config.items() if k in accepted and v is not None}
        self.call('PUT',path,json=payload,expected=(200,201))
        read,_=self.call('GET',path)
        if read.get('grantTypes') != grant_types and not set(grant_types)<=set(read.get('grantTypes',[])):
            raise WSO2Error('Readback mismatch of grant types: '+name)
        if kind in ('user','user_public'):
            subject=read.get('subject',{})
            if kind=='user_public':
                if str(subject.get('subjectType','')).lower()!='public':
                    raise WSO2Error('Public subject readback failed for isolated delegation client: '+name)
            elif str(subject.get('subjectType','')).lower()!='pairwise' or subject.get('sectorIdentifierUri')!=sector:
                raise WSO2Error('Pairwise configuration readback failed: '+name)
            if not read.get('pkce',{}).get('mandatory'):
                raise WSO2Error('PKCE not mandatory in application: '+name)
        return {'app_id':app_id,'client_id':read['clientId'],
                'client_secret':read.get('clientSecret') or config.get('clientSecret'),
                'grants':read.get('grantTypes',[])}

    def list_root_tenants(self):
        """List real WSO2 root tenants via the management API, with pagination.

        WSO2 can return HTTP 400 (TM-60015) for GET /tenants/domain/{domain}
        when the tenant is absent. Listing avoids treating that expected condition
        as an authentication or infrastructure failure.
        """
        tenants=[]
        page_size=100
        for offset in range(0, 10000, page_size):
            data,_=self.call('GET',
                f'/api/server/v1/tenants?limit={page_size}&offset={offset}',
                expected=(200,))
            if not isinstance(data, dict):
                raise WSO2Error('Tenant listing returned an invalid response type')
            chunk=data.get('tenants')
            if chunk is None and data.get('totalResults')==0:
                return tenants
            if not isinstance(chunk, list):
                raise WSO2Error('Tenant listing did not contain a tenants array')
            if any(not isinstance(item,dict) for item in chunk):
                raise WSO2Error('Tenant listing contained an invalid tenant entry')
            tenants.extend(chunk)
            if len(chunk)<page_size:
                return tenants
        raise WSO2Error('Tenant listing exceeded safe pagination limit')

    def ensure_root_tenant(self, domain: str, name: str, owner: str, owner_password: str):
        """Create or verify an INDEPENDENT WSO2 root tenant via REST API.

        This never provisions a child organization. Idempotent reads use the
        authenticated tenant list, not a domain lookup that returns 400 for
        missing tenants on some WSO2 IS updates.
        """
        def find():
            matches=[tenant for tenant in self.list_root_tenants()
                     if str(tenant.get('domain','')).casefold()==domain.casefold()]
            if len(matches)>1:
                raise WSO2Error('Multiple root tenants reported with domain '+domain)
            return matches[0] if matches else None

        data=find()
        if data is None:
            payload={'name':name,'domain':domain,'owners':[{
                'username':owner,'password':owner_password,
                'email':f'{owner}@{domain}','firstname':'Magalu',
                'lastname':'PoC Administrator','provisioningMethod':'inline-password'}]}
            self.call('POST','/api/server/v1/tenants',json=payload,expected=(201,))
            LOG.info('Created ROOT TENANT %s',domain)
            # Read back the newly created root tenant, rather than treating a
            # successful POST alone as proof of its existence.
            data=find()
        else:
            LOG.info('ROOT TENANT already exists: %s',domain)
        if not data or data.get('domain')!=domain or not data.get('id'):
            raise WSO2Error('Root tenant readback mismatch for '+domain)
        return data['id']

    def ensure_application_role(self, name: str, app_id: str, user_ids: list[str]):
        """Provision a v2 SCIM application-scoped role, with explicit member IDs."""
        if not user_ids or not app_id:
            raise WSO2Error('Role requires existing users and application audience')
        data,_=self.call('GET','/scim2/v2/Roles?count=100',expected=(200,))
        for role in data.get('Resources',[]):
            audience=role.get('audience') or {}
            if role.get('displayName')==name and audience.get('value')==app_id:
                return role['id']
        payload={
            'schemas':['urn:ietf:params:scim:schemas:extension:2.0:Role'],
            'displayName':name,
            'audience':{'type':'application','value':app_id},
            'users':[{'value':u} for u in user_ids],
            'permissions':[],
        }
        data,_=self.call('POST','/scim2/v2/Roles',json=payload,
                         headers={'Content-Type':'application/scim+json'},expected=(201,))
        if not data.get('id'):
            raise WSO2Error('Role creation returned no ID: '+name)
        role, _ = self.call('GET','/scim2/v2/Roles/'+quote(data['id'],safe=''),expected=(200,))
        if role.get('displayName')!=name or (role.get('audience') or {}).get('value')!=app_id:
            raise WSO2Error('Application role readback mismatch: '+name)
        LOG.info('Created and verified application role %s for %s',name,app_id)
        return role['id']
