"""Customer-owned immutable consent and attribute provenance ledger."""
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import psycopg
from psycopg.rows import dict_row


class Ledger:
    def __init__(self, dsn: str):
        self.dsn = dsn

    @contextmanager
    def tx(self):
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.transaction():
                yield conn

    def seed(self, manifest: dict):
        """Provision synthetic evaluation ledger; never changes WSO2-owned tables."""
        with self.tx() as conn:
            for root,t in manifest['root_tenants'].items():
                conn.execute("""INSERT INTO demo.root_tenants(root_key,domain,display_name,tenant_id)
                    VALUES(%s,%s,%s,%s) ON CONFLICT(root_key) DO UPDATE SET
                    tenant_id=EXCLUDED.tenant_id,display_name=EXCLUDED.display_name""",
                    (root,t['domain'],t['name'],t['id']))
            for key,b in manifest['brands'].items():
                conn.execute("""INSERT INTO demo.brands(brand_key,display_name,organization_id,
                    sector_identifier_uri,root_key)
                    VALUES(%s,%s,%s,%s,%s) ON CONFLICT(brand_key) DO UPDATE SET
                    organization_id=EXCLUDED.organization_id,
                    sector_identifier_uri=EXCLUDED.sector_identifier_uri,
                    root_key=EXCLUDED.root_key""",
                    (key,b['name'],None,b['sector_uri'],b['root']))
            for key,cl in manifest['clients'].items():
                if cl['kind']!='user':
                    continue
                conn.execute("""INSERT INTO demo.clients(client_key,brand_key,channel,oauth_client_id,claim_profile)
                    VALUES(%s,%s,%s,%s,%s) ON CONFLICT(client_key) DO UPDATE SET
                    oauth_client_id=EXCLUDED.oauth_client_id,claim_profile=EXCLUDED.claim_profile""",
                    (key,cl['brand'],cl['channel'],cl['client_id'],cl['claim_profile']))
            # Person key is a *private and explicit* synthetic vault association.
            # Identical usernames in two roots do not indicate account identity.
            for key,user in manifest['users'].items():
                pid=uuid.uuid5(uuid.NAMESPACE_URL,'magalu-ciam-synthetic-person:'+user['person_key'])
                conn.execute("""INSERT INTO demo.principals(principal_id,scim_user_id,username)
                    VALUES(%s,%s,%s) ON CONFLICT(principal_id) DO NOTHING""",
                    (pid,user['id'],user['username']))
                conn.execute("""INSERT INTO demo.tenant_identities(root_key,scim_user_id,
                    local_username,principal_id) VALUES(%s,%s,%s,%s)
                    ON CONFLICT(root_key,local_username) DO UPDATE SET
                    scim_user_id=EXCLUDED.scim_user_id,principal_id=EXCLUDED.principal_id""",
                    (user['root'],user['id'],user['username'],pid))
            for key,p in manifest['purposes'].items():
                conn.execute("""INSERT INTO demo.purposes(purpose_key,source_brand,target_brand,scope_name,
                    consent_text,title,icon,visibility,consent_required)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(purpose_key) DO UPDATE SET
                    consent_text=EXCLUDED.consent_text,title=EXCLUDED.title,
                    target_brand=EXCLUDED.target_brand""",
                    (key,p['source'],p.get('target'),p['scope'],p['text'],p['title'],
                    p['icon'],p['visibility'],p['required']))

    def seed_business(self):
        with self.tx() as conn:
            conn.execute('''INSERT INTO demo.businesses(business_key,public_name,synthetic_cnpj,owning_brand)
                 VALUES('seller-demo','Seller Demo LTDA','00.000.000/0000-00','magalu')
                 ON CONFLICT (business_key) DO NOTHING''')
            conn.execute('''INSERT INTO demo.business_representatives
                 (business_key,principal_id,role_name,is_legal_representative)
                 SELECT 'seller-demo',principal_id,'OWNER',TRUE FROM demo.principals
                 WHERE username='bruno.seller'
                 ON CONFLICT (business_key,principal_id) DO NOTHING''')

    def business_access(self, principal_id: str, business_key='seller-demo'):
        with self.tx() as conn:
            return conn.execute('''SELECT b.public_name,b.synthetic_cnpj,r.role_name,
                r.is_legal_representative,r.active FROM demo.business_representatives r
                JOIN demo.businesses b ON b.business_key=r.business_key
                WHERE r.business_key=%s AND r.principal_id=%s''',
                (business_key,principal_id)).fetchone()

    def business_authorize(self, principal_id: str, action: str):
        if action not in ('view-dashboard','change-payout-account'):
            raise ValueError('Unrecognized seller operation')
        with self.tx() as conn:
            member=conn.execute('''SELECT role_name,is_legal_representative,active
                  FROM demo.business_representatives WHERE business_key='seller-demo'
                  AND principal_id=%s''',(principal_id,)).fetchone()
            allowed=bool(member and member['active'] and
                (action=='view-dashboard' or
                 (member['role_name']=='OWNER' and member['is_legal_representative'])))
            reason='ROLE_AND_REPRESENTATION' if allowed else 'ROLE_OR_REPRESENTATION_DENIED'
            conn.execute('''INSERT INTO demo.business_policy_events(principal_id,business_key,action,decision,reason)
                 VALUES(%s,'seller-demo',%s,%s,%s)''',
                 (principal_id,action,'ALLOW' if allowed else 'DENY',reason))
            return {'decision':'ALLOW' if allowed else 'DENY','reason':reason}

    def principal_by_username(self, username: str):
        with self.tx() as conn:
            return conn.execute('SELECT * FROM demo.principals WHERE username=%s', (username,)).fetchone()

    def bind_subject(self, username: str, client_key: str, sub: str):
        """Resolve a verified tenant-local login through the private fixture mapping."""
        with self.tx() as conn:
            record=conn.execute("""SELECT ti.principal_id
                FROM demo.tenant_identities ti
                JOIN demo.root_tenants rt ON rt.root_key=ti.root_key
                JOIN demo.brands b ON b.root_key=ti.root_key
                JOIN demo.clients c ON c.brand_key=b.brand_key
                WHERE c.client_key=%s AND ti.local_username=%s""",
                (client_key,username)).fetchone()
            if not record:
                raise ValueError('No independently seeded identity mapping in this root tenant')
            conn.execute("""INSERT INTO demo.subject_bindings(principal_id,client_key,pairwise_sub)
                VALUES(%s,%s,%s) ON CONFLICT(principal_id,client_key)
                DO UPDATE SET pairwise_sub=EXCLUDED.pairwise_sub,last_seen=now()""",
                (record['principal_id'],client_key,sub))
            return str(record['principal_id'])

    def bindings(self, principal_id: str):
        with self.tx() as conn:
            records = conn.execute('SELECT client_key,pairwise_sub FROM demo.subject_bindings WHERE principal_id=%s',
                                   (principal_id,)).fetchall()
            return {r['client_key']:r['pairwise_sub'] for r in records}

    def active_purposes(self, source: str):
        with self.tx() as conn:
            return conn.execute('SELECT * FROM demo.purposes WHERE source_brand=%s ORDER BY purpose_key',
                                (source,)).fetchall()

    def current_consent(self, principal_id: str, client_key: str, purpose_key: str):
        with self.tx() as conn:
            return conn.execute('''SELECT * FROM demo.consent_current WHERE principal_id=%s
               AND client_key=%s AND purpose_key=%s''', (principal_id,client_key,purpose_key)).fetchone()

    def transition_consent(self, principal_id: str, client_key: str, purpose_key: str,
                           action: str, idem_key: str, evidence_source='user-action'):
        if action not in ('GRANTED','REVOKED'):
            raise ValueError('Invalid transition')
        if not idem_key or len(idem_key) > 200:
            raise ValueError('Invalid idempotency key')
        with self.tx() as conn:
            # One global linear chain in this POC; advisory lock makes the append atomic.
            conn.execute('SELECT pg_advisory_xact_lock(7283018)')
            existing=conn.execute('SELECT event_id FROM demo.consent_events WHERE idempotency_key=%s',
                                  (idem_key,)).fetchone()
            if existing:
                return str(existing['event_id'])
            p = conn.execute('''SELECT p.*,c.brand_key AS client_brand FROM demo.purposes p
               JOIN demo.clients c ON c.client_key=%s WHERE p.purpose_key=%s''',
               (client_key,purpose_key)).fetchone()
            if not p or p['source_brand'] != p['client_brand']:
                raise ValueError('Cross-tenant scope/client mismatch: fail closed')
            prev=conn.execute('SELECT event_hash FROM demo.consent_events ORDER BY event_seq DESC LIMIT 1').fetchone()
            prev_hash=prev['event_hash'] if prev else None
            event_id=str(uuid.uuid4())
            payload = dict(event_id=event_id,principal_id=str(principal_id),source=p['source_brand'],
                target=p['target_brand'],client=client_key,scope=p['scope_name'],purpose=purpose_key,
                action=action,evidence_source=evidence_source,idempotency_key=idem_key,previous_hash=prev_hash)
            digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            conn.execute('''INSERT INTO demo.consent_events(event_id,principal_id,source_brand,target_brand,
               client_key,scope_name,purpose_key,action,evidence_source,idempotency_key,previous_hash,event_hash)
               VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
               (event_id,principal_id,p['source_brand'],p['target_brand'],client_key,p['scope_name'],purpose_key,
                action,evidence_source,idem_key,prev_hash,digest))
            return event_id

    def histories(self, principal_id: str, brand_key: str):
        with self.tx() as conn:
            return conn.execute('''SELECT event_id,event_seq,source_brand,target_brand,client_key,
               scope_name,purpose_key,action,evidence_source,recorded_at,event_hash FROM demo.consent_events
               WHERE principal_id=%s AND source_brand=%s ORDER BY event_seq DESC LIMIT 100''',
               (principal_id, brand_key)).fetchall()

    def record_attribute(self, principal_id: str, attribute_key: str, verified: bool, method='demo-verification'):
        allowed={'cpf','email_otp','phone_otp','device','face_liveness','address'}
        if attribute_key not in allowed:
            raise ValueError('Unknown attribute')
        expires_at=datetime.now(timezone.utc)+timedelta(days=365)
        with self.tx() as conn:
            conn.execute('''INSERT INTO demo.attribute_events(principal_id,attribute_key,assertion_hash,
                verification_source,verification_method,effective_at,expires_at,state,reason)
                VALUES(%s,%s,%s,%s,%s,now(),%s,%s,%s)''',
                (principal_id,attribute_key,hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest(),
                 'synthetic-demo-provider',method,expires_at,'VERIFIED' if verified else 'INVALIDATED',
                 'POC fixture; not a real CPF/OTP/biometric verification'))

    def attributes(self, principal_id: str):
        with self.tx() as conn:
            return conn.execute('SELECT * FROM demo.attribute_latest WHERE principal_id=%s ORDER BY attribute_key',
                                (principal_id,)).fetchall()
