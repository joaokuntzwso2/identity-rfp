"""Milestone 3: real consent-gated demo API using WSO2-verified browser sessions.

This is a *customer-owned* consent model. It does NOT replace or falsely claim
native WSO2 Consent Management v2 API enforcement. The resource is synthetic.
"""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import json
import secrets
import uuid

import psycopg
from psycopg.rows import dict_row
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

TENANTS={'magalu':'magalu.demo','netshoes':'magalu.demo','magalupay':'magalupay.demo'}
PURPOSES={('magalu','netshoes'):'magalu-netshoes',
          ('netshoes','magalu'):'netshoes-magalu',
          ('magalu','magalupay'):'magalu-pay',
          ('magalupay','magalu'):'pay-magalu'}


def verified_subject(rows,brand):
    """Only subjects coming from a storefront's validated BFF session are trusted."""
    expected=TENANTS.get(brand)
    if expected is None:
        raise HTTPException(400,'Unsupported brand')
    matches=[e for e in rows if e.get('brand')==brand and
             e.get('status')=='authenticated' and e.get('tenant')==expected and
             e.get('channel') in ('web','app') and isinstance(e.get('sub'),str) and
             0<len(e['sub'])<=255]
    if not matches:
        raise HTTPException(401,f'Log in to {brand} in this browser first')
    if len({e['sub'] for e in matches})>1:
        raise HTTPException(409,'Conflicting users across web/mobile; log out and retry')
    return expected,matches[0]['sub']


def correct_link_owner(link,tenant,sub):
    return link['source_tenant']==tenant and secrets.compare_digest(link['source_sub'],sub)


def correct_recipient(link,tenant,sub):
    return link['recipient_tenant']==tenant and secrets.compare_digest(link['recipient_sub'],sub)


def permission_for_share(link, action,recipient_tenant,recipient_sub):
    if not correct_recipient(link,recipient_tenant,recipient_sub):
        return False,'WRONG_RECIPIENT_OR_TENANT'
    if action != 'GRANTED':
        return False,'CONSENT_NOT_GRANTED_OR_REVOKED'
    return True,'ACTIVE_DIRECTIONAL_CONSENT'


class ConsentDb:
    def __init__(self,dsn): self.dsn=dsn

    @contextmanager
    def tx(self):
        with psycopg.connect(self.dsn,row_factory=dict_row) as conn:
            with conn.transaction(): yield conn

    def link(self,source,recipient):
        source_brand,source_tenant,source_sub=source
        recipient_brand,recipient_tenant,recipient_sub=recipient
        purpose=PURPOSES.get((source_brand,recipient_brand))
        if not purpose:
            raise HTTPException(400,'No registered directional consent purpose for these brands')
        with self.tx() as conn:
            p=conn.execute('''SELECT p.purpose_key FROM demo.purposes p
                JOIN demo.brands sb ON sb.brand_key=p.source_brand
                JOIN demo.brands rb ON rb.brand_key=p.target_brand
                JOIN demo.root_tenants st ON st.root_key=sb.root_key
                JOIN demo.root_tenants rt ON rt.root_key=rb.root_key
                WHERE p.purpose_key=%s AND p.source_brand=%s AND p.target_brand=%s
                AND st.domain=%s AND rt.domain=%s''',
                (purpose,source_brand,recipient_brand,source_tenant,recipient_tenant)).fetchone()
            if not p: raise HTTPException(409,'Purpose/tenant boundary not provisioned')
            r=conn.execute('''INSERT INTO demo.m3_links
                (purpose_key,source_brand,source_tenant,source_sub,recipient_brand,recipient_tenant,recipient_sub)
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(purpose_key,source_tenant,source_brand,source_sub,
                     recipient_tenant,recipient_brand,recipient_sub)
                DO UPDATE SET purpose_key=EXCLUDED.purpose_key RETURNING link_id''',
                (purpose,source_brand,source_tenant,source_sub,
                 recipient_brand,recipient_tenant,recipient_sub)).fetchone()
            return str(r['link_id'])

    def get(self,link_id,conn):
        try: identifier=uuid.UUID(str(link_id))
        except (TypeError,ValueError): raise HTTPException(404,'Consent link not found')
        r=conn.execute('''SELECT l.*,c.action FROM demo.m3_links l
          LEFT JOIN demo.m3_current c ON c.link_id=l.link_id
          WHERE l.link_id=%s''',(identifier,)).fetchone()
        if not r: raise HTTPException(404,'Consent link not found')
        return r

    def list_for(self,subjects):
        # Enforce tenant/subject selection in SQL: never scan other users' links.
        if not subjects: return []
        clauses=[];params=[]
        for tenant,sub in sorted(subjects):
            clauses.append('((l.source_tenant=%s AND l.source_sub=%s) OR '
                           '(l.recipient_tenant=%s AND l.recipient_sub=%s))')
            params.extend((tenant,sub,tenant,sub))
        statement='''SELECT l.*,c.action,c.created_at AS latest_transition
            FROM demo.m3_links l
            LEFT JOIN demo.m3_current c ON c.link_id=l.link_id
            WHERE '''+(' OR '.join(clauses))+'''
            ORDER BY l.created_at DESC LIMIT 100'''
        with self.tx() as conn:
            return [self.display(row) for row in conn.execute(statement,params).fetchall()]

    @staticmethod
    def display(row):
        return {'link_id':str(row['link_id']),'purpose':row['purpose_key'],
                'source_brand':row['source_brand'],'recipient_brand':row['recipient_brand'],
                'source_tenant':row['source_tenant'],'recipient_tenant':row['recipient_tenant'],
                'state':row.get('action') or 'NOT_GRANTED',
                'latest_transition':str(row.get('latest_transition') or '')}

    def change(self,link_id,actor_tenant,actor_sub,action,key):
        if action not in ('GRANTED','REVOKED'): raise HTTPException(400,'Invalid action')
        if not isinstance(key,str) or not 12<=len(key)<=160:
            raise HTTPException(400,'Invalid idempotency key')
        with self.tx() as conn:
            conn.execute('SELECT pg_advisory_xact_lock(730018)')
            link=self.get(link_id,conn)
            if not correct_link_owner(link,actor_tenant,actor_sub):
                raise HTTPException(403,'Only the source identity may change consent')
            old=conn.execute('SELECT event_id,link_id,action FROM demo.m3_events WHERE idempotency_key=%s',
                             (key,)).fetchone()
            if old:
                if old['link_id']!=link['link_id'] or old['action']!=action:
                    raise HTTPException(409,'Idempotency key was reused for another operation')
                return str(old['event_id'])
            previous=conn.execute('SELECT event_hash FROM demo.m3_events ORDER BY seq DESC LIMIT 1').fetchone()
            prior=previous['event_hash'] if previous else None
            eid=uuid.uuid4()
            payload={'event_id':str(eid),'link_id':str(link['link_id']),
                     'actor_tenant':actor_tenant,'actor_sub':actor_sub,
                     'action':action,'idempotency_key':key,'prior_hash':prior}
            digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            conn.execute('''INSERT INTO demo.m3_events(event_id,link_id,action,actor_tenant,actor_sub,
                idempotency_key,prior_hash,event_hash) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)''',
                (eid,link['link_id'],action,actor_tenant,actor_sub,key,prior,digest))
            return str(eid)

    def shared_profile(self,link_id,recipient_tenant,recipient_sub):
        with self.tx() as conn:
            conn.execute('SELECT pg_advisory_xact_lock(730018)')
            link=self.get(link_id,conn)
            ok,reason=permission_for_share(link,link.get('action'),recipient_tenant,recipient_sub)
            conn.execute('''INSERT INTO demo.m3_access_audit
                (link_id,recipient_tenant,recipient_sub,decision,reason)
                VALUES(%s,%s,%s,%s,%s)''',
                (link['link_id'],recipient_tenant,recipient_sub,'ALLOW' if ok else 'DENY',reason))
            if not ok:
                return None,reason
            # Synthetic, purpose-minimized demonstration data, NOT identity PII.
            return {'subject_reference':hashlib.sha256(
                (link['source_tenant']+':'+link['source_sub']).encode()).hexdigest()[:16],
                'source_brand':link['source_brand'],
                'recipient_brand':link['recipient_brand'],
                'purpose':link['purpose_key'],
                'synthetic_customer_tier':'Prata'},reason

    def audit(self,link_id,actor_subjects):
        with self.tx() as conn:
            l=self.get(link_id,conn)
            if not l_can_view(l,actor_subjects):
                raise HTTPException(403,'No access to this consent audit')
            ev=conn.execute('''SELECT action,created_at,event_hash,prior_hash FROM demo.m3_events
                              WHERE link_id=%s ORDER BY seq''',(l['link_id'],)).fetchall()
            accesses=conn.execute('''SELECT decision,reason,created_at FROM demo.m3_access_audit
                          WHERE link_id=%s ORDER BY created_at DESC LIMIT 50''',(l['link_id'],)).fetchall()
            return {'events':[{'action':e['action'],'at':e['created_at'].isoformat(),
                               'hash':e['event_hash'],'previous':e['prior_hash']} for e in ev],
                    'accesses':[{'decision':a['decision'],'reason':a['reason'],
                                 'at':a['created_at'].isoformat()} for a in accesses]}


def l_can_view(row,subjects):
    return ((row['source_tenant'],row['source_sub']) in subjects or
            (row['recipient_tenant'],row['recipient_sub']) in subjects)


def install(app,dsn,probe,make_session,check_csrf):
    """Attach isolated M3 BFF routes to the existing port-8180 dashboard."""
    db=ConsentDb(dsn)
    template=Jinja2Templates(directory=str(Path(__file__).parent/'templates'))

    def subjects(request):
        rows=probe(request)
        result={}
        for brand in TENANTS:
            try: result[brand]=verified_subject(rows,brand)
            except HTTPException: pass
        return result

    def guard(request):
        origin=request.headers.get('origin','')
        if origin != 'http://localhost:8180':
            raise HTTPException(403,'Origin check rejected')
        s=make_session(request)
        check_csrf(s,request.headers.get('x-csrf-token',''))
        return subjects(request)

    @app.get('/m3/consent',response_class=HTMLResponse)
    def consent_page(request:Request):
        s=make_session(request)
        response=template.TemplateResponse('m3_consent.html',{
            'request':request,'csrf':s['csrf']})
        response.headers['Cache-Control']='no-store, private'
        return response

    @app.get('/api/m3/consents')
    def list_consents(request:Request):
        identities=subjects(request)
        pairs=set(identities.values())
        response=JSONResponse({'consents':db.list_for(pairs),
                'authenticated_brands':sorted(identities.keys()),
                'notice':'Verified storefront sessions; source/recipient linking is explicit, not inferred.'})
        response.headers['Cache-Control']='no-store, private'
        return response

    @app.post('/api/m3/link')
    async def new_link(request:Request):
        identities=guard(request)
        body=await request.json()
        if not isinstance(body,dict):
            raise HTTPException(400,'Invalid JSON object')
        source=body.get('source'); recipient=body.get('recipient')
        if source not in TENANTS or recipient not in TENANTS:
            raise HTTPException(400,'Unsupported brand')
        if source not in identities or recipient not in identities:
            raise HTTPException(401,'Both storefronts must be authenticated to link subjects')
        lid=db.link((source,*identities[source]),(recipient,*identities[recipient]))
        return {'link_id':lid,'status':'LINKED_NOT_CONSENTED'}

    @app.post('/api/m3/consents/{link_id}/{action}')
    async def transition(request:Request,link_id:str,action:str):
        identities=guard(request)
        with db.tx() as conn: link=db.get(link_id,conn)
        source=link['source_brand']
        if source not in identities:
            raise HTTPException(401,'Source storefront session required')
        tenant,sub=identities[source]
        event=db.change(link_id,tenant,sub,action.upper(),request.headers.get('x-idempotency-key',''))
        return {'event_id':event,'state':action.upper()}

    @app.get('/api/m3/resource/{link_id}')
    def resource(request:Request,link_id:str):
        identities=subjects(request)
        with db.tx() as conn: link=db.get(link_id,conn)
        recipient=link['recipient_brand']
        if recipient not in identities:
            # No authenticated recipient session: never release data.
            raise HTTPException(401,'Recipient storefront login required')
        tenant,sub=identities[recipient]
        data,reason=db.shared_profile(link_id,tenant,sub)
        if data is None:
            raise HTTPException(403,'Access denied: '+reason)
        resp=JSONResponse({'decision':'ALLOW','protected_profile':data})
        resp.headers['Cache-Control']='no-store, private'
        return resp

    @app.get('/api/m3/audit/{link_id}')
    def audit(request:Request,link_id:str):
        identities=subjects(request)
        return db.audit(link_id,set(identities.values()))
