"""Tenant- and brand-scoped request approvals. SQL operations are fail-closed.

This is a demonstration business API, not the native WSO2 consent database.
Authorization is enforced by the calling service from actual WSO2-issued scopes.
"""
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from uuid import UUID
import psycopg
from psycopg.rows import dict_row


class WorkflowError(Exception):
    pass


class Workflow:
    def __init__(self, dsn: str):
        self.dsn = dsn

    @staticmethod
    def amount(value: str):
        try:
            number = Decimal(value.strip().replace(',','.')).quantize(Decimal('0.01'))
        except (InvalidOperation, ValueError):
            raise WorkflowError('Informe um valor numérico válido.') from None
        if not (Decimal('0.01') <= number <= Decimal('999999.99')):
            raise WorkflowError('Valor fora dos limites permitidos.')
        return number

    def list_requests(self, tenant: str, brand: str):
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            return conn.execute('''SELECT request_id,subject,amount,currency,status,
                requested_by_sub,approved_by_sub,created_at,approved_at
                FROM demo_workflow.requests WHERE tenant_domain=%s AND brand=%s
                ORDER BY created_at DESC LIMIT 24''', (tenant,brand)).fetchall()

    def request(self, tenant: str, brand: str, subject: str, amount: str,
                actor_sub: str, issuer: str, client_id: str):
        title = subject.strip()[:120]
        if not 4 <= len(title) <= 120:
            raise WorkflowError('Descreva a solicitação com pelo menos quatro caracteres.')
        if not actor_sub or not issuer or not client_id:
            raise WorkflowError('Identidade ou cliente OIDC não verificado.')
        total = self.amount(amount)
        with psycopg.connect(self.dsn) as conn:
            with conn.transaction():
                identifier = conn.execute('''INSERT INTO demo_workflow.requests
                    (tenant_domain,brand,subject,amount,currency,status,requested_by_sub,requester_issuer,requester_client_id)
                    VALUES(%s,%s,%s,%s,'BRL','PENDING',%s,%s,%s) RETURNING request_id''',
                    (tenant,brand,title,total,actor_sub,issuer,client_id)).fetchone()[0]
                conn.execute('''INSERT INTO demo_workflow.events(request_id,action,actor_sub,acr,amr)
                    VALUES(%s,'CREATED',%s,NULL,NULL)''',(identifier,actor_sub))
                return str(identifier)

    def pending(self, request_id: str, tenant: str, brand: str):
        try: UUID(request_id)
        except ValueError: raise WorkflowError('Identificador inválido.') from None
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            return conn.execute('''SELECT * FROM demo_workflow.requests
                WHERE request_id=%s AND tenant_domain=%s AND brand=%s''',
                (request_id,tenant,brand)).fetchone()

    def approve(self, request_id: str, tenant: str, brand: str, actor_sub: str,
                issuer: str, acr: str, amr: list[str], auth_time: int):
        """Uses SQL lock: same person cannot approve; no cross-brand/tenant leakage."""
        if not actor_sub or not issuer or 'totp' not in [str(x).lower() for x in amr]:
            raise WorkflowError('WSO2 TOTP proof missing.')
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.transaction():
                target=conn.execute('''SELECT * FROM demo_workflow.requests
                    WHERE request_id=%s AND tenant_domain=%s AND brand=%s FOR UPDATE''',
                    (request_id,tenant,brand)).fetchone()
                if not target or target['status']!='PENDING':
                    raise WorkflowError('Solicitação não encontrada ou já processada.')
                if target['requester_issuer'] != issuer:
                    raise WorkflowError('Aprovação de outro emissor não permitida.')
                if target['requested_by_sub']==actor_sub:
                    raise WorkflowError('Segregação de funções: o solicitante não pode aprovar.')
                conn.execute('''UPDATE demo_workflow.requests SET status='APPROVED',
                    approved_by_sub=%s, approved_at=now() WHERE request_id=%s''',
                    (actor_sub,request_id))
                conn.execute('''INSERT INTO demo_workflow.events
                    (request_id,action,actor_sub,acr,amr,auth_time)
                    VALUES(%s,'APPROVED',%s,%s,%s,%s)''',
                    (request_id,actor_sub,acr,amr,auth_time))
        return True
