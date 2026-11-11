"""Section 7 test topology: two ROOT tenants, three brands; no child organizations.

No cross-tenant identities are implicitly shared by WSO2. `person_key` is an
explicit, operator-controlled synthetic vault mapping for this PoC only.
"""
from dataclasses import dataclass

ROOT_TENANTS = {
    'commerce': {
        'domain': 'magalu.demo', 'name': 'Magalu Commerce',
        'owner': 'tenantadmin', 'brands': ('magalu', 'netshoes'),
        'people': (
            ('ana.magalu', 'ana', 'Ana', 'ana.commerce@example.test'),
            ('bruno.seller', 'bruno', 'Bruno', 'bruno.seller@example.test'),
        ),
        'roles': ('poc_buyer', 'poc_seller_admin'),
    },
    'fintech': {
        'domain': 'magalupay.demo', 'name': 'MagaluPay Fintech',
        'owner': 'tenantadmin', 'brands': ('magalupay',),
        'people': (
            ('ana.magalu', 'ana', 'Ana', 'ana.pay@example.test'),
            ('carla.risk', 'carla', 'Carla', 'carla.risk@example.test'),
        ),
        'roles': ('poc_customer', 'poc_risk_operator'),
    },
}

BRANDS = {
    'magalu': {'name': 'Magalu · Retail', 'root': 'commerce', 'color': '#005cf0'},
    'netshoes': {'name': 'Netshoes · Sports', 'root': 'commerce', 'color': '#64ceaa'},
    'magalupay': {'name': 'MagaluPay · Fintech', 'root': 'fintech', 'color': '#6941c6'},
}

PURPOSES = {
    'retail-profile': dict(source='magalu', target=None, scope='profile:basic',
        title='Experiência personalizada Magalu', text='Dados básicos de perfil para a experiência de compra Magalu.',
        icon='user-round', visibility='private', required=True),
    'netshoes-profile': dict(source='netshoes', target=None, scope='profile:basic',
        title='Experiência personalizada Netshoes', text='Dados básicos de perfil para a experiência de compra Netshoes.',
        icon='user-round', visibility='private', required=True),
    'pay-risk': dict(source='magalupay', target=None, scope='risk:assessment',
        title='Prevenção a fraude MagaluPay', text='Análise de risco no contexto MagaluPay.',
        icon='shield-check', visibility='private', required=True),
    'magalu-netshoes': dict(source='magalu', target='netshoes', scope='share:identity',
        title='Compartilhar Magalu → Netshoes', text='Compartilhamento explícito nesta direção, sem reciprocidade automática.',
        icon='arrow-right-left', visibility='allow-list', required=False),
    'netshoes-magalu': dict(source='netshoes', target='magalu', scope='share:identity',
        title='Compartilhar Netshoes → Magalu', text='Consentimento independente, não herdado de Magalu → Netshoes.',
        icon='arrow-right-left', visibility='allow-list', required=False),
    'magalu-pay': dict(source='magalu', target='magalupay', scope='share:identity',
        title='Compartilhar Magalu → MagaluPay', text='Consentimento entre raízes, apenas com autorização explícita.',
        icon='arrow-right-left', visibility='allow-list', required=False),
    'pay-magalu': dict(source='magalupay', target='magalu', scope='share:identity',
        title='Compartilhar MagaluPay → Magalu', text='Permissão reversa independente e auditável.',
        icon='arrow-right-left', visibility='allow-list', required=False),
}


def validate_topology():
    assert len(ROOT_TENANTS) == 2
    assert len(BRANDS) == 3
    assert {b for t in ROOT_TENANTS.values() for b in t['brands']} == set(BRANDS)
    assert len({t['domain'] for t in ROOT_TENANTS.values()}) == 2
    assert len(ROOT_TENANTS['commerce']['brands']) >= 2
    assert all(b['root'] in ROOT_TENANTS for b in BRANDS.values())
    return True

validate_topology()
