import ast
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_consent_is_append_only_and_directional():
    sql=(ROOT/'consent/migrations/001_ledger.sql').read_text()
    assert 'BEFORE UPDATE OR DELETE' in sql
    assert 'source_brand' in sql and 'target_brand' in sql
    assert 'idempotency_key' in sql
    assert 'client_key' in sql and 'scope_name' in sql


def test_load_profile_defines_hard_slo():
    js=(ROOT/'load/m2m.js').read_text()
    assert '1000' in js and '30m' in js
    assert 'rate<=0.001' in js
    assert 'p(95)' in js and 'p(99)' in js
    assert 'dropped_iterations' in js


def test_bootstrap_uses_supported_external_apis():
    src=(ROOT/'bootstrap/wso2.py').read_text()
    assert '/api/server/v1/tenants' in src
    assert 'ensure_root_tenant' in src
    assert 'ensure_application_role' in src
    assert "'subjectType':'pairwise'" in src
    ast.parse(src)


def test_sector_hostname_must_vary_by_brand():
    from urllib.parse import urlparse
    template='https://sector-{brand}'
    first=urlparse(template.format(brand='magalu')).hostname
    second=urlparse(template.format(brand='magalupay')).hostname
    assert first!=second, 'OpenID Connect sector is determined by URI hostname'
    from bootstrap.topology import ROOT_TENANTS, BRANDS
    assert len(ROOT_TENANTS)==2 and len(BRANDS)==3
    assert BRANDS['magalu']['root']==BRANDS['netshoes']['root']
    assert BRANDS['magalupay']['root']!=BRANDS['magalu']['root']
