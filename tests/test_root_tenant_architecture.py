from pathlib import Path
import ast
from bootstrap.topology import ROOT_TENANTS, BRANDS, PURPOSES, validate_topology

ROOT=Path(__file__).resolve().parents[1]


def test_hard_root_boundaries_and_three_brands():
    assert validate_topology()
    assert {v['domain'] for v in ROOT_TENANTS.values()} == {'magalu.demo','magalupay.demo'}
    assert set(BRANDS)=={'magalu','netshoes','magalupay'}
    assert ROOT_TENANTS['commerce']['brands']==('magalu','netshoes')
    assert ROOT_TENANTS['fintech']['brands']==('magalupay',)


def test_no_org_share_or_root_user_share_in_active_bootstrap():
    active=(ROOT/'bootstrap/main.py').read_text()
    assert 'ensure_root_tenant(' in active
    assert 'ensure_org(' not in active
    assert 'share_app(' not in active
    assert 'share_users(' not in active
    assert "for channel in ('web','app')" in active
    assert "for root,api in tenant_apis.items()" in active
    ast.parse(active)


def test_separate_identity_vault_and_consent_boundaries():
    sql=(ROOT/'consent/migrations/003_root_tenants.sql').read_text()
    assert 'CREATE TABLE IF NOT EXISTS demo.root_tenants' in sql
    assert 'CREATE TABLE IF NOT EXISTS demo.tenant_identities' in sql
    assert 'FOREIGN KEY (root_key)' in sql
    assert len(PURPOSES)>=7


def test_new_compose_has_isolated_wso2_and_consent_postgres():
    compose=(ROOT/'compose.isolated.yaml').read_text()
    assert 'name: magalu-ciam73-isolated' in compose
    assert 'identity-db:' in compose
    assert 'identity-db-data:' in compose
    assert '9543' in compose
    assert 'Dockerfile.isolated' in compose


def test_no_user_linkage_by_shared_wso2_user_id():
    source=(ROOT/'demo/store.py').read_text()
    assert 'demo.tenant_identities' in source
    assert 'synthetic-person' in source
    assert 'ti.local_username' in source
