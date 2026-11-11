"""Regression coverage for APP-60001 in WSO2 IS 7.3.18."""
import ast
from pathlib import Path
import pytest

from bootstrap.app_naming import application_name, check_application_name
from bootstrap.topology import BRANDS, ROOT_TENANTS
from bootstrap.wso2 import WSO2

ROOT = Path(__file__).resolve().parents[1]


def test_all_baseline_channel_apps_have_legal_unique_names():
    names = [application_name(brand, channel)
             for brand in BRANDS for channel in ('web', 'app')]
    assert len(names) == 6
    assert len(set(names)) == 6
    assert all('|' not in name for name in names)


def test_seller_and_m2m_apps_have_legal_unique_names():
    names = [application_name('seller', 'web')]
    names += [application_name(root, 'm2m', suffix)
              for root in ROOT_TENANTS for suffix in ('cc', 'jwt', 'exchange')]
    assert len(names) == 7
    assert len(set(names)) == 7
    assert all('|' not in name for name in names)


def test_onboarding_app_names_are_valid():
    assert application_name('magalufresh', 'web') == 'MAGALU CIAM POC - MAGALUFRESH - WEB'
    assert application_name('magalufresh', 'app') == 'MAGALU CIAM POC - MAGALUFRESH - APP'


@pytest.mark.parametrize('bad', [
    'MAGALU CIAM POC | MAGALU | WEB',
    'MAGALU  CIAM POC',
    'Bad/Name',
    'MAGALU CIAM POC ',
    '',
])
def test_invalid_names_blocked_before_http(bad):
    with pytest.raises(ValueError):
        check_application_name(bad)


def test_adapter_fails_fast_before_api_call(monkeypatch):
    api = WSO2.__new__(WSO2)
    def forbidden(*args, **kwargs):
        raise AssertionError('HTTP call must not occur for invalid application name')
    monkeypatch.setattr(api, 'application_id', forbidden)
    with pytest.raises(ValueError):
        api.ensure_app('MAGALU CIAM POC | MAGALU | WEB', [], None, None)


def test_no_legacy_bad_names_in_bootstrap_or_onboarding():
    for relative in ('bootstrap/main.py', 'scripts/onboard_brand.py'):
        source=(ROOT / relative).read_text()
        ast.parse(source)
        assert 'MAGALU CIAM POC |' not in source
        assert 'application_name(' in source
