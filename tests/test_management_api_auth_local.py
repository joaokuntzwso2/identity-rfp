from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_management_api_local_compatibility_is_explicit():
    path = ROOT / 'docker/wso2/deployment.isolated.template.toml'
    template = path.read_text()
    for key in ('IS_ADMIN_PASSWORD', 'IS_DB_USER', 'IS_DB_PASSWORD'):
        template = template.replace('${' + key + '}', 'dummy')
    parsed = tomllib.loads(template)
    assert parsed['compatibility_setting']['basic_auth']['disable_basic_auth'] == {
        'default_value': False, 'target_value': False
    }


def test_fix_is_restricted_and_does_not_touch_database_volumes():
    script = (ROOT / 'scripts/fix-management-api-auth-local.sh').read_text()
    assert "MAGALU_STACK_MODE:-" in script
    assert 'independent-root-tenants-v2' in script
    assert 'magalu-ciam73-s7lab' in script
    assert '--force-recreate is' in script
    assert 'down -v' not in script
    assert 'docker system prune' not in script
    assert 'Tenant API authentication preflight' in script
    assert '  200) ;;' in script
    assert 'tenants?limit=1&offset=0' in script
