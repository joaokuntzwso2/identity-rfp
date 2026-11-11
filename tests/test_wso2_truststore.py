from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_73_dockerfile_truststore_and_jdbc():
    dockerfile = (ROOT / "docker/wso2/Dockerfile.isolated").read_text()
    assert "client-truststore.p12" in dockerfile
    assert 'TRUSTSTORE="$SECURITY/client-truststore.p12"' in dockerfile
    assert "-storetype PKCS12" in dockerfile
    assert "-alias magalu-poc-sector-ca" in dockerfile
    assert "postgresql-jdbc.jar" in dockerfile
    assert "repository/resources/security/client-truststore.jks" not in dockerfile


def test_73_template_points_to_patched_truststore():
    config = (ROOT / "docker/wso2/deployment.isolated.template.toml").read_text()
    config = config.replace("${IS_ADMIN_PASSWORD}", "dummy").replace("${IS_DB_USER}", "wso2").replace("${IS_DB_PASSWORD}", "dummy")
    parsed = tomllib.loads(config)
    assert parsed["truststore"] == {
        "file_name": "client-truststore.p12",
        "type": "PKCS12",
        "password": "wso2carbon",
    }
    assert parsed["database"]["identity_db"]["name"] == "wso2_identity"
