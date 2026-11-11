# WSO2 IS 7.3.0.18 — Local management API auth compatibility

## Symptom

`GET /api/server/v1/tenants/domain/magalu.demo: HTTP 401` with
`Basic authentication is not allowed for this tenant.`

## Root cause

The bootstrap uses HTTP Basic authentication with `admin/admin` to provision
root tenants in the isolated **local-only** WSO2 instance. In recent WSO2
updates, Basic authentication for management REST APIs is disabled by default.
The instance's OAuth2 Discovery endpoint can still be healthy while these
calls fail.

WSO2 documents this behavior and the temporary compatibility setting at:
https://healthcare.docs.wso2.com/docs/install-and-setup/manual/
(Configure IS as Key Manager; section describing recent updates.)

## Apply without data loss

From the project root:

```bash
./scripts/fix-management-api-auth-local.sh
```

The script is idempotent. It adds (or retains) the following setting in the
**isolated** WSO2 template, re-renders `generated/wso2/deployment.toml`,
recreates **only** the isolated WSO2 service, checks the tenant API returns
200 or 404 under Basic authentication, then runs the bootstrap and smoke tests.
It does not remove any PostgreSQL container, volume, or database; it does
not modify another Compose project.

```toml
[compatibility_setting.basic_auth.disable_basic_auth]
default_value = false
target_value = false
```

## Security boundary

This is a development compatibility workaround for a loopback-bound PoC,
**not** a production recommendation. Do not expose the WSO2 HTTP listener on
public interfaces with `admin/admin` or this setting. Replace the management
bootstrap with OAuth2 bearer tokens granted only the relevant internal scopes
and remove the compatibility setting before deployment.

The 401 fix does not prove that tenant, SCIM, OIDC, consent, or token exchange
bootstrap payloads are compatible with the exact updated server. The
idempotent provisioning report records subsequent operations and failures.
