# WSO2 7.3.18 callbackURLs hotfix

## Cause

WSO2 application management `PUT /applications/{id}/inbound-protocols/oidc` returns 501 when supplied two separate OAuth callbackURLs. Previously the second-stage provisioner tried to add an independent storefront callback to the legacy demo portal callback.

## Fix

The provisioner now stores **one callbackURLs element** per client, for example:

```json
{"callbackURLs": ["regexp=^(?:http://localhost:8180/oidc/callback|http://localhost:8181/callback)$"]}
```

The actual generated expression escapes regex metacharacters and retains only the two exact local URLs for that specific client. Every Web/Mobile client has a separate redirect port (`8181`–`8186`). An existing generated expression is reused without rewriting. Unexpected or broad redirect patterns are rejected, rather than silently replaced.

No `regexp=.*` / wildcard redirect is used. This is an intentional **localhost-only PoC** configuration; in production use a single exact HTTPS redirect URI per OAuth client wherever possible.

## Apply

From your existing isolated demo directory:

```bash
cp bootstrap/storefront_provision.py bootstrap/storefront_provision.py.before-callback-hotfix
unzip -o ~/Downloads/magalu-ciam-is73-six-frontends-callback-hotfix.zip
chmod +x scripts/fix-storefront-callbacks.sh
./scripts/fix-storefront-callbacks.sh
```

The launcher re-runs the idempotent provisioning stage, configures request scopes, application roles, and WSO2 TOTP policy, then starts the frontends if those stages succeed. It leaves the separate root tenants and persistent WSO2/PostgreSQL volumes in place. Existing stage failures are reported in `generated/storefront-provision-report.json`.

## Verify

```bash
./scripts/validate-six-frontends.sh
curl -fsS http://localhost:8181/healthz
```

Then test real browser flows and MFA; passing provisioning does not prove real TOTP or session isolation.
