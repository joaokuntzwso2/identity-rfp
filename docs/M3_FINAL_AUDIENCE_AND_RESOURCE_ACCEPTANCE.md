# Milestone 3 — RFC 8693: final resource audience and protected API evidence

## Scope

This additive overlay updates **only** the existing `magalu.demo` M2M RFC 8693
exchange client's OIDC `idToken.audience` list through the WSO2 Management API,
plus the dashboard at port 8180. It does not mutate WSO2 internal tables,
change the six pairwise storefront clients, consent data, or workflow requests.

The registration script preserves all existing audience entries and the other
OIDC settings, writes a private pre-update backup, performs a GET readback,
and only then writes a local receipt to `generated/m3-resource-audience-readback.json`.
A receipt by itself is **not acceptance**: the token must be issued for the
requested audience and the separate resource server must independently validate
signature, issuer, expiry, audience, and scopes.

## Install

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
mkdir -p /tmp/magalu-m3-final
unzip -oq ~/Downloads/magalu-ciam-m3-final-audience-resource-acceptance.zip -d /tmp/magalu-m3-final
bash /tmp/magalu-m3-final/scripts/install-m3-final-acceptance.sh "$PWD"
```

On a WSO2 API 400/403 response, **stop** and inspect the relevant application
configuration; do not lower security controls or change other clients.
The installer archives the overwritten dashboard files under
`generated/backup-m3-final-<timestamp>/` for rollback. The prior WSO2 OIDC
object (which may contain confidential client metadata) is kept as a chmod-600
backup in `generated/`.

## Guided live acceptance

1. Refresh both login captures if needed:

   ```bash
   ./scripts/m3-local.sh capture-subject --insecure-local
   ./scripts/m3-local.sh capture-actor --insecure-local
   ```

2. Open `http://localhost:8180/m3/exchange`, enter the operator key locally,
   confirm that `urn:magalu:poc:requests` was read back as registered. It is
   automatically selected and locked by the frontend.
3. Click **Executar 3 testes reais**. This must call the live WSO2 endpoint,
   use its actual exchanged JWTs in two real HTTP requests to the dashboard's
   synthetic protected resource API, and save the sanitized report.
4. Verify:

   | Gate | Required result |
   |---|---|
   | Ana-only exchange | HTTP 200, valid JWT, `requests:read` only |
   | Bruno delegated exchange | HTTP 200, `sub = Ana`, `act.sub = Bruno`, `requests:read` only |
   | Approval escalation attempt | JWT verified if issued; no `requests:approve` |
   | Protected read endpoint | HTTP **200**; `ALLOW`; verified signature/audience |
   | Protected approve endpoint | HTTP **403**; `INSUFFICIENT_SCOPE`; verified signature/audience |
   | WSO2 audience registration | Management API readback confirmed |
   | Issued JWT audience | Exactly `urn:magalu:poc:requests` |
   | Overall verdict | `PASS` — all gates evidenced |

5. Export JSON from the page or retrieve `/api/m3/exchange/evidence`, and inspect
   the `resource_api` and `audience` objects. Do not share raw tokens, the
   `.env`, or `generated/manifest.json`.

The synthetic approve endpoint **does not update a request**. Functional TOTP
approval is a separate Milestone 2 validation. The overall Milestone 3 still
requires cross-root isolation and native consent-management integration checks.

## Recovery

If no new report appears, inspect only the demo service logs:

```bash
docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml logs --tail=80 demo
```

A stale report is identified by the page as missing `resource_api` HTTP evidence.
If JWTs expire, capture fresh tokens and rerun. If an audience request returns
`invalid_target`, the registration did not take effect in the intended WSO2
client or the client ID differs from the manifest. Review the server's application
OIDC GET readback before changing any configuration.

### Security notes

The existing diagnostic and synthetic endpoints are local-development-only. They
accept the token in an Authorization header and do not log or store raw issued
JWTs. `--insecure-local` is for self-signed localhost certificates only.
Before any externally accessible sandbox deployment, enforce normal TLS trust,
strong secrets, service network boundaries, and authenticated operator access.
