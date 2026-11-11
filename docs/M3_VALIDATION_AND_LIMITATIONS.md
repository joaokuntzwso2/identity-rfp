# Magalu CIAM Milestone 3 — Consent Enforcement + RFC 8693

**Status:** Source patch and local policy tests only. Execute live tests on the customer's isolated WSO2 7.3.0.18 stack before claiming PASS.

## 0. Scope and architectural limits

This extends the **customer-owned consent ledger** with a live resource-server authorization check. It does not modify WSO2-owned tables, and it does not claim WSO2 Consent Management v2 is synchronized. A native WSO2 v2 integration/verification is still required if the RFP evaluation expects native consent receipts and self-service views.

Each root tenant retains its own WSO2 accounts, OAuth clients, and issuer. The central dashboard checks each storefront's independently signed browser session via its private Docker hostname. A linking ceremony requires authentication to both source and recipient storefronts; it **does not imply** real-world person equality or silently correlate brands. The consent grants **sharing to a specified recipient identity**, not all accounts with matching username.

This module shares only **synthetic, minimized demonstration data**. It enforces current consent state at API request time and uses append-only grant, revoke, and access records in the dedicated demo PostgreSQL database. Backend/session authentication is backed by WSO2-signed OIDC ID tokens already verified by each storefront.

## 1. Install without resetting the environment

From `/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc`, after extracting the overlay:

```bash
chmod +x scripts/install-m3-enforcement.sh scripts/provision-m3-oauth-test.sh
./scripts/install-m3-enforcement.sh
open http://localhost:8180/m3/consent
```

Only the **`demo`** container on port 8180 is rebuilt, and a new customer-owned migration is applied. The WSO2 container, six storefronts and both databases are not reset.

## 2. Consent browser acceptance — D-01, D-07, Q6, RFP 7.2.4

Use `localhost` for every storefront in **one browser profile**. Log in as `ana.magalu` to Magalu Web (`8181`) and Netshoes Web (`8183`) using the Commerce tenant credentials. The two applications must retain their own independent sessions.

1. Open `http://localhost:8180/m3/consent`.
2. Select **Magalu → Netshoes**, create the explicit link. No access is granted yet.
3. Click **Testar acesso**. **Expected HTTP 403** (`CONSENT_NOT_GRANTED_OR_REVOKED`). This also writes a DENY access audit record.
4. Click **Conceder** as the source account and test again. **Expected HTTP 200** with a *synthetic* minimal profile and an ALLOW audit event.
5. Create separate **Netshoes → Magalu** link. Test it without grant. **Expected HTTP 403**; reverse consent must not be inherited.
6. Log in to MagaluPay Web (`8185`) using the independent `magalupay.demo` account. Create **Magalu → MagaluPay** link but do **not** grant it. Test: **403**; Magalu → Netshoes consent must not be inherited across WSO2 roots.
7. Return to Magalu → Netshoes and click **Revogar**. Retest the resource using the same authenticated browser sessions: **403**. This check consults the latest database state, not OAuth token lifetime.
8. Click **Auditoria** and verify GRANTED then REVOKED (both immutable hashes) and ALLOW/DENY resource access history.
9. Log out of Netshoes and try reading the Magalu → Netshoes resource. Expected **401** — recipient authentication required.
10. Log in as a **different** recipient user, if configured, and test the same link: **403** — binding is to a specific tenant-qualified recipient `sub`.

**Do not mark PASS** unless the browser has produced real 403→200→403 responses and the audit history reflects each action. The preflight's seven pre-existing REVOKED entries are not this test's evidence; the new `demo.m3_*` tables start independently.

## 3. Secure Token Exchange evidence — RFC 8693 / RFP 7.2.5

### Provision a dedicated, safe test client

```bash
./scripts/provision-m3-oauth-test.sh
```

This creates a new confidential Authorization Code + PKCE OAuth application **in `magalu.demo`** with a single exact loopback callback `http://localhost:8991/callback`, and app-scoped roles for `ana.magalu` (`requests:read`, `requests:create`) and `bruno.seller` (`requests:read`, `requests:approve`). It does not modify existing storefront callback allowlists or login policies. The credentials remain in `generated/m3-oauth-test-client.json` (mode 0600).

### Acquire two real WSO2-issued JWTs (Mac only)

The existing storefronts intentionally do not expose bearer tokens to the browser or central dashboard. Instead use a dedicated one-use loopback OAuth code flow:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install 'PyJWT[crypto]' requests
python scripts/m3_oidc_capture.py --as-user subject --insecure-local
# Authenticate in WSO2 as ana.magalu in magalu.demo.
python scripts/m3_oidc_capture.py --as-user actor --insecure-local
# Authenticate in WSO2 as bruno.seller in magalu.demo.
```

The local helper uses `state`, `nonce`, mandatory PKCE and `prompt=login`; it only listens on `127.0.0.1:8991` and never prints tokens. It verifies signed ID/access JWTs and saves files at mode 0600 under `generated/m3-tokens/`, which is excluded by `.gitignore`.

### Exchange and verify delegated tokens

```bash
python scripts/m3_token_exchange_verify.py \
  --root commerce \
  --subject-file generated/m3-tokens/subject.jwt \
  --actor-file generated/m3-tokens/actor.jwt \
  --insecure-local
```

The first run is a diagnostic because `audience` is not yet bound. For complete acceptance, configure a resource audience on the requesting WSO2 exchange application, then rerun with the **actual registered value**:

```bash
python scripts/m3_token_exchange_verify.py \
  --root commerce \
  --subject-file generated/m3-tokens/subject.jwt \
  --actor-file generated/m3-tokens/actor.jwt \
  --audience 'YOUR_REGISTERED_RESOURCE_AUDIENCE' \
  --insecure-local
```

The harness verifies JWT signatures using the tenant JWKS, actual issuer, expiration, subject, `act.sub`, stricter scopes, `issued_token_type`, requested audience, and a negative `requests:approve` escalation attempt. It does not log raw tokens or client secrets. The test should fail closed if WSO2 returns opaque tokens, mismatched issuers, missing actor claims, or excessive privileges.

**Critical acceptance note:** The negative test only proves scope non-escalation if Ana's *subject access token lacks `requests:approve`*. The CLI checks this and rejects a test subject that could legitimately approve.

### Remove short-lived JWT test data

```bash
rm -f generated/m3-tokens/subject.jwt generated/m3-tokens/actor.jwt
```

Do not commit generated tokens, passwords, private keys, test-client credentials or bearer token values.

## 4. Remaining before Milestone 3 can be marked fully complete

- Live consent 403→200→403 testing (including reverse direction and cross-root separation).
- Real native WSO2 Consent Management v2 registration/readback, purpose mapping and, if required, lifecycle synchronization; currently **NOT VERIFIED**.
- Live local Token Exchange success using both distinct human-subject/actor tokens, correct `act`, strict scope subset, correct `issued_token_type`, signed tokens, registered audience and negative escalation.
- Separate cross-root token exchange rejection test (do **not** assume cross-root exchange is supported).
- Evidence exporting and optional token-cache/introspection policy for immediate revocation across downstream APIs.
- Threat-model review of the cross-brand link ceremony; same-browser dual login does not independently prove real-world account ownership.

Reference product docs:
- https://is.docs.wso2.com/en/latest/guides/authentication/configure-token-exchange/
- https://is.docs.wso2.com/en/latest/guides/authorization/delegation/
- https://is.docs.wso2.com/en/latest/guides/consent-management/
