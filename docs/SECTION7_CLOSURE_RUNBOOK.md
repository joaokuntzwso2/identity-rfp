# Magalu CIAM Section 7 — B2C, B2B, Consent, RFC 8693, LDAP and M2M

## Status discipline

This is an **additive implementation** and evidence console, not a claim that every live acceptance gate has been passed. The current tenant model remains 2 root tenants (`magalu.demo` and `magalupay.demo`), with Magalu and Netshoes brands within Commerce. N2/N3 identity verification is intentionally deferred. Do not describe demo CNPJ records as real registry verification, or a seller policy table as enterprise federation.

Production-like deployment (HTTPS, server session sharing, external identity broker, official revocation API verification, monitoring and authorized 1,000 RPS test) is a separate workstream.

## Install and deploy

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
python3 /tmp/magalu-closure/scripts/install-poc-closure.py --check
python3 /tmp/magalu-closure/scripts/install-poc-closure.py
source .venv/bin/activate
bash scripts/verify-poc-closure.sh
bash scripts/deploy-poc-closure.sh
```

Open `http://localhost:8180/m3/completion` and enter the local `DEMO_OPERATOR_KEY`. Never publish this key. Existing M3 `/m3/exchange`, `/m3/native-consent`, and `/m3/section7` routes remain available.

## 1 — Consent and audit (D-01, D-07, Section 7 demonstration 4)

1. Use the **same browser profile**. Sign in `ana.magalu` at `http://localhost:8181/login` (Magalu Web) and `http://localhost:8183/login` (Netshoes Web). Do not reuse a prior browser's link UUID.
2. Use `http://localhost:8180/m3/consent`: create a **new explicit directional relationship** and grant Magalu → Netshoes. Confirm ledger state `GRANTED`.
3. In the new Completion Studio click **Encontrar links desta sessão**. It lists only links owned by both signed current storefront sessions; a 403 on a different link is correct fail-closed behavior, not a request to bypass ownership.
4. In `http://localhost:8180/m3/native-consent`, select the fresh link, run both root catalog preflight, create the **admin mirror of explicitly authorized consent**, read back native `ACTIVE` and call protected read; capture real HTTP **200 / BOTH_CONSENTS_ACTIVE**.
5. Revocation **must use the exact method supported by the running WSO2 update**. The current native connector uses DELETE and demands WSO2 `REVOKED` readback. WSO2 may delete records (404) or reject DELETE. If so: **stop**; do not call 404 a revoked-record readback. Confirm API contract, supported update and record state transition before changing implementation.
6. If and only if WSO2 independently returns native `REVOKED`, retest while custom ledger is still `GRANTED`: require **403 NATIVE_REVOKED**. Then reconcile and verify custom state `REVOKED`, with audit event that actually made the transition.
7. Return to Completion Studio, choose current owned link, click **Validar aceite completo**. Pass requires ordered native-create→200→native-revoke→403-native→reconcile events, two root catalogs, and negative native consent ID lookup in Fintech. No fake successes. Store sanitized evidence only.

**Known gap:** An administrator-created native record is not WSO2 My Account's end-user application consent. That distinct flow has already been tested in the storefront, but native record synchronization to My Account is not asserted here.

## 2 — RFC 8693 Token Exchange (Section 7 demonstration 5)

```bash
./scripts/m3-local.sh capture-subject --insecure-local
./scripts/m3-local.sh capture-actor --insecure-local
```

Sign in as Commerce Ana (`ana.magalu`) and Bruno (`bruno.seller`) respectively. Tokens live only in ignored `generated/m3-tokens/`. Run the already-provisioned `http://localhost:8180/m3/support-journey` or `/m3/exchange` and choose **Executar** in the Completion Studio. Do not weaken the engine to bypass resource audience registration. Required evidence: HTTP 200 on `requests:read`, HTTP 403 on `requests:approve`; verified signed JWT `sub` / `act.sub`; no scope elevation; `issued_token_type` correct; dedicated audience verified. Export the existing `/api/m3/exchange/evidence` sanitized JSON after completion. Do not commit tokens.

## 3 — Simultaneous primary + LDAP user store (Section 7 demonstration 6)

WSO2 must be configured to consume LDAP; running a container is not enough. **Do not delete or reinitialize existing LDAP volumes.** The repository's current `docker/ldap/seed-users.ldif` includes a static development credential; rotate or replace it and do not publish real passwords.

Optional private *new fixture* generation and safe start (does not mutate WSO2 or replace an existing running LDAP service):

```bash
python3 scripts/prepare-poc-ldap.py --generate
bash scripts/start-poc-ldap.sh
```

The script creates a new random test-user password, LDAP admin password, and an ignored Docker Compose override under `generated/poc-ldap/`. It checks the resolved bind mount and **refuses to replace a currently running LDAP instance**. This is only LDAP preparation; registering the secondary user store in WSO2 is still required. Do not use `docker compose down -v`.

For an already-running seeded LDAP fixture, verify it first and rotate the published demo password before accepting it as evidence. WSO2 Console at `https://localhost:9543/t/magalu.demo/console` → User Stores → Add Secondary User Store. Configure a unique domain, for example `SELLER_LDAP`, and a readonly LDAP user store. Settings to confirm against your selected WSO2 store-manager type: `ldap://ldap:389` **only inside the isolated local Docker network**, bind DN `cn=admin,dc=example,dc=test`, base DN `ou=people,dc=example,dc=test`, username attribute `uid`, filter `(&(objectClass=inetOrgPerson)(uid=?))`. Provide bind credentials privately in Console. Secure external environments with LDAPS.

Then perform two **actual WSO2 OIDC logins** without disconnecting either store:

- PRIMARY: `bruno.seller` in `magalu.demo` using seller app `http://localhost:8180/m3/seller/login` (or Ana on Magalu Web).
- SECONDARY: `SELLER_LDAP/ldap.seller` using the same tenant's valid OIDC login route, if that test client permits the external user. If user store domain cannot be established from a verified WSO2 response or Console evidence, mark this test `NOT_PROVEN`.

Capture tenant/subject and source domain from WSO2 Console/auth audit for both sessions. Never infer LDAP membership from an arbitrary username string alone. These manual settings depend on the WSO2 7.3 LDAP manager UI and cannot be asserted as configured by this ZIP.

## 4 — B2C (Section 7.3 PF)

Authenticate `ana.magalu` in Magalu Web at port 8181 and Magalu App at port 8182. In the new UI select B2C verification to confirm signed independent WSO2 sessions with the same within-brand `sub`. The application OIDC attribute-consent prompt, TOTP and step-up already exist and should be covered in the customer live PF journey. The current check **does not** prove identifier-first registration, passkeys, social login, or full 90-day session policy; add these only if included in the agreed PoC.

## 5 — B2B (Section 7.3 PJ)

Before this change, `/seller` sent users to an unsupported retired route. This package adds a dedicated seller-app login at `/m3/seller/login`, using OIDC Authorization Code + PKCE + state + nonce and signed ID Token verification. WSO2 `userinfo.sub` must match the ID token, and the seller username must be an actual approved WSO2 claim, not an unchecked form value.

In WSO2 Commerce Console ensure the existing Seller Web application (registered in the private manifest under `seller:web`) includes redirect `http://localhost:8180/oidc/callback` and returns a trustworthy `preferred_username` or `username` UserInfo claim for your synthetic seller. Log in as `bruno.seller`; then click **Consultar representação** and **Visualizar empresa**. Observe the seeded synthetic CNPJ, role `OWNER`, and database policy audit. **Tentar alterar repasse** is authorization check only; it does not change real payment data. Run negative test with a user lacking a representative record: both operations must be denied. Company federated SAML/OIDC and delegated organization admin remain separate unimplemented RFP capabilities.

## 6 — M2M (Section 7.3)

In the new UI issue Client Credentials for both tenants. Verify the token's JWKS signature and tenant issuer and that a token with no delegated privilege cannot read `/api/m3/exchange/resource/read` (real resource HTTP 401 or 403, depending on missing audience/scope). Do not call a 401 an application-scope denial; 401 is issuer/audience/authentication denial, 403 is authenticated scope denial.

For **JWT Bearer RFC 7523**, the assertion signer/public key MUST first be registered and trusted by WSO2 for the selected client and subject. The package cannot do that without a compatible WSO2 server-specific configuration. Once configured, create a 120-second signed *test-only* assertion:

```bash
python3 scripts/prepare-poc-jwt-assertion.py \
  --root commerce \
  --issuer 'https://YOUR-CONFIGURED-TEST-ISSUER.example' \
  --subject 'YOUR-REGISTERED-TEST-SUBJECT' \
  --token-endpoint 'https://localhost:9543/t/magalu.demo/oauth2/token'
```

Private signer and assertion are ignored in `generated/m3-tokens/`; public PEM is there for authorized registration. In the UI click **Testar JWT Bearer + replay** promptly (assertion expires after two minutes). WSO2 must issue on first use and reject **the exact same signed JWT** on second use; the second success is a failed replay test. Proper cross-node replay handling, jti storage and expiry are WSO2 integration concerns and cannot be guaranteed by this PoC code. If not supported, mark `FAIL_OR_INCOMPLETE` and document a compensating enforcement component only if actually built.

The dedicated RFC 8693 lab remains the source of truth for delegated scopes, actor and protected-resource HTTP acceptance. UI **Validar isolamento de emissores** checks both independent tenant token issuers but does not substitute for resource HTTP cross-root negative tests. Use existing `/m3/isolation` for that.

## Final acceptance checklist

- [ ] Consent: active 200, verified native REVOKED readback, native-caused 403, ledger transition and cross-root negative lookup
- [ ] RFC 8693: signed actor/subject, privilege reduction, issued token type, real resource 200 and 403
- [ ] LDAP: WSO2 authenticates independent users simultaneously in PRIMARY and `SELLER_LDAP`; origin confirmed independently
- [ ] B2C: PF journey agreed with customer, real authentication + authorization and negative evidence
- [ ] B2B: seller client login, authorized/unauthorized role matrix, organization model and federation as agreed
- [ ] M2M: CC, registered JWT Bearer + replay rejection, exchange, negative scope, cross-root resource denial, evidence
- [ ] No N2/N3 claimed; postponed by operator
- [ ] Section 7 remaining: third-tenant onboarding, public sandbox and authorized 1,000 RPS performance test separately

Never commit: `.env`, generated secrets, private keys, full JWTs, raw WSO2 tokens, LDAP passwords or customer confidential artifacts.
