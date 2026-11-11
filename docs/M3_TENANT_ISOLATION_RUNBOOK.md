# Magalu CIAM · Milestone 3 — Cross-root tenant isolation

## Purpose and boundaries

This chapter adds one page to the existing **port 8180** lab: `/m3/isolation`.
It exercises **real authenticated storefront sessions**, the existing PostgreSQL
consent enforcement (`demo.m3_consent.ConsentDb`), and **real tenant-scoped WSO2
OAuth endpoints**. It is not a mocked success page.

Two independent root tenants:

- **Commerce `magalu.demo`**: Magalu, Netshoes.
- **Fintech `magalupay.demo`**: MagaluPay.

The test uses independently authenticated synthetic accounts. It **does not**
claim these root-tenant identities are globally linked by WSO2 or that root
Tenant B automatically inherits the Commerce account.

### Safety and scope

- Existing WSO2 users, storefront apps, root tenants, consumer sessions,
  consent history and Docker volumes are **not reset**.
- `install-m3-isolation-lab.sh` copies the new dashboard code and rebuilds
  **only** the `demo` service (`8180`).
- The separate `prepare-m3-fintech-control.sh` modifies **only** the existing
  MagaluPay **M2M Client Credentials test application's** OAuth protocol:
  signed JWT access tokens and a dedicated audience
  `urn:magalupay:poc:isolation`. It also **reads back** the existing MagaluPay
  Token Exchange application's grant configuration. It makes a private backup
  of the modified OIDC configuration in `generated/` and never prints secrets.
- The consent "Preparar" action creates two direction-specific *link records*
  but **does not grant consent**. Only an explicit, separate confirmation can
  grant consent. Grant and revoke add real audit events.
- The synthetic Pay resource tests **tenant issuer and dedicated audience**;
  it is not a transaction or a production MagaluPay API.
- The negative RFC 8693 requests use a **real** MagaluPay exchange client and
  a genuine Commerce user subject token. They deliberately do not configure
  cross-root trusted issuer federation. If your actual policy explicitly allows
  such federation, this negative expectation needs to be reviewed with the RFP.
- Do not enable `IS_TLS_VERIFY=false` beyond the isolated self-signed local PoC.
- **Native WSO2 Consent Management v2 integration is separate and not certified**
  by these tests; the ledger is a customer-owned extension.

## 1. Install

Download `magalu-ciam-m3-tenant-isolation-storytelling.zip` to `~/Downloads`.

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
mkdir -p /tmp/magalu-m3-isolation
unzip -oq ~/Downloads/magalu-ciam-m3-tenant-isolation-storytelling.zip -d /tmp/magalu-m3-isolation
bash /tmp/magalu-m3-isolation/scripts/install-m3-isolation-lab.sh "$PWD"
```

Only the port 8180 dashboard is rebuilt. It prints a backup path such as
`generated/backup-m3-isolation-YYYYMMDD-HHMMSS`.

## 2. Prepare MagaluPay's positive control

```bash
./scripts/prepare-m3-fintech-control.sh
```

Expected: `FINTECH_CONTROL_READY`, the Fintech audience name, and
`readback_verified: true`.

This is not a tenant bootstrap or a database migration. If management API
readback fails, stop and inspect the failure rather than treating it as PASS.

## 3. Capture recent Commerce tokens

```bash
./scripts/m3-local.sh capture-subject --insecure-local  # Ana in magalu.demo
./scripts/m3-local.sh capture-actor --insecure-local    # Bruno in magalu.demo
```

Files under `generated/m3-tokens/` stay private with mode 0600. Never paste or
commit raw JWTs. The scripts may prompt for browser login on port 8991.

## 4. Consent isolation: guided browser flow

1. Open **Magalu Web** (`http://localhost:8181`) and authenticate as
   `ana.magalu` in Commerce.
2. Open **Netshoes Web** (`http://localhost:8183`) and authenticate as the
   Commerce test identity `ana.magalu`.
3. Open **MagaluPay Web** (`http://localhost:8185`) and authenticate as
   `ana.magalu` in the independent Fintech tenant.
4. In **the same `localhost` browser profile**, open
   `http://localhost:8180/m3/isolation`. Confirm the three session indicators
   show **AUTENTICADO**. If not, confirm the URL hostname is `localhost`, not
   `127.0.0.1`, and log into the correct storefront.
5. In the local Terminal, inspect `.env` for `DEMO_OPERATOR_KEY` without sending
   it to anyone; enter the key in the page's **Chave de operador** field.
6. Click **Preparar vínculos de teste**. This only creates real directional
   link records (forward and reverse). It **does not grant** consent.
7. Check the explicit consent acknowledgement and click
   **Conceder consentimento**.
8. Click **Executar 3 verificações HTTP**.
   - Netshoes recipient: **HTTP 200**, `ACTIVE_DIRECTIONAL_CONSENT`.
   - MagaluPay recipient using the **same Commerce grant**: **HTTP 403**,
     `WRONG_RECIPIENT_OR_TENANT`.
   - Netshoes → Magalu reverse link: **HTTP 403**,
     `CONSENT_NOT_GRANTED_OR_REVOKED`.
9. Check the explicit revocation acknowledgement and click
   **Revogar consentimento**.
10. Click **Retestar acesso após revogação**. Netshoes now returns **HTTP 403**
    with `CONSENT_NOT_GRANTED_OR_REVOKED`, without logout or issuing fresh
    credentials. Pay and reverse remain denied.
11. Inspect the sanitized JSON detail for `GRANTED` and `REVOKED` events,
    hash chain fields and access-audit ALLOW/DENY records.

If the reverse link was already independently granted by an earlier demo, the
reverse-denial check will (correctly) FAIL. Revoke that reverse grant in the
existing `/m3/consent` page, then run the acceptance flow again. Do not delete
history to make a test pass.

## 5. Cross-root RFC 8693: guided browser flow

Keep the operator key set. Click **Executar prova OAuth entre tenants**.
The backend makes these calls in sequence:

1. **Commerce positive control:** exchange Ana+Bruno in `magalu.demo`,
   verifying WSO2 signature, `sub`, `act.sub`, `requests:read`, and the previously
   verified dedicated Commerce audience `urn:magalu:poc:requests`.
2. **Fintech positive control:** `client_credentials` on
   `magalupay.demo`, verifying a real signed JWT, expected issuer, and its
   **dedicated** audience `urn:magalupay:poc:isolation`.
3. **Pay protected-resource control:** Pay-issued JWT -> **HTTP 200**;
   Commerce-issued JWT on that same Pay resource -> **HTTP 401** due to
   invalid tenant issuer / audience.
4. **Cross-root subject token exchange:** submit Commerce Ana JWT to the
   **Fintech** Token Exchange app and endpoint; no token should be issued.
5. **Cross-root subject+actor exchange:** submit Commerce Ana+Bruno JWTs to
   the Fintech Token Exchange app and endpoint; again, no token should issue.

The workbench reports the real HTTP status and sanitized OAuth error codes.
Both cross-root attempts must return a 4xx protocol rejection with no token;
HTTP 200 with a token is a **FAIL**. A failed/opaque Fintech positive control
means the negative result is **BLOCKED**, not an acceptance PASS.

A generic OAuth 4xx is evidence of **the current tested configuration's
rejection**, not a universal proof that any possible cross-tenant federation is
unsupported. Review explicit trusted issuer relationships separately.

## 6. Export evidence

From the page, select **Exportar relatório JSON saneado** or open:

`http://localhost:8180/api/m3/isolation/evidence`

All live reports are written locally:

- `generated/m3-isolation-consent-evidence.json`
- `generated/m3-isolation-token-evidence.json`
- `generated/m3-fintech-cc-control-readback.json`

**Do not commit** `generated/`, tokens, `.env`, client secrets, or tenant admin
credentials. You may commit the exported sanitized evidence after reviewing it.

The entire **cross-root isolation chapter** is PASS only when the current
consent after-revocation state and all token controls/negative tests pass.
Native WSO2 Consent Management v2 still needs its own acceptance assessment.

## Troubleshooting

- **Missing session:** reauthenticate in each storefront using `localhost`
  consistently; do not attempt to copy cookies between apps.
- **Token expired:** recapture Ana and Bruno (both) and rerun.
- **Fintech client token opaque:** run the targeted
  `./scripts/prepare-m3-fintech-control.sh` again and check the WSO2 API
  readback; do not change any other client.
- **Pay JWT audience mismatch:** verify the receipt in
  `generated/m3-fintech-cc-control-readback.json` and WSO2's actual `aud`
  claim privately; never share the token.
- **Cross-root exchange unexpectedly succeeds:** status FAIL; inspect trust
  policies and the issued token's issuer, scopes, subject, and intended
  audience using a safe local verifier. Do not weaken signature checks.
- **HTTP 400 from both normal and cross-root controls:** status BLOCKED, not
  PASS; fix the same-tenant baseline first.
- **Dashboard route fails:**
  `docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml logs --tail=100 demo`

## Acceptance record

Suggested RFP traceability: root-tenant isolation, directional consent, denial
on revocation, RFC 8693 cross-root misuse, issuer/audience enforcement. Every
claim must cite an actual **time-stamped report**. This package does not claim
to validate the entire RFP or to integrate native WSO2 Consent Management v2.
