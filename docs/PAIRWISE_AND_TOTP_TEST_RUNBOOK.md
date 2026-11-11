# Magalu Login — Evidências Pairwise + TOTP (WSO2 IS 7.3.0.18)

## Upgrade (no destructive changes)

This overlay only replaces `demo/main.py`, `demo/templates/{base,home}.html`, and
`demo/static/style.css`, adds `demo/templates/pairwise.html`, and adds the installer.
No WSO2, database, scopes, consent records, users, six-storefront services or existing
signed-in browser sessions are modified.

1. Download `magalu-ciam-8180-pairwise-evidence-overlay.zip` to `~/Downloads`.
2. From `/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc`, back up the
   dashboard directory before extracting (see assistant instructions).
3. Unzip the overlay, then run `./scripts/install-pairwise-evidence.sh`.
4. Open **http://localhost:8180/pairwise** in the **same browser profile** as all six
   independent storefronts. Always use the hostname `localhost`; using `127.0.0.1`
   starts a different cookie scope.

### Live data source

- The dashboard receives *only the browser's six distinct storefront session cookies*.
- It makes private Docker-network requests to each storefront's `/api/session`, forwarding
  only that storefront's own cookie, never other cookies, user passwords or OAuth tokens.
- Each storefront resolves the cookie to its in-memory session and reports the exact `sub`
  it previously verified from the WSO2 signed ID token at interactive login.
- A missing or expired cookie yields no `sub`. A mismatched tenant/brand/channel or malformed
  `sub` is shown as invalid, never as a pass.
- No identifier is read from the seed manifest, synthesized, or cached by the dashboard.
- `/api/pairwise-evidence` returns a no-store JSON report from the current browser session.
- **CLI curl without the browser cookies will correctly show zero subjects.** It does not
  mean browser login failed.

### RFP 7.2.1 check matrix

1. Magalu Web=Mobile (`sub` equal).
2. Netshoes Web=Mobile (`sub` equal).
3. MagaluPay Web=Mobile (`sub` equal).
4. Magalu≠Netshoes (`sub` different; *same WSO2 root tenant*).
5. Magalu≠MagaluPay (`sub` different; separate root tenants).
6. Netshoes≠MagaluPay (`sub` different; separate root tenants).

A comparison is **PENDING** until relevant storefront sessions exist. It is **FAIL** when
nonempty `sub` values contradict the expected relation. Only 6/6 authenticated clients
with all comparisons passing yields **OBSERVED_PASS**.

**Critical qualification:** the dashboard cannot verify on its own that users signed in
across the different tenants represent the same person. Confirm the test persona manually.
Observed subject relations do not alone establish that `subject_types_supported` includes
`pairwise`, or that the correct brand-level `sector_identifier_uri` was used. Those require
separate WSO2 configuration and protocol checks.

## Approve request using WSO2 TOTP

**Commerce:**
- `magalu.demo/ana.magalu`: creator (`requests:create`).
- `magalu.demo/bruno.seller`: approver (`requests:approve`).

**Payments:**
- `magalupay.demo/ana.magalu`: creator.
- `magalupay.demo/carla.risk`: approver.

Retrieve the synthetic account passwords *locally* on your Mac; do not post them to chat:

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
python3 - <<'PY'
import json
with open('generated/manifest.json') as f:
    m=json.load(f)
for domain,user in m['users'].items():
    if user['username'] in ('bruno.seller','carla.risk'):
        print(user['username'], '|', domain, '|', user['password'])
PY
```

### Enrollment

Open the WSO2 My Account portal **https://localhost:9543/myaccount**. Sign in as the
approver, selecting/qualifying the correct root tenant if required. Inside **Security →
Additional Authentication → Authenticator App**, add an authenticator; scan the QR code
in Google Authenticator, Microsoft Authenticator or another standard TOTP app, then
enter its first code to verify enrollment. Do not share the QR code or TOTP seed.

### Workflow

1. Sign in to **http://localhost:8181** as `ana.magalu` and create a request.
2. Log out of that same storefront (or use a separate browser profile) and sign back
   in to **Magalu Web** as `bruno.seller`. Separate roles are tested with distinct users.
3. Verify `requests:approve` is granted in the approver's `/api/session`.
4. Click **Aprovar** for the request. The app initiates a new `prompt=login` OIDC
   authorization with `acr_values=urn:magalu:aal2:totp`.
5. WSO2 must require a real TOTP code; submit a valid code from the enrolled device.
6. On redirect, the application must validate WSO2-signed `acr`, `amr` (including `totp`),
   the *same subject*, and a fresh `auth_time` before committing the approval.
7. Verify APPROVED state and audit record. A wrong OTP must leave the request PENDING.

If no TOTP challenge appears or approval remains blocked, **do not bypass the gate**.
Inspect application Login Flow / ACR script and actual claims from the signed token.
Provisioning tests do not prove that 7.3.0.18 emits the exact required `amr` casing.

References: WSO2 documentation for TOTP enrollment and application login flows.
