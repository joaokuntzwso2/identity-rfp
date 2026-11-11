# Magalu CIAM · Six independent storefronts

## Architecture

Six Docker application services are exposed at `localhost:8181`–`8186`.
They share audited request records in the **customer-owned demo PostgreSQL** but do not share session memory, browser cookie names, OIDC client IDs, or authorization callback URLs. Each storefront mounts **only** the reduced `storefront-manifest.json` file (not the whole generated directory), containing only the six required OAuth client records and confidential web-client credentials; it cannot read the synthetic users’ passwords or tenant-admin secrets from the host filesystem.

| Tenant | Brand | Web | Mobile simulation |
| --- | --- | --- | --- |
| `magalu.demo` | Magalu Retail | http://localhost:8181 | http://localhost:8182 |
| `magalu.demo` | Netshoes | http://localhost:8183 | http://localhost:8184 |
| `magalupay.demo` | MagaluPay | http://localhost:8185 | http://localhost:8186 |

> Mobile pages emulate an app viewport in a **browser** and use authorization code + PKCE. They are **not actual iOS/Android native clients** or OS-backed token stores.

Each site is backed by a different WSO2 OIDC client and its own site-specific cookie, session state, PKCE verifier and nonce. Cookies are not scoped to TCP ports, so distinctive cookie names are necessary. All OIDC logins send `prompt=login` and `max_age=0`, requiring fresh credentials even if the browser has another WSO2 session. Logout is **RP-local** and does not sign out any other brand/channel; no invalidation of the central WSO2 browser session is claimed. `prompt=login` is a protocol request whose effect must be verified in WSO2 7.3.18.

### Expected independent-session acceptance

1. Log into Magalu Web (`8181`); open Netshoes Web (`8183`) and confirm it still shows **Entrar**.
2. Click Netshoes **Entrar**; confirm WSO2 asks for user credentials. Login and verify only Netshoes Web is authenticated.
3. Open Magalu Mobile (`8182`); confirm it is not automatically signed in despite Web being signed in.
4. Log out of Magalu Web; confirm Netshoes Web and Magalu Mobile remain unchanged.
5. Click Magalu Web **Entrar** again; confirm WSO2 prompts for credentials.
6. Repeat across all six. For equal subjects, verify Magalu Web/App match, Netshoes Web/App match, Pay Web/App match; cross-brand `sub` must be distinct.

### Workflow demonstration

`ana.magalu` is a **request creator** in both root tenants. `bruno.seller` is a **request approver** for Magalu and Netshoes in Commerce. `carla.risk` is a **request approver** for MagaluPay in Fintech. Tenant SCIM accounts are independent, and permissions are represented by WSO2 application-scoped roles and a root-local API Resource:

- `requests:read`: request dashboard
- `requests:create`: insert a pending request
- `requests:approve`: enter approval flow (not sufficient on its own)

The storefronts request `openid` plus the business scopes, **not profile/email claims**, minimizing user attributes by default. Token endpoint-issued scopes are checked server-side; merely requesting a scope does not grant it. Role permissions are configured via WSO2's SCIM v2 Role API. The business API must still enforce scopes; WSO2 does not do this automatically.

The creator cannot approve their own request. Approval triggers a fresh authorization request with `acr_values=urn:magalu:aal2:totp`. The WSO2 application login flow must execute Basic Authentication followed by TOTP for this ACR. The backend verifies cryptographic signature, issuer, audience, nonce, subject continuity, granted `requests:approve`, `acr`, `amr` including `totp`, and fresh `auth_time` **before** updating the request in an atomic SQL transaction. No demo OTP or generated passcode is accepted.

### TOTP enrollment

**Enrollment is a user-driven operation and must be completed in the WSO2 My Account portal**. The bootstrap configures the TOTP policy and roles, but does not fabricate an authenticator secret or mark enrollment complete.

1. Authenticate to the **Commerce root My Account** with `bruno.seller`, and **Fintech root My Account** with `carla.risk` (different tenant-specific accounts).
2. Open *Security → Additional Authentication → Authenticator App*.
3. Scan WSO2's QR using a TOTP authenticator; verify the first code.
4. Return to the appropriate storefront as the approver, select **Aprovar com TOTP**, and complete WSO2's actual TOTP challenge.
5. Check `/api/session` and the PostgreSQL `demo_workflow.events` audit record. Never paste TOTP secrets or access tokens into chat.

First-use progressive TOTP enrollment may be enabled on WSO2 7.3.18, depending on tenant governance. If WSO2 prompts enrollment during step-up, complete the WSO2 QR enrollment flow. Test rejection for wrong code and for an ID token missing TOTP ACR/AMR evidence.

### Setup on the existing project

Download the patch ZIP and unzip it over the *existing* `magalu-ciam-is73-poc` project (no replacement of `.env` or `generated/` needed). Then:

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
unzip -o ~/Downloads/magalu-ciam-six-storefronts-v3-overlay.zip
chmod +x scripts/run-six-frontends.sh
./scripts/run-six-frontends.sh
```

This launcher applies the idempotent workflow SQL migration, rebuilds only the demo/runner, updates each WSO2 OIDC client with a new callback URL and root-local API permissions, configures the ACR login flow, and starts six new frontend containers. It does **not** remove or recreate the existing WSO2/PostgreSQL volumes.

If WSO2 rejects an API request, the second-stage bootstrap writes `generated/storefront-provision-report.json` and stops without claiming completion. Verify the API error and the application Login Flow in WSO2 Console; do not delete root tenants or database volumes.

### Boundaries and limitations

- The original evaluation shell on `8180` remains available. Its trusted-claim mapping still requires WSO2 UserInfo or a verified profile claim. **The six independent storefronts do not depend on the `preferred_username` claim**: they use signed pairwise `sub` and WSO2-granted scopes.
- No claim of **end-to-end TOTP approval passing** is made until a real browser login/approval succeeds on your 7.3.18 instance. Static tests cannot simulate that.
- These flows are a subset of Section 7.2 and 7.3, not a substitute for Token Exchange, JWT Bearer, multi-store, consent-enforcement, or 1,000 RPS load verification.
- Session dictionaries reside in each process and are cleared on container restart. For production, use Redis-backed sessions and HTTPS/cookie Secure flags; the current localhost-only HTTP frontends are for controlled development.
