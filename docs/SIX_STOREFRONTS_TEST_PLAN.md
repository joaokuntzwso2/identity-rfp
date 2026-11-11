# Magalu Login — Six-Storefront Validation Sheet

**Scope:** Magalu Retail, Netshoes and MagaluPay, Web + Mobile browser simulation.
**Execution target:** Docker project `magalu-ciam73-s7lab`, WSO2 Identity Server 7.3.0.18.
**Safety:** Test users and local environment only. Never paste access tokens, passwords, OTP seeds or client secrets in reports.

## URL matrix

| Brand | Web | Mobile | Root tenant |
|---|---|---|---|
| Magalu | http://localhost:8181 | http://localhost:8182 | `magalu.demo` |
| Netshoes | http://localhost:8183 | http://localhost:8184 | `magalu.demo` |
| MagaluPay | http://localhost:8185 | http://localhost:8186 | `magalupay.demo` |

All six must load anonymously with **Entrar** and distinct session cookie names. The mobile pages simulate a native-app layout within the browser; they are not packaged mobile applications.

## Acceptance cases

| ID | Procedure | Expected |
|---|---|---|
| S01 | Open all six URLs without logging in | All show anonymous state; no shared login |
| S02 | Authenticate Ana in Magalu Web | Only Magalu Web has an authenticated BFF session |
| S03 | Switch to Netshoes Web; click Entrar | WSO2 requests credentials again, not silent SSO |
| S04 | Switch to Magalu Mobile; click Entrar | Credentials required despite Magalu Web login |
| S05 | Log out of Magalu Web | Magalu Web becomes anonymous; five others unchanged |
| S06 | Click Entrar again in Magalu Web | WSO2 prompts for user credentials again |
| S07 | Repeat S02–S06 for six clients | Every session is independent |
| S08 | Collect authenticated `sub` from `/api/session` at each client | Same within each brand; different between brands |
| W01 | Log in as Ana (`requests:create`); create request in Magalu | Request PENDING, CREATE audit event |
| W02 | Try to approve as creator | Server refuses; self-approval impossible |
| W03 | Log in as Bruno (`requests:approve`) in Magalu; select approval | WSO2 new login with step-up requiring TOTP |
| W04 | Submit incorrect TOTP | Approval rejected; request remains PENDING |
| W05 | Submit valid TOTP; inspect `/api/session` | `acr=urn:magalu:aal2:totp`, `amr` contains `totp` |
| W06 | Verify approved request | APPROVED, appends immutable APPROVED audit event |
| W07 | Attempt Netshoes approver on Magalu request | Rejected by brand scope |
| W08 | Attempt Fintech approver on Commerce request | Rejected by issuer/root tenant and brand scope |
| W09 | Repeat W01–W06 for Netshoes and MagaluPay | Same workflow, independent tenant/brand permissions |
| W10 | Log in as creator, inspect scope badges | `requests:approve` absent and approve action unavailable |
| W11 | Log in as approver, inspect scope badges | `requests:create` absent and creation action unavailable |

## Test principals

- `magalu.demo/ana.magalu`: creator for Magalu and Netshoes.
- `magalu.demo/bruno.seller`: approver for Magalu and Netshoes, **must enroll TOTP in WSO2**.
- `magalupay.demo/ana.magalu`: creator for MagaluPay (independent account).
- `magalupay.demo/carla.risk`: approver for MagaluPay, **must enroll TOTP in WSO2**.

Retrieve credentials privately on the Mac from `generated/manifest.json`. The six storefront Docker containers do not mount this file.

## Observable evidence (without exposing secrets)

- `/healthz`: metadata, unique cookie key, configured manifest status.
- `/api/session`: current storefront's authenticated state, scoped permissions and ACR/AMR evidence.
- `generated/storefront-provision-report.json`: live provisioning gates and manual TOTP enrollment tasks.
- PostgreSQL: `SELECT * FROM demo_workflow.requests ORDER BY created_at DESC;` and `SELECT * FROM demo_workflow.events ORDER BY occurred_at DESC;`.
- WSO2 Console: Login Flow with Basic and TOTP; API Authorization; application-scoped Roles; allowed scopes per client.

**Release gate:** Do not mark W03–W06 as passing on static evidence alone. A real WSO2 TOTP prompt, a valid OTP, signed `acr`/`amr` evidence, and successful atomic approval are mandatory. Do not mark the total RFP Section 7 PoC accepted from these storefront tests alone; Token Exchange, JWT Bearer, multi-user-store, consent enforcement and 1,000 RPS/30-minute M2M load remain separate tests.
