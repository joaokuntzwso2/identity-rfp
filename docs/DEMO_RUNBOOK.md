# Section 7 demonstration sequence — two root tenants, three brands

1. Show `https://localhost:9543/console` and tenant domain list `magalu.demo` and `magalupay.demo`. Confirm these are **root tenants**, not child organizations.
2. Show applications: Commerce has Magalu web/mobile and Netshoes web/mobile; Fintech has MagaluPay web/mobile. Show isolated tenant admins and different issuer/clients.
3. Sign in as the explicitly mapped synthetic user `ana.magalu` on **all six** clients in the architecture portal `http://localhost:8180` and export `/api/evidence`. Compare `sub` equal within each brand, distinct across brands. Prove no raw common key leaks in any brand token.
4. Compare web and mobile claims (UserInfo, ID tokens, access tokens) to test deny-by-default claim mappings. Present the real native policy configuration.
5. Grant and revoke directional consent on both tenant portals and inspect the append-only ledger. Cross-brand sharing requires an explicitly enforced WSO2 policy, not just the ledger.
6. Show transaction step-up after risk policy: validate actual challenge and OIDC ACR/AMR change; do not present the synthetic IAL fixture as actual MFA.
7. Show Client Credentials, signed JWT Bearer and Token Exchange, including down-scoped token, issued_token_type and actor preservation with negative cases.
8. Authenticate with two WSO2 user stores if the optional LDAP store was configured; record proof of distinct stores.
9. Provision `magalufresh.demo` using `python -m scripts.onboard_brand`. Show no interruptions or changed client IDs for the first two roots.
10. Run k6 on the separately sized environment at 1,000 RPS × 30 minutes. Measure 0.1% error ceiling and report p95/p99. The localhost single-node deployment is not sufficient evidence for the performance/SLA requirement.

Never call a script-side success or demonstration fixture a verified product feature unless it was executed through real WSO2 authentication/authorization/consent APIs.
