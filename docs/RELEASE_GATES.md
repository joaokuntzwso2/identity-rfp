# RFP Section 7 — live release gates and honest acceptance criteria

| Gate | Demonstration | Automated work in this package | To be proven live |
|---|---|---|---|
| M-01 / 7.1 | Public discovery, at least 2 real tenants, 2 user clients each, Console | Tenant API bootstrap, scoped discovery, six-app inventory | Public endpoint/network reachability, Console access, real tenant/admin separation |
| 7.2 #1 | Same person 3 brands × web/mobile | Three HTTPS sectors and 6 OIDC apps, identity vault | All six signed ID tokens; within-brand `sub` equal, between-brand `sub` different; no ID leaked cross-brand |
| 7.2 #2 | Different claims for same person | Different web/mobile requested scopes | Real claim allowlists per client; default deny; ID token/UserInfo/access-token evidence |
| 7.2 #3 | Risk-triggered step-up | Assurance attribute event fixture and N1/N2/N3 policy | Actual WSO2 conditional step-up + MFA provider, ACR/AMR before/after and transaction continuity |
| 7.2 #4 | Tenant-isolated consent history | Append-only directional ledger, client/scope isolation | Native WSO2 consent APIs integrated, enforced at token/data release, revocation and retention |
| 7.2 #5 | Token exchange | Tenant-specific exchange grant clients, request CLI | Trusted issuers, down-scoping, valid actor_token/`act`, `issued_token_type` and negative tests |
| 7.2 #6 | Two user stores | Optional LDAP service | WSO2 secondary store registration and successful authentication from both stores |
| 7.2 #7 | Onboard third tenant | Third **root tenant** provisioner with two apps/user/role | Before/after app & policy inventory, login with new tenant and unaffected existing roots |
| 7.3 PF | Retail consumer login | OIDC authorization code/PKCE and synthetic end user | Actual identifier-first, account security, consent, MFA in agreed flow |
| 7.3 PJ | Seller login | Seller OIDC app, seller representation policy, application role | External corporate IdP federation / CNPJ + user / delegated administration as agreed |
| 7.3 M2M | Load | 2 root × (CC, JWT Bearer, Token Exchange), k6 | 1,000 RPS for 30m with error ≤0.1%, p95/p99 captured and customer-agreed latency targets |

## Not certified from localhost

This source tree can be statically tested here, but WSO2 IS 7.3.0 update level 18 was not available to the authoring session. Neither its management endpoints nor its OAuth flows were executed here. **Bootstrap is designed to fail if a real API call fails.**

Separate root tenants do not automatically have a shared customer identity or SSO. A controlled broker/federation design is required if the final architecture must combine hard tenant separation with seamless cross-tenant login. The private synthetic identity-vault link exists solely to compare Section 7 test subjects; it must not be mistaken for a deployable cross-tenant correlation service.

Tenant-scoped WSO2 roles and application-specific claim release may require additional permissions/configuration on the exact updated server. Do not reclassify a blocked setup as a success; use the generated report to trace the failing API call.
