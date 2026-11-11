# Architecture decision: separate ROOT TENANTS, three logical brands

```
                        macOS / Docker Desktop
        localhost:8180         localhost:9543
         Magalu portal          WSO2 IS update 18
                |                     |
                |          WSO2 tenant management (root only)
                |                     |
                |       +-------------+--------------+
                |       |                            |
                |  /t/magalu.demo              /t/magalupay.demo
                |  ROOT Commerce               ROOT Fintech
                |   +-- Magalu Retail                +-- MagaluPay
                |   |    web / mobile                 |    web / mobile
                |   +-- Netshoes                     +-- own users/roles
                |        web / mobile                +-- own M2M
                |   +-- own users/roles               +-- own consent
                |   +-- own M2M
                |       |
       +--------+-------+----------------------------+
       |                  |                          |
 Dedicated consent PG   WSO2 identity PG       WSO2 shared PG
     demo schema             new volume             new volume
       |
 Private identity fixture vault (only synthetic, never distributed as token claim)
```

**Boundary 1 — root isolation:** `magalu.demo` and `magalupay.demo` are WSO2 **tenants** registered with the Tenant Management REST API, not `/o/...` child organizations. Their SCIM users, roles, client registrations, administrators and OAuth issuer are tenant-specific. Native consent policy must also be tested within each tenant.

**Boundary 2 — brand separation within Commerce:** Magalu and Netshoes have different pairwise sector *hostnames*. Each brand has web and app using a single sector URI; users are shared only because they are in the **same root tenant**. An OIDC ID token must be observed to certify continuity/separation.

**Boundary 3 — cross-root person link:** The PoC shows the same intentionally seeded synthetic person in both roots by preserving a privileged mapping in the dedicated demo database. That does not imply one physical WSO2 user record, automatic SSO or permission to correlate real users. Production needs a governed broker/federation workflow with explicit privacy policy.

**Database strategy:** The WSO2-owned identity, consent and shared schemas are initialized from the *actual updated server distribution* into two new PostgreSQL databases. The customer-owned directional consent ledger is a separate schema in a separate PoC PostgreSQL container. Never modify WSO2-internal IDN_/UM_ tables by custom migrations.

**Security:** local `admin/admin` is permitted at the user's request for Docker-only dev and must be changed before any shared/sandbox exposure. The WSO2 image and container are new to this project; the `WSO2_DIST_PATH` may reference software files from elsewhere, but volumes, containers and data never do.
