# Magalu Login — Section 7 Enterprise Architecture Lab

**WSO2 Identity Server 7.3.0, update level 18 (7.3.18)**  
**Architecture revision:** 2 independent *root tenants* (not child organizations), 3 brands, 6 OIDC channel clients, 1 B2B seller app, 6 M2M apps, tenant-local synthetic users and application-scoped roles.  
**Classification:** CONFIDENTIAL — customer evaluation / localhost laboratory only.

> **Live status:** The repository is an implementation kit, **not a statement that the live eliminatory PoC has passed**. Its code and syntax have been tested offline. The exact updated WSO2 binary, Docker runtime and credentialed tenant APIs have not been executed here. Every live API call fails closed rather than returning simulated success. Read [docs/RELEASE_GATES.md](docs/RELEASE_GATES.md).

## Root-tenant architecture

| WSO2 root tenant (`/t/<domain>`) | Logical brand / pairwise sector | OIDC clients |
|---|---|---|
| **magalu.demo** — Magalu Commerce | Magalu Retail (`sector-magalu`) | Retail Web + Retail Mobile |
| Same root tenant | Netshoes (`sector-netshoes`) | Netshoes Web + Netshoes Mobile |
| **magalupay.demo** — MagaluPay | MagaluPay (`sector-magalupay`) | Pay Web + Pay Mobile |

- Each **root tenant** gets a separate administrator, SCIM user set, role namespace, OIDC issuer and application inventory. These are true WSO2 tenants created by `/api/server/v1/tenants`, **never child organizations**.
- Each **brand** has a distinct OIDC sector hostname. Web/mobile **within** a brand use the same sector URI; brand subjects should be different even for one synthetic customer in Commerce.
- A separate, access-controlled PoC identity vault maps synthetic users across roots. This is **not** a shared root-user store and does **not** silently enable cross-root SSO. Production SSO requires federation/broker architecture to be explicitly built and tested.
- Root/brand-specific consent purposes and audit history live in a dedicated PostgreSQL schema. The WSO2 native consent adapter and policy enforcement remain separately gated.

## Run as a brand-new, isolated Docker project on macOS

Requirements: Docker Desktop + Compose v2, `python3`, `openssl`, `curl`, `unzip` and `zip`. **Do not start the old `run-local.sh` for this revision.**

1. Extract this package into a **new folder** (for example, `magalu-ciam-root-tenants-v2`). Keep your existing projects intact.
2. Run `./scripts/setup-isolated.sh`. This sets localhost `admin/admin`, creates fresh independent database passwords and selects host ports `9543`, `8180`, `8543`.
3. On this Mac the updated image `registry.wso2.com/wso2-is/is:7.3.0.18` is already available, so `setup-isolated.sh` selects that exact tag by default. If using a different **updated** WSO2 Docker image, set `WSO2_IMAGE` in `.env` to its exact image tag. If you have the updated distribution ZIP/folder rather than an image, set `WSO2_DIST_PATH` in `.env` to the absolute ZIP/folder path; `prepare-updated-image.sh` builds a **new** local image from that pack.
4. Run `./scripts/run-isolated.sh`.

```bash
cd /path/to/magalu-ciam-root-tenants-v2
chmod +x scripts/*.sh
./scripts/setup-isolated.sh
# Set WSO2_DIST_PATH if the updated distribution is present but no image is loaded:
# printf '\nWSO2_DIST_PATH=/absolute/path/to/wso2is-7.3.0.zip\n' >> .env
./scripts/run-isolated.sh
```

The launcher:
- Reuses **only** the updated IS *software bits* you point it to—not any running WSO2 or PostgreSQL instance.
- Extracts PostgreSQL schema scripts from that same WSO2 distribution, downloads or takes a verified JDBC driver, prepares HTTPS trust, and launches a new isolated Compose project `magalu-ciam73-s7lab`.
- Initializes **fresh** `wso2_identity` and `wso2_shared` PostgreSQL databases plus a separate `ciam` consent database using dedicated Compose volumes.
- Creates two root tenants using the WSO2 tenant-management API; then provisions actual tenant-specific SCIM users, roles, OIDC apps and M2M credentials. If any API fails, bootstrap stops and writes `generated/bootstrap-report.json` with the last verified operation.
- Runs a root-specific OIDC/M2M smoke test, writing `generated/smoke-result.json`.

**URLs:** [WSO2 Console](https://localhost:9543/console) · [Magalu Architecture Portal](http://localhost:8180) · [sector service](https://localhost:8543/sectors/magalu.json).

**Default super-admin:** `admin` / `admin` — acceptable only for your isolated localhost environment; tenant owner credentials are randomly generated and stored in `generated/tenant-secrets.json` (0600). Neither these nor other client secrets should be committed or sent over chat.

To start without bootstrap, run `./scripts/run-isolated.sh --skip-bootstrap`. To bootstrap again:

```bash
docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml --profile tools run --rm bootstrap
```

For the seventh Section 7.2 demonstration (adding a new tenant **without using child organizations**):

```bash
docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml --profile tools run --rm bootstrap python -m scripts.onboard_brand
```

That adds `magalufresh.demo` as a **third root tenant**, with its own user, role, consent purpose and two OIDC clients. Preserve a before/after inventory and perform live sign-in to complete this acceptance test.

## Reports and safety

- `generated/manifest.json`: **SENSITIVE** — actual tenant accounts, app IDs and local PoC secrets.
- `generated/tenant-secrets.json`: **SENSITIVE** — root-tenant administrator passwords.
- `generated/bootstrap-report.json`: machine-readable provisioning gates.
- `generated/smoke-result.json`: actual OIDC issuer and M2M outcomes.
- `docs/RELEASE_GATES.md`: what still requires actual live test evidence.

Use `./scripts/reset-isolated.sh --destroy-magalu-poc-data` **only** if you explicitly want to destroy **this project's** Docker volumes; it does not call `docker system prune` or touch any other project.

## Non-negotiable validation boundaries

1. A client with a pairwise sector is not proof that the same six real ID tokens have correct `sub` behavior; run six interactive sign-ins using the seeded synthetic identity.
2. Creating demo consent rows is not the same as enforcing native WSO2 consent at authentication/token issuance; this is an integration gate.
3. The UI's N1/N2/N3 fixture is **not** an actual WSO2 ACR/AAL step-up until the policy and second factor are wired to IS.
4. JWT Bearer replay, RFC 8693 actor preservation, a second user store, B2B federation, and 1,000 RPS × 30 min must each produce their own real evidence.
5. `admin/admin`, self-signed TLS and a single localhost WSO2 node are **not** production/security/SLA architectures.

Sources: [WSO2 tenant API](https://is.docs.wso2.com/en/latest/apis/tenant-management-rest-api/), [pairwise sector configuration](https://is.docs.wso2.com/en/7.0.0/guides/authentication/user-attributes/enable-attributes-for-oidc-app/), [PostgreSQL preparation](https://is.docs.wso2.com/en/latest/deploy/configure/databases/carbon-database/change-to-postgresql/).
