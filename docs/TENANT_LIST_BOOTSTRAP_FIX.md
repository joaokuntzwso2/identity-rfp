# Root-tenant lookup hotfix for WSO2 IS 7.3.0.18

## Why this patch exists

`GET /api/server/v1/tenants/domain/magalu.demo` may respond with HTTP 400 (`TM-60015`) when the root tenant has not yet been created. The original project treated all HTTP 400 responses as an error and only accepted 200/404 as a valid preflight outcome.

The new bootstrap checks access using `GET /api/server/v1/tenants?limit=1&offset=0` and uses a paginated tenant list to determine if a root tenant exists. Only then does it issue a root-tenant `POST`. It verifies the tenant in a new tenant list after creation. Unexpected 400 responses still abort.

## Apply to already-running isolated PoC

From the project root:

```bash
unzip -o ~/Downloads/magalu-ciam-is73-tenant-list-bootstrap-hotfix.zip
chmod +x scripts/fix-tenant-list-bootstrap.sh
./scripts/fix-tenant-list-bootstrap.sh
```

This patch does not restart the WSO2 container or delete any database volumes. It rebuilds **only the bootstrap image** and reruns the idempotent bootstrap; WSO2 and PostgreSQL remain running.

If tenant-list authorization returns other than 200, the script prints the WSO2 JSON error code/description without printing credentials. Do not reset databases. Read `generated/bootstrap-report.json` after the bootstrap.

## Caveat

Passing the root-tenant provisioning gate does **not** establish that native consent, SSO, step-up, Token Exchange, JWT Bearer, multi-userstore or the 1,000 RPS performance criteria are fully implemented. They need live functional tests and evidence.
