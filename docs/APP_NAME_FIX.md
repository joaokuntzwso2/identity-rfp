# WSO2 7.3.18 application name validation — APP-60001

The WSO2 IS 7.3.18 application-create API enforces:

```text
^[a-zA-Z0-9._-]+(?: [a-zA-Z0-9._-]+)*$
```

Earlier bootstrap names (`MAGALU CIAM POC | MAGALU | WEB`) contained `|` and were refused. New deterministic application names are constructed by `bootstrap/app_naming.py`, e.g. `MAGALU CIAM POC - MAGALU - WEB`, `MAGALU CIAM POC - NETSHOES - APP`, and `MAGALU CIAM POC - COMMERCE - M2M - CC`.

## Apply this hotfix

From the existing **isolated** PoC root, extract the ZIP over the project and run:

```bash
chmod +x scripts/fix-application-names.sh
./scripts/fix-application-names.sh
```

The script verifies the Compose project identity, compiles the changed Python, builds only the bootstrap image, reruns the idempotent bootstrap, and then attempts live smoke checks. It does not stop or recreate WSO2 or PostgreSQL, change secrets, or remove volumes.

Existing tenants and SCIM users were already created before the `APP-60001` failure; the rerun looks them up before attempting to provision them again.

## Scope and limitations

- This patch fixes *only* app name validation (`APP-60001`). Other WSO2 API compatibility issues may still be found by the next live call.
- The application's names must remain stable to preserve bootstrap idempotency. Do not change names after registration without a migration plan.
- User-visible brand names and UI branding remain unchanged.
- A successful bootstrap is not proof of complete RFP Section 7 acceptance. Consent enforcement, step-up and M2M load tests must be demonstrated separately.
