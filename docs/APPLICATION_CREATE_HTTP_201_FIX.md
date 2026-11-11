# Magalu CIAM: WSO2 application `201 Created` response hotfix

## Observed error

WSO2 returned `201 Created` to `POST /api/server/v1/applications`, but the bootstrap's `data.get('id')` dereferenced `None` when the response body was empty. The POST **may already have created the application** despite the Python exception.

## Fix

- Read application IDs from the JSON response **if supplied**.
- Otherwise, accept a properly formed application `Location` header.
- Always attempt a **tenant-scoped exact-name readback**, including if response body and `Location` are both absent.
- If the listing is not immediately visible, verify the application resource at its returned ID.
- Fail closed on contradictory IDs, ambiguous names, malformed responses or unverifiable application creation.
- Re-running the bootstrap reuses applications already present in the tenant rather than automatically creating another.

## Apply

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
unzip -o ~/Downloads/magalu-ciam-is73-app-create-201-hotfix.zip
chmod +x scripts/fix-application-create-response.sh
./scripts/fix-application-create-response.sh
```

The installer rebuilds only the bootstrap container image. It preserves WSO2, PostgreSQL volumes, identities, users, and applications. Existing `generated/manifest.json` and `.env` are untouched by the patch.

## Acceptance scope

This change fixes the Python response handling and the application-ID recovery strategy. It does **not** independently certify the downstream OIDC inbound-protocol payload, pairwise behavior, policy enforcement, or PoC flows. If WSO2 rejects the next management API operation, inspect its exact `HTTP status`, `code`, and `description`; do not reset the database.

Unit tests simulate API responses. A live pass only occurs when `generated/bootstrap-report.json` records `BOOTSTRAP_VERIFIED` after the real server roundtrip; that still does not certify the RFP's interactive/performance acceptance criteria.
