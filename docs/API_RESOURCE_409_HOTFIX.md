# WSO2 IS 7.3.18 — API Resource 409 bootstrap correction

## Root cause

The WSO2 `GET /api/server/v1/api-resources` response represents its list as `APIResources` (capital A, P, I and R). The older storefront bootstrap only checked `apiResources` and `resources`, so it failed to find a resource already created in `magalu.demo`. A second `POST` then returned `409 API-RESOURCE-60003`.

## Fix

- Query the resource by **exact** identifier `urn:magalu:poc:requests` with WSO2's documented `filter` parameter, not the unsupported `offset` parameter.
- Read the documented `APIResources` response property and reject malformed or incomplete lists; never interpret an unrecognized response as an empty resource collection.
- Reuse an existing resource only if a separate `GET /api-resources/{id}` verifies the ID, identifier, intended name, and authorization requirement.
- On a concurrent duplicate-create `409`, permit recovery only for `API-RESOURCE-60003`, then perform the same authoritative readback.
- Verify scopes `requests:read`, `requests:create`, `requests:approve`; add only missing scopes and read back again.
- Leave unrelated API resources, applications, root tenants and data untouched.

## Installation

From the extracted Magalu CIAM project (not inside the ZIP):

```sh
unzip -o ~/Downloads/magalu-ciam-is73-api-resource-409-hotfix.zip
chmod +x scripts/fix-storefront-api-resource.sh
./scripts/fix-storefront-api-resource.sh
```

The launcher rebuilds the bootstrap and resumes the six-storefront provisioning against the existing isolated WSO2 stack. It does not delete volumes or reboot WSO2. If later steps fail, the exact error is written to `generated/storefront-provision-report.json` and emitted to the terminal.

## Technical evidence

WSO2 API Resource Management REST API reference documents `APIResources`, `totalResults`, `filter=identifier eq ...`, and `PUT /api-resources/{id}/scopes`:
https://is.docs.wso2.com/en/7.0.0/apis/api-resource-management-rest-api/

## Validation limitations

Unit tests cover the response formats and idempotent behavior; this patch has not been executed against the user's localhost WSO2 server. Successful API resource provisioning does not prove interactive authentication, six-way session isolation, role enforcement, TOTP step-up, or full RFP Section 7 compliance. These require live tests.
