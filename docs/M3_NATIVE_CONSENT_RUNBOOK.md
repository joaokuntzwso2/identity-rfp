# Magalu CIAM — Native WSO2 Consent Management v2 / Milestone 3

## Security and scope

This overlay adds an **operator-controlled integration demonstration**, not an automatic replacement of the application's directional consent ledger. It maintains an explicit record in the native WSO2 Consent Management v2 API, and its synthetic data API **consults WSO2 native state on every call** alongside the existing PostgreSQL grant.

The native consent created by this PoC is an **administrator-created mirror of an explicit user-authorized business grant** (`ADMIN_API_MIRROR_OF_EXPLICIT_CUSTOM_GRANT`); it is not evidence of an end-user consent screen inside WSO2 OIDC or My Account. The signed public subject token and private SCIM user ID, plus an explicit operator attestation, bind the synthetic Ana test fixture; production account linking needs a protocol-level identity proof, not an operator attestation.

This package has not been run against your Mac WSO2 instance. The native revocation path `DELETE /consents/{id}` is **build-version-sensitive** and must be verified live; HTTP 404/405, deletion without `REVOKED` readback, or any unsupported response remain **BLOCKED**, never PASS. The customer's native application-consent requirements may need a separate OIDC/My Account test.

## Installation (only demo service rebuilt)

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
mkdir -p /tmp/magalu-m3-native
unzip -oq ~/Downloads/magalu-ciam-m3-native-consent-compliance.zip -d /tmp/magalu-m3-native
bash /tmp/magalu-m3-native/scripts/install-m3-native-consent-lab.sh "$PWD"
```

Installer backs up `demo/main.py` and existing module files under private `generated/backups/`; does not touch WSO2 tenants, other Docker projects, volumes, six storefronts, or consent ledger.

## Provision native management clients and catalog

```bash
./scripts/setup-m3-native-consent.sh
```

This checks tenant-specific native Consent Management v2 Purposes, Elements, and Consents API resources, creates a separate M2M management application per root tenant, authorizes only the needed scopes, and creates a synthetic purpose and element in Commerce. The management scope names are documented by WSO2. Outputs private, mode-0600 files `generated/m3-native-clients.json` and `generated/m3-native-catalog.json` **(never commit)**. The WSO2 identity database is never altered by SQL. On a native 500 response, verify the official consent migration for the actual image/update before changing the existing database; never apply blind migrations.

## Exact browser demo

1. Log in to Magalu Web `http://localhost:8181` and Netshoes Web `http://localhost:8183` as Commerce `ana.magalu` in the same localhost browser profile. Optionally authenticate to MagaluPay Web (`8185`) as Fintech Ana for a visual tenant separation indicator.
2. Refresh the subject token capture if needed: `./scripts/m3-local.sh capture-subject --insecure-local`, authenticate as Commerce `ana.magalu`; file is private and contains a signed JWT with public `sub`, not the brand-pairwise sub.
3. Open `http://localhost:8180/m3/consent`: link Magalu → Netshoes if not already linked; explicitly **grant** directional consent. Do not use a revoked old link as a new grant.
4. Open `http://localhost:8180/m3/native-consent`, input `DEMO_OPERATOR_KEY` from your private `.env` (never share the key).
5. **Act 01**: Verify native API in Commerce and Fintech with *Consultar WSO2 v2 nos dois tenants*; expect both catalogs reachable and purpose readback true.
6. **Act 02**: Click refresh and select the consent link with state GRANTED.
7. **Act 03**: Check both explicit confirmations and click *Criar e verificar consentimento nativo*. Expect `NATIVE_CONSENT_CREATED_AND_READBACK_VERIFIED`; a native API response and follow-up readback must match.
8. **Act 04**: Click *Testar acesso protegido*. Expect HTTP **200** with both grants ACTIVE, and a synthetic profile. No raw JWT/private ID is returned.
9. **Act 05**: Check the explicit native-revocation confirmation and click *Revogar no WSO2*. Expect only **verified native state REVOKED** to count as success. If WSO2 returns `NATIVE_METHOD_NOT_SUPPORTED`, stop. **Do not substitute a database delete or a UI-only state change.** Consult the generated WSO2 7.3.0.18 OpenAPI or use native My Account self-service for a *separate*, properly linked application consent before implementing the correct native revoke operation.
10. Once native revocation is confirmed, click *Retestar API após mudança*. Expect HTTP **403** and reason `NATIVE_REVOKED`, **without browser logout**.
11. Click *Reconciliar*: this must revoke the custom ledger when native is inactive. It never restores a grant automatically.
12. Click *Avaliar critérios de aceite*, export sanitized JSON; the native scenario only qualifies PASS if every relevant live check is true. If WSO2 does not support the tested native revoke contract, it must remain INCOMPLETE.

## Native vs customer-owned behavior

| Aspect | WSO2 native API | Customer-owned ledger |
|---|---|---|
| Identity | SCIM ID/public-sub (operator-attested fixture) | Separate brand-specific pairwise subject |
| Purpose/element | WSO2 v2 purpose and element | Directional `magalu-netshoes` purpose |
| Grant | Admin mirror after explicit custom grant | User-confirmed in authenticated browser |
| Revocation | Native API; must be read back as `REVOKED` | Ledger transition and append-only hash chain |
| Protected data release | WSO2 ACTIVE state queried fresh | Grant direction and recipient checked transactionally |
| Failure to reach WSO2 | HTTP 503, deny access | No fallback or stale-allow cache |

## Troubleshooting

- `MANAGEMENT_SCOPE_NOT_GRANTED` / `NATIVE_SCOPE_DENIED`: inspect authorized API scopes on the M2M native application *in the correct root tenant*. Do not copy credentials between tenants.
- `NATIVE_NOT_FOUND`: inspect tenant-specific path, native consent ID, and whether the record was **deleted** rather than revoked; do not claim native revoked state from a 404.
- `NATIVE_SERVER_ERROR`: inspect WSO2 logs and verify consent schema migration for this updated build. Do not reset your WSO2 database.
- `CAPTURED_ANA_SUBJECT_NOT_SCIM_ID`: recapture from the dedicated **public-sub** evidence application, not the six pairwise OIDC storefront clients.
- `NATIVE_RESPONSE_INVALID` / native purpose creation 4xx: compare your build's generated API OpenAPI schema and adjust **payload mapping**, not security controls. Preserve the original error only in private local WSO2 logs.
- If native `DELETE /consents/{id}` returns 404 or 405, keep the scenario BLOCKED. Do not invent an alternative endpoint or send a destructive SQL operation.

## Evidence & source control

Only commit sanitized reports (review pseudonymous references and identifiers), not:

`generated/m3-native-clients.json`, `generated/m3-native-catalog.json`, `generated/m3-native-consent-links.json`, `generated/m3-native-consent-evidence.json`, `generated/m3-tokens/`, private manifests, `.env`, private keys or Docker volumes.

Read official product docs:
- https://is.docs.wso2.com/en/latest/guides/consent-management/
- https://is.docs.wso2.com/en/latest/apis/consent-management-v2-api-definition/
- https://healthcare.docs.wso2.com/docs/secure-health-apis/guides/configure-smart-on-fhir/
- https://is.docs.wso2.com/en/latest/guides/user-self-service/manage-consents/
