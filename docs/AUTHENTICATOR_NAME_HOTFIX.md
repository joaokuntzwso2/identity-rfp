# WSO2 IS 7.3.0.18 — ACR/TOTP authenticator name repair

## Observed live failure

At the first six-storefront login-flow PATCH:

- `PATCH /t/magalu.demo/api/server/v1/applications/{appId}` → `400 APP-60001`
- Description: `Authenticator basic is not available in the server.`

Cause: The provisioning code used the **display name** `basic` in
`authenticationSequence.steps[].options[].authenticator`. WSO2 exposes a
separate internal name, usually `BasicAuthenticator`. For TOTP the documented
internal name is commonly `totp`.

## Changes

- Before mutating an application, `GET /api/server/v1/configs/authenticators?type=LOCAL`
  for its *current root tenant*.
- Require an enabled, internal `BasicAuthenticator` and a real enabled TOTP
  authenticator. No generic fallback that could bypass MFA.
- Register 2 steps: password then TOTP. Keep conditional ACR selection for
  approval (`urn:magalu:aal2:totp`).
- Refuse to overwrite an unrelated user-customized login flow.
- Read back both steps. Keep the distinction between script write success and
  demonstrable script/AMR enforcement.

## Apply

From the existing project folder:

```sh
unzip -o ~/Downloads/magalu-ciam-is73-acr-totp-authenticator-hotfix.zip
chmod +x scripts/fix-storefront-authenticators.sh
./scripts/fix-storefront-authenticators.sh
```

The launcher rebuilds **bootstrap** and **demo** images, reruns an idempotent
schema migration and provisioning pass, and then starts all six storefronts.
It does not intentionally replace WSO2/identity-db/db containers or delete
volumes. Do not run `docker compose down -v`.

## Next acceptance checks

1. Confirm `/healthz` on ports 8181–8186.
2. Confirm each storefront can login, logout, and requires authentication on
   the next login. Test cross-brand and web/mobile session independence.
3. TOTP-enroll `bruno.seller` and `carla.risk` via the appropriate tenant's
   My Account portal.
4. Create request with `requests:create`, approve with separate user who has
   `requests:approve`. Check WSO2-signed ID token's **ACR**, **AMR (`totp`)**,
   and **auth_time**, and ensure self-approval and cross-brand approvals fail.
5. Approval is **NOT validated** until a real browser TOTP step-up completes.

If `BasicAuthenticator` or TOTP is not listed as enabled, the repair stops with
an explicit list of authenticator names for the affected tenant. Review the
WSO2 Login Flow or authenticator availability; do not disable the check.
