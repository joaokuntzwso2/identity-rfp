# Magalu RFP Section 7.2 — Acceptance Studio

**Classification:** Customer evaluation / confidential. Keep the repository private.

## Purpose and technical boundaries

This package extends the existing WSO2 Identity Server 7.3.0.18 PoC. It preserves tenant databases, storefront OAuth registrations, six OIDC BFFs, Token Exchange, existing consent ledger, TOTP approval and Native Consent v2 workbench. It adds a dedicated operator UI at `http://localhost:8180/m3/section7` and separately validated, sanitized evidence.

Inputs are the RFP of 23 September 2026 and the customer Q&A workbook. The customer defines:

* **B-01 / B-02:** brand-level pairwise `sub` with continuity across the same brand's web/app/PDV; four distinct real clients for Section 7.2.1.
* **B-09:** client-specific allowlists for claims, deny by default and actual token/UserInfo proof.
* **C-01 / C-02 / C-03 / C-05 / C-07:** N1 self-declared; N2 verified CPF by Receita Federal, own OTP-verified e-mail and phone, associated device; N3 adds facial biometrics **with live liveness** from specialist provider. `acr`/`amr` carry AAL/authentication; N1/N2/N3 are **separate derived identity levels**, not interchangeable with ACR or necessarily equivalent to NIST IAL1/2/3. High-risk transactions require an in-journey challenge and must not lose state.
* **D-01 / D-02 / D-07:** explicit tenant, client/scope, direction, purpose, and append-only grant/revoke audit. A->B must not grant B->A, and tenant data must not leak.

## 1 — Sub: four live sessions / two roots

1. Open Magalu Web `http://localhost:8181/login` and Magalu App `http://localhost:8182/login` in the **same browser profile**; use Commerce `ana.magalu` on both.
2. Open MagaluPay Web `http://localhost:8185/login` and MagaluPay App `http://localhost:8186/login`; use Fintech `ana.magalu`. Identity is the same *synthetic person* by a private, operator-controlled vault association, not by WSO2 native cross-root federation.
3. On `8180/m3/section7`, enter `DEMO_OPERATOR_KEY`, assert only if you used the same synthetic Ana, then compare four sessions.
4. Expected: `magalu:web.sub == magalu:app.sub`, `magalupay:web.sub == magalupay:app.sub`, and Commerce `sub !=` Fintech `sub`. The report returns **hashes**, no bearer tokens. Session source: BFF's verified WSO2 ID-token claims. The test is `PASS_WITH_OPERATOR_IDENTITY_ATTESTATION`, NOT proof of an identity broker, federation, or root-per-brand architecture.
5. Inspect `/pairwise` for the separate Magalu/Netshoes sectors within Commerce. A full B-01 claim about shared identity with each brand as a tenant requires migration to per-brand roots and authenticated federation/broker. **Do not mark that gap closed by the four sessions alone.**

## 2 — Claim minimization / compare actual JWT and UserInfo

1. In `https://localhost:9543/t/magalu.demo/console`, configure **Magalu Web** under Applications → User Attributes to allow only approved profile/e-mail fields (`name`, `given_name`, `family_name`, `email`, `email_verified` as applicable) and **Magalu App** to allow **no PII attributes**. Preserve minimum OIDC protocol claims. Disable any application defaults that expose unspecified attributes. Ensure the client scope configuration matches the intended test.
2. Login again to `8181` and `8182` as the **same** Commerce Ana, since the updated BFF records claim metadata during actual OIDC callback.
3. Click "Validar dois clients". The BFF keeps verified issuer, client_id, subject, and names of claims from the validated ID token and sub-matched UserInfo response. It never returns raw token or user attributes.
4. A `PASS_OBSERVED` means no non-allowlisted PII claim name was observed in **either** client and both had matching subjects. The source check does not directly introspect WSO2 application-management configuration; capture sanitized Console configuration/readback separately to claim native deny-by-default.
5. To prove the different **sets**, Magalu Web must actually return one or more allowed PII names while App returns none. An all-empty result does not demonstrate differentiated disclosure. This is a necessary manual gate.
6. Do not mistake an API/BFF omission for IdP claim minimization: if WSO2 emits unexpected PII in an ID token or UserInfo, the report returns FAIL even if your frontend never displays it.

## 3 — N2→N3 and AAL2: real provider bridge required

### WSO2 AAL2

1. Authenticate Ana in MagaluPay Web at `8185/login`, with real TOTP enrolled.
2. In Studio enter risk score 85 and select unknown device, then start a synthetic fintech transfer. The app stores a random transaction ID, bound to the live Pay issuer+pairwise subject, and a nonce. It keeps context for up to 15 minutes.
3. Click **Abrir step-up WSO2 TOTP**. The same Pay BFF requests `acr_values=urn:magalu:aal2:totp`, `prompt=login`, and passes a state/nonce/PKCE challenge to WSO2. WSO2's adaptive authentication flow must actually have step 2 configured for TOTP.
4. Authenticate with Ana and provide the real TOTP. WSO2 returns a signed ID token; the BFF validates signature, issuer, audience, nonce, actual `acr`, `amr=totp`, and recent `auth_time` before binding the result to the original transaction. Refresh Studio, reenter operator key, then click **Validar AAL2**.

### External N2 and N3 authoritative evidence

**Nothing in this code processes a camera feed or executes face recognition.** You must contract/configure an actual specialized verification provider (WSO2's supported IDVP workflow can connect, e.g., Onfido/Entrust according to installed connector support), plus real Receita CPF validation, real e-mail/phone OTP verifications and device registration. The trusted integration bridge should perform those steps externally, match the verified person's identity to the WSO2 session and sign a short-lived JWT result.

The bridge's signing public keys must be installed in a local generated-only file, and its issuer/audience configured on the `demo` service; example environment values (not credentials):

```text
S7_PROVIDER_JWKS_FILE=/project/generated/s7-provider-jwks.json
S7_PROVIDER_ISSUER=https://your-real-verifier.example
S7_PROVIDER_AUDIENCE=magalu-ciam-rfp-s7
```

Instead of manually editing the Compose service, place your **real provider's public JWKS** in a local file and run this command (replace the example with actual signer information):

```bash
python3 scripts/configure-s7-provider.py \
  --issuer 'https://your-real-verifier.example' \
  --audience 'magalu-ciam-rfp-s7' \
  --jwks-file '/path/to/vendor-public-jwks.json'
bash scripts/run-s7-acceptance.sh
```

The configuration script rejects private keys, saves the public JWKS under ignored `generated/`, creates `compose.s7-provider.local.yaml` (automatically ignored) and updates the `demo` service environment when the standard run script restarts it. **It does not provision a vendor account, capture a face, complete CPF/OTP verification or sign N2/N3 results.** You must implement and operate the independently trusted bridge and use real vendor/authority evidence.

Never place the signing private key, vendor API key, liveness image, full CPF or OTP in the repository or in the browser evidence report.

Bridge-issued JWT mandatory standard claims: `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`, `tx`, `nonce`, `subject_ref`. `subject_ref` is the first 20 hex chars of SHA-256 of `WSO2 issuer + '|' + WSO2 verified sub`. The nonce and transaction ID are returned by the Studio's start endpoint only to the authorized operator. The **trusted bridge** must additionally bind the provider's user session to that WSO2 authenticated subject server-side. Simply accepting an arbitrary client-supplied subject reference is insecure.

Use RS256 or ES256 with a configured, pinned `kid`. Maximum `exp - iat` is 300 seconds; single-use `jti` stored in the persistent, untracked `generated/s7-acceptance.sqlite3` database.

**N2 assertion** (`evidence_type: "N2_BASELINE"`) additionally contains four verification objects as `evidence`: `cpf` with source=`receita_federal`, method=`cpf_registry`; `email_otp` with source=`magalu`, method=`email_otp`; `phone_otp` with source=`magalu`, method=`phone_otp`; `device` with source=`magalu`, method=`device_binding`. Each object requires `attribute_key`, `source`, `method`, `state: "VERIFIED"`, `verified_at` (epoch seconds) and future `expires_at` (epoch seconds). Values, images and OTP secrets are never transmitted to this backend.

**N3 assertion** (`evidence_type: "N3_FACE_LIVENESS"`) additionally requires `decision:"approved"`, `liveness:true`, `face_match:true`, `document_match:true`, and a non-empty `vendor_case_id`. The verifier must actually check these before signing. The backend refuses N3 until N2 is present. Replayed or expired assertions are rejected.

After AAL2, N2 and N3 are independently verified, click "Decidir transação". Only then does the synthetic transaction move to `ALLOW`, maintaining the exact transaction ID. The implementation's AAL2 proof comes from WSO2, and the app's N3 proof from an externally signed verification attestation. **It does not automatically add a WSO2 `identity_level` claim**; that requires a defined custom claim, issuance policy, and signed token readback for C-02.

**Scope warning:** Without a vendor contract, connector configured in WSO2, live authoritative N2 checks, and signed vendor bridge, the real N2→N3 RFP demonstration is **not complete** even if the UI displays a challenge. No synthetic flag may be used to upgrade assurance.

## 4 — Consent isolation and audit

1. Authenticate Ana in Magalu Web and Netshoes Web in one browser profile.
2. Open `http://localhost:8180/m3/consent`, create/choose a **fresh** Magalu → Netshoes directional relationship. Grant it explicitly; record the link UUID. The reverse consent is a different authorization.
3. Open `http://localhost:8180/m3/native-consent`, run root-tenant preflight, create/read back the native administrator mirror, and test the API: expected 200 only when native ACTIVE + custom GRANTED.
4. Without revoking the custom grant, attempt native revocation using the current WSO2 v2 API contract; **the existing integration tries DELETE and requires state REVOKED on readback**. A 204 followed by 404/deletion is not proof of an auditable REVOKED state. If unsupported, record BLOCKED and stop; do not run untested SQL or falsify native records.
5. Only after native readback reports REVOKED: retest protected resource (403 `NATIVE_REVOKED`) while custom is still GRANTED; then reconcile and verify custom becomes REVOKED and append-only event exists.
6. Copy the UUID into Section 7 Studio and click "Verificar readback e trilha". The backend also tries reading the native record ID from the **other WSO2 root** and expects NOT_FOUND. Any API/network error is BLOCKED, not PASS.
7. **Gaps:** existing native mirror is an administrative action rather than Ana's native user-facing application-consent lifecycle; it is separate from My Account. Cross-root absence is evidence of an isolation boundary but is not an exhaustive proof of all tenant attributes/scopes. The final export must include the live negative tests and append-only custom ledger events. Current UI audit is a summarized event view; do not call it a signed or immutable forensic log.

## Testing, privacy and change management

* Run `python -m pytest -q tests/test_s7_acceptance.py`. The fixture signing key is generated **in memory** for cryptographic unit tests; it does not simulate a real biometric provider or count as compliance evidence.
* Restart only dashboard and four BFFs via `bash scripts/run-s7-acceptance.sh`. WSO2, PostgreSQL and other BFFs are not restarted. Browser sessions in rebuilt BFFs must be reauthenticated.
* Download the UI's sanitised JSON report; keep credentialed manifests, JWTs, vendor API keys, private signing keys and biometric content under `generated/` outside Git.
* The repository's `generated/` directory must remain ignored. Do not publish RFP/Q&A customer spreadsheets on public GitHub.
* A complete Section 7 score requires independent live evidence for each demonstration and customer-approved acceptance parameters. This package does **not** replace broader tenant-as-brand architecture, identity broker, signed N3 token claim integration, or the Section 7.3 authorized 1,000 RPS load test.

## Source references

WSO2: https://is.docs.wso2.com/en/latest/guides/consent-management/

WSO2: https://is.docs.wso2.com/en/latest/guides/user-self-service/manage-consents/

WSO2: https://is.docs.wso2.com/en/next/guides/identity-verification/configure-identity-verification-provider/

WSO2: https://is.docs.wso2.com/en/7.2.0/guides/authentication/conditional-auth/

RFP: Sections 4, 6 (B-01/B-02/B-09/C-01..C-07/D-01/D-02/D-07), 7.2.1–7.2.4, and the customer's written Q&A of 28 October 2026.
