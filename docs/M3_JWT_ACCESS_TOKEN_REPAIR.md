# M3 RFC 8693 — JWT access token repair

## Symptom

`m3_oidc_capture.py` reports `DecodeError: Not enough segments` after a successful WSO2 browser login. The application can issue a standard OIDC `id_token` JWT while issuing an **opaque OAuth access token**. The previous capture code tried to decode the opaque access token as a JWT and did not save either token.

## Scoped fix

This patch changes **only** `MAGALU CIAM POC - M3 - TOKEN EVIDENCE` in the `magalu.demo` root tenant. It uses `GET` then `PUT` of `/api/server/v1/applications/{appId}/inbound-protocols/oidc`, setting `accessToken.type` to `JWT` and checking the GET readback. Existing redirects, PKCE, sector configuration, client ID and OAuth grant types are preserved. This is required for the WSO2 locally-issued token exchange demonstration using JWT subject and actor tokens.

It does not modify the six storefront applications, the exchange M2M client, consent data, or any PostgreSQL schema.

## Install

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
unzip -o ~/Downloads/magalu-ciam-m3-jwt-access-token-fix.zip
chmod +x scripts/fix-m3-jwt-access-tokens.sh
./scripts/fix-m3-jwt-access-tokens.sh
```

## Verify

Once the output includes `jwt_access_tokens_verified: true`, **restart the two authorization flows**:

```bash
./scripts/m3-local.sh capture-subject --insecure-local
./scripts/m3-local.sh capture-actor --insecure-local
ls -l generated/m3-tokens/{subject,actor}.jwt
./scripts/m3-local.sh verify --insecure-local
```

The capture script verifies the signed ID token and access token (using WSO2 JWKS) and stores only valid access JWTs in locally permission-restricted files. It now reports an actionable non-JWT error rather than a raw decoder exception.

**Do not post token files, OIDC callback codes, client credentials, or JWTs in chat.** Share only sanitized error codes and the verifier's final JSON status.

## Important remaining acceptance scope

A successful `subject.jwt` / `actor.jwt` capture is **not** Token Exchange evidence. The RFC 8693 verifier must successfully validate a delegated exchanged token, `act.sub`, audience restriction, `issued_token_type`, and scope reduction. The current verifier deliberately does not report full PASS without a registered audience; validate that next. Its negative test and cross-root rejection should also be independently reviewed before final customer signoff.

References:
- https://is.docs.wso2.com/en/7.2.0/guides/authentication/configure-token-exchange/
- https://is.docs.wso2.com/en/next/apis/application-rest-api/
