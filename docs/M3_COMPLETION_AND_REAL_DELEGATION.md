# M3 completion: Native Consent and a business-facing RFC 8693 demo

## Trust boundaries

- `/m3/native-consent` mirrors a custom directional GRANTED link via an **operator-created** WSO2 Consent Management v2 record. It is *not* the My Account OIDC application-consent flow.
- `/m3/support-journey` issues real token-exchange requests and invokes protected APIs; it uses a synthetic support request, not a production order store.
- The subject and actor JWTs, management credentials, the test-client manifest, and WSO2 private data remain on the server inside excluded `generated/` paths.
- A returned HTTP `403` alone is not enough: the resource server must have cryptographically verified the token, issuer, audience and scopes.
- The final RFC 8693 report passes only with a dedicated registered audience and WSO2 management API readback.

## Apply without destroying the running environment

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
python3 /tmp/m3-completion/scripts/install-m3-completion.py --check
python3 /tmp/m3-completion/scripts/install-m3-completion.py
python3 -m py_compile demo/m3_native_lab.py demo/m3_exchange_lab.py
python3 -m pytest -q tests/test_m3_completion.py tests/test_m3_native_consent.py tests/test_m3_exchange_storytelling.py
DC=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
"${DC[@]}" build demo
"${DC[@]}" up -d --no-deps demo
curl -fsS http://localhost:8180/m3/native-consent -o /dev/null
curl -fsS http://localhost:8180/m3/support-journey -o /dev/null
```

The installer creates backups only under the ignored `generated/backups/` directory, does not modify WSO2/DB, and refuses a wrong Git root. The overlay modifies the source only; the restart is solely for the `demo` service.

## A. Native consent live acceptance

1. Open `http://localhost:8181` and `http://localhost:8183`, sign in as `ana.magalu` in both. Open `http://localhost:8180/m3/consent` and create a **new** Magalu → Netshoes directional link. This is important: the earlier link already has a revoked custom grant and an active native mirror.
2. Grant the **new** link explicitly through the existing application UI; its custom state must remain `GRANTED` until after the native revocation test.
3. Capture a fresh subject token: `./scripts/m3-local.sh capture-subject --insecure-local`. Do not show its contents.
4. Open `http://localhost:8180/m3/native-consent`. Enter `DEMO_OPERATOR_KEY`, run both-tenant preflight, refresh/select the new GRANTED link, acknowledge the two confirmations, and create the native mirror.
5. Click **Ler estados atuais: native + ledger**. Record `ACTIVE`, `GRANTED`, and the effective ALLOW decision. Click **Testar acesso protegido** and verify HTTP 200, `BOTH_CONSENTS_ACTIVE`.
6. Next, click the existing WSO2 native revocation action with explicit confirmation. The current adapter uses `DELETE /consents/{id}` and demands `GET` readback with state `REVOKED`. This method's compatibility with your exact WSO2 update has not been established. If it responds `BLOCKED`, do not proceed as though revocation succeeded or blindly switch the HTTP method.
7. Only if native `REVOKED` is read back, click **Retestar API após mudança** while the custom ledger is still `GRANTED`. The native decision must deny HTTP 403 due to `NATIVE_REVOKED`. Then reconcile: the custom grant must change to `REVOKED` and the acceptance report can become `PASS`.
8. If custom state was revoked first, do not reuse that same link for the full demonstration: it cannot prove a native-caused denial and reconciliation transition. Create another link.

The additional `live-state` readback endpoint does not mutate either authority and reports the current state of both independently. It never fabricates a passed consent outcome.

## B. Distinct WSO2 My Account end-user consent

1. Sign into `https://localhost:9543/console`, select the `magalu.demo` tenant, open the Magalu Web OIDC application.
2. Configure a specific user attribute for release, such as `email` or `given_name` for synthetic Ana; make sure the client requests the matching scope and **Skip login consent** is disabled.
3. Sign out and initiate a fresh interactive Magalu Web authentication at `http://localhost:8181` as `ana.magalu`. Observe the native WSO2 attribute-consent prompt and approve it.
4. Log in to `https://localhost:9543/myaccount` as exactly the same Ana in the same root tenant, go to **Consents / Application Consents**, and confirm the application and attributes are listed.
5. Revoke from My Account. Confirm the portal reflects it; start a new OIDC login and observe consent requested again. Preserve screenshots and a sanitized operator checklist outside Git, if authorized.

This is a separate acceptance path. The admin-created record's `serviceId=magalu-ciam-consent-lab` is not expected to show as Magalu Web's OIDC application consent. Do not treat My Account visibility as a property of the admin-mirrored record.

## C. Real WSO2 token exchange, business story

**Story:** Ana owns a synthetic Magalu support request. Bruno is the acting support agent. Bruno is permitted to read the request in Ana's context but cannot approve it using Ana's authority.

1. Ensure WSO2 and demo are healthy. Refresh local identity tokens:

   ```bash
   ./scripts/m3-local.sh setup
   ./scripts/m3-local.sh capture-subject --insecure-local
   ./scripts/m3-local.sh capture-actor --insecure-local
   ```

   Use `ana.magalu` for the subject and `bruno.seller` for the actor. The two sign-ins are real. Each JWT must have the expected scopes.

2. Verify a dedicated resource audience is configured in WSO2 and has management API readback. If the new UI says audience not registered, follow `docs/M3_FINAL_AUDIENCE_AND_RESOURCE_ACCEPTANCE.md` and the repository's existing `scripts/register-m3-resource-audience.sh`/`scripts/set-m3-resource-audience.sh`. Do not enter an arbitrary audience value to make the check pass.
3. Open `http://localhost:8180/m3/support-journey`. Enter `DEMO_OPERATOR_KEY` from your local `.env` (do not publish it), and click **Executar transação de atendimento real**.
4. The backend makes three RFC 8693 exchanges with real signed subject/actor JWTs, validates the returned JWT using the WSO2 JWKS, and makes HTTP calls to `/api/m3/exchange/resource/read` and `/api/m3/exchange/resource/approve-check`:
   - Ana's subject-only read token exchange (control)
   - Bruno acting on behalf of Ana; reduced `requests:read`, `sub`=Ana, `act.sub`=Bruno, read API returns HTTP 200
   - Attempt to escalate to `requests:approve` is rejected or reduced by WSO2; the protected approval check returns HTTP 403 due to `INSUFFICIENT_SCOPE`
5. Only when all security gates and audience registration are validated does the report show `PASS`. Export sanitized evidence. For deeper protocol details see `/m3/exchange`.

**Boundary:** The resource is a synthetic support request. The approval check intentionally does not mutate workflow state. Wiring to real Magalu order/status systems is a separate integration, not part of this local PoC.

## D. Remaining acceptance work (not automatically implemented)

- A compatible **native administrative revocation method**, confirmed against the running WSO2 Consent v2 OpenAPI contract, with `REVOKED` readback (not deletion/404).
- Native end-user self-service OIDC application consent as a tested login/My Account scenario, distinct from the admin API mirror.
- Optional production synchronization with WSO2 consent webhooks / replay protection, if required by the RFP. The local policy already rechecks native state on resource reads; this is not webhook synchronization.
- An actual business order API integration, if required beyond the synthetic support request.

Do not call the current acceptance report `PASS` until the corresponding live evidence is recorded.
