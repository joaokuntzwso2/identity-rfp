# M3 RFC 8693 actor resolution correction

The 2026-11-11 local trace showed `Actor token could not be resolved to a registered user.` WSO2's delegation guide says the actor is resolved by `actor_token.sub` against an active user in the organization. The special M3 evidence app had pairwise subject configured; this is a likely mismatch with its SCIM user ID.

## Before applying the fix

Run `./.venv-m3/bin/python scripts/m3_actor_identity_probe.py --insecure-local`. It **cryptographically verifies** the actor JWT against tenant JWKS before comparing `sub` to the SCIM `id` already recorded in `generated/manifest.json`. Only booleans appear in output; no user ID, JWT or credentials.

If `actor_sub_equals_scim_id` is `false`, apply `./scripts/apply-m3-actor-resolution-fix.sh`. This updates **only** the separate `MAGALU CIAM POC - M3 - TOKEN EVIDENCE` client to public subject, and ensures the Commerce exchange client has `requests:read` API authorization plus Ana's app-scoped read role. Existing storefront clients remain pairwise, and only the Commerce exchange app is affected, not Fintech.

IMPORTANT: This technical evidence client is intentionally different from customer-facing pairwise clients. For the customer PoC, document that public stable identifiers are restricted to an isolated internal trusted application and not distributed to storefronts.

After applying, capture *both* fresh JWTs:

```
./scripts/m3-local.sh capture-subject --insecure-local
./scripts/m3-local.sh capture-actor --insecure-local
./.venv-m3/bin/python scripts/m3_actor_identity_probe.py --insecure-local
./scripts/diagnose-m3-exchange.sh
```

Expected actor comparison: `actor_sub_equals_scim_id: true`. Expected delegated exchange: HTTP 200, signed JWT, `sub=Ana`, `act.sub=Bruno`, and exactly `requests:read`. Then verify a configured audience; do not mark Milestone 3 complete before that and negative tests.

If `actor_sub_equals_scim_id` was already `true` **before** applying the fix, do not apply blindly. Check the tenant's live SCIM user record, account active/unlocked status, subject lookup configuration, and WSO2 OAuth logs; avoid changing subjects without a reason.

The empty scope in the earlier successful exchange is a separate issue. This patch grants `requests:read` at the requesting exchange application and binds Ana to an application-scoped read-only role. It does not claim success until the exchanged JWT actually contains that scope. It does not grant approval to this role.

## Security / operational notes

- Never paste `generated/manifest.json`, JWTs, `.env`, or client secrets into chat or Git.
- The local self-signed `--insecure-local` option is for this isolated Mac lab only.
- Do not alter pairwise settings of the six storefronts.
- Preserve earlier consent evidence; this patch makes no consent or database modifications.
- Local static checks cannot prove that the WSO2 management API on your Mac accepts the new setting. Readback will fail closed if it does not.
