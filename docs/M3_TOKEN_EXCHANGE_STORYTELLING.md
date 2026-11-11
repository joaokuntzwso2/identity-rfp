# Milestone 3 — RFC 8693 Token Exchange, live storytelling demo

This is an **operator-only, locally hosted** workbench at `http://localhost:8180/m3/exchange`.
It does not replace the WSO2 source of truth and does not generate tokens in a browser.

## The narrative (3–5 minutes)

**Act 1 — Authority starts with Ana.** A real Ana JWT has `requests:read` and `requests:create`, but not `requests:approve`. The Workbench verifies its signature using WSO2's published JWKS. The subject-only exchange isolates whether the exchange client is trusted and permitted the requested resource scope.

**Act 2 — Bruno acts, but does not become Ana.** A different, real Bruno JWT identifies the actor. The second request sends `subject_token` and `actor_token` to WSO2. The resulting signed token must preserve `sub` for Ana, include `act.sub` for Bruno, and have only read access among business scopes.

**Act 3 — Authority cannot be escalated.** An exchange request for `requests:approve` should be denied because Ana did not possess that scope. This negative test is **BLOCKED**, not PASS, until the legitimate delegated exchange succeeds. Review the OAuth error without exposing secrets.

**Separate from TOTP:** These captures prove actor identity and tokens, not a TOTP ceremony. TOTP approval is demonstrated in Milestone 2.

**Final gate — Audience.** Provide a real, registered resource audience in the workbench. The issuer must set and sign that `aud` in the delegated token. A delegated exchange without an explicitly verified audience can at best reach *PARTIAL* acceptance.

## Install

Download the overlay and extract over the **existing** project. It does not replace `.env`, generated JWTs, existing DB migrations, or past code changes.

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
unzip -o ~/Downloads/magalu-ciam-m3-exchange-storytelling-workbench.zip
chmod +x scripts/install-m3-exchange-lab.sh scripts/validate-m3-exchange-lab.sh
./scripts/install-m3-exchange-lab.sh
./scripts/validate-m3-exchange-lab.sh
open http://localhost:8180/m3/exchange
```

## Credentials and evidence

The operator input is `DEMO_OPERATOR_KEY` from the existing `.env`. To view it **only on your Mac**, run:

```bash
python3 - <<'PY'
from pathlib import Path
for line in Path('.env').read_text().splitlines():
    if line.startswith('DEMO_OPERATOR_KEY='):
        print(line.split('=',1)[1]); break
PY
```

Do not share, screenshot or commit the operator key. The workbench holds it in page memory only during the live action; do not use this development-only HTTP setup on the public internet.

The token files must exist and be permission 0600:

```bash
./scripts/m3-local.sh capture-subject --insecure-local
./scripts/m3-local.sh capture-actor --insecure-local
```

Use those fresh captures quickly, before expiration. The only file output from the workbench is the **sanitized report** at `generated/m3-exchange-lab-report.json` (mode 0600). Downloading `GET /api/m3/exchange/evidence` returns the same sanitized report.

## What to investigate if HTTP 400 persists

- `invalid_scope`: inspect authorized API-resource scopes on the **requesting exchange client**, not just the subject and actor tokens.
- `unauthorized_client`: verify `urn:ietf:params:oauth:grant-type:token-exchange` on the exchange client.
- `invalid_grant` / `invalid_request`: confirm subject/actor signatures, tenant issuer, token types, account resolution and WSO2 logs.
- `invalid_target`: register the chosen audience on the exchange client; do not guess a value.

Local-only diagnostic; all endpoint URLs are fixed to configured WSO2 localhost/Docker origins. No arbitrary URLs, tokens, or client secrets are accepted from the browser.

## Evidence versus acceptance

1. A status of **PASS** requires signature-verified delegated token with correct `sub`, `act.sub`, reduced scopes, safe escalation rejection, and target `aud` match.
2. A `400` response to `requests:approve` by itself never constitutes security acceptance.
3. Native WSO2 Consent Management v2 integration is a separate RFP gate and remains unverified by this page.
4. Do not claim any test passed before examining the live report and verifying the target audience registration in WSO2.
