# RFC 8693 diagnostic (local WSO2 IS 7.3.18)

This patch **does not modify** WSO2 configuration, users, grants, containers or databases.
It sends three token requests: subject-only read exchange, delegated read exchange,
and delegated forbidden approve request. Results are *diagnostics*, not acceptance.

```sh
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
unzip -o ~/Downloads/magalu-ciam-m3-exchange-diagnostic.zip
chmod +x scripts/diagnose-m3-exchange.sh
./scripts/diagnose-m3-exchange.sh
```

Output: `generated/m3-exchange-diagnostic.json` (chmod 600).
Never share raw `generated/manifest.json` or files under `generated/m3-tokens/`.
Share only the redacted diagnostic JSON. Run quickly after capturing JWTs;
if expired, rerun capture-subject and capture-actor.

Typical interpretations:

* `subject_only_read` fails: check `error`/`description`, token `aud`, client grant,
  and the requesting client's API-resource `requests:read` authorization.
* `subject_only_read` succeeds, `delegated_read` fails: check actor user
  resolution, account enabled/locked, and actor token type.
* `delegated_read` succeeds, `delegated_forbidden_approve` issues approve scope:
  privilege escalation; fail the PoC.
* A denied `requests:approve` request is not a security pass if the baseline
  `requests:read` exchange also fails.

Do not treat `--insecure-local` (TLS verification bypass) as acceptable outside
isolated localhost development. For customer demonstration use trusted TLS.
