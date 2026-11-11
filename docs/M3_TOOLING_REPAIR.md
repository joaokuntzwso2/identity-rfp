# Milestone 3: RFC 8693 tooling repair

The consent demo **already passed** its grant/revoke enforcement sequence in the user's live stack. This repair changes **only** M3 launcher scripts; it does not reset WSO2, restart services, modify users, or change PostgreSQL.

## Errors corrected

- `ModuleNotFoundError: No module named 'bootstrap'`: the provisioner was called as a file from `scripts/`; Python's import path then excluded the `/project` repository root. The Docker bootstrap runner now uses `python -m scripts.m3_provision_oauth_test_client` from the Dockerfile's `/project` working directory.
- `ModuleNotFoundError: No module named 'jwt'`: the command ran with a host Python interpreter lacking PyJWT. The new `scripts/m3-local.sh setup` creates a dedicated local virtual environment with pinned PyJWT, requests and cryptography. WSO2's Docker bootstrap image already carries these Python dependencies.

## Commands

From the existing Magalu project root:

```bash
chmod +x scripts/provision-m3-oauth-test.sh scripts/m3-local.sh scripts/check-m3-tooling.sh
./scripts/check-m3-tooling.sh
./scripts/provision-m3-oauth-test.sh
./scripts/m3-local.sh setup
./scripts/m3-local.sh capture-subject --insecure-local
./scripts/m3-local.sh capture-actor --insecure-local
./scripts/m3-local.sh verify --insecure-local
```

The initial verifier run without `--audience` is **diagnostic only**; it returns `INCOMPLETE_OR_FAIL` even if delegation works, because full validation needs the registered resource audience. Once the actual audience is configured on the exchange client and verified, repeat with:

```bash
./scripts/m3-local.sh verify --insecure-local --audience 'ACTUAL_CONFIGURED_RESOURCE_AUDIENCE'
```

Do **not** use an arbitrary audience just to achieve a PASS. The audience must correspond to the configured WSO2 resource server. A separately executed cross-tenant rejection test is still required. Native WSO2 Consent Management v2 synchronization is also not tested by the customer-owned consent demonstration.

## Security

Keep `.venv-m3/`, `generated/m3-oauth-test-client.json`, and `generated/m3-tokens/` out of Git. Do not paste raw tokens or secrets in chat. Once the exchange test is complete, delete the two JWT token files.
