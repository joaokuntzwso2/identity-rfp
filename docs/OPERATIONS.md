# Operations — brand-new root-tenant-only stack

Use `./scripts/setup-isolated.sh` and `./scripts/run-isolated.sh`. No other project's WSO2/PostgreSQL containers or volumes are reused. Compose project name: `magalu-ciam73-s7lab`. Logs: `docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml logs -f is`. To deliberately clear **only** this project's data: `./scripts/reset-isolated.sh --destroy-magalu-poc-data`.

The first run requires an updated 7.3.0.18 binary archive (`WSO2_DIST_PATH`) or an updated image (`WSO2_IMAGE`). Without either, the launcher aborts. Don't relabel a vanilla 7.3.0 image as update-level 18.

The bootstrap report and local credentials are saved under `generated/` (private). Live tests are required for a PoC PASS; follow `RELEASE_GATES.md`.
