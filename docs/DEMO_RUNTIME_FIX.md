# Demo portal runtime dependency hotfix

## Root cause

The demo Python image installs `requirements.txt`, but it previously omitted
`itsdangerous`, which Starlette's `SessionMiddleware` imports at application startup.
That causes `ModuleNotFoundError: No module named 'itsdangerous'` and an exit-code-1
restart loop. The container therefore never publishes a live HTTP service on port 8180.

## Apply

From the project directory, after unzipping the patch:

```bash
chmod +x scripts/fix-demo-runtime.sh
./scripts/fix-demo-runtime.sh
```

This adds a pinned dependency if absent, builds only the demo image, force-recreates
only the demo container and validates `/healthz`. No `down`, volume removal, WSO2
recreation, or bootstrap operation is performed.

The portal should then respond at `http://127.0.0.1:8180/`.

If it does not, the script displays the last 100 demo container log lines. Treat a
healthy `/healthz` response as portal availability, **not** proof that all Section 7
OIDC flows have passed their acceptance checks.
