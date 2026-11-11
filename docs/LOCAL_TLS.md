# TLS and pairwise sectors — isolated root-tenant demo

The demo sector HTTPS service runs on the host at `https://localhost:8543` and inside the Compose network as three different hostnames: `https://sector-magalu`, `https://sector-netshoes` and `https://sector-magalupay`.

The OIDC `sectorIdentifierUri` **must have a distinct hostname for each brand**; a distinct path alone would not separate sectors. Web and mobile of a given brand share exactly the same URI. The URI response lists the redirect URIs.

`./scripts/generate-local-tls.sh` creates a local CA and a server cert with SANs for those names. `docker/wso2/Dockerfile.isolated` imports that CA into the updated WSO2 7.3 PKCS12 `client-truststore.p12` (not the obsolete `.jks` path). The generated `deployment.toml` explicitly selects this file. Keep CA keys in ignored `generated/tls` and never expose development server to the public internet using `admin/admin`.

The WSO2 public endpoint is `https://localhost:9543`; the portal is `http://localhost:8180`. Local `IS_TLS_VERIFY=false` is a lab-only convenience for the Python demo; it **does not** disable WSO2's outbound sector certificate validation.
