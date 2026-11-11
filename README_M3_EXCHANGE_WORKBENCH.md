# Magalu CIAM Milestone 3 — Visual Token Exchange Workbench

Professional local technical evidence page for **RFP Section 7.2, Demonstration 5**.

New UI: http://localhost:8180/m3/exchange

- Ana (subject), Bruno (actor), WSO2 authorization server, and narrowed access token are presented as a coherent, Portuguese-language story.
- Three real requests: subject-only read, delegated read, and attempted approval-scope escalation.
- Full safe diagnostics: HTTP result, sanitized OAuth error, verified JWT claims, `sub`, `act.sub`, scopes, `issued_token_type`, and audience match.
- Rejection cannot be credited as a pass unless the legitimate delegated exchange succeeds.
- `PASS` requires a verified audience; absent audience is reported as PARTIAL.
- No raw JWTs, client secrets, or passwords are sent to the browser.
- Operator key and same-origin browser check protect active Token Exchange execution.
- Installer adds only a new route, assets, and navigation link; it rebuilds only the **demo** container.
- WSO2 and PostgreSQL remain untouched; existing consent and pairwise pages remain in place.

See `docs/M3_TOKEN_EXCHANGE_STORYTELLING.md` for exact Mac commands and customer presentation script.

**This ZIP passed local tests and route checks; it has not been run against your Mac's WSO2 instance.**
