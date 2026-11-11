# RFP Section 7 architecture traceability

| Section | New evidence artifact | Status |
|---|---|---|
| 7.1 | `generated/bootstrap-report.json`, `generated/manifest.json`, two root tenants + web/mobile clients | Automated but unverified until run against actual 7.3.18 |
| 7.2 #1 | `demo/policy.py`, six-login `/api/evidence` | Requires six real logins |
| 7.2 #2 | App requested scopes and real claims comparison | Native deny-by-default release mapping still required |
| 7.2 #3 | Assurance ledger, step-up fixture | Native authentication policy integration required |
| 7.2 #4 | `consent/migrations`, directional grant/revoke events | Native consent enforcement still required |
| 7.2 #5 | `scripts/m2m_cli.py` RFC 8693 | Actor/issued_token_type/down-scope live test required |
| 7.2 #6 | `compose.stores.yaml` (optional LDAP) | Tenant-specific WSO2 user store registration required |
| 7.2 #7 | `scripts/onboard_brand.py` creates third **root** tenant | Existing roots' unaffected operation requires live evidence |
| 7.3 PF/PJ | Portal retail/seller, SCIM users, roles | Functional acceptance walkthrough not yet performed |
| 7.3 M2M | `load/m2m.js` | 1,000 RPS 30-min real run, p95/p99 and error ceiling pending |
