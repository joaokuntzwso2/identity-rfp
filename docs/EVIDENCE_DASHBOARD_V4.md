# Magalu Login | Six-storefront session observability (port 8180)

## Purpose

The original portal at port 8180 attempted to run an additional OIDC login flow,
then depended on a `preferred_username` mapping claim that wasn't released. It
also had its own in-memory authentication sessions and could not see sessions
created by the six independent applications.

Version 4 deliberately **retires the original 8180 OIDC callback and login flow**.
Port 8180 becomes a **read-only evaluation dashboard**, never a seventh relying
party. It does not authenticate, approve, revoke, or correlate users.

Existing old-style URLs `/auth/start/{brand}/{channel}` now redirect to the
corresponding independent storefront `/login` route. The retired 8180 callback
shows a restart message rather than accepting tokens.

## Status algorithm

1. Browser visits `http://localhost:8180`.
2. Browser automatically sends all cookies scoped to the `localhost` hostname.
   HTTP cookies are hostname scoped, **not port scoped**, hence the six services
   use distinct session-cookie names.
3. Port 8180 selects only the one expected session cookie for each storefront,
   and forwards it over the fixed, private Compose network to that storefront's
   `/api/session` endpoint. It doesn't forward any WSO2 session cookie, bearer
   token, or another storefront's cookie.
4. Each storefront independently verifies the signature and server-side SID,
   returning `authenticated: true` only if its own session is still live.
5. The dashboard returns only per-application authenticated/unavailable status.
   No `sub`, scope, username, ID token, access token, or refresh token is exposed.
6. If the browser doesn't have that storefront's cookie, the dashboard only
   checks the storefront's `/healthz` endpoint.

## Session independence

- Logging into one storefront never creates another storefront session.
- Logging out only invalidates that storefront session.
- Each new login requests interactive authentication from WSO2 using
  `prompt=login` and `max_age=0`.
- Dashboard polling is read-only and never changes authentication state.

## Constraints and evidence

- Open all applications using `localhost` (not `127.0.0.1`), in the same browser
  profile. Browser incognito profiles do not share cookies.
- This status mechanism uses the original project's process-local session store,
  so restarting a storefront invalidates that storefront's login. This is a
  demonstration architecture, not a highly available session cluster.
- The dashboard reflects *browser sessions*, **not** WSO2 central SSO state,
  account linking, or pairwise `sub` correctness.
- Pairwise OIDC subject evidence still requires reading each application's
  `/api/session` after authenticating the same test identity to all six clients.
- Scope and TOTP enforcement must be verified separately by live request approval.

## Install (only demo service changes)

```bash
cd /Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc
unzip -o ~/Downloads/magalu-ciam-8180-evidence-dashboard-hotfix.zip
chmod +x scripts/fix-8180-dashboard.sh
./scripts/fix-8180-dashboard.sh
```

## Smoke validation

In a *single browser profile*, sign into Magalu Web (`localhost:8181`) and
Netshoes Web (`localhost:8183`). Visit `localhost:8180`: both corresponding
cards should show "Autenticado". Log out of Magalu Web, return to 8180 and
click "Atualizar status". Magalu Web must show "Não autenticado" while
Netshoes Web remains "Autenticado".

For API-side structure (not browser-auth evidence):

```bash
curl -fsS http://localhost:8180/api/storefront-status | python3 -m json.tool
```

This command uses no browser cookies and therefore reports logged out even
when you are signed in using a browser.
