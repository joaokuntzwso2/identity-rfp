#!/usr/bin/env bash
set -euo pipefail
PROJECT='/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc'
cd "$PROJECT"
[[ "$(git rev-parse --show-toplevel)" == "$PROJECT" ]] || { echo 'Wrong Git root'; exit 1; }
private='generated/poc-ldap'
[[ -f "$private/50-seller.ldif" && -f "$private/compose.poc-ldap.yaml" && -f "$private/ldap-admin-password.txt" ]] || {
  echo 'Prepare a private new LDAP fixture first: python3 scripts/prepare-poc-ldap.py --generate'; exit 1;
}
export LDAP_ADMIN_PASSWORD
LDAP_ADMIN_PASSWORD="$(cat "$private/ldap-admin-password.txt")"
DC=(docker compose -p magalu-ciam73-s7lab \
  -f compose.yaml -f compose.isolated.yaml -f compose.stores.yaml \
  -f "$private/compose.poc-ldap.yaml")
if "${DC[@]}" ps --services --status running | grep -qx ldap; then
  echo 'LDAP already running; no changes made. Never blindly replace existing directory data.'
  exit 0
fi
# Confirm override actually supersedes the tracked fixed-password fixture.
if ! "${DC[@]}" config | grep -F "${PROJECT}/${private}/50-seller.ldif" >/dev/null; then
  echo 'ERROR: Private LDAP seed override is not present in resolved Compose configuration.'
  exit 1
fi
"${DC[@]}" up -d --no-deps ldap
echo 'LDAP container started with private seed fixture. WSO2 secondary store still requires Console registration.'
