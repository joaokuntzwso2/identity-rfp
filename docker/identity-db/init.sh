#!/bin/sh
# Executed only on a genuinely empty PostgreSQL data directory.
set -eu
: "${POSTGRES_USER:?}"
for database in wso2_identity wso2_shared; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -c "CREATE DATABASE \"${database}\";"
done
for file in \
  /opt/wso2-db-scripts/identity.sql \
  /opt/wso2-db-scripts/consent.sql; do
  test -s "$file" || { echo "Missing WSO2 schema: $file" >&2; exit 1; }
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname wso2_identity -f "$file"
done
test -s /opt/wso2-db-scripts/shared.sql || { echo 'Missing shared.sql' >&2; exit 1; }
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname wso2_shared -f /opt/wso2-db-scripts/shared.sql
printf '%s\n' 'WSO2 identity, consent and shared database schemas initialized.'
