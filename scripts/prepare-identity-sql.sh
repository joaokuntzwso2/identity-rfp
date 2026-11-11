#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
image="${WSO2_IMAGE:?WSO2_IMAGE not set}"
dest=generated/wso2-db-scripts
mkdir -p "$dest"
container="$(docker create "$image")"
trap 'docker rm -v "$container" >/dev/null 2>&1 || true' EXIT
base=/home/wso2carbon/wso2is-7.3.0
for part in identity consent shared; do
  case "$part" in
    identity) filename="$base/dbscripts/identity/postgresql.sql";;
    consent) filename="$base/dbscripts/consent/postgresql.sql";;
    shared) filename="$base/dbscripts/postgresql.sql";;
  esac
  docker cp "$container:$filename" "$dest/$part.sql" \
    || { echo "WSO2 distribution missing SQL: $filename" >&2; exit 1; }
  test -s "$dest/$part.sql" || { echo "Empty WSO2 SQL file: $part.sql" >&2; exit 1; }
done
if [[ -n "${POSTGRES_JDBC_JAR_PATH:-}" ]]; then
  cp "$POSTGRES_JDBC_JAR_PATH" "$dest/postgresql-jdbc.jar"
else
  curl --fail --location --retry 3 --silent --show-error \
    'https://repo.maven.apache.org/maven2/org/postgresql/postgresql/42.7.4/postgresql-42.7.4.jar' \
    --output "$dest/postgresql-jdbc.jar"
fi
[[ -s "$dest/postgresql-jdbc.jar" ]] || { echo 'PostgreSQL JDBC jar not available' >&2; exit 1; }
# Jar has a ZIP header, rejecting accidental HTTP error pages.
python3 - "$dest/postgresql-jdbc.jar" <<'PY'
from pathlib import Path
import sys,zipfile
if not zipfile.is_zipfile(sys.argv[1]):
    raise SystemExit('PostgreSQL JDBC download is not a valid JAR')
PY
echo 'Extracted updated WSO2 PostgreSQL identity/shared/consent scripts and JDBC driver.'
