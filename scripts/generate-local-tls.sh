#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p generated/tls
chmod 700 generated/tls
if [[ -f generated/tls/sector.key && -f generated/tls/sector.crt ]]; then
  echo "Local sector certificates already exist (not overwritten)."
  exit 0
fi
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -subj '/CN=Magalu POC local CA' \
  -keyout generated/tls/ca.key -out generated/tls/ca.crt >/dev/null 2>&1
cat > generated/tls/san.cnf <<'CFG'
[req]
prompt=no
distinguished_name=dn
req_extensions=v3_req
[dn]
CN=sector
[v3_req]
subjectAltName=DNS:sector-magalu,DNS:sector-magalupay,DNS:sector-magalufresh,DNS:sector-netshoes,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
CFG
openssl req -new -nodes -newkey rsa:3072 -keyout generated/tls/sector.key \
  -out generated/tls/sector.csr -config generated/tls/san.cnf >/dev/null 2>&1
openssl x509 -req -in generated/tls/sector.csr -CA generated/tls/ca.crt \
  -CAkey generated/tls/ca.key -CAcreateserial -days 180 -sha256 \
  -extfile generated/tls/san.cnf -extensions v3_req \
  -out generated/tls/sector.crt >/dev/null 2>&1
chmod 600 generated/tls/*.key
printf 'Local TLS certificate generated. Server WSO2 must trust generated/tls/ca.crt; see docs/LOCAL_TLS.md\n'
