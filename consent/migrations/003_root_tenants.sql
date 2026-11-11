-- New, isolated PoC database. Root tenants are first-class; brands are not organizations.
CREATE TABLE IF NOT EXISTS demo.root_tenants (
  root_key TEXT PRIMARY KEY,
  domain TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  tenant_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE demo.brands ADD COLUMN IF NOT EXISTS root_key TEXT;
ALTER TABLE demo.brands DROP CONSTRAINT IF EXISTS brands_root_key_fkey;
ALTER TABLE demo.brands ADD CONSTRAINT brands_root_key_fkey
    FOREIGN KEY (root_key) REFERENCES demo.root_tenants(root_key);
ALTER TABLE demo.clients DROP CONSTRAINT IF EXISTS clients_brand_key_channel_key;
-- One synthetic global person can have *different* WSO2 user identities in each root.
-- This private vault table must NEVER be included in OIDC token claims.
CREATE TABLE IF NOT EXISTS demo.tenant_identities (
  root_key TEXT NOT NULL REFERENCES demo.root_tenants(root_key),
  scim_user_id TEXT NOT NULL,
  local_username TEXT NOT NULL,
  principal_id UUID NOT NULL REFERENCES demo.principals(principal_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (root_key, local_username),
  UNIQUE (root_key, scim_user_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_identity_principal
  ON demo.tenant_identities (principal_id, root_key);
