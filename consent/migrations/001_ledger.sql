-- Customer-owned POC extension schema. NEVER ALTER WSO2_* internal product tables.
-- Run on the dedicated ciam PostgreSQL database, not the IS_IDENTITY_DB.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS demo;

CREATE TABLE IF NOT EXISTS demo.brands (
  brand_key TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  organization_id TEXT,
  sector_identifier_uri TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS demo.clients (
  client_key TEXT PRIMARY KEY,
  brand_key TEXT NOT NULL REFERENCES demo.brands(brand_key),
  channel TEXT NOT NULL,
  oauth_client_id TEXT NOT NULL UNIQUE,
  claim_profile TEXT NOT NULL CHECK (claim_profile IN ('minimum','profile','m2m')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (brand_key, channel)
);

CREATE TABLE IF NOT EXISTS demo.principals (
  principal_id UUID PRIMARY KEY,
  scim_user_id TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Server-only mapping. NEVER expose this via the end-user API.
CREATE TABLE IF NOT EXISTS demo.subject_bindings (
  principal_id UUID NOT NULL REFERENCES demo.principals(principal_id),
  client_key TEXT NOT NULL REFERENCES demo.clients(client_key),
  pairwise_sub TEXT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, client_key),
  UNIQUE (client_key, pairwise_sub)
);

-- Explicit source tenant, target tenant (directional), client and scope.
CREATE TABLE IF NOT EXISTS demo.purposes (
  purpose_key TEXT PRIMARY KEY,
  source_brand TEXT NOT NULL REFERENCES demo.brands(brand_key),
  target_brand TEXT REFERENCES demo.brands(brand_key),
  scope_name TEXT NOT NULL,
  consent_text TEXT NOT NULL,
  title TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT 'shield-check',
  visibility TEXT NOT NULL CHECK (visibility IN ('public','private','allow-list')),
  consent_required BOOLEAN NOT NULL DEFAULT TRUE,
  CHECK (target_brand IS NULL OR source_brand <> target_brand),
  UNIQUE (source_brand, target_brand, scope_name)
);

CREATE TABLE IF NOT EXISTS demo.consent_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_seq BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
  principal_id UUID NOT NULL REFERENCES demo.principals(principal_id),
  source_brand TEXT NOT NULL REFERENCES demo.brands(brand_key),
  target_brand TEXT REFERENCES demo.brands(brand_key),
  client_key TEXT NOT NULL REFERENCES demo.clients(client_key),
  scope_name TEXT NOT NULL,
  purpose_key TEXT NOT NULL REFERENCES demo.purposes(purpose_key),
  action TEXT NOT NULL CHECK (action IN ('GRANTED','REVOKED')),
  evidence_source TEXT NOT NULL CHECK (evidence_source IN ('user-action','migration','synthetic-demo')),
  effective_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  idempotency_key TEXT NOT NULL UNIQUE,
  previous_hash TEXT,
  event_hash TEXT NOT NULL,
  CHECK (target_brand IS NULL OR source_brand <> target_brand)
);
CREATE INDEX IF NOT EXISTS consent_event_lookup ON demo.consent_events
  (principal_id, source_brand, client_key, purpose_key, event_seq DESC);

CREATE OR REPLACE FUNCTION demo.block_event_mutation() RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Consent events are append-only: % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS no_consent_event_mutation ON demo.consent_events;
CREATE TRIGGER no_consent_event_mutation BEFORE UPDATE OR DELETE ON demo.consent_events
FOR EACH ROW EXECUTE FUNCTION demo.block_event_mutation();

CREATE OR REPLACE VIEW demo.consent_current AS
SELECT DISTINCT ON (principal_id,source_brand,client_key,purpose_key)
  principal_id, source_brand, target_brand, client_key, scope_name, purpose_key,
  action, effective_at, recorded_at, event_seq
FROM demo.consent_events
ORDER BY principal_id,source_brand,client_key,purpose_key,event_seq DESC;

-- Attribute proofs are NOT a user-level 'verified' boolean. Latest proof per attribute wins.
CREATE TABLE IF NOT EXISTS demo.attribute_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_seq BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
  principal_id UUID NOT NULL REFERENCES demo.principals(principal_id),
  attribute_key TEXT NOT NULL,
  assertion_hash TEXT NOT NULL,
  verification_source TEXT NOT NULL,
  verification_method TEXT NOT NULL,
  effective_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ,
  state TEXT NOT NULL CHECK (state IN ('VERIFIED','INVALIDATED')),
  reason TEXT,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS attribute_proof_latest ON demo.attribute_events
  (principal_id,attribute_key,event_seq DESC);
DROP TRIGGER IF EXISTS no_attribute_event_mutation ON demo.attribute_events;
CREATE TRIGGER no_attribute_event_mutation BEFORE UPDATE OR DELETE ON demo.attribute_events
FOR EACH ROW EXECUTE FUNCTION demo.block_event_mutation();

CREATE OR REPLACE VIEW demo.attribute_latest AS
SELECT DISTINCT ON (principal_id,attribute_key)
  principal_id,attribute_key,verification_source,verification_method,
  effective_at,expires_at,state,event_seq
FROM demo.attribute_events
ORDER BY principal_id,attribute_key,event_seq DESC;

CREATE TABLE IF NOT EXISTS demo.operator_audit (
  audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  outcome TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
