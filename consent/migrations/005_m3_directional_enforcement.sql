-- Customer-owned CIAM PoC consent enforcement. Does not alter WSO2-owned tables.
CREATE TABLE IF NOT EXISTS demo.m3_links (
    link_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose_key TEXT NOT NULL REFERENCES demo.purposes(purpose_key),
    source_tenant TEXT NOT NULL,
    source_brand TEXT NOT NULL REFERENCES demo.brands(brand_key),
    source_sub TEXT NOT NULL,
    recipient_tenant TEXT NOT NULL,
    recipient_brand TEXT NOT NULL REFERENCES demo.brands(brand_key),
    recipient_sub TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(purpose_key,source_tenant,source_brand,source_sub,
           recipient_tenant,recipient_brand,recipient_sub),
    CHECK (source_brand <> recipient_brand),
    CHECK (length(source_sub) BETWEEN 1 AND 255),
    CHECK (length(recipient_sub) BETWEEN 1 AND 255)
);
CREATE TABLE IF NOT EXISTS demo.m3_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seq BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    link_id UUID NOT NULL REFERENCES demo.m3_links(link_id),
    action TEXT NOT NULL CHECK(action IN ('GRANTED','REVOKED')),
    actor_tenant TEXT NOT NULL,
    actor_sub TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    prior_hash TEXT,
    event_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS m3_event_latest ON demo.m3_events(link_id,seq DESC);
CREATE OR REPLACE VIEW demo.m3_current AS
SELECT DISTINCT ON(link_id) link_id, action, created_at, seq
FROM demo.m3_events ORDER BY link_id,seq DESC;
CREATE TABLE IF NOT EXISTS demo.m3_access_audit (
    access_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id UUID REFERENCES demo.m3_links(link_id),
    recipient_tenant TEXT,
    recipient_sub TEXT,
    action TEXT NOT NULL DEFAULT 'READ_SHARED_PROFILE',
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW','DENY')),
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION demo.m3_prevent_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'Audit rows are immutable'; END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS m3_no_event_mutation ON demo.m3_events;
CREATE TRIGGER m3_no_event_mutation BEFORE UPDATE OR DELETE ON demo.m3_events
FOR EACH ROW EXECUTE FUNCTION demo.m3_prevent_mutation();
DROP TRIGGER IF EXISTS m3_no_audit_mutation ON demo.m3_access_audit;
CREATE TRIGGER m3_no_audit_mutation BEFORE UPDATE OR DELETE ON demo.m3_access_audit
FOR EACH ROW EXECUTE FUNCTION demo.m3_prevent_mutation();
