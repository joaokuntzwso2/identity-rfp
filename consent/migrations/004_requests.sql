-- Business workflow extension. Deployed to the DEMO database, not WSO2 internal tables.
CREATE SCHEMA IF NOT EXISTS demo_workflow;
CREATE TABLE IF NOT EXISTS demo_workflow.requests (
 request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_domain TEXT NOT NULL,
 brand TEXT NOT NULL CHECK (brand IN ('magalu','netshoes','magalupay')),
 subject VARCHAR(120) NOT NULL,
 amount NUMERIC(12,2) NOT NULL CHECK (amount > 0 AND amount <= 999999.99),
 currency CHAR(3) NOT NULL DEFAULT 'BRL',
 status TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED')),
 requested_by_sub TEXT NOT NULL,
 requester_issuer TEXT NOT NULL,
 requester_client_id TEXT NOT NULL,
 approved_by_sub TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 approved_at TIMESTAMPTZ,
 CHECK (approved_by_sub IS NULL OR approved_by_sub <> requested_by_sub)
);
CREATE INDEX IF NOT EXISTS requests_tenant_brand_idx
 ON demo_workflow.requests(tenant_domain,brand,created_at DESC);
CREATE TABLE IF NOT EXISTS demo_workflow.events (
 event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 request_id UUID NOT NULL REFERENCES demo_workflow.requests(request_id),
 action TEXT NOT NULL CHECK (action IN ('CREATED','APPROVED','REJECTED')),
 actor_sub TEXT NOT NULL,
 acr TEXT,
 amr TEXT[],
 auth_time BIGINT,
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION demo_workflow.prevent_history_changes() RETURNS TRIGGER AS $$
BEGIN RAISE EXCEPTION 'Append-only audit history cannot be modified'; END
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS prevent_history_changes ON demo_workflow.events;
CREATE TRIGGER prevent_history_changes BEFORE UPDATE OR DELETE ON demo_workflow.events
FOR EACH ROW EXECUTE FUNCTION demo_workflow.prevent_history_changes();
