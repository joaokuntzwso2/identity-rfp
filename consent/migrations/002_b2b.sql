-- Separate sandbox B2B authorization model, not a substitute for federated IdP integration.
CREATE TABLE IF NOT EXISTS demo.businesses (
  business_key TEXT PRIMARY KEY,
  public_name TEXT NOT NULL,
  synthetic_cnpj TEXT NOT NULL UNIQUE,
  owning_brand TEXT NOT NULL REFERENCES demo.brands(brand_key),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS demo.business_representatives (
  business_key TEXT NOT NULL REFERENCES demo.businesses(business_key),
  principal_id UUID NOT NULL REFERENCES demo.principals(principal_id),
  role_name TEXT NOT NULL CHECK (role_name IN ('OWNER','OPERATOR','AUDITOR')),
  is_legal_representative BOOLEAN NOT NULL DEFAULT FALSE,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY(business_key, principal_id)
);
CREATE TABLE IF NOT EXISTS demo.business_policy_events (
  event_id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  principal_id UUID NOT NULL REFERENCES demo.principals(principal_id),
  business_key TEXT NOT NULL REFERENCES demo.businesses(business_key),
  action TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY')),
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
