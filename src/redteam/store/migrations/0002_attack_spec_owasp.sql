-- Persist the OWASP tags on each spec so coverage can be queried per taxonomy category
-- (E1). Demonstrates the migration path: an added field, existing rows keep NULL, no loss.
ALTER TABLE attack_specs ADD COLUMN owasp TEXT;  -- json array of OWASP tags
CREATE INDEX IF NOT EXISTS ix_attack_specs_category ON attack_specs(category);
