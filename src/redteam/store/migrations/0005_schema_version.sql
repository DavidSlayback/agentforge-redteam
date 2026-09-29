-- Make inter-agent records self-describing: each carries the contract version it conforms to
-- (contracts/v1/*.schema.json). The store still versions itself via these numbered migrations;
-- this column is the *message* version an auditor (or a future consumer) reads off the record,
-- so a contract test validates the real row's declared version instead of assuming it.

ALTER TABLE attack_specs ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE attempts     ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE verdicts     ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE findings     ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE vuln_reports ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
