-- Initial schema for the AgentForge Red Team store (docs/HARNESS_SPEC.md).
-- The store is the single source of truth: work queue, audit trail, and the
-- observability substrate the Orchestrator reads. JSON-shaped fields are held as TEXT
-- (json); columns that queries filter or sort on are denormalized out for indexing (E12).

CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id     TEXT PRIMARY KEY,
    target_id       TEXT NOT NULL,
    target_sha      TEXT,
    surface         TEXT,
    categories      TEXT,   -- json: OWASP tags
    objective_ref   TEXT,
    budget          TEXT,   -- json
    priority_inputs TEXT,   -- json
    selector        TEXT,   -- json: {jev_version, top_k, chosen, probabilities}
    status          TEXT NOT NULL DEFAULT 'new',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_specs (
    spec_id           TEXT PRIMARY KEY,
    campaign_id       TEXT REFERENCES campaigns(campaign_id),
    parent_spec_id    TEXT REFERENCES attack_specs(spec_id),
    mutation_op       TEXT,
    category          TEXT,
    target_route      TEXT,
    turns             TEXT,   -- json: [{ordinal, input_ref}]
    oracle_ref        TEXT,
    expected_safe_ref TEXT,
    budget_slice      TEXT,   -- json
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id      TEXT PRIMARY KEY,
    spec_id         TEXT REFERENCES attack_specs(spec_id),
    target_id       TEXT NOT NULL,
    target_sha      TEXT,
    target_env      TEXT,   -- local | deployed
    retrieval_mode  TEXT,   -- hybrid | sparse_only | no_rerank | stub
    exchanges       TEXT,   -- json: [{request_hash, response_hash, status_code, latency_ms}]
    provider_events TEXT,   -- json
    cost            TEXT,   -- json: {tokens, calls, usd}
    evidence_ref    TEXT,
    started_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id              TEXT PRIMARY KEY,
    attempt_id              TEXT NOT NULL REFERENCES attempts(attempt_id),
    outcome                 TEXT NOT NULL,   -- SUCCESS | PARTIAL | FAIL | INCONCLUSIVE
    oracle_results          TEXT,            -- json: [{oracle, tier, pass}]
    rubric                  TEXT,            -- json | null
    evidence_ref            TEXT,
    calibration_set_version TEXT,
    judged_at               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id       TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    taxonomy         TEXT,   -- json: [{scheme, version, id}]
    primary_category TEXT,   -- denormalized for indexing
    severity         TEXT,   -- json: {cvss_v4_vector, score, safety_supplemental}
    severity_score   REAL,   -- denormalized for indexing
    clinical_axis    TEXT,   -- json, separate from CVSS
    component        TEXT,
    first_seen_sha   TEXT,
    status           TEXT NOT NULL DEFAULT 'new',
    verdict_ids      TEXT,   -- json
    dedup_key        TEXT UNIQUE,  -- (oracle, sink, component); enforces no duplicate finding
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vuln_reports (
    report_id          TEXT PRIMARY KEY,
    finding_id         TEXT NOT NULL REFERENCES findings(finding_id),
    severity           TEXT,
    description        TEXT,
    clinical_impact    TEXT,
    repro              TEXT,   -- json: {minimal_spec_id, steps_ref}
    observed_vs_expected TEXT,
    remediation        TEXT,
    status             TEXT NOT NULL DEFAULT 'draft',
    fix_validation     TEXT,   -- json: {sha, result}
    approval           TEXT,   -- json: {required, approver, at}
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS regression_cases (
    case_id     TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL REFERENCES findings(finding_id),
    spec_id     TEXT REFERENCES attack_specs(spec_id),
    oracle_ref  TEXT,
    frozen_at   TEXT NOT NULL,
    last_result TEXT,
    last_sha    TEXT
);

CREATE TABLE IF NOT EXISTS agent_actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    agent       TEXT NOT NULL,
    action      TEXT NOT NULL,
    campaign_id TEXT,
    refs        TEXT,   -- json
    reason      TEXT
);

CREATE TABLE IF NOT EXISTS cost_ledger (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    campaign_id TEXT,
    kind        TEXT,   -- generation | conversion | target | retry | judge
    tokens      INTEGER,
    calls       INTEGER,
    usd         REAL
);

CREATE TABLE IF NOT EXISTS coverage (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_sha TEXT,
    dimension  TEXT,   -- endpoint | method | workflow_edge | category | oracle | ...
    key        TEXT,
    value      TEXT,
    updated_at TEXT NOT NULL
);

-- Indexes on the common query patterns (E12): by severity, category, and version (SHA).
CREATE INDEX IF NOT EXISTS ix_attempts_target_sha  ON attempts(target_sha);
CREATE INDEX IF NOT EXISTS ix_attempts_spec        ON attempts(spec_id);
CREATE INDEX IF NOT EXISTS ix_verdicts_attempt     ON verdicts(attempt_id);
CREATE INDEX IF NOT EXISTS ix_findings_status      ON findings(status);
CREATE INDEX IF NOT EXISTS ix_findings_severity    ON findings(severity_score);
CREATE INDEX IF NOT EXISTS ix_findings_category    ON findings(primary_category);
CREATE INDEX IF NOT EXISTS ix_regression_finding   ON regression_cases(finding_id);
CREATE INDEX IF NOT EXISTS ix_agent_actions_campaign ON agent_actions(campaign_id, ts);
