-- Discovery candidates: open-ended, LLM-proposed suspicions the deterministic oracles did not
-- catch. A candidate is NOT a finding — it is a lead for a human to confirm and harden into a
-- deterministic oracle+probe. Kept separate from `findings` on purpose so an LLM judge can never
-- auto-publish a security verdict (the no-drifting-judge rule). `status` tracks triage.

CREATE TABLE IF NOT EXISTS discovery_candidates (
    candidate_id TEXT PRIMARY KEY,
    attempt_id   TEXT REFERENCES attempts(attempt_id),
    target_sha   TEXT,
    vuln_class   TEXT,
    severity     TEXT,
    confidence   REAL,
    why          TEXT,
    route        TEXT,
    status       TEXT NOT NULL DEFAULT 'new',   -- new | confirmed | dismissed | promoted
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_discovery_status ON discovery_candidates(status, confidence);
