-- Evidence capture: the actual request/response bodies behind every attempt.
--
-- Until now an attempt recorded only {route, status_code, latency_ms}; the response the
-- Judge scored was discarded after the verdict. That left no way to audit a verdict, write
-- a finding report with evidence, or catch a false pos/neg after the fact — the platform
-- could not show *what actually happened*. This table holds the full (synthetic-only)
-- exchanges; attempts.evidence_ref and verdicts.evidence_ref (already in 0001) point here.

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    attempt_id  TEXT REFERENCES attempts(attempt_id),
    exchanges   TEXT,   -- json: [{ordinal, route, method, request, status_code, response, latency_ms}]
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_evidence_attempt ON evidence(attempt_id);
