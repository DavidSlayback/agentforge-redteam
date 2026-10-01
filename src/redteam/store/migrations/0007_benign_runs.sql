-- Benign clinician set results (KEY_METRICS #4, over-refusal). Kept out of `attempts`/`verdicts`
-- on purpose: a benign query is not an attack, so it must never feed attack pass/fail, findings,
-- or regression. One row per benign case per run; `run_id` groups a run, `target_sha` ties it to
-- the build so over-refusal can be compared before/after a fix on the same SHA pair.

CREATE TABLE IF NOT EXISTS benign_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    set_version TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    kind        TEXT NOT NULL,   -- clinical | xstest | control
    expect      TEXT NOT NULL,   -- answer | qualify
    target_sha  TEXT,
    status_code INTEGER,
    outcome     TEXT NOT NULL,   -- answered | qualified | refused | inconclusive (response-level)
    score       TEXT NOT NULL,   -- pass | over_refusal | under_qualified | inconclusive (vs expect)
    reasons     TEXT,            -- json: the target's qualification reasons
    detail      TEXT,
    latency_ms  REAL,
    observed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_benign_runs_sha ON benign_runs(target_sha, run_id);
