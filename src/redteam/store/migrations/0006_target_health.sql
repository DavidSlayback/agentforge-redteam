-- Recon SHA-change signal (T3.5). Each row is one /health observation of a target's running
-- build. `changed` marks an observation whose git_sha differs from the prior one — the signal
-- that triggers a regression replay against the new build. The latest row per target_id is the
-- last-seen SHA the poller compares against, so no separate mutable state row can drift.

CREATE TABLE IF NOT EXISTS target_health (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   TEXT NOT NULL,
    git_sha     TEXT NOT NULL,
    changed     INTEGER NOT NULL DEFAULT 0,  -- 1 when git_sha differs from the prior observation
    observed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_target_health_target ON target_health(target_id, id);
