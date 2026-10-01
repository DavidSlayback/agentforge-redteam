-- The Orchestrator now writes one real Campaign row per scheduled brief (GitLab #4, commit 3),
-- filling the v1 Campaign contract's previously-missing producer. Two additive columns:
--
--   outcome        -- the scheduled brief's result: tested | skipped | provider_blocked | errored.
--                     An added property on the v1 Campaign contract (additionalProperties), so no
--                     version bump; the status enum is unchanged.
--   schema_version -- the message version an auditor reads off the row, matching the other records
--                     (migration 0005). Lets the contract test read a real persisted Campaign.
--
-- Historical rows have neither (NULL outcome, version 1) and simply do not count as campaign
-- coverage, which is correct: nothing wrote a Campaign row before this.

ALTER TABLE campaigns ADD COLUMN outcome        TEXT;
ALTER TABLE campaigns ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;

-- Coverage and starvation scoring filter campaigns by target and group by (category, route);
-- the category lives in the categories json and the route in surface.
CREATE INDEX IF NOT EXISTS ix_campaigns_target_outcome ON campaigns(target_id, outcome);
