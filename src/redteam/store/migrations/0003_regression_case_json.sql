-- A regression case must be replayable deterministically, so it stores the full frozen
-- case definition (turns + oracle + auth), not just a reference. attack_specs persists
-- turns but not the oracle config, which the replay needs to re-judge identically.
ALTER TABLE regression_cases ADD COLUMN case_json TEXT;
