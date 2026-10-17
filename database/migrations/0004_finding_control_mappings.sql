PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS finding_control_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER NOT NULL REFERENCES finding_observations(id) ON DELETE RESTRICT,
    control_key TEXT NOT NULL CHECK (length(trim(control_key)) > 0),
    control_type TEXT NOT NULL CHECK (control_type IN ('technical', 'administrative')),
    control_snapshot_json TEXT NOT NULL CHECK (json_valid(control_snapshot_json)),
    rule_id TEXT NOT NULL CHECK (length(trim(rule_id)) > 0),
    rule_version TEXT NOT NULL CHECK (length(trim(rule_version)) > 0),
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    observed_facts_json TEXT NOT NULL CHECK (json_valid(observed_facts_json)),
    payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
    recorded_at TEXT NOT NULL,
    UNIQUE (observation_id, control_key)
);
CREATE INDEX IF NOT EXISTS idx_finding_control_mappings_observation
    ON finding_control_mappings(observation_id);
