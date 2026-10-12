PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER NOT NULL UNIQUE REFERENCES finding_observations(id) ON DELETE RESTRICT,
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
    model_name TEXT NOT NULL CHECK (length(trim(model_name)) > 0),
    input_json TEXT NOT NULL CHECK (json_valid(input_json)),
    content_json TEXT NOT NULL CHECK (json_valid(content_json)),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recommendations_observation
    ON recommendations(observation_id);
