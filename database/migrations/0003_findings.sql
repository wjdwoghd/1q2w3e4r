PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    cve_id TEXT NOT NULL CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-*'),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status = 'open'),
    created_at TEXT NOT NULL,
    UNIQUE (asset_id, cve_id)
);
CREATE TABLE IF NOT EXISTS finding_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    match_evidence_id INTEGER NOT NULL UNIQUE REFERENCES vulnerability_match_evidence(id) ON DELETE RESTRICT,
    risk_json TEXT NOT NULL,
    asset_context_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_observations_finding
    ON finding_observations(finding_id);
CREATE TRIGGER IF NOT EXISTS trg_finding_observation_source
BEFORE INSERT ON finding_observations
WHEN NOT EXISTS (
    SELECT 1 FROM findings AS f
    JOIN vulnerability_match_evidence AS e ON e.cve_id = f.cve_id
    JOIN vulnerability_match_runs AS r ON r.id = e.run_id AND r.status = 'matched'
    JOIN components AS c ON c.id = r.component_id AND c.purl = r.component_purl
    JOIN sboms AS s ON s.id = c.sbom_id AND s.asset_id = f.asset_id
    WHERE f.id = NEW.finding_id AND e.id = NEW.match_evidence_id
)
BEGIN
    SELECT RAISE(ABORT, 'finding evidence does not belong to asset and CVE');
END;
CREATE TABLE IF NOT EXISTS finding_status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status = 'open'),
    recorded_at TEXT NOT NULL,
    UNIQUE (finding_id, status)
);
