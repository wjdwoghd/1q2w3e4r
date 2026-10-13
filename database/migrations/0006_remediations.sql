-- Run once, outside an existing transaction. SQLite needs a table rebuild for CHECK changes.
PRAGMA foreign_keys = OFF;
BEGIN;
DROP TRIGGER trg_finding_observation_source;
CREATE TABLE findings_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    cve_id TEXT NOT NULL CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-*'),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN
        ('open', 'recommendation_created', 'remediation_applied')),
    created_at TEXT NOT NULL,
    UNIQUE (asset_id, cve_id)
);
INSERT INTO findings_new SELECT * FROM findings;
DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;
CREATE TRIGGER trg_finding_observation_source
BEFORE INSERT ON finding_observations
WHEN NOT EXISTS (
    SELECT 1 FROM findings AS f
    JOIN vulnerability_match_evidence AS e ON e.cve_id = f.cve_id
    JOIN vulnerability_match_runs AS r ON r.id = e.run_id AND r.status = 'matched'
    JOIN components AS c ON c.id = r.component_id AND c.purl = r.component_purl
    JOIN sboms AS s ON s.id = c.sbom_id AND s.asset_id = f.asset_id
    WHERE f.id = NEW.finding_id AND e.id = NEW.match_evidence_id
)
BEGIN SELECT RAISE(ABORT, 'finding evidence does not belong to asset and CVE'); END;
CREATE TABLE finding_status_history_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN
        ('open', 'recommendation_created', 'remediation_applied')),
    recorded_at TEXT NOT NULL,
    UNIQUE (finding_id, status)
);
INSERT INTO finding_status_history_new SELECT * FROM finding_status_history;
DROP TABLE finding_status_history;
ALTER TABLE finding_status_history_new RENAME TO finding_status_history;
CREATE TABLE remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    recommendation_id INTEGER NOT NULL REFERENCES recommendations(id) ON DELETE RESTRICT,
    observation_id INTEGER NOT NULL REFERENCES finding_observations(id) ON DELETE RESTRICT,
    action_key TEXT NOT NULL CHECK (length(trim(action_key)) > 0),
    planned_action TEXT NOT NULL CHECK (length(trim(planned_action)) > 0),
    owner TEXT NOT NULL CHECK (length(trim(owner)) > 0),
    before_json TEXT NOT NULL CHECK (json_valid(before_json)),
    created_at TEXT NOT NULL,
    UNIQUE (recommendation_id, action_key)
);
CREATE INDEX idx_remediations_finding ON remediations(finding_id);
CREATE TRIGGER trg_remediation_source BEFORE INSERT ON remediations
WHEN NOT EXISTS (
    SELECT 1 FROM recommendations AS r
    JOIN finding_observations AS o ON o.id = r.observation_id
    WHERE r.id = NEW.recommendation_id AND o.id = NEW.observation_id
      AND o.finding_id = NEW.finding_id
)
BEGIN SELECT RAISE(ABORT, 'remediation source mismatch'); END;
CREATE TRIGGER trg_remediation_immutable BEFORE UPDATE ON remediations
BEGIN SELECT RAISE(ABORT, 'remediation plan is immutable'); END;
CREATE TRIGGER trg_remediation_no_delete BEFORE DELETE ON remediations
BEGIN SELECT RAISE(ABORT, 'remediation plan is immutable'); END;
CREATE TABLE remediation_applications (
    remediation_id INTEGER PRIMARY KEY REFERENCES remediations(id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK (length(trim(action)) > 0),
    actor TEXT NOT NULL CHECK (length(trim(actor)) > 0),
    applied_at TEXT NOT NULL CHECK (length(trim(applied_at)) > 0),
    evidence_type TEXT NOT NULL CHECK (evidence_type IN
        ('deployment_record', 'change_execution_log', 'installed_package_record')),
    evidence_reference TEXT NOT NULL CHECK (length(trim(evidence_reference)) > 0),
    evidence_source TEXT NOT NULL CHECK (length(trim(evidence_source)) > 0),
    recorded_at TEXT NOT NULL
);
CREATE TRIGGER trg_application_immutable BEFORE UPDATE ON remediation_applications
BEGIN SELECT RAISE(ABORT, 'remediation application is immutable'); END;
CREATE TRIGGER trg_application_no_delete BEFORE DELETE ON remediation_applications
BEGIN SELECT RAISE(ABORT, 'remediation application is immutable'); END;
CREATE TRIGGER trg_finding_remediation_transition BEFORE UPDATE OF status ON findings
WHEN NOT (
    (OLD.status = 'open' AND NEW.status = 'recommendation_created'
     AND EXISTS (SELECT 1 FROM remediations WHERE finding_id = NEW.id))
    OR (OLD.status = 'recommendation_created' AND NEW.status = 'remediation_applied'
     AND EXISTS (SELECT 1 FROM remediation_applications AS a
                 JOIN remediations AS r ON r.id = a.remediation_id
                 WHERE r.finding_id = NEW.id))
)
BEGIN SELECT RAISE(ABORT, 'invalid finding remediation transition'); END;
CREATE TRIGGER trg_finding_status_event BEFORE INSERT ON finding_status_history
WHEN NEW.status != (SELECT status FROM findings WHERE id = NEW.finding_id)
  AND NOT EXISTS (SELECT 1 FROM finding_status_history
                  WHERE finding_id = NEW.finding_id AND status = NEW.status)
BEGIN SELECT RAISE(ABORT, 'finding status history mismatch'); END;
COMMIT;
PRAGMA foreign_keys = ON;
