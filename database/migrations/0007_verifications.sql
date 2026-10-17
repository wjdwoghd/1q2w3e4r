-- Apply once to a Phase 8 database outside an existing transaction.
-- Keep a backup. On failure ROLLBACK and re-enable foreign_keys before reuse.
PRAGMA foreign_keys = OFF;
BEGIN;
DROP TRIGGER trg_finding_observation_source;
DROP TRIGGER trg_finding_remediation_transition;
DROP TRIGGER trg_finding_status_event;
CREATE TABLE findings_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    cve_id TEXT NOT NULL CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-*'),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN
        ('open', 'recommendation_created', 'remediation_applied',
         'verification_in_progress', 'verification_passed', 'verification_failed')),
    created_at TEXT NOT NULL,
    UNIQUE (asset_id, cve_id)
);
INSERT INTO findings_new SELECT * FROM findings;
DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;
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
CREATE TABLE finding_status_history_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN
        ('open', 'recommendation_created', 'remediation_applied',
         'verification_in_progress', 'verification_passed', 'verification_failed')),
    recorded_at TEXT NOT NULL,
    verification_id INTEGER REFERENCES verifications(id) ON DELETE RESTRICT,
    UNIQUE (verification_id, status),
    CHECK ((verification_id IS NULL AND status IN
             ('open', 'recommendation_created', 'remediation_applied'))
        OR (verification_id IS NOT NULL AND status IN
             ('verification_in_progress', 'verification_passed', 'verification_failed')))
);
INSERT INTO finding_status_history_new (id,finding_id,status,recorded_at)
SELECT id,finding_id,status,recorded_at FROM finding_status_history;
DROP TABLE finding_status_history;
ALTER TABLE finding_status_history_new RENAME TO finding_status_history;


CREATE TABLE IF NOT EXISTS verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    remediation_id INTEGER NOT NULL REFERENCES remediation_applications(remediation_id) ON DELETE RESTRICT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    attempt_key TEXT NOT NULL CHECK (length(trim(attempt_key)) > 0),
    before_json TEXT NOT NULL CHECK (json_valid(before_json)),
    before_sbom_json TEXT NOT NULL CHECK (json_valid(before_sbom_json)),
    application_json TEXT NOT NULL CHECK (json_valid(application_json)),
    required_tests_json TEXT NOT NULL CHECK
        (json_valid(required_tests_json) AND json_type(required_tests_json) = 'array'
         AND json_array_length(required_tests_json) > 0),
    started_at TEXT NOT NULL,
    UNIQUE (remediation_id, attempt_key)
);
CREATE INDEX IF NOT EXISTS idx_verifications_finding ON verifications(finding_id);
CREATE TABLE IF NOT EXISTS verification_after_evidence (
    verification_id INTEGER PRIMARY KEY REFERENCES verifications(id) ON DELETE RESTRICT,
    sbom_id INTEGER REFERENCES sboms(id) ON DELETE RESTRICT,
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verification_results (
    verification_id INTEGER PRIMARY KEY REFERENCES verification_after_evidence(verification_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('verification_passed', 'verification_failed')),
    rule_version TEXT NOT NULL CHECK (length(trim(rule_version)) > 0),
    reasons_json TEXT NOT NULL CHECK (json_valid(reasons_json) AND json_type(reasons_json) = 'array'
                                     AND json_array_length(reasons_json) > 0),
    sbom_diff_json TEXT CHECK (sbom_diff_json IS NULL OR json_valid(sbom_diff_json)),
    completed_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS trg_verification_source BEFORE INSERT ON verifications
WHEN NOT EXISTS (
    SELECT 1 FROM remediations AS r
    JOIN remediation_applications AS a ON a.remediation_id = r.id
    JOIN recommendations AS p ON p.id = r.recommendation_id AND p.observation_id = r.observation_id
    JOIN finding_observations AS o ON o.id = r.observation_id AND o.finding_id = r.finding_id
    JOIN findings AS f ON f.id = r.finding_id
    JOIN vulnerability_match_evidence AS e ON e.id = o.match_evidence_id AND e.cve_id = f.cve_id
    JOIN vulnerability_match_runs AS m ON m.id = e.run_id AND m.status = 'matched'
    JOIN components AS c ON c.id = m.component_id AND c.purl = m.component_purl
    JOIN sboms AS s ON s.id = c.sbom_id AND s.asset_id = f.asset_id
    WHERE r.id = NEW.remediation_id AND r.finding_id = NEW.finding_id
      AND f.asset_id = NEW.asset_id AND r.before_json = NEW.before_json
      AND COALESCE(json_extract(NEW.before_sbom_json, '$.id') = s.id, 0)
      AND COALESCE(json_extract(NEW.before_sbom_json, '$.asset_id') = f.asset_id, 0)
      AND COALESCE(json_extract(NEW.application_json, '$.action') = a.action, 0)
      AND COALESCE(json_extract(NEW.application_json, '$.actor') = a.actor, 0)
      AND COALESCE(json_extract(NEW.application_json, '$.applied_at') = a.applied_at, 0)
      AND COALESCE(json_extract(NEW.application_json, '$.evidence_type') = a.evidence_type, 0)
      AND COALESCE(json_extract(NEW.application_json, '$.evidence_reference') = a.evidence_reference, 0)
      AND COALESCE(json_extract(NEW.application_json, '$.evidence_source') = a.evidence_source, 0)
      AND COALESCE(json_extract(NEW.application_json, '$.recorded_at') = a.recorded_at, 0)
      AND f.status IN ('remediation_applied', 'verification_passed', 'verification_failed')
) OR EXISTS (
    SELECT 1 FROM verifications AS v LEFT JOIN verification_results AS d ON d.verification_id = v.id
    WHERE v.finding_id = NEW.finding_id AND d.verification_id IS NULL
)
BEGIN SELECT RAISE(ABORT, 'verification source or active attempt mismatch'); END;
CREATE TRIGGER IF NOT EXISTS trg_verification_after_source BEFORE INSERT ON verification_after_evidence
WHEN EXISTS (SELECT 1 FROM verification_results WHERE verification_id = NEW.verification_id)
 OR NOT EXISTS (
    SELECT 1 FROM verifications AS v JOIN findings AS f ON f.id = v.finding_id
    WHERE v.id = NEW.verification_id AND f.status = 'verification_in_progress'
      AND COALESCE(json_extract(NEW.payload_json, '$.asset_id') = v.asset_id, 0)
      AND (NEW.sbom_id IS NULL OR EXISTS
          (SELECT 1 FROM sboms AS s WHERE s.id = NEW.sbom_id AND s.asset_id = v.asset_id
            AND json_extract(NEW.payload_json, '$.sbom.id') = s.id
            AND json_extract(NEW.payload_json, '$.sbom.asset_id') = v.asset_id))
)
 OR EXISTS (
    SELECT 1 FROM json_each(NEW.payload_json, '$.sbom.components') AS item
    WHERE NOT EXISTS (SELECT 1 FROM components AS c
                      WHERE c.id = json_extract(item.value, '$.id') AND c.sbom_id = NEW.sbom_id)
 )
 OR EXISTS (
    SELECT 1 FROM json_each(NEW.payload_json, '$.match_runs') AS item
    WHERE NOT EXISTS (SELECT 1 FROM vulnerability_match_runs AS m JOIN components AS c ON c.id = m.component_id
                      WHERE m.id = json_extract(item.value, '$.id') AND c.sbom_id = NEW.sbom_id
                        AND m.component_id = json_extract(item.value, '$.component_id'))
 )
 OR EXISTS (
    SELECT 1 FROM json_each(NEW.payload_json, '$.functional_tests') AS item
    JOIN verifications AS v ON v.id = NEW.verification_id
    WHERE NOT COALESCE(json_extract(item.value, '$.asset_id') = v.asset_id
                      AND json_extract(item.value, '$.sbom_id') = NEW.sbom_id, 0)
 )
 OR EXISTS (
    SELECT 1 FROM json_each(NEW.payload_json, '$.scanner_results') AS item
    JOIN verifications AS v ON v.id = NEW.verification_id
    WHERE NOT COALESCE(json_extract(item.value, '$.asset_id') = v.asset_id
                      AND json_extract(item.value, '$.sbom_id') = NEW.sbom_id, 0)
 )
BEGIN SELECT RAISE(ABORT, 'after evidence source mismatch'); END;
CREATE TRIGGER IF NOT EXISTS trg_verification_result_source BEFORE INSERT ON verification_results
WHEN NOT EXISTS (
    SELECT 1 FROM verifications AS v JOIN findings AS f ON f.id = v.finding_id
    WHERE v.id = NEW.verification_id AND f.status = 'verification_in_progress'
      AND v.id = (SELECT MAX(id) FROM verifications WHERE finding_id = v.finding_id)
)
BEGIN SELECT RAISE(ABORT, 'verification result is not for the active attempt'); END;
DROP TRIGGER IF EXISTS trg_finding_remediation_transition;
CREATE TRIGGER trg_finding_remediation_transition BEFORE UPDATE OF status ON findings
WHEN NOT (
    (OLD.status = 'open' AND NEW.status = 'recommendation_created'
     AND EXISTS (SELECT 1 FROM remediations WHERE finding_id = NEW.id))
    OR (OLD.status = 'recommendation_created' AND NEW.status = 'remediation_applied'
     AND EXISTS (SELECT 1 FROM remediation_applications AS a
                 JOIN remediations AS r ON r.id = a.remediation_id WHERE r.finding_id = NEW.id))
    OR (OLD.status IN ('remediation_applied', 'verification_passed', 'verification_failed')
        AND NEW.status = 'verification_in_progress' AND EXISTS (
          SELECT 1 FROM verifications AS v LEFT JOIN verification_results AS d ON d.verification_id = v.id
          WHERE v.finding_id = NEW.id AND d.verification_id IS NULL))
    OR (OLD.status = 'verification_in_progress'
        AND NEW.status IN ('verification_passed', 'verification_failed') AND EXISTS (
          SELECT 1 FROM verification_results AS d JOIN verifications AS v ON v.id = d.verification_id
          WHERE v.finding_id = NEW.id AND d.status = NEW.status
            AND v.id = (SELECT MAX(id) FROM verifications WHERE finding_id = NEW.id)))
)
BEGIN SELECT RAISE(ABORT, 'invalid finding remediation or verification transition'); END;
DROP TRIGGER IF EXISTS trg_finding_status_event;
CREATE TRIGGER trg_finding_status_event BEFORE INSERT ON finding_status_history
WHEN (NEW.verification_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM verifications AS v WHERE v.id = NEW.verification_id AND v.finding_id = NEW.finding_id
      AND NEW.status = (SELECT status FROM findings WHERE id = NEW.finding_id)))
 OR (NEW.verification_id IS NULL
     AND NEW.status != (SELECT status FROM findings WHERE id = NEW.finding_id)
     AND NOT EXISTS (SELECT 1 FROM finding_status_history
                    WHERE finding_id = NEW.finding_id AND status = NEW.status))
BEGIN SELECT RAISE(ABORT, 'finding status history mismatch'); END;
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_legacy_status
    ON finding_status_history(finding_id, status) WHERE verification_id IS NULL;

CREATE TRIGGER IF NOT EXISTS trg_verifications_update BEFORE UPDATE ON verifications
BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_verifications_delete BEFORE DELETE ON verifications
BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_verification_after_evidence_update BEFORE UPDATE ON verification_after_evidence
BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_verification_after_evidence_delete BEFORE DELETE ON verification_after_evidence
BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_verification_results_update BEFORE UPDATE ON verification_results
BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_verification_results_delete BEFORE DELETE ON verification_results
BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_finding_status_history_update BEFORE UPDATE ON finding_status_history
BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_finding_status_history_delete BEFORE DELETE ON finding_status_history
BEGIN SELECT RAISE(ABORT, 'verification records are immutable'); END;
COMMIT;
PRAGMA foreign_keys = ON;
PRAGMA foreign_key_check;
