"""SQLite connection and schema lifecycle for local platform persistence."""

from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS business_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    business_service_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    environment TEXT NOT NULL CHECK (environment IN ('production', 'development')),
    internet_exposed INTEGER NOT NULL CHECK (internet_exposed IN (0, 1)),
    business_criticality TEXT NOT NULL
        CHECK (business_criticality IN ('critical', 'high', 'medium', 'low')),
    customer_information INTEGER NOT NULL CHECK (customer_information IN (0, 1)),
    credit_information INTEGER NOT NULL CHECK (credit_information IN (0, 1)),
    patch_status TEXT NOT NULL CHECK (patch_status IN ('current', 'pending', 'overdue', 'unknown')),
    vendor TEXT NOT NULL,
    owner TEXT NOT NULL,
    UNIQUE (business_service_id, name),
    FOREIGN KEY (business_service_id) REFERENCES business_services(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS sboms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    bom_format TEXT NOT NULL,
    spec_version TEXT NOT NULL,
    serial_number TEXT,
    raw_document TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,
    source_bom_ref TEXT,
    issues_json TEXT NOT NULL,
    UNIQUE (sbom_id, position),
    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS vulnerability_match_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    analysis_key TEXT NOT NULL CHECK (length(trim(analysis_key)) > 0),
    status TEXT NOT NULL CHECK (status IN
        ('matched', 'no_match', 'unmatched', 'ambiguous', 'error')),
    component_purl TEXT,
    reasons_json TEXT NOT NULL,
    osv_query_json TEXT,
    kev_snapshot_json TEXT,
    recorded_at TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    UNIQUE (component_id, analysis_key),
    FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS vulnerability_match_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-*'),
    evidence_json TEXT NOT NULL,
    UNIQUE (run_id, cve_id),
    FOREIGN KEY (run_id) REFERENCES vulnerability_match_runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_match_evidence_cve
    ON vulnerability_match_evidence(cve_id);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    cve_id TEXT NOT NULL CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-*'),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN
        ('open', 'recommendation_created', 'remediation_applied')),
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
    status TEXT NOT NULL CHECK (status IN
        ('open', 'recommendation_created', 'remediation_applied')),
    recorded_at TEXT NOT NULL,
    UNIQUE (finding_id, status)
);
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
CREATE TABLE IF NOT EXISTS remediations (
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
CREATE INDEX IF NOT EXISTS idx_remediations_finding ON remediations(finding_id);
CREATE TRIGGER IF NOT EXISTS trg_remediation_source BEFORE INSERT ON remediations
WHEN NOT EXISTS (
    SELECT 1 FROM recommendations AS r
    JOIN finding_observations AS o ON o.id = r.observation_id
    WHERE r.id = NEW.recommendation_id AND o.id = NEW.observation_id
      AND o.finding_id = NEW.finding_id
)
BEGIN SELECT RAISE(ABORT, 'remediation source mismatch'); END;
CREATE TRIGGER IF NOT EXISTS trg_remediation_immutable BEFORE UPDATE ON remediations
BEGIN SELECT RAISE(ABORT, 'remediation plan is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_remediation_no_delete BEFORE DELETE ON remediations
BEGIN SELECT RAISE(ABORT, 'remediation plan is immutable'); END;
CREATE TABLE IF NOT EXISTS remediation_applications (
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
CREATE TRIGGER IF NOT EXISTS trg_application_immutable BEFORE UPDATE ON remediation_applications
BEGIN SELECT RAISE(ABORT, 'remediation application is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_application_no_delete BEFORE DELETE ON remediation_applications
BEGIN SELECT RAISE(ABORT, 'remediation application is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_finding_remediation_transition BEFORE UPDATE OF status ON findings
WHEN NOT (
    (OLD.status = 'open' AND NEW.status = 'recommendation_created'
     AND EXISTS (SELECT 1 FROM remediations WHERE finding_id = NEW.id))
    OR (OLD.status = 'recommendation_created' AND NEW.status = 'remediation_applied'
     AND EXISTS (SELECT 1 FROM remediation_applications AS a
                 JOIN remediations AS r ON r.id = a.remediation_id
                 WHERE r.finding_id = NEW.id))
)
BEGIN SELECT RAISE(ABORT, 'invalid finding remediation transition'); END;
CREATE TRIGGER IF NOT EXISTS trg_finding_status_event BEFORE INSERT ON finding_status_history
WHEN NEW.status != (SELECT status FROM findings WHERE id = NEW.finding_id)
  AND NOT EXISTS (SELECT 1 FROM finding_status_history
                  WHERE finding_id = NEW.finding_id AND status = NEW.status)
BEGIN SELECT RAISE(ABORT, 'finding status history mismatch'); END;
"""


def connect_database(path: str | Path = ":memory:") -> sqlite3.Connection:
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.commit()
