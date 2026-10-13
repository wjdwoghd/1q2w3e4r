"""Read the explicitly selected immutable comparison sources; never select latest."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

from database.models.verification import Verification
from database.repositories.recommendation_repository import SQLiteRecommendationRepository, canonical_json
from database.repositories.remediation_repository import SQLiteRemediationRepository
from database.repositories.verification_repository import SQLiteVerificationRepository


class ComparisonSourceError(ValueError):
    """The selected attempt and its source graph do not belong together."""


@dataclass(frozen=True)
class ComparisonSource:
    verification: Verification
    asset_id: int
    finding_id: int
    recommendation_id: int
    before_facts: dict
    observation_recorded_at: str
    recommendation_recorded_at: str


class SQLiteComparisonRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def load(self, *, asset_id: int, finding_id: int, remediation_id: int,
             verification_id: int) -> ComparisonSource:
        verification = SQLiteVerificationRepository(self.connection).get(verification_id)
        remediation = SQLiteRemediationRepository(self.connection).get(remediation_id)
        recommendation = SQLiteRecommendationRepository(self.connection).get(remediation.recommendation_id)
        row = self.connection.execute(
            """SELECT v.asset_id, o.finding_id, o.recorded_at, f.asset_id AS finding_asset,
                      f.cve_id, e.cve_id AS evidence_cve, r.component_id, r.analysis_key
               FROM verifications v
               JOIN finding_observations o ON o.id = ?
               JOIN findings f ON f.id = o.finding_id
               JOIN vulnerability_match_evidence e ON e.id = o.match_evidence_id
               JOIN vulnerability_match_runs r ON r.id = e.run_id
               WHERE v.id = ? AND o.match_evidence_id = ?""",
            (verification.before.observation_id, verification_id, verification.before.match_evidence_id),
        ).fetchone()
        before = verification.before
        component = next((item for item in verification.before_sbom.get("components", [])
                          if item.get("id") == before.component_id), None)
        if (row is None or verification.remediation_id != remediation_id
                or verification.finding_id != finding_id or remediation.finding_id != finding_id
                or row["finding_id"] != finding_id or recommendation.finding_id != finding_id
                or row["asset_id"] != asset_id or row["finding_asset"] != asset_id
                or row["cve_id"] != before.cve_id or row["evidence_cve"] != before.cve_id
                or row["component_id"] != before.component_id or row["analysis_key"] != before.analysis_key
                or remediation.before != before or remediation.application != verification.application
                or recommendation.observation_id != before.observation_id
                or verification.before_sbom.get("asset_id") != asset_id
                or component is None or component.get("sbom_id") != verification.before_sbom.get("id")
                or (component.get("name"), component.get("version"), component.get("purl"))
                != (before.component_name, before.component_version, before.component_purl)):
            raise ComparisonSourceError("Remediation, Verification, Finding and asset ownership disagree")
        facts = recommendation.input_data
        if hashlib.sha256(canonical_json(facts).encode("utf-8")).hexdigest() != recommendation.input_digest:
            raise ComparisonSourceError("Recommendation input snapshot digest disagrees with stored facts")
        expected = {
            "finding_id": finding_id, "observation_id": before.observation_id,
            "component": before.component_name, "version": before.component_version,
            "purl": before.component_purl, "cve": before.cve_id,
            "risk_score": before.risk_score, "risk_priority": before.risk_priority,
            "risk_reasons": list(before.risk_reasons), "risk_rule_version": before.risk_rule_version,
        }
        if any(facts.get(key) != value for key, value in expected.items()):
            raise ComparisonSourceError("immutable Recommendation facts and Before Snapshot disagree")
        return ComparisonSource(verification, asset_id, finding_id, recommendation.id, facts,
                                row["recorded_at"], recommendation.created_at)
