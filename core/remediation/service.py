"""Plan a change from verified observation evidence; record execution separately."""

from __future__ import annotations

import logging
from datetime import datetime

from database.models.remediation import BeforeSnapshot, Remediation
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.recommendation_repository import SQLiteRecommendationRepository
from database.repositories.remediation_repository import SQLiteRemediationRepository

logger = logging.getLogger(__name__)
EVIDENCE_TYPES = frozenset({"deployment_record", "change_execution_log",
                            "installed_package_record"})


class RemediationInputError(ValueError):
    pass


def _positive_id(value: object, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RemediationInputError(f"positive {name} is required")


def _required_text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RemediationInputError(f"non-empty {name} is required")


class RemediationService:
    def __init__(self, *, findings: SQLiteFindingRepository,
                 recommendations: SQLiteRecommendationRepository,
                 remediations: SQLiteRemediationRepository) -> None:
        self.findings = findings
        self.recommendations = recommendations
        self.remediations = remediations

    def create_plan(self, *, finding_id: int, observation_id: int,
                    recommendation_id: int, action_key: str,
                    planned_action: str, owner: str) -> Remediation:
        for name, value in (("finding ID", finding_id), ("observation ID", observation_id),
                            ("recommendation ID", recommendation_id)):
            _positive_id(value, name)
        for name, value in (("action key", action_key), ("planned action", planned_action),
                            ("owner", owner)):
            _required_text(value, name)
        recommendation = self.recommendations.get(recommendation_id)
        finding = self.findings.get(finding_id)
        observation = next((item for item in finding.observations
                            if item.id == observation_id), None)
        if (recommendation.finding_id != finding_id
                or recommendation.observation_id != observation_id or observation is None):
            raise RemediationInputError("recommendation, observation and Finding do not belong together")
        source = self.recommendations.source_for_observation(observation_id)
        input_data = recommendation.input_data
        expected = {
            "finding_id": finding_id, "observation_id": observation_id,
            "component": source["component_name"], "version": source["version"],
            "purl": source["purl"], "cve": finding.cve_id,
            "risk_score": observation.risk.score,
            "risk_priority": observation.risk.priority,
            "risk_reasons": list(observation.risk.reasons),
            "risk_rule_version": observation.risk.rule_version,
        }
        if (any(input_data.get(key) != value for key, value in expected.items())
                or source["finding_id"] != finding_id
                or source["match_evidence_id"] != observation.match_evidence_id
                or source["component_id"] != observation.component_id
                or source["analysis_key"] != observation.analysis_key
                or observation.risk.cve_id != finding.cve_id):
            raise RemediationInputError("stored recommendation and observation evidence disagree")
        before = BeforeSnapshot(
            observation_id=observation_id, match_evidence_id=observation.match_evidence_id,
            analysis_key=observation.analysis_key, component_id=observation.component_id,
            component_name=source["component_name"], component_version=source["version"],
            component_purl=source["purl"], cve_id=finding.cve_id,
            risk_score=observation.risk.score, risk_priority=observation.risk.priority,
            risk_reasons=tuple(observation.risk.reasons),
            risk_rule_version=observation.risk.rule_version,
        )
        result = self.remediations.create(
            finding_id=finding_id, observation_id=observation_id,
            recommendation_id=recommendation_id, action_key=action_key,
            planned_action=planned_action, owner=owner, before=before)
        logger.info("Remediation plan recorded: remediation_id=%d finding_id=%d",
                    result.id, finding_id)
        return result

    def record_application(self, remediation_id: int, *, action: str, actor: str,
                           applied_at: str, evidence_type: str,
                           evidence_reference: str, evidence_source: str) -> Remediation:
        _positive_id(remediation_id, "remediation ID")
        for name, value in (("applied action", action), ("actor", actor),
                            ("applied time", applied_at),
                            ("evidence reference", evidence_reference),
                            ("evidence source", evidence_source)):
            _required_text(value, name)
        if evidence_type not in EVIDENCE_TYPES:
            raise RemediationInputError("unsupported execution evidence type")
        try:
            parsed = datetime.fromisoformat(applied_at)
        except ValueError as exc:
            raise RemediationInputError("applied time must be ISO 8601") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise RemediationInputError("applied time must include a timezone")
        result = self.remediations.apply(
            remediation_id, action=action, actor=actor, applied_at=applied_at,
            evidence_type=evidence_type, evidence_reference=evidence_reference,
            evidence_source=evidence_source)
        logger.info("Remediation application recorded: remediation_id=%d", result.id)
        return result

    def get(self, remediation_id: int) -> Remediation:
        _positive_id(remediation_id, "remediation ID")
        return self.remediations.get(remediation_id)

    def list_for_finding(self, finding_id: int) -> tuple[Remediation, ...]:
        _positive_id(finding_id, "finding ID")
        self.findings.get(finding_id)
        return self.remediations.list_for_finding(finding_id)
