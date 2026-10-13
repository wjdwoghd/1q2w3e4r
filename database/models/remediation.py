"""Immutable Phase 8 remediation plan, before snapshot and application record."""

from dataclasses import dataclass
from enum import Enum


class RemediationStatus(str, Enum):
    PLANNED = "planned"
    APPLIED = "applied"


@dataclass(frozen=True)
class BeforeSnapshot:
    observation_id: int
    match_evidence_id: int
    analysis_key: str
    component_id: int
    component_name: str
    component_version: str | None
    component_purl: str | None
    cve_id: str
    risk_score: int
    risk_priority: str
    risk_reasons: tuple[str, ...]
    risk_rule_version: str


@dataclass(frozen=True)
class RemediationApplication:
    action: str
    actor: str
    applied_at: str
    evidence_type: str
    evidence_reference: str
    evidence_source: str
    recorded_at: str


@dataclass(frozen=True)
class Remediation:
    id: int
    finding_id: int
    recommendation_id: int
    observation_id: int
    action_key: str
    planned_action: str
    owner: str
    before: BeforeSnapshot
    created_at: str
    application: RemediationApplication | None

    @property
    def status(self) -> RemediationStatus:
        return RemediationStatus.APPLIED if self.application else RemediationStatus.PLANNED
