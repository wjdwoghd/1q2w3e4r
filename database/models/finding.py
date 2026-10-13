"""Finding snapshots and the supported remediation workflow states."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from core.assets.context import AssetContext
from core.risk.engine import RiskResult


class FindingStatus(str, Enum):
    OPEN = "open"
    RECOMMENDATION_CREATED = "recommendation_created"
    REMEDIATION_APPLIED = "remediation_applied"
    VERIFICATION_IN_PROGRESS = "verification_in_progress"
    VERIFICATION_PASSED = "verification_passed"
    VERIFICATION_FAILED = "verification_failed"


@dataclass(frozen=True)
class FindingObservation:
    id: int
    match_evidence_id: int
    match_run_id: int
    component_id: int
    analysis_key: str
    risk: RiskResult
    asset_context: AssetContext
    recorded_at: str


@dataclass(frozen=True)
class FindingStatusEvent:
    id: int
    status: FindingStatus
    recorded_at: str


@dataclass(frozen=True)
class Finding:
    id: int
    asset_id: int
    cve_id: str
    status: FindingStatus
    created_at: str
    observations: tuple[FindingObservation, ...]
    status_history: tuple[FindingStatusEvent, ...]
