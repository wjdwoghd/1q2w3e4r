"""Immutable verification attempts, evidence snapshots and decisions."""

from dataclasses import dataclass
from enum import Enum

from database.models.remediation import BeforeSnapshot, RemediationApplication


class VerificationStatus(str, Enum):
    IN_PROGRESS = "verification_in_progress"
    PASSED = "verification_passed"
    FAILED = "verification_failed"


class ScannerStatus(str, Enum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    ERROR = "error"
    INCONCLUSIVE = "inconclusive"


class FunctionalStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class ScannerEvidence:
    asset_id: int
    sbom_id: int
    cve_id: str
    status: ScannerStatus
    source: str
    reference: str
    collected_at: str
    scope: str = "asset"


@dataclass(frozen=True)
class FunctionalEvidence:
    asset_id: int
    sbom_id: int
    test_id: str
    status: FunctionalStatus
    source: str
    reference: str
    collected_at: str


@dataclass(frozen=True)
class VerificationDecision:
    status: VerificationStatus
    rule_version: str
    reasons: tuple[str, ...]
    sbom_diff: dict | None = None


@dataclass(frozen=True)
class AfterEvidence:
    payload: dict
    digest: str
    recorded_at: str


@dataclass(frozen=True)
class Verification:
    id: int
    remediation_id: int
    finding_id: int
    attempt_key: str
    before: BeforeSnapshot
    before_sbom: dict
    application: RemediationApplication
    required_functional_tests: tuple[str, ...]
    started_at: str
    after: AfterEvidence | None
    decision: VerificationDecision | None
    completed_at: str | None

    @property
    def status(self) -> VerificationStatus:
        return self.decision.status if self.decision else VerificationStatus.IN_PROGRESS
