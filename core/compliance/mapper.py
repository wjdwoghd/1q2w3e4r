"""Deterministic Finding observation to reference-control mapping."""

from __future__ import annotations

from dataclasses import dataclass

from core.compliance.controls import SecurityControl, load_controls
from database.models.finding import FindingObservation

RULE_VERSION = "7.1.1"


@dataclass(frozen=True)
class ControlMappingCandidate:
    observation_id: int
    control: SecurityControl
    rule_id: str
    rule_version: str
    reason: str
    observed_facts: tuple[tuple[str, str], ...]


def map_observation(observation: FindingObservation,
                    controls: dict[str, SecurityControl] | None = None
                    ) -> tuple[ControlMappingCandidate, ...]:
    """Use persisted Phase 6 facts; category references are not detailed requirements."""
    if not isinstance(observation, FindingObservation) or observation.id <= 0:
        raise ValueError("a persisted Finding observation is required")
    if observation.risk.cve_id == "" or observation.match_evidence_id <= 0:
        raise ValueError("observation lacks verified CVE evidence")
    catalog = load_controls() if controls is None else controls
    required = {"FIN-37-2-5-1", "ISMS-P-2.10", "ISMS-P-1.2"}
    if observation.asset_context.patch_status.value == "overdue":
        required.add("FIN-37-2-5")
    if not required.issubset(catalog):
        raise ValueError("control catalog is missing required verified entries")
    common = (("cve_id", observation.risk.cve_id),
              ("match_evidence_id", str(observation.match_evidence_id)),
              ("analysis_key", observation.analysis_key))

    def candidate(key: str, rule: str, reason: str,
                  facts: tuple[tuple[str, str], ...]) -> ControlMappingCandidate:
        return ControlMappingCandidate(observation.id, catalog[key], rule, RULE_VERSION,
                                       reason, facts)

    result = [
        candidate("FIN-37-2-5-1", "verified_cve_remediation",
                  "확인된 CVE가 있어 취약점 제거 또는 상응 조치 조항을 참고할 수 있음", common),
        candidate("ISMS-P-2.10", "verified_cve_system_security",
                  "확인된 CVE가 있어 시스템 및 서비스 보안관리 기준 영역을 참고할 수 있음", common),
        candidate("ISMS-P-1.2", "assessed_risk_management",
                  "Finding의 위험 분석 결과가 있어 위험관리 기준 영역을 참고할 수 있음",
                  common + (("risk_rule_version", observation.risk.rule_version),
                            ("priority", observation.risk.priority))),
    ]
    if observation.asset_context.patch_status.value == "overdue":
        result.append(candidate(
            "FIN-37-2-5", "overdue_patch_plan",
            "관측 당시 패치 상태가 overdue여서 취약점 이행계획 수립·시행 조항을 참고할 수 있음",
            common + (("patch_status", "overdue"),)))
    return tuple(result)
