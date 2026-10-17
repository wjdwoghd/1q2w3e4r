"""Calculate per-CVE priority from verified matching and asset context."""

from __future__ import annotations

import math
import logging
from dataclasses import dataclass

from core.assets.context import AssetContext, BusinessCriticality, PatchStatus
from core.risk.priority import priority_for_score
from core.risk.rules import CVSS_BANDS, RISK_WEIGHTS, RULE_VERSION
from core.vulnerability.cve_client import CVERecord, CVE_PATTERN
from core.vulnerability.cvss import CVSSMetric
from core.vulnerability.kev_client import KEVSnapshot
from core.vulnerability.matcher import MatchResult, MatchStatus, MatchedCVE

logger = logging.getLogger(__name__)


class RiskInputError(ValueError):
    """Verified evidence or required risk input is missing or inconsistent."""


@dataclass(frozen=True)
class AppliedRule:
    factor: str
    reason: str
    points: int


@dataclass(frozen=True)
class RiskResult:
    cve_id: str
    cvss_score: float
    score: int
    priority: str
    applied_rules: tuple[AppliedRule, ...]
    unassessed_factors: tuple[str, ...]
    rule_version: str

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(f"{rule.reason}: +{rule.points}" for rule in self.applied_rules)


def _validate_match(match: MatchedCVE) -> None:
    if (not isinstance(match, MatchedCVE) or not isinstance(match.cve, CVERecord)
            or not isinstance(match.cve.cvss, CVSSMetric)):
        raise RiskInputError("matched CVE must have a verified CVSS metric")
    if not isinstance(match.cve.cve_id, str) or not CVE_PATTERN.fullmatch(match.cve.cve_id):
        raise RiskInputError("matched CVE must have a valid identifier")
    score = match.cve.cvss.score
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10:
        raise RiskInputError("CVSS score must be a finite number between 0 and 10")
    if not isinstance(match.kev_snapshot, KEVSnapshot) or not isinstance(match.kev, bool):
        raise RiskInputError("validated CISA KEV snapshot is required")
    catalog_entry = match.kev_snapshot.lookup(match.cve.cve_id)
    if match.kev_entry != catalog_entry or match.kev != (catalog_entry is not None):
        raise RiskInputError("KEV flag and entry disagree with the catalog snapshot")


def _calculate_one(match: MatchedCVE, context: AssetContext) -> RiskResult:
    cvss_score = match.cve.cvss.score
    rules: list[AppliedRule] = []
    for minimum, points, reason in CVSS_BANDS:
        if cvss_score >= minimum:
            rules.append(AppliedRule("cvss", reason, points))
            break
    if match.kev:
        rules.append(AppliedRule("kev", "CISA KEV registered", RISK_WEIGHTS["kev"]))
    if context.internet_exposed:
        rules.append(AppliedRule("internet_exposure", "Internet exposed", RISK_WEIGHTS["internet_exposure"]))
    if context.is_production:
        rules.append(AppliedRule("production", "Production environment", RISK_WEIGHTS["production"]))
    if context.business_criticality is BusinessCriticality.CRITICAL:
        rules.append(AppliedRule("business_criticality", "Critical service", RISK_WEIGHTS["critical_service"]))
    elif context.business_criticality is BusinessCriticality.HIGH:
        rules.append(AppliedRule("business_criticality", "High-criticality service", RISK_WEIGHTS["high_criticality"]))
    if context.patch_status is PatchStatus.OVERDUE:
        rules.append(AppliedRule("patch_status", "Patch overdue", RISK_WEIGHTS["patch_overdue"]))
    if context.credit_information:
        rules.append(AppliedRule("credit_information", "Credit information processed", RISK_WEIGHTS["credit_information"]))
    unassessed = ("eol",)
    if context.patch_status is PatchStatus.UNKNOWN:
        unassessed += ("patch_status",)
    total = sum(rule.points for rule in rules)
    return RiskResult(match.cve.cve_id, float(cvss_score), total, priority_for_score(total),
                      tuple(rules), unassessed, RULE_VERSION)


def calculate_risk_priorities(match_result: MatchResult, context: AssetContext) -> tuple[RiskResult, ...]:
    """Return one priority per matched CVE; reject incomplete or failed matching."""
    if not isinstance(match_result, MatchResult) or match_result.status is not MatchStatus.MATCHED:
        raise RiskInputError("a successful MATCHED MatchResult is required")
    if not isinstance(context, AssetContext):
        raise RiskInputError("a validated AssetContext is required")
    if not match_result.matches or not isinstance(match_result.matches, tuple):
        raise RiskInputError("MATCHED result must contain at least one CVE")
    if not isinstance(match_result.component_purl, str) or not match_result.component_purl:
        raise RiskInputError("MATCHED result must identify a component PURL")
    # Validate all CVEs before producing any result, so partial scoring is impossible.
    for match in match_result.matches:
        _validate_match(match)
    identifiers = [match.cve.cve_id for match in match_result.matches]
    if len(set(identifiers)) != len(identifiers):
        raise RiskInputError("duplicate CVE in MatchResult")
    results = tuple(_calculate_one(match, context) for match in match_result.matches)
    logger.info("Risk calculated: count=%d rule_version=%s", len(results), RULE_VERSION)
    return results
