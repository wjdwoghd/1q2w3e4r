"""Build a Recommendation input from a single persisted Finding observation."""

from __future__ import annotations

from database.repositories.control_mapping_repository import SQLiteControlMappingRepository
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.recommendation_repository import SQLiteRecommendationRepository
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository


class RecommendationInputError(ValueError):
    pass


def build_recommendation_input(
    observation_id: int, *, findings: SQLiteFindingRepository,
    mappings: SQLiteControlMappingRepository,
    matches: SQLiteVulnerabilityRepository,
    recommendations: SQLiteRecommendationRepository,
) -> dict:
    if not isinstance(observation_id, int) or isinstance(observation_id, bool) or observation_id <= 0:
        raise RecommendationInputError("positive observation ID is required")
    source = recommendations.source_for_observation(observation_id)
    finding = findings.get(source["finding_id"])
    observation = next((item for item in finding.observations if item.id == observation_id), None)
    if (observation is None or observation.match_evidence_id != source["match_evidence_id"]
            or observation.match_run_id != source["run_id"]
            or observation.component_id != source["component_id"]
            or observation.risk.cve_id != finding.cve_id):
        raise RecommendationInputError("observation provenance disagrees with Finding")
    run = matches.get(observation.match_run_id)
    match = next((item for item in run.result.matches
                  if item.cve.cve_id == finding.cve_id), None)
    if (run.component_id != source["component_id"] or run.analysis_key != source["analysis_key"]
            or match is None or match.cve.cvss is None
            or match.cve.cvss.score != observation.risk.cvss_score
            or match.kev != (match.kev_entry is not None)
            or source["evidence_cve_id"] != finding.cve_id
            or source["purl"] != run.result.component_purl):
        raise RecommendationInputError("stored CVE, CVSS, KEV, or component evidence disagrees")
    controls = tuple(mapping for mapping in mappings.list_for_finding(finding.id)
                     if mapping.observation_id == observation_id)
    if not controls or any(mapping.finding_id != finding.id for mapping in controls):
        raise RecommendationInputError("observation control mapping is missing or mismatched")
    for mapping in controls:
        facts = dict(mapping.observed_facts)
        if (facts.get("cve_id") != finding.cve_id
                or facts.get("match_evidence_id") != str(observation.match_evidence_id)
                or facts.get("analysis_key") != observation.analysis_key):
            raise RecommendationInputError("control mapping facts disagree with observation")
    context = observation.asset_context
    if source["asset_name"] != context.name:
        raise RecommendationInputError("asset name changed from observation snapshot")
    return {
        "finding_id": finding.id, "observation_id": observation.id,
        "business_service": source["business_service"], "asset": context.name,
        "component": source["component_name"], "version": source["version"],
        "purl": source["purl"], "cve": finding.cve_id,
        "cvss": observation.risk.cvss_score, "cwes": list(match.cve.cwes),
        "kev": match.kev, "eol": "unknown",
        "environment": context.environment.value,
        "internet_exposed": context.internet_exposed,
        "business_criticality": context.business_criticality.value,
        "customer_information": context.customer_information,
        "credit_information": context.credit_information,
        "patch_status": context.patch_status.value,
        "risk_score": observation.risk.score,
        "risk_priority": observation.risk.priority,
        "risk_reasons": list(observation.risk.reasons),
        "risk_rule_version": observation.risk.rule_version,
        "unassessed_factors": list(observation.risk.unassessed_factors),
        "controls": [{"key": item.control.key, "identifier": item.control.identifier,
                      "title": item.control.title, "type": item.control.control_type.value,
                      "source_url": item.control.source_url,
                      "mapping_reason": item.reason} for item in controls],
    }
