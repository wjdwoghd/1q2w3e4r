"""Read-only, attempt-specific Before / After data, independent of any UI."""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from copy import deepcopy
from dataclasses import asdict
from math import isfinite

from core.risk.rules import PRIORITY_THRESHOLDS
from core.sbom.diff import compare_sbom_versions, package_identity
from core.sbom.normalizer import normalize_components
from core.sbom.parser import SBOMParsingError, parse_sbom
from core.verification.evidence import evidence_time, provenance_errors
from core.verification.vulnerability_verify import verify_vulnerability
from database.repositories.comparison_repository import ComparisonSource, SQLiteComparisonRepository
from database.repositories.verification_repository import evidence_json

logger = logging.getLogger(__name__)
PRIORITIES = tuple(priority for _, priority in PRIORITY_THRESHOLDS)
CRITICAL_CVSS_MINIMUM = 9.0  # Technical severity, independent of remediation priority.
NO_BEFORE_ANALYSIS = "attempt has no immutable whole-inventory Before vulnerability analysis"
NO_AFTER_RISK = "After Evidence has no verified RiskResult or asset-context snapshot"
NO_EOL = "selected snapshots have no verified EOL evidence"


def _value(value: object, *, scope: str, provenance: dict, reason: str | None = None) -> dict:
    return {"value": value, "scope": scope, "provenance": deepcopy(provenance),
            "unknown_reason": reason if value is None else None}


def compare_values(before: dict, after: dict, *, basis: str) -> dict:
    """Never subtract unknown values or observations of different populations."""
    reason = None
    if before["scope"] != after["scope"]:
        reason = "analysis scopes differ; subtraction would compare different populations"
    elif before["value"] is None or after["value"] is None:
        reason = "; ".join(dict.fromkeys(item["unknown_reason"] or "value unconfirmed"
                                        for item in (before, after) if item["value"] is None))
    numeric = all(isinstance(item["value"], (int, float)) and not isinstance(item["value"], bool)
                  for item in (before, after))
    return {"before": before, "after": after, "delta": after["value"] - before["value"]
            if reason is None and numeric else None, "comparable": reason is None,
            "comparison_reason": reason, "basis": basis}


def _inventory(sbom: dict | None) -> tuple[list[dict] | None, str | None]:
    if sbom is None:
        return None, "SBOM evidence missing"
    try:
        normalized = normalize_components(parse_sbom(sbom["raw_document"]).components)
        expected = [(item.name, item.version, item.purl, list(item.issues)) for item in normalized.components]
        actual = [(item["name"], item["version"], item["purl"], item["issues"]) for item in sbom["components"]]
        if expected != actual:
            return None, "SBOM raw document and component occurrences disagree"
    except (SBOMParsingError, ValueError, TypeError, KeyError) as exc:
        return None, f"invalid SBOM evidence ({type(exc).__name__})"
    return sbom["components"], None


def _source_metadata(source: ComparisonSource, side: str) -> dict:
    attempt = source.verification
    if side == "before":
        return {"source": "immutable Before Snapshot, original SBOM copy and Recommendation input",
                "collected_at": None, "collection_time_reason": "Before copies contain no collection timestamp",
                "recorded_at": source.observation_recorded_at,
                "snapshot_recorded_at": attempt.started_at,
                "recommendation_recorded_at": source.recommendation_recorded_at,
                "evidence_ids": {"verification_id": attempt.id, "remediation_id": attempt.remediation_id,
                                 "recommendation_id": source.recommendation_id,
                                 "observation_id": attempt.before.observation_id,
                                 "match_evidence_id": attempt.before.match_evidence_id,
                                 "component_id": attempt.before.component_id,
                                 "sbom_id": attempt.before_sbom["id"]},
                "analysis_key": attempt.before.analysis_key,
                "sbom_source": attempt.before_sbom.get("source")}
    payload = attempt.after.payload if attempt.after else {}
    sbom = payload.get("sbom") or {}
    runs = sorted(payload.get("match_runs", []), key=lambda item: item["id"])
    return {"source": "selected attempt immutable After Evidence",
            "collected_at": sbom.get("collected_at"),
            "recorded_at": attempt.after.recorded_at if attempt.after else None,
            "evidence_ids": {"verification_id": attempt.id, "after_evidence_verification_id": attempt.id
                             if attempt.after else None, "sbom_id": sbom.get("id"),
                             "match_run_ids": [item["id"] for item in runs]},
            "payload_digest": attempt.after.digest if attempt.after else None,
            "sbom_source": sbom.get("source"), "sbom_reference": sbom.get("reference"),
            "matching_sources": [
                {"run_id": run["id"], "component_id": run["component_id"],
                 "analysis_key": run["analysis_key"], "osv_query": deepcopy(run["result"].get("osv_query")),
                 "cve_sources": [{"cve_id": match["cve"]["cve_id"],
                                  "nvd_source": match["cve"].get("source_url"),
                                  "nvd_collected_at": match["cve"].get("fetched_at"),
                                  "kev_source": match["kev_snapshot"].get("source_url"),
                                  "kev_collected_at": match["kev_snapshot"].get("fetched_at")}
                                 for match in run["result"]["matches"]]} for run in runs],
            "scanner_results": sorted(deepcopy(payload.get("scanner_results", [])), key=evidence_json)}


def _time_errors(source: ComparisonSource, item: dict) -> list[str]:
    attempt = source.verification
    errors = provenance_errors(item, attempt.application.applied_at, "After analysis")
    collected = evidence_time(item.get("collected_at"))
    recorded = evidence_time(attempt.after.recorded_at) if attempt.after else None
    sbom_time = evidence_time((attempt.after.payload.get("sbom") or {}).get("collected_at")) if attempt.after else None
    if collected and (recorded is None or collected > recorded or sbom_time is None or collected < sbom_time):
        errors.append("After analysis collection time lies outside the selected evidence interval")
    return errors


def _after_analysis(source: ComparisonSource, components: list[dict] | None) -> tuple[dict | None, str | None]:
    """Require exactly one complete run for every occurrence; no scanner-based asset totals."""
    attempt = source.verification
    if components is None or attempt.after is None:
        return None, "valid After inventory and analysis evidence missing"
    runs = attempt.after.payload.get("match_runs", [])
    identifiers = [item["component_id"] for item in runs]
    if not components or Counter(identifiers) != Counter(item["id"] for item in components):
        return None, "analysis scope mismatch: exactly one complete re-matching run per After occurrence is required"
    by_id = {item["id"]: item for item in components}
    if len(by_id) != len(components) or any(not item.get("purl") or not item.get("version") for item in components):
        return None, "After component occurrence identity or version unresolved"
    cves: dict[str, list[dict]] = {}
    vulnerable = set()
    for run in runs:
        result, component = run["result"], by_id[run["component_id"]]
        query = result.get("osv_query")
        if query is None or result["component_purl"] != component["purl"]:
            return None, "After re-matching identity or OSV provenance missing"
        if _time_errors(source, {"source": query["source_url"], "reference": run["analysis_key"],
                                 "collected_at": query["fetched_at"]}):
            return None, "After OSV provenance or collection time invalid"
        matches = result["matches"]
        candidates = query["candidates"]
        ids = {match["cve"]["cve_id"] for match in matches}
        candidate_ids = {cve for candidate in candidates for cve in candidate["cve_ids"]}
        no_match = result["status"] == "no_match" and not candidates and not matches
        matched = (result["status"] == "matched" and bool(matches) and ids == candidate_ids
                   and len(ids) == len(matches) and all(len(item["cve_ids"]) == 1 for item in candidates))
        if not (no_match or matched):
            return None, "After re-matching incomplete, ambiguous, erroneous or contradictory"
        for match in matches:
            cve, kev = match["cve"], match["kev_snapshot"]
            for item in ({"source": cve["source_url"], "reference": cve["cve_id"], "collected_at": cve["fetched_at"]},
                         {"source": kev["source_url"], "reference": run["analysis_key"], "collected_at": kev["fetched_at"]}):
                if _time_errors(source, item):
                    return None, "After NVD/KEV provenance or collection time invalid"
            if (not match["osv_record_ids"]
                    or not len(match["osv_record_ids"]) == len(match["osv_source_urls"]) == len(match["osv_fetched_at"])):
                return None, "After matched CVE OSV record provenance incomplete"
            for record_id, url, collected in zip(match["osv_record_ids"], match["osv_source_urls"], match["osv_fetched_at"]):
                if _time_errors(source, {"source": url, "reference": record_id, "collected_at": collected}):
                    return None, "After matched CVE OSV record collection time or provenance invalid"
            if (not isinstance(match["kev"], bool)
                    or match["kev"] != (match.get("kev_entry") is not None)
                    or match.get("kev_entry") != kev["entries"].get(cve["cve_id"])):
                return None, "After KEV flag and catalog evidence disagree"
            cves.setdefault(cve["cve_id"], []).append(match)
            vulnerable.add(component["id"])
    # A supplied scanner contradiction invalidates totals, even when matching coverage is complete.
    for scan in attempt.after.payload.get("scanner_results", []):
        if (_time_errors(source, scan) or scan.get("scope") != "asset"
                or scan["status"] not in ("detected", "not_detected")
                or (scan["status"] == "detected") != (scan["cve_id"] in cves)):
            return None, "After Scanner and re-matching evidence conflict or are inconclusive"
    return {"cves": cves, "vulnerable_component_count": len(vulnerable)}, None


def _critical_count(cves: dict[str, list[dict]]) -> int | None:
    count = 0
    for matches in cves.values():
        scores = [(match["cve"].get("cvss") or {}).get("score") for match in matches]
        if any(isinstance(score, bool) or not isinstance(score, (float, int))
               or not isfinite(score) or not 0 <= score <= 10 for score in scores):
            return None
        flags = {score >= CRITICAL_CVSS_MINIMUM for score in scores}
        if len(flags) != 1:
            return None
        count += flags.pop()
    return count


def _kev_count(cves: dict[str, list[dict]]) -> int | None:
    flags = [{match["kev"] for match in matches} for matches in cves.values()]
    return sum(next(iter(flag)) for flag in flags) if all(len(flag) == 1 for flag in flags) else None


def _versions(components: list[dict] | None) -> list[dict] | None:
    if components is None:
        return None
    # Occurrence IDs remain visible; never collapse duplicate packages or versions.
    return [{**{key: item.get(key) for key in ("id", "name", "version", "purl", "position")},
             "version_unknown_reason": "version missing from SBOM snapshot" if not item.get("version") else None,
             "purl_unknown_reason": "PURL missing from SBOM snapshot" if not item.get("purl") else None}
            for item in sorted(components, key=lambda item: (item.get("position", 0), item["id"]))]


def compare_attempt(source: ComparisonSource) -> dict:
    """Use only this attempt's copied inventory, immutable facts and detached evidence."""
    attempt, before = source.verification, source.verification.before
    old, old_error = _inventory(attempt.before_sbom)
    payload = attempt.after.payload if attempt.after else None
    if payload:
        if payload.get("asset_id") != source.asset_id:
            raise ValueError("After Evidence belongs to another asset")
        sbom = payload.get("sbom")
        if sbom and sbom.get("asset_id") != source.asset_id:
            raise ValueError("After SBOM belongs to another asset")
        component_ids = {item["id"] for item in (sbom or {}).get("components", [])}
        for run in payload.get("match_runs", []):
            if run["component_id"] not in component_ids:
                raise ValueError("After re-matching run belongs to another SBOM")
        if sbom and any(item.get("sbom_id") != sbom["id"] for item in sbom["components"]):
            raise ValueError("After component occurrence belongs to another SBOM")
        for item in payload.get("scanner_results", []) + payload.get("functional_tests", []):
            if not sbom or item["asset_id"] != source.asset_id or item["sbom_id"] != sbom["id"]:
                raise ValueError("After test evidence ownership disagrees")
        if hashlib.sha256(evidence_json(payload).encode("utf-8")).hexdigest() != attempt.after.digest:
            raise ValueError("After Evidence digest disagrees with payload")
    new, new_error = _inventory(payload.get("sbom") if payload else None)
    if new is not None and _time_errors(source, payload["sbom"]):
        new, new_error = None, "After SBOM provenance or collection time invalid"
    analysis, analysis_error = _after_analysis(source, new)
    old_meta, new_meta = _source_metadata(source, "before"), _source_metadata(source, "after")

    def metric(old_value: object, new_value: object, scope: str, basis: str,
               old_reason: str | None = None, new_reason: str | None = None) -> dict:
        return compare_values(_value(old_value, scope=scope, provenance=old_meta, reason=old_reason),
                              _value(new_value, scope=scope, provenance=new_meta, reason=new_reason), basis=basis)

    asset_scope = f"asset:{source.asset_id}:whole_sbom_inventory"
    finding_scope = f"asset:{source.asset_id}:cve:{before.cve_id}"
    cves = analysis["cves"] if analysis else None
    # When the entire copied inventory is a single confirmed vulnerable occurrence,
    # its component count is exact even without a full Before CVE enumeration.
    old_vulnerable_count = (1 if old is not None and len(old) == 1
                            and old[0]["id"] == before.component_id else None)
    asset = {
        "component_count": metric(len(old) if old is not None else None, len(new) if new is not None else None,
                                  asset_scope, "SBOM component occurrences, including duplicates", old_error, new_error),
        "component_versions": metric(_versions(old), _versions(new), asset_scope,
                                     "version per occurrence; missing version remains None", old_error, new_error),
        "vulnerable_component_count": metric(old_vulnerable_count, analysis["vulnerable_component_count"] if analysis else None,
                                             asset_scope, "distinct occurrence IDs with verified CVE matches",
                                             NO_BEFORE_ANALYSIS, analysis_error),
        "cve_count": metric(None, len(cves) if cves is not None else None, asset_scope,
                            "distinct verified CVE IDs across whole inventory", NO_BEFORE_ANALYSIS, analysis_error),
        "critical_cve_count": metric(None, _critical_count(cves) if cves is not None else None, asset_scope,
                                     "distinct CVEs with technical CVSS score >= 9.0", NO_BEFORE_ANALYSIS,
                                     analysis_error or "CVSS missing or conflicting for the same CVE"),
        "kev_cve_count": metric(None, _kev_count(cves) if cves is not None else None, asset_scope,
                                "distinct CVEs confirmed in CISA KEV catalog", NO_BEFORE_ANALYSIS,
                                analysis_error or "KEV evidence conflicts for the same CVE"),
        "eol_component_count": metric(None, None, asset_scope, "verified EOL component occurrences", NO_EOL, NO_EOL),
        "finding_priority_counts": metric(None, None, asset_scope, "unique (asset_id, cve_id) per internal priority",
                                          NO_BEFORE_ANALYSIS, NO_AFTER_RISK),
        "risk_score": metric(None, None, asset_scope, "no implicit asset risk score formula",
                             "no whole-asset Before risk snapshot or aggregate risk policy", NO_AFTER_RISK),
    }
    identity = package_identity(before.component_purl)
    old_target = [item for item in old if package_identity(item["purl"]) == identity] if old is not None and identity else None
    new_target = [item for item in new if package_identity(item["purl"]) == identity] if new is not None and identity else None
    present, presence_reason = None, analysis_error
    if analysis:
        present = int(before.cve_id in cves)
    elif payload and new is not None:
        errors, _ = verify_vulnerability(before.cve_id, payload, attempt.application.applied_at)
        scans = payload.get("scanner_results", [])
        if not errors and scans and all(not _time_errors(source, scan) for scan in scans):
            present = 0  # Only this CVE; never a whole-asset vulnerability total.
            presence_reason = None
    after_cves = {before.cve_id: cves[before.cve_id]} if cves is not None and before.cve_id in cves else {}
    old_cvss, old_kev = source.before_facts.get("cvss"), source.before_facts.get("kev")
    old_critical = (int(old_cvss >= CRITICAL_CVSS_MINIMUM)
                    if isinstance(old_cvss, (int, float)) and not isinstance(old_cvss, bool)
                    and isfinite(old_cvss) and 0 <= old_cvss <= 10 else None)
    after_critical = 0 if present == 0 else _critical_count(after_cves) if present == 1 else None
    after_kev = 0 if present == 0 else _kev_count(after_cves) if present == 1 else None
    priorities = {priority: int(priority == before.risk_priority) for priority in PRIORITIES}
    finding = {
        "component_count": metric(len(old_target) if old_target is not None else None,
                                  len(new_target) if new_target is not None else None,
                                  f"package:{identity}", "versionless PURL identity, preserving occurrences",
                                  old_error or "target package identity missing", new_error or "target package identity missing"),
        "component_versions": metric(_versions(old_target), _versions(new_target), f"package:{identity}",
                                     "target package occurrence versions", old_error, new_error),
        "vulnerable_component_count": metric(old_vulnerable_count, sum(any(match["cve"]["cve_id"] == before.cve_id
                                                               for match in run["result"]["matches"])
                                                        for run in payload["match_runs"]) if analysis else None,
                                             finding_scope, "occurrences with this CVE across inventory",
                                             NO_BEFORE_ANALYSIS, analysis_error),
        "cve_count": metric(1, present, finding_scope, "selected (asset_id, cve_id) presence; not all asset CVEs",
                            new_reason=presence_reason),
        "critical_cve_count": metric(old_critical, after_critical, finding_scope,
                                     "selected CVE technical severity: CVSS >= 9.0",
                                     "Before CVSS unconfirmed", presence_reason or "After CVSS missing or conflicting"),
        "kev_cve_count": metric(int(old_kev) if isinstance(old_kev, bool) else None, after_kev, finding_scope,
                                "selected CVE KEV catalog membership", "Before KEV unconfirmed",
                                presence_reason or "After KEV conflicting"),
        "eol_component_count": metric(None, None, f"package:{identity}", "verified EOL occurrences", NO_EOL, NO_EOL),
        "finding_priority_counts": metric(priorities, None, finding_scope,
                                          "one Finding, internal P1/P2/P3/P4 priority; independent of CVSS",
                                          new_reason=NO_AFTER_RISK),
        "risk_score": metric(before.risk_score, None, finding_scope, "stored Phase 5 internal Risk Score",
                             new_reason=NO_AFTER_RISK),
    }
    return {"selection": {"asset_id": source.asset_id, "finding_id": source.finding_id,
                          "remediation_id": attempt.remediation_id, "verification_id": attempt.id,
                          "attempt_key": attempt.attempt_key, "cve_id": before.cve_id},
            "finding": finding, "asset": asset,
            "verification": {"status": attempt.status.value, "started_at": attempt.started_at,
                             "after_status": attempt.status.value, "delta": None,
                             "basis": "stored selected attempt outcome, independent of metric deltas",
                             "completed_at": attempt.completed_at,
                             "decision": asdict(attempt.decision) if attempt.decision else None,
                             "before_status": None, "before_status_reason": "Before Snapshot contains no verification status"},
            "snapshots": {"before": asdict(before), "before_sbom": deepcopy(attempt.before_sbom),
                          "before_facts": deepcopy(source.before_facts),
                          "after": deepcopy(payload), "application": asdict(attempt.application)},
            "sbom_diff": compare_sbom_versions(old, new) if old is not None and new is not None else None,
            "basis": {"finding_identity": "(asset_id, cve_id)", "delta_direction": "After minus Before",
                      "inventory_scope": "selected copied SBOMs, not all assets or all historical SBOMs",
                      "unknown_is_zero": False, "recomputes_verification": False}}


class ComparisonService:
    def __init__(self, repository: SQLiteComparisonRepository) -> None:
        self.repository = repository

    def compare_finding(self, *, asset_id: int, finding_id: int, remediation_id: int,
                        verification_id: int) -> dict:
        for value in (asset_id, finding_id, remediation_id, verification_id):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError("explicit positive asset, Finding, Remediation and Verification IDs required")
        result = compare_attempt(self.repository.load(asset_id=asset_id, finding_id=finding_id,
                                                     remediation_id=remediation_id, verification_id=verification_id))
        logger.info("Before/After compared: verification_id=%d", verification_id)
        return result

    def compare_asset(self, *, asset_id: int, selections: tuple[tuple[int, int, int], ...]) -> dict:
        """Selections are (finding_id, remediation_id, verification_id), never latest attempts."""
        if not isinstance(selections, tuple) or not selections:
            raise ValueError("explicit non-empty attempt selections required")
        if any(not isinstance(item, tuple) or len(item) != 3 for item in selections):
            raise ValueError("each selection must contain Finding, Remediation and Verification IDs")
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0
               for item in selections for value in item):
            raise ValueError("positive selection IDs required")
        comparisons = [self.compare_finding(asset_id=asset_id, finding_id=finding,
                                            remediation_id=remediation, verification_id=verification)
                       for finding, remediation, verification in sorted(set(selections))]
        cohorts = {evidence_json((item["snapshots"]["before_sbom"], item["snapshots"]["after"]))
                   for item in comparisons}
        distinct_findings = {item["selection"]["finding_id"] for item in comparisons}
        reason = None
        if len(cohorts) != 1 or len(distinct_findings) != len(comparisons):
            reason = "selected attempts have different inventory/analysis scopes or multiple attempts for one Finding"
        metrics = deepcopy(comparisons[0]["asset"])
        if reason:
            for item in metrics.values():
                for side in ("before", "after"):
                    item[side]["value"], item[side]["unknown_reason"] = None, reason
                item.update(delta=None, comparable=False, comparison_reason=reason)
        counts = {priority: 0 for priority in PRIORITIES}
        if not reason:
            for item in comparisons:
                for priority, count in item["finding"]["finding_priority_counts"]["before"]["value"].items():
                    counts[priority] += count
        # This subset metric must not masquerade as a whole-asset priority total.
        metrics["selected_finding_priority_counts"] = compare_values(
            _value(counts if not reason else None, scope=f"asset:{asset_id}:explicitly_selected_findings",
                   provenance={"contributors": [item["finding"]["finding_priority_counts"]["before"]["provenance"]
                                                for item in comparisons]}, reason=reason),
            _value(None, scope=f"asset:{asset_id}:explicitly_selected_findings",
                   provenance={"contributors": [item["finding"]["finding_priority_counts"]["after"]["provenance"]
                                                for item in comparisons]}, reason=NO_AFTER_RISK),
            basis="deduplicated (asset_id, cve_id) in explicit selection; not all asset Findings")
        return {"asset_id": asset_id, "comparisons": comparisons, "metrics": metrics,
                "aggregation_reason": reason,
                "verification_statuses": [{"verification_id": item["selection"]["verification_id"],
                                           **item["verification"]} for item in comparisons]}
