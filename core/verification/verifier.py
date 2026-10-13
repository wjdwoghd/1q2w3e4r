"""Pure deterministic Phase 9 decision; no risk-score or AI inputs."""

from core.verification.functional_verify import verify_functional_tests
from core.verification.sbom_verify import verify_sbom
from core.verification.vulnerability_verify import verify_vulnerability
from core.verification.evidence import evidence_time
from core.sbom.diff import compare_sbom_versions
from database.models.remediation import BeforeSnapshot
from database.models.verification import VerificationDecision, VerificationStatus

VERIFICATION_RULE_VERSION = "verification-1.0"


def verify_remediation(before: BeforeSnapshot, *, applied_at: str,
                       required_functional_tests: tuple[str, ...], after: dict,
                       before_components: list[dict], recorded_at: str) -> VerificationDecision:
    checks = (
        verify_sbom(before, after, applied_at),
        verify_vulnerability(before.cve_id, after, applied_at),
        verify_functional_tests(required_functional_tests, after, applied_at),
    )
    errors = [reason for failures, _ in checks for reason in failures]
    reasons = [reason for _, successes in checks for reason in successes]
    evidence_items = ([after["sbom"]] if after["sbom"] else []) + after["scanner_results"] + after["functional_tests"]
    evidence_items += [{"collected_at": run["result"]["osv_query"]["fetched_at"]}
                       for run in after["match_runs"] if run["result"].get("osv_query")]
    for run in after["match_runs"]:
        for match in run["result"]["matches"]:
            evidence_items.append({"collected_at": match["cve"]["fetched_at"]})
            evidence_items.extend({"collected_at": value} for value in match["osv_fetched_at"])
            evidence_items.append({"collected_at": match["kev_snapshot"]["fetched_at"]})
    recorded = evidence_time(recorded_at)
    sbom_time = evidence_time((after["sbom"] or {}).get("collected_at"))
    for item in evidence_items:
        collected = evidence_time(item.get("collected_at"))
        if collected is None:
            errors.append("Evidence: timezone-aware collection time is required")
        if collected and (recorded is None or collected > recorded):
            errors.append("Evidence: collection time is later than evidence recording time")
        if collected and sbom_time and collected < sbom_time:
            errors.append("Evidence: test or query predates after SBOM collection")
    if not required_functional_tests:
        errors.append("Functional tests: explicit requirements are missing")
    diff = compare_sbom_versions(before_components, after["sbom"]["components"]) if after["sbom"] else None
    status = VerificationStatus.FAILED if errors else VerificationStatus.PASSED
    return VerificationDecision(status, VERIFICATION_RULE_VERSION, tuple(errors + reasons), diff)
