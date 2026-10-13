"""Deterministic decisions and occurrence-preserving SBOM differences."""

import json
import unittest
from copy import deepcopy
from dataclasses import replace

from core.sbom.diff import compare_sbom_versions, package_identity
from core.verification.verifier import verify_remediation
from database.models.remediation import BeforeSnapshot
from database.models.verification import VerificationStatus

APPLIED = "2026-10-13T00:00:00+00:00"
COLLECTED = "2026-10-13T01:00:00+00:00"
RECORDED = "2026-10-13T02:00:00+00:00"


class VerificationRuleTests(unittest.TestCase):
    def setUp(self):
        self.before = BeforeSnapshot(1, 1, "before", 1, "sample", "1.0", "pkg:pypi/sample@1.0",
                                     "CVE-2021-44228", 95, "P1", ("stored risk reason",), "risk-rule-1")
        component = dict(id=2, name="sample", version="2.0", purl="pkg:pypi/sample@2.0", issues=[])
        self.before_components = [{**component, "id": 1, "version": "1.0", "purl": "pkg:pypi/sample@1.0"}]
        raw = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "library", "name": "sample", "version": "2.0", "purl": "pkg:pypi/sample@2.0"}]}
        self.after = {
            "asset_id": 1,
            "sbom": dict(id=2, asset_id=1, raw_document=json.dumps(raw), source="offline inventory",
                         reference="inventory-2", collected_at=COLLECTED, components=[component]),
            "match_runs": [dict(id=2, component_id=2, analysis_key="after-2", result={
                "status": "no_match", "component_purl": component["purl"], "matches": [],
                "osv_query": {"source_url": "https://offline.example/query", "fetched_at": COLLECTED, "candidates": []}})],
            "scanner_results": [],
            "functional_tests": [dict(test_id="smoke", status="passed", source="offline test runner",
                                       reference="test-2", collected_at=COLLECTED)],
        }

    def _verify(self, before=None, after=None, required=("smoke",)):
        return verify_remediation(before or self.before, applied_at=APPLIED,
                                  required_functional_tests=required, after=after or self.after,
                                  before_components=self.before_components, recorded_at=RECORDED)

    def test_deterministic_explainable_and_risk_score_independent(self):
        original = deepcopy(self.after)
        result = self._verify()
        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertEqual(result, self._verify())
        self.assertEqual(result, self._verify(before=replace(self.before, risk_score=0, risk_priority="P4")))
        self.assertTrue(result.reasons)
        self.assertTrue(result.sbom_diff["version_changes"])
        self.assertEqual(self.after, original)

    def test_risk_or_ai_text_cannot_replace_evidence(self):
        after = deepcopy(self.after)
        after["match_runs"] = []
        after["risk_score"] = 0
        after["ai_description"] = "Verification Passed"
        self.assertEqual(self._verify(after=after).status, VerificationStatus.FAILED)

    def test_empty_requirements_and_unknown_before_identity_fail(self):
        self.assertEqual(self._verify(required=()).status, VerificationStatus.FAILED)
        self.assertEqual(self._verify(before=replace(self.before, component_purl=None)).status, VerificationStatus.FAILED)

    def test_inconsistent_no_match_and_purl_fail(self):
        for change in ("query", "purl"):
            after = deepcopy(self.after)
            result = after["match_runs"][0]["result"]
            if change == "query":
                result["osv_query"]["candidates"] = [{"cve_ids": [self.before.cve_id]}]
            else:
                result["component_purl"] = "pkg:pypi/different@2.0"
            self.assertEqual(self._verify(after=after).status, VerificationStatus.FAILED)
        after = deepcopy(self.after)
        other_cve = "CVE-2021-45046"
        result = after["match_runs"][0]["result"]
        result["status"] = "matched"
        result["osv_query"]["candidates"] = [{"cve_ids": [other_cve]}]
        result["matches"] = [{
            "cve": {"cve_id": other_cve, "source_url": "offline NVD", "fetched_at": COLLECTED},
            "osv_source_urls": ["offline OSV"], "osv_fetched_at": [COLLECTED],
            "kev_snapshot": {"source_url": "", "fetched_at": COLLECTED},
        }]
        self.assertEqual(self._verify(after=after).status, VerificationStatus.FAILED)

    def test_versionless_identity_keeps_qualifiers_namespace_and_subpath(self):
        self.assertEqual(package_identity("pkg:maven/org.example/sample@1?type=jar#lib"),
                         "pkg:maven/org.example/sample?type=jar#lib")
        self.assertNotEqual(package_identity("pkg:maven/org.example/sample@1"),
                            package_identity("pkg:maven/org.other/sample@1"))

    def test_diff_keeps_duplicate_occurrences_and_unresolved_components(self):
        before = self.before_components * 2 + [{"name": "unknown", "purl": None}]
        after = self.after["sbom"]["components"] + [{"name": "added", "version": "1", "purl": "pkg:pypi/added@1"}]
        diff = compare_sbom_versions(before, after)
        self.assertEqual(len(diff["version_changes"][0]["before"]), 2)
        self.assertEqual(len(diff["added"]), 1)
        self.assertEqual(len(diff["unresolved_before"]), 1)
        removed = compare_sbom_versions(before, [])
        self.assertEqual(len(removed["removed"]), 2)


if __name__ == "__main__":
    unittest.main()
