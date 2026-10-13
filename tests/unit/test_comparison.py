"""Aggregation scope, unknown values and occurrence-preserving differences."""

import unittest

from core.verification.comparison import compare_values, _critical_count, _kev_count
from core.sbom.diff import compare_sbom_versions


class ComparisonUnitTests(unittest.TestCase):
    def _value(self, value, scope="selected-cve", reason=None):
        return {"value": value, "scope": scope, "unknown_reason": reason, "provenance": {}}

    def test_scope_mismatch_does_not_subtract(self):
        result = compare_values(self._value(1, "one-cve"), self._value(0, "whole-asset"), basis="CVE count")
        self.assertIsNone(result["delta"])
        self.assertFalse(result["comparable"])
        self.assertIn("scopes differ", result["comparison_reason"])

    def test_unknown_values_retain_reasons(self):
        result = compare_values(self._value(1), self._value(None, reason="analysis missing"), basis="CVE count")
        self.assertIsNone(result["delta"])
        self.assertEqual(result["comparison_reason"], "analysis missing")

    def test_delta_direction_and_numeric_boundary(self):
        self.assertEqual(compare_values(self._value(4), self._value(1), basis="occurrences")["delta"], -3)
        self.assertIsNone(compare_values(self._value(["1.0"]), self._value(["2.0"]), basis="versions")["delta"])
        matches = lambda score: [{"cve": {"cvss": {"score": score}}, "kev": True}]
        self.assertEqual(_critical_count({"CVE-A": matches(8.9)}), 0)
        self.assertEqual(_critical_count({"CVE-A": matches(9.0)}), 1)
        self.assertIsNone(_critical_count({"CVE-A": matches(None)}))
        self.assertIsNone(_critical_count({"CVE-A": matches(8.9) + matches(9.8)}))
        self.assertEqual(_kev_count({"CVE-A": matches(9.8) * 2}), 1)
        self.assertIsNone(_kev_count({"CVE-A": matches(9.8) + [{"kev": False}]}))

    def test_diff_add_remove_version_and_count_without_merging_occurrences(self):
        component = lambda purl, version: {"purl": purl, "version": version}
        before = [component("pkg:pypi/old@1", "1"), component("pkg:pypi/same@1", "1")] * 2
        after = [component("pkg:pypi/new@1", "1"), component("pkg:pypi/same@2", "2")]
        result = compare_sbom_versions(before, after)
        self.assertEqual(len(result["removed"]), 2)
        self.assertEqual(len(result["added"]), 1)
        self.assertEqual(len(result["version_changes"][0]["before"]), 2)
        self.assertEqual(result["occurrence_count_changes"][0]["before_count"], 2)


if __name__ == "__main__":
    unittest.main()
