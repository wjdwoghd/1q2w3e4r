"""Offline contract and boundary tests for Phase 5."""

import unittest
from dataclasses import replace
from datetime import datetime, timezone

from core.assets.context import AssetContext, AssetContextError
from core.risk.engine import RiskInputError, calculate_risk_priorities
from core.risk.priority import priority_for_score
from core.vulnerability.cve_client import CVERecord
from core.vulnerability.cvss import CVSSMetric
from core.vulnerability.kev_client import KEVEntry, KEVSnapshot
from core.vulnerability.matcher import MatchResult, MatchStatus, MatchedCVE

NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
CVE_ID = "CVE-2021-44228"
PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def context(**changes):
    values = dict(name="Internet Banking API", environment="production",
                  internet_exposed=True, business_criticality="critical",
                  customer_information=True, credit_information=False,
                  patch_status="current", vendor="Internal", owner="Digital Banking")
    return AssetContext.create(**{**values, **changes})


def result(*, score=9.8, kev=True, status=MatchStatus.MATCHED, cvss_missing=False):
    entry = KEVEntry(CVE_ID, "2021-12-10", "https://cisa.test/kev", "1", "2026-10-10", NOW)
    snapshot = KEVSnapshot({CVE_ID: entry} if kev else {}, "https://cisa.test/kev",
                           "1", "2026-10-10", NOW)
    metric = None if cvss_missing else CVSSMetric("3.1", score, "CVSS:3.1/...", "NVD", "Primary")
    cve = CVERecord(CVE_ID, metric, (), "https://nvd.test/cve", NOW, None, None, None)
    match = MatchedCVE(cve, ("GHSA-test",), ("https://osv.test/record",),
                       (NOW.isoformat(),), kev, entry if kev else None, snapshot)
    return MatchResult(status, PURL, (match,) if status is MatchStatus.MATCHED else (), ())


class RiskEngineTests(unittest.TestCase):
    def test_determinism_and_explanation(self):
        first = calculate_risk_priorities(result(), context())
        self.assertEqual(first, calculate_risk_priorities(result(), context()))
        risk = first[0]
        self.assertEqual((risk.cvss_score, risk.score, risk.priority), (9.8, 95, "P1"))
        self.assertEqual(sum(rule.points for rule in risk.applied_rules), risk.score)
        self.assertEqual([rule.factor for rule in risk.applied_rules],
                         ["cvss", "kev", "internet_exposure", "production", "business_criticality"])
        self.assertIn("eol", risk.unassessed_factors)
        self.assertEqual(risk.reasons[0], "CVSS >= 9.0: +30")
        self.assertEqual(risk.rule_version, "1.0")

    def test_priority_boundaries(self):
        for score, expected in ((0, "P4"), (19, "P4"), (20, "P3"), (49, "P3"),
                                (50, "P2"), (79, "P2"), (80, "P1")):
            with self.subTest(score=score):
                self.assertEqual(priority_for_score(score), expected)
        for invalid in (-1, 1.5, True, None):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                priority_for_score(invalid)

    def test_factor_effects(self):
        base = context(environment="development", internet_exposed=False,
                       business_criticality="low", patch_status="current")
        cases = ((result(kev=False), base, 30),
                 (result(kev=True), base, 60),
                 (result(kev=False), context(environment="development", internet_exposed=True,
                                             business_criticality="low"), 45),
                 (result(kev=False), context(environment="development", internet_exposed=False,
                                             business_criticality="critical"), 40),
                 (result(kev=False), context(environment="development", internet_exposed=False,
                                             business_criticality="high"), 35),
                 (result(kev=False), context(environment="development", internet_exposed=False,
                                             business_criticality="low", patch_status="overdue",
                                             credit_information=True), 40))
        for match, asset, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(calculate_risk_priorities(match, asset)[0].score, expected)

    def test_cvss_bands_and_zero_score(self):
        asset = context(environment="development", internet_exposed=False,
                        business_criticality="low")
        for cvss, expected in ((0.0, 0), (3.9, 0), (4.0, 10), (6.9, 10),
                               (7.0, 20), (8.9, 20), (9.0, 30)):
            with self.subTest(cvss=cvss):
                risk = calculate_risk_priorities(result(score=cvss, kev=False), asset)[0]
                self.assertEqual(risk.score, expected)
                self.assertEqual(risk.applied_rules[0].points, expected)

    def test_non_matches_are_rejected(self):
        for status in (MatchStatus.ERROR, MatchStatus.AMBIGUOUS,
                       MatchStatus.UNMATCHED, MatchStatus.NO_MATCH):
            with self.subTest(status=status), self.assertRaises(RiskInputError):
                calculate_risk_priorities(result(status=status), context())
        with self.assertRaises(RiskInputError):
            calculate_risk_priorities(replace(result(), matches=()), context())

    def test_missing_cvss_and_unverified_kev_are_rejected(self):
        with self.assertRaisesRegex(RiskInputError, "CVSS"):
            calculate_risk_priorities(result(cvss_missing=True), context())
        original = result()
        match = original.matches[0]
        for changed in (replace(match, kev_snapshot=None),
                        replace(match, kev=False),
                        replace(match, kev_entry=None),
                        *(replace(match, cve=replace(match.cve,
                           cvss=replace(match.cve.cvss, score=score)))
                          for score in (float("nan"), float("inf"), -0.1, 10.1, True))):
            with self.subTest(changed=changed), self.assertRaises(RiskInputError):
                calculate_risk_priorities(replace(original, matches=(changed,)), context())

    def test_unknown_patch_status_is_explicit_and_invalid_context_rejected(self):
        risk = calculate_risk_priorities(result(), context(patch_status="unknown"))[0]
        self.assertEqual(risk.unassessed_factors, ("eol", "patch_status"))
        self.assertFalse(any(rule.factor == "patch_status" for rule in risk.applied_rules))
        with self.assertRaises(RiskInputError):
            calculate_risk_priorities(result(), None)
        with self.assertRaises(AssetContextError):
            context(internet_exposed=None)

    def test_multiple_cves_are_scored_separately_and_duplicates_rejected(self):
        original = result()
        second = replace(original.matches[0],
                         cve=replace(original.matches[0].cve, cve_id="CVE-2021-45046"),
                         kev=False, kev_entry=None,
                         kev_snapshot=replace(original.matches[0].kev_snapshot, entries={}))
        both = replace(original, matches=(original.matches[0], second))
        risks = calculate_risk_priorities(both, context())
        self.assertEqual([(risk.cve_id, risk.score) for risk in risks],
                         [(CVE_ID, 95), ("CVE-2021-45046", 65)])
        with self.assertRaisesRegex(RiskInputError, "duplicate"):
            calculate_risk_priorities(replace(original, matches=(original.matches[0],) * 2), context())
