"""Offline selected-attempt comparisons without workflow or snapshot mutations."""

import json
import unittest
from copy import deepcopy
from dataclasses import replace

from core.verification.comparison import ComparisonService, compare_attempt
from database.models.verification import FunctionalStatus, ScannerStatus, VerificationStatus
from database.repositories.comparison_repository import ComparisonSourceError, SQLiteComparisonRepository
from tests.integration import test_verification as preparation
from tests.unit.test_vulnerability import fixture


class ComparisonTests(unittest.TestCase):
    _recommendation = preparation.VerificationTests._recommendation
    _plan = preparation.VerificationTests._plan
    _start = preparation.VerificationTests._start
    _inventory = preparation.VerificationTests._inventory
    _runs = preparation.VerificationTests._runs
    _functional = preparation.VerificationTests._functional
    _scanner = preparation.VerificationTests._scanner
    _record = preparation.VerificationTests._record

    def setUp(self):
        preparation.VerificationTests.setUp(self)
        self.sources = SQLiteComparisonRepository(self.connection)
        self.comparisons = ComparisonService(self.sources)

    def _compare(self, attempt, **changes):
        return self.comparisons.compare_finding(**{
            "asset_id": self.asset.id, "finding_id": self.finding.id,
            "remediation_id": self.plan.id, "verification_id": attempt.id, **changes})

    def _complete(self, *, key="comparison-1", matched=False, **record_changes):
        attempt = self._start(key)
        sbom, components, normalized = self._inventory()
        runs = self._runs(components, normalized, osv=fixture("osv_log4j_query.json") if matched else None)
        self._record(attempt, sbom, match_run_ids=runs, **record_changes)
        return self.verification_service.complete(attempt.id)

    def test_normal_comparison_has_changes_sources_and_distinct_severity(self):
        attempt = self._complete()
        result = self._compare(attempt)
        self.assertEqual(result["finding"]["cve_count"]["delta"], -1)
        self.assertEqual(result["finding"]["critical_cve_count"]["delta"], -1)
        self.assertEqual(result["finding"]["kev_cve_count"]["delta"], -1)
        self.assertEqual(result["asset"]["component_count"]["delta"], 0)
        self.assertEqual(result["asset"]["cve_count"]["after"]["value"], 0)
        self.assertEqual(result["finding"]["vulnerable_component_count"]["delta"], -1)
        self.assertIsNone(result["asset"]["cve_count"]["before"]["value"])
        self.assertFalse(result["asset"]["cve_count"]["comparable"])
        self.assertEqual(result["sbom_diff"], attempt.decision.sbom_diff)
        self.assertEqual(result["verification"]["status"], VerificationStatus.PASSED.value)
        self.assertIn("technical", result["finding"]["critical_cve_count"]["basis"])
        self.assertEqual(result["finding"]["risk_score"]["before"]["value"], attempt.before.risk_score)
        self.assertIsNone(result["finding"]["risk_score"]["after"]["value"])
        self.assertIsNone(result["finding"]["eol_component_count"]["after"]["value"])
        provenance = result["finding"]["cve_count"]["after"]["provenance"]
        self.assertEqual(provenance["recorded_at"], attempt.after.recorded_at)
        self.assertEqual(provenance["collected_at"], preparation.AFTER.isoformat())
        self.assertEqual(provenance["evidence_ids"]["verification_id"], attempt.id)
        self.assertTrue(provenance["matching_sources"])
        json.dumps(result)  # UI-independent, serializable result.

    def test_missing_evidence_never_becomes_zero_or_passed(self):
        attempt = self._start()
        in_progress = self._compare(attempt)
        self.assertEqual(in_progress["verification"]["status"], VerificationStatus.IN_PROGRESS.value)
        self.assertIsNone(in_progress["asset"]["component_count"]["after"]["value"])
        self.verification_service.record_after(attempt.id, asset_id=self.asset.id)
        failed = self.verification_service.complete(attempt.id)
        result = self._compare(failed)
        for metric in result["asset"].values():
            self.assertIsNone(metric["after"]["value"])
            self.assertIsNone(metric["delta"])
            self.assertTrue(metric["after"]["unknown_reason"])
        self.assertEqual(result["verification"]["status"], VerificationStatus.FAILED.value)
        self.assertEqual(result["verification"]["decision"]["reasons"], failed.decision.reasons)

    def test_scanner_for_one_cve_does_not_establish_asset_totals(self):
        attempt = self._start()
        sbom, _, _ = self._inventory()
        self._record(attempt, sbom, scanner_results=self._scanner(sbom))
        completed = self.verification_service.complete(attempt.id)
        result = self._compare(completed)
        self.assertEqual(result["finding"]["cve_count"]["after"]["value"], 0)
        self.assertIsNone(result["asset"]["cve_count"]["after"]["value"])
        self.assertIsNone(result["asset"]["vulnerable_component_count"]["after"]["value"])
        self.assertIn("scope", result["asset"]["cve_count"]["after"]["unknown_reason"])

    def test_partial_matching_and_duplicate_occurrences_are_not_full_coverage(self):
        attempt = self._start()
        raw = fixture("cyclonedx_log4j.json")["components"][0]
        raw.update(version="2.17.1", purl=raw["purl"].replace("2.14.1", "2.17.1"))
        second = {**raw, "bom-ref": "duplicate-2"}
        sbom, components, normalized = self._inventory(components=[raw, second])
        runs = self._runs(components, normalized)
        self._record(attempt, sbom, match_run_ids=runs[:1])
        completed = self.verification_service.complete(attempt.id)
        result = self._compare(completed)
        self.assertEqual(result["asset"]["component_count"]["after"]["value"], 2)
        self.assertIsNone(result["asset"]["cve_count"]["after"]["value"])
        self.assertEqual(result["sbom_diff"]["occurrence_count_changes"][0]["after_count"], 2)

    def test_duplicate_packages_count_occurrences_and_deduplicate_cves_findings(self):
        attempt = self._start()
        raw = fixture("cyclonedx_log4j.json")["components"][0]
        sbom, components, normalized = self._inventory(components=[raw, {**raw, "bom-ref": "duplicate-2"}])
        runs = self._runs(components, normalized, osv=fixture("osv_log4j_query.json"))
        for run in runs:
            self.finding_service.create_from_match_run(asset_id=self.asset.id, match_run_id=run)
        self._record(attempt, sbom, match_run_ids=runs)
        completed = self.verification_service.complete(attempt.id)
        result = self._compare(completed)
        self.assertEqual(result["asset"]["vulnerable_component_count"]["after"]["value"], 2)
        self.assertEqual(result["asset"]["cve_count"]["after"]["value"], 1)
        self.assertEqual(result["asset"]["critical_cve_count"]["after"]["value"], 1)
        self.assertEqual(result["asset"]["kev_cve_count"]["after"]["value"], 1)
        selection = (self.finding.id, self.plan.id, completed.id)
        aggregate = self.comparisons.compare_asset(asset_id=self.asset.id, selections=(selection, selection))
        self.assertEqual(len(aggregate["comparisons"]), 1)
        self.assertEqual(sum(aggregate["metrics"]["selected_finding_priority_counts"]["before"]["value"].values()), 1)
        self.assertEqual(len(self.findings.list_for_asset(self.asset.id)), 1)

    def test_failed_functional_result_keeps_original_decision_and_valid_inventory_counts(self):
        attempt = self._start()
        sbom, components, normalized = self._inventory()
        self._record(attempt, sbom, match_run_ids=self._runs(components, normalized),
                     functional_tests=self._functional(sbom, status=FunctionalStatus.FAILED))
        failed = self.verification_service.complete(attempt.id)
        result = self._compare(failed)
        self.assertEqual(result["verification"]["decision"]["reasons"], failed.decision.reasons)
        self.assertEqual(result["verification"]["status"], VerificationStatus.FAILED.value)
        self.assertEqual(result["asset"]["cve_count"]["after"]["value"], 0)
        self.assertEqual(result["finding"]["cve_count"]["delta"], -1)

    def test_scanner_contradiction_invalidates_counts_but_preserves_failed_reasons(self):
        attempt = self._start()
        sbom, components, normalized = self._inventory()
        self._record(attempt, sbom, match_run_ids=self._runs(components, normalized),
                     scanner_results=self._scanner(sbom, status=ScannerStatus.DETECTED))
        failed = self.verification_service.complete(attempt.id)
        result = self._compare(failed)
        self.assertIsNone(result["asset"]["cve_count"]["after"]["value"])
        self.assertIsNone(result["finding"]["cve_count"]["after"]["value"])
        self.assertEqual(result["verification"]["decision"]["reasons"], failed.decision.reasons)

    def test_repeated_attempts_are_explicit_and_past_results_remain_stable(self):
        first = self._complete(key="failed-first", matched=True)
        original = self._compare(first)
        second = self._complete(key="passed-second")
        self.assertEqual(self._compare(first), original)
        self.assertEqual(self._compare(first)["verification"]["status"], VerificationStatus.FAILED.value)
        self.assertEqual(self._compare(second)["verification"]["status"], VerificationStatus.PASSED.value)
        selections = ((self.finding.id, self.plan.id, first.id), (self.finding.id, self.plan.id, second.id))
        aggregate = self.comparisons.compare_asset(asset_id=self.asset.id, selections=selections)
        self.assertTrue(aggregate["aggregation_reason"])
        self.assertIsNone(aggregate["metrics"]["component_count"]["delta"])
        self.assertEqual(aggregate, self.comparisons.compare_asset(asset_id=self.asset.id, selections=selections[::-1]))

    def test_foreign_asset_finding_and_remediation_are_rejected(self):
        attempt = self._complete()
        for changes in ({"asset_id": self.other_asset.id}, {"finding_id": self.finding.id + 1}):
            with self.assertRaises(ComparisonSourceError):
                self._compare(attempt, **changes)
        plan = self._plan(self.finding, self.observation, self.recommendation, key="other-remediation")
        self.service.record_application(plan.id, **preparation.preparation.APPLICATION)
        with self.assertRaises(ComparisonSourceError):
            self._compare(attempt, remediation_id=plan.id)

    def test_invalid_ids_and_implicit_attempt_selection_are_rejected(self):
        attempt = self._complete()
        for value in (None, True, 0, -1, "1"):
            with self.assertRaises(ValueError):
                self._compare(attempt, verification_id=value)
        for selections in ((), [], ((self.finding.id, self.plan.id),)):
            with self.assertRaises(ValueError):
                self.comparisons.compare_asset(asset_id=self.asset.id, selections=selections)

    def test_comparison_does_not_write_and_returned_data_is_detached(self):
        attempt = self._complete()
        before = list(self.connection.iterdump())
        changes = self.connection.total_changes
        result = self._compare(attempt)
        original = deepcopy(result)
        result["snapshots"]["before_sbom"]["components"].clear()
        result["snapshots"]["after"]["match_runs"].clear()
        result["verification"]["decision"]["sbom_diff"].clear()
        self.assertEqual(self._compare(attempt), original)
        self.assertEqual(list(self.connection.iterdump()), before)
        self.assertEqual(self.connection.total_changes, changes)
        self.assertEqual(self.verification_service.get(attempt.id), attempt)

    def test_latest_mutable_source_rows_are_not_used_for_old_snapshot(self):
        attempt = self._complete()
        original = self._compare(attempt)
        # Phase 4/SBOM records lack append-only guards; Phase 9 copies must protect the comparison.
        with self.connection:
            self.connection.execute("UPDATE components SET version = '9.9' WHERE id = ?", (self.component_id,))
            self.connection.execute("UPDATE sboms SET raw_document = '{}' WHERE id = ?", (attempt.before_sbom["id"],))
            self.connection.execute("UPDATE vulnerability_match_runs SET osv_query_json = NULL WHERE id IN "
                                    "(SELECT run_id FROM vulnerability_match_evidence WHERE id = ?)",
                                    (attempt.before.match_evidence_id,))
        self.assertEqual(self._compare(attempt), original)

    def test_missing_cvss_does_not_zero_critical_count(self):
        attempt = self._start()
        sbom, components, normalized = self._inventory()
        runs = self._runs(components, normalized, osv=fixture("osv_log4j_query.json"))
        # Missing NVD metrics are supported Phase 4 evidence, although not risk inputs.
        row = self.connection.execute("SELECT id, evidence_json FROM vulnerability_match_evidence WHERE run_id = ?",
                                      (runs[0],)).fetchone()
        evidence = json.loads(row["evidence_json"])
        evidence["cve"]["cvss"] = None
        with self.connection:
            self.connection.execute("UPDATE vulnerability_match_evidence SET evidence_json = ? WHERE id = ?",
                                    (json.dumps(evidence), row["id"]))
        self._record(attempt, sbom, match_run_ids=runs)
        failed = self.verification_service.complete(attempt.id)
        result = self._compare(failed)
        self.assertEqual(result["asset"]["cve_count"]["after"]["value"], 1)
        self.assertIsNone(result["asset"]["critical_cve_count"]["after"]["value"])
        self.assertIsNone(result["finding"]["critical_cve_count"]["after"]["value"])

    def test_provenance_times_are_checked_even_for_failed_attempts(self):
        attempt = self._complete(sbom_collected_at="")
        result = self._compare(attempt)
        self.assertEqual(result["verification"]["status"], VerificationStatus.FAILED.value)
        self.assertIsNone(result["asset"]["component_count"]["after"]["value"])
        self.assertIsNone(result["asset"]["cve_count"]["after"]["value"])

    def test_corrupt_digest_and_foreign_test_ownership_are_rejected_by_pure_comparison(self):
        attempt = self._complete()
        source = self.sources.load(asset_id=self.asset.id, finding_id=self.finding.id,
                                   remediation_id=self.plan.id, verification_id=attempt.id)
        with self.assertRaisesRegex(ValueError, "digest"):
            compare_attempt(replace(source, verification=replace(attempt, after=replace(attempt.after, digest="invalid"))))
        payload = deepcopy(attempt.after.payload)
        payload["functional_tests"][0]["asset_id"] = self.other_asset.id
        with self.assertRaisesRegex(ValueError, "ownership"):
            compare_attempt(replace(source, verification=replace(attempt, after=replace(attempt.after, payload=payload))))

    def test_empty_after_inventory_scanner_only_never_claims_full_asset_zero(self):
        attempt = self._start()
        sbom, _, _ = self._inventory(components=[])
        self._record(attempt, sbom, scanner_results=self._scanner(sbom))
        completed = self.verification_service.complete(attempt.id)
        result = self._compare(completed)
        self.assertEqual(result["asset"]["component_count"]["after"]["value"], 0)
        self.assertEqual(result["finding"]["cve_count"]["delta"], -1)
        self.assertIsNone(result["asset"]["cve_count"]["after"]["value"])
        self.assertEqual(len(result["sbom_diff"]["removed"]), 1)

    def test_asset_aggregation_multiple_findings_counts_inventory_once(self):
        # Synthetic second CVE exists only in this offline test's structured input.
        second_id = "CVE-2099-9999"
        original_match = self.match.matches[0]
        second_match = replace(original_match, cve=replace(original_match.cve, cve_id=second_id),
                               kev=False, kev_entry=None)
        query = replace(self.match.osv_query, candidates=(replace(self.match.osv_query.candidates[0], cve_ids=(second_id,)),))
        run = self.matches.save(component_id=self.component_id, analysis_key="synthetic-second-cve",
                                result=replace(self.match, matches=(second_match,), osv_query=query))
        finding = self.finding_service.create_from_match_run(asset_id=self.asset.id, match_run_id=run.id)[0]
        self.mapping_service.map_finding(finding.id)
        observation = finding.observations[-1]
        recommendation = self.recommendation_service.create_for_observation(observation.id)
        plan = self._plan(finding, observation, recommendation, key="second-finding-change")
        applied = self.service.record_application(plan.id, **preparation.preparation.APPLICATION)
        first = self._start("first-finding")
        sbom, components, normalized = self._inventory()
        runs = self._runs(components, normalized)
        self._record(first, sbom, match_run_ids=runs)
        self.verification_service.complete(first.id)
        second = self._start("second-finding", remediation=applied)
        self._record(second, sbom, match_run_ids=runs)
        self.verification_service.complete(second.id)
        selections = ((self.finding.id, self.plan.id, first.id), (finding.id, plan.id, second.id))
        result = self.comparisons.compare_asset(asset_id=self.asset.id, selections=selections + selections)
        self.assertIsNone(result["aggregation_reason"])
        self.assertEqual(len(result["comparisons"]), 2)
        self.assertEqual(result["metrics"]["component_count"]["after"]["value"], 1)
        self.assertEqual(sum(result["metrics"]["selected_finding_priority_counts"]["before"]["value"].values()), 2)
        self.assertEqual(result, self.comparisons.compare_asset(asset_id=self.asset.id, selections=selections[::-1]))

    def test_before_duplicate_inventory_is_preserved_without_guessing_full_analysis(self):
        raw = fixture("cyclonedx_log4j.json")["components"][0]
        _, components, normalized = self._inventory(components=[raw, {**raw, "bom-ref": "before-duplicate"}])
        runs = self._runs(components, normalized, osv=fixture("osv_log4j_query.json"),
                          timestamp=preparation.preparation.NOW)
        finding = self.finding_service.create_from_match_run(asset_id=self.asset.id, match_run_id=runs[0])[0]
        self.mapping_service.map_finding(finding.id)
        observation = finding.observations[-1]
        recommendation = self.recommendation_service.create_for_observation(observation.id)
        plan = self._plan(finding, observation, recommendation, key="duplicate-before-change")
        applied = self.service.record_application(plan.id, **preparation.preparation.APPLICATION)
        attempt = self._start("duplicate-before-attempt", remediation=applied)
        sbom, components, normalized = self._inventory()
        self._record(attempt, sbom, match_run_ids=self._runs(components, normalized))
        completed = self.verification_service.complete(attempt.id)
        result = self._compare(completed, remediation_id=plan.id)
        self.assertEqual(result["asset"]["component_count"]["before"]["value"], 2)
        self.assertEqual(result["asset"]["component_count"]["delta"], -1)
        self.assertIsNone(result["asset"]["vulnerable_component_count"]["before"]["value"])
        self.assertEqual(len(result["sbom_diff"]["version_changes"][0]["before"]), 2)
        self.assertEqual(self.repository.get(plan.id).before, completed.before)

    def test_after_query_future_time_does_not_become_zero_count(self):
        attempt = self._start()
        sbom, components, normalized = self._inventory()
        runs = self._runs(components, normalized, timestamp=preparation.RECORDED + preparation.timedelta(hours=1))
        self._record(attempt, sbom, match_run_ids=runs)
        completed = self.verification_service.complete(attempt.id)
        result = self._compare(completed)
        self.assertEqual(result["verification"]["status"], VerificationStatus.FAILED.value)
        self.assertIsNone(result["asset"]["cve_count"]["after"]["value"])
        self.assertIsNone(result["finding"]["cve_count"]["delta"])

    def test_corrupt_recommendation_fact_digest_is_rejected(self):
        attempt = self._complete()
        row = self.connection.execute("SELECT input_json FROM recommendations WHERE id = ?",
                                      (self.recommendation.id,)).fetchone()
        facts = json.loads(row["input_json"])
        facts["cvss"] = 1.0
        with self.connection:
            self.connection.execute("UPDATE recommendations SET input_json = ? WHERE id = ?",
                                    (json.dumps(facts), self.recommendation.id))
        with self.assertRaisesRegex(ComparisonSourceError, "digest"):
            self._compare(attempt)

    def test_missing_component_version_keeps_none_and_explanation(self):
        attempt = self._start()
        raw = fixture("cyclonedx_log4j.json")["components"][0]
        raw.pop("version")
        raw.pop("purl")
        sbom, _, _ = self._inventory(components=[raw])
        self._record(attempt, sbom)
        completed = self.verification_service.complete(attempt.id)
        result = self._compare(completed)
        version = result["asset"]["component_versions"]["after"]["value"][0]
        self.assertIsNone(version["version"])
        self.assertTrue(version["version_unknown_reason"])
        self.assertIsNone(version["purl"])
        self.assertTrue(version["purl_unknown_reason"])
        self.assertEqual(result["asset"]["component_count"]["after"]["value"], 1)
        self.assertIsNone(result["asset"]["cve_count"]["after"]["value"])


if __name__ == "__main__":
    unittest.main()
