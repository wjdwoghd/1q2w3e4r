"""Offline HTTP/UI contracts reuse Phase 9/10 evidence preparation and policies."""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from app.main import create_app
from app.dashboard.client import DashboardAPIError, DashboardClient
from app.dashboard.presentation import display_value, metric_rows
from core.dashboard.service import DashboardService
from database.database import initialize_database
from database.models.verification import FunctionalStatus
from database.repositories.dashboard_repository import open_dashboard_database
from tests.integration import test_comparison as preparation
from tests.unit.test_vulnerability import fixture

ROOT = Path(__file__).resolve().parents[2]


class DashboardTests(unittest.TestCase):
    _recommendation = preparation.ComparisonTests._recommendation
    _plan = preparation.ComparisonTests._plan
    _start = preparation.ComparisonTests._start
    _inventory = preparation.ComparisonTests._inventory
    _runs = preparation.ComparisonTests._runs
    _functional = preparation.ComparisonTests._functional
    _scanner = preparation.ComparisonTests._scanner
    _record = preparation.ComparisonTests._record
    _complete = preparation.ComparisonTests._complete

    def setUp(self):
        preparation.ComparisonTests.setUp(self)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "execution with spaces.db"
        self.empty = Path(directory.name) / "empty.db"
        with closing(sqlite3.connect(self.empty)) as connection:
            initialize_database(connection)
        self.client = create_app({"run-a": self.path, "empty-run": self.empty}).test_client()
        self.reads = DashboardService(self.connection)

    def publish(self):
        with closing(sqlite3.connect(self.path)) as connection:
            self.connection.backup(connection)

    def get(self, resource, **changes):
        return self.client.get("/api/" + resource, query_string={"database": "run-a", **changes})

    def ids(self, attempt):
        return dict(asset_id=self.asset.id, finding_id=self.finding.id,
                    remediation_id=self.plan.id, verification_id=attempt.id)

    def test_lists_details_and_structured_data(self):
        attempt = self._complete()
        self.publish()
        self.assertEqual(len(self.client.get("/api/databases").json), 2)
        self.assertEqual(len(self.get("services").json), 1)
        self.assertEqual(len(self.get("assets", service_id=1).json), 2)
        self.assertIn("context", self.get("asset", asset_id=self.asset.id).json)
        sboms = self.get("sboms", asset_id=self.asset.id).json
        self.assertEqual(len(sboms), 2)
        sbom = self.get("sbom", asset_id=self.asset.id, sbom_id=sboms[0]["id"]).json
        self.assertEqual(sbom["components"][0]["id"], self.component_id)
        self.assertIn("raw_document", sbom)
        self.assertEqual(len(self.get("findings", asset_id=self.asset.id).json), 1)
        scope = dict(asset_id=self.asset.id, finding_id=self.finding.id)
        finding = self.get("finding", **scope).json
        self.assertIn("risk_reasons", finding["observations"][0])
        self.assertIn("match_run", finding["observations"][0])
        self.assertTrue(finding["control_mappings"])
        self.assertEqual(self.get("recommendations", **scope).json[0]["id"], self.recommendation.id)
        self.assertEqual(self.get("remediations", **scope).json[0]["id"], self.plan.id)
        self.assertEqual(self.get("remediation", **scope, remediation_id=self.plan.id).json["status"], "applied")
        result = self.get("attempt", **self.ids(attempt))
        self.assertEqual(result.status_code, 200)
        expected = self.comparisons.compare_finding(**self.ids(attempt))
        self.assertEqual(result.json["comparison"], json.loads(json.dumps(expected)))
        self.assertEqual(result.json["functional_tests"][0]["status"], "passed")

    def test_explicit_repeated_attempts_keep_original_failed_and_passed(self):
        first = self._complete(key="failed-first", matched=True)
        second = self._complete(key="passed-second")
        self.publish()
        rows = self.get("attempts", asset_id=self.asset.id, finding_id=self.finding.id,
                        remediation_id=self.plan.id).json
        self.assertEqual([row["id"] for row in rows], [first.id, second.id])
        self.assertEqual([row["attempt_key"] for row in rows], ["failed-first", "passed-second"])
        for attempt in (first, second):
            result = self.get("attempt", **self.ids(attempt)).json
            self.assertEqual(result["status"], attempt.status.value)
            self.assertEqual(result["comparison"]["verification"]["decision"]["reasons"], list(attempt.decision.reasons))
        ids = self.ids(first)
        del ids["verification_id"]
        self.assertEqual(self.get("attempt", **ids).status_code, 400)

    def test_foreign_asset_finding_remediation_and_missing_ids(self):
        attempt = self._complete()
        _, components, normalized = self._inventory(version="2.14.1", asset_id=self.other_asset.id)
        run = self._runs(components, normalized, osv=fixture("osv_log4j_query.json"))[0]
        other_finding = self.finding_service.create_from_match_run(asset_id=self.other_asset.id, match_run_id=run)[0]
        other_plan = self._plan(self.finding, self.observation, self.recommendation, key="other-plan")
        # Same Finding, different Remediation must still reject the selected attempt.
        self.publish()
        for changes in ({"asset_id": self.other_asset.id}, {"finding_id": other_finding.id},
                        {"remediation_id": other_plan.id}):
            response = self.get("attempt", **{**self.ids(attempt), **changes})
            self.assertEqual(response.status_code, 400, response.json)
            self.assertTrue(response.json["error"]["message"])
        for key in self.ids(attempt):
            response = self.get("attempt", **{**self.ids(attempt), key: 99999})
            self.assertEqual(response.status_code, 404, response.json)
        foreign = self.get("sbom", asset_id=self.other_asset.id, sbom_id=attempt.before_sbom["id"])
        self.assertEqual(foreign.status_code, 400)
        self.assertEqual(self.get("finding", asset_id=self.asset.id,
                                  finding_id=other_finding.id).status_code, 400)

    def test_invalid_selection_and_database_aliases(self):
        self.publish()
        self.assertEqual(self.client.get("/api/services").status_code, 400)
        self.assertEqual(self.get("services", database="C:/arbitrary.db").status_code, 400)
        for value in ("", "0", "-1", "true", "1.5", "１", "99999999999999999999"):
            self.assertEqual(self.get("asset", asset_id=value).status_code, 400)
        response = self.client.get("/api/asset?database=run-a&asset_id=1&asset_id=2")
        self.assertEqual(response.status_code, 400)

    def test_none_and_missing_evidence_remain_unknown_in_progress_and_failed(self):
        attempt = self._start()
        self.publish()
        detail = self.get("attempt", **self.ids(attempt)).json
        self.assertEqual(detail["status"], "verification_in_progress")
        self.assertIsNone(detail["functional_tests"])
        self.assertIsNone(detail["comparison"]["verification"]["decision"])
        self.verification_service.record_after(attempt.id, asset_id=self.asset.id)
        failed = self.verification_service.complete(attempt.id)
        self.publish()
        result = self.get("attempt", **self.ids(failed)).json
        self.assertEqual(result["status"], "verification_failed")
        for metric in result["comparison"]["asset"].values():
            self.assertIsNone(metric["after"]["value"])
            self.assertIsNone(metric["delta"])
            self.assertTrue(metric["after"]["unknown_reason"])
        rows = metric_rows(result["comparison"]["asset"])
        self.assertTrue(all(row["After"] == "미확인" for row in rows))

    def test_after_risk_eol_and_asset_before_totals_not_synthesized(self):
        attempt = self._complete()
        self.publish()
        result = self.get("attempt", **self.ids(attempt)).json
        comparison = result["comparison"]
        for name in ("risk_score", "finding_priority_counts", "eol_component_count"):
            self.assertIsNone(comparison["finding"][name]["after"]["value"])
        self.assertIsNone(comparison["asset"]["cve_count"]["before"]["value"])
        self.assertEqual(comparison["asset"]["cve_count"]["after"]["value"], 0)
        self.assertIsNone(comparison["asset"]["cve_count"]["delta"])
        self.assertEqual(display_value(None), "미확인")
        self.assertEqual(display_value(0), "0")
        self.assertEqual(display_value(False), "False")

    def test_partial_scope_and_duplicate_components_are_preserved(self):
        attempt = self._start()
        raw = fixture("cyclonedx_log4j.json")["components"][0]
        sbom, components, normalized = self._inventory(components=[raw, {**raw, "bom-ref": "duplicate"}])
        runs = self._runs(components, normalized, osv=fixture("osv_log4j_query.json"))
        for run in runs:
            self.finding_service.create_from_match_run(asset_id=self.asset.id, match_run_id=run)
        self._record(attempt, sbom, match_run_ids=runs[:1])
        self.verification_service.complete(attempt.id)
        self.publish()
        result = self.get("attempt", **self.ids(attempt)).json
        self.assertEqual(result["comparison"]["asset"]["component_count"]["after"]["value"], 2)
        self.assertIsNone(result["comparison"]["asset"]["cve_count"]["after"]["value"])
        self.assertIn("scope", result["comparison"]["asset"]["cve_count"]["after"]["unknown_reason"])
        self.assertEqual(len(self.get("findings", asset_id=self.asset.id).json), 1)
        self.assertEqual(len(self.get("sbom", asset_id=self.asset.id, sbom_id=sbom.id).json["components"]), 2)
        self.assertEqual(result["comparison"]["sbom_diff"]["occurrence_count_changes"][0]["after_count"], 2)

    def test_failed_functional_result_is_visible_even_with_no_cve_matches(self):
        attempt = self._start()
        sbom, components, normalized = self._inventory()
        self._record(attempt, sbom, match_run_ids=self._runs(components, normalized),
                     functional_tests=self._functional(sbom, status=FunctionalStatus.FAILED))
        failed = self.verification_service.complete(attempt.id)
        self.publish()
        result = self.get("attempt", **self.ids(attempt)).json
        self.assertEqual(result["status"], "verification_failed")
        self.assertEqual(result["functional_tests"][0]["status"], "failed")
        self.assertEqual(result["comparison"]["verification"]["decision"]["reasons"], list(failed.decision.reasons))

    def test_full_duplicate_analysis_counts_occurrences_but_not_findings_twice(self):
        attempt = self._start()
        raw = fixture("cyclonedx_log4j.json")["components"][0]
        sbom, components, normalized = self._inventory(components=[raw, {**raw, "bom-ref": "duplicate"}])
        runs = self._runs(components, normalized, osv=fixture("osv_log4j_query.json"))
        for run in runs:
            self.finding_service.create_from_match_run(asset_id=self.asset.id, match_run_id=run)
        self._record(attempt, sbom, match_run_ids=runs)
        self.verification_service.complete(attempt.id)
        self.publish()
        detail = self.get("attempt", **self.ids(attempt)).json
        self.assertEqual(detail["comparison"]["asset"]["vulnerable_component_count"]["after"]["value"], 2)
        self.assertEqual(detail["comparison"]["asset"]["cve_count"]["after"]["value"], 1)
        counts = detail["asset_comparison"]["metrics"]["selected_finding_priority_counts"]["before"]["value"]
        self.assertEqual(sum(counts.values()), 1)

    def test_recorded_after_without_completion_keeps_progress_status(self):
        attempt = self._start()
        sbom, components, normalized = self._inventory()
        self._record(attempt, sbom, match_run_ids=self._runs(components, normalized))
        self.publish()
        detail = self.get("attempt", **self.ids(attempt)).json
        self.assertEqual(detail["status"], "verification_in_progress")
        self.assertIsNone(detail["comparison"]["verification"]["decision"])
        self.assertEqual(detail["functional_tests"][0]["status"], "passed")

    def test_past_attempt_does_not_use_changed_mutable_sbom_or_matching_rows(self):
        attempt = self._complete()
        self.publish()
        original = self.get("attempt", **self.ids(attempt)).json
        with self.connection:
            self.connection.execute("UPDATE sboms SET raw_document='{}'")
            self.connection.execute("UPDATE components SET version='changed'")
            self.connection.execute("UPDATE vulnerability_match_runs SET osv_query_json=NULL")
        self.publish()
        result = self.get("attempt", **self.ids(attempt))
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json, original)

    def test_read_queries_do_not_mutate_database_snapshots_or_decisions(self):
        attempt = self._complete()
        self.publish()
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        original = list(self.connection.iterdump())
        with patch("core.risk.engine.calculate_risk_priorities", side_effect=AssertionError("risk recomputed")), \
             patch("core.verification.service.verify_remediation", side_effect=AssertionError("decision recomputed")), \
             patch("core.consulting.recommender.RecommendationService.create_for_observation", side_effect=AssertionError("AI invoked")):
            result = self.get("attempt", **self.ids(attempt))
            self.assertEqual(result.status_code, 200)
            self.get("finding", asset_id=self.asset.id, finding_id=self.finding.id)
            self.get("sbom", asset_id=self.asset.id, sbom_id=attempt.before_sbom["id"])
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), digest)
        self.assertEqual(list(self.connection.iterdump()), original)
        self.assertEqual(self.verification_service.get(attempt.id), attempt)
        with open_dashboard_database(self.path) as connection:
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("UPDATE findings SET status='open'")

    def test_no_write_http_methods_or_workflow_routes(self):
        self.publish()
        for method in ("post", "put", "patch", "delete"):
            response = getattr(self.client, method)("/api/attempt", json=self.ids(self._start()))
            self.assertEqual(response.status_code, 405)
        for resource in ("scan", "complete", "apply", "report", "accept"):
            self.assertEqual(self.get(resource).status_code, 404)

    def test_empty_database_missing_file_and_old_schema(self):
        self.assertEqual(self.get("services", database="empty-run").json, [])
        missing = self.path.parent / "does-not-exist.db"
        client = create_app({"missing": missing}).test_client()
        self.assertEqual(client.get("/api/services?database=missing").status_code, 503)
        self.assertFalse(missing.exists())
        old = self.path.parent / "old.db"
        with closing(sqlite3.connect(old)):
            pass
        before = old.read_bytes()
        client = create_app({"old": old}).test_client()
        response = client.get("/api/services?database=old")
        self.assertEqual(response.status_code, 503)
        self.assertIn("Phase 9", response.json["error"]["message"])
        self.assertEqual(old.read_bytes(), before)

    def _screen(self):
        from streamlit.testing.v1 import AppTest

        def api_get(_client, resource, **scope):
            response = self.client.get("/api/" + resource, query_string=scope)
            if response.status_code >= 400:
                raise DashboardAPIError(response.json["error"]["message"])
            return response.json

        patcher = patch.object(DashboardClient, "get", api_get)
        patcher.start()
        self.addCleanup(patcher.stop)
        return AppTest.from_file(str(ROOT / "app/dashboard/Home.py"), default_timeout=30).run()

    def _select_screen(self, screen, key, index=0):
        widget = screen.selectbox(key=key)
        value = widget.options[index] if key == "database" else int(widget.options[index].split(" · ")[0])
        widget.select(value).run()
        self.assertFalse(screen.exception, screen.exception)

    def test_screen_explicit_attempt_selection_and_parent_reset(self):
        first = self._complete(key="failed", matched=True)
        self._complete(key="passed")
        self.publish()
        digest = self.path.read_bytes()
        screen = self._screen()
        self.assertFalse(screen.exception)
        self.assertIsNone(screen.selectbox(key="database").value)
        for key in ("database", "service", "asset", "finding", "remediation"):
            self._select_screen(screen, key)
        self.assertIsNone(screen.selectbox(key="verification").value)
        self._select_screen(screen, "verification")
        self.assertIn(first.status.value, [item.value for item in screen.metric])
        self._select_screen(screen, "verification", 1)
        self.assertIn("verification_passed", [item.value for item in screen.metric])
        self._select_screen(screen, "asset", 1)
        self.assertFalse(any(item.key == "verification" for item in screen.selectbox))
        self._select_screen(screen, "asset", 0)
        self.assertIsNone(screen.selectbox(key="finding").value)
        self._select_screen(screen, "database", 1)
        self.assertTrue(any("데이터가 없습니다" in item.value for item in screen.info))
        self._select_screen(screen, "database", 0)
        self.assertIsNone(screen.selectbox(key="service").value)
        self.assertEqual(self.path.read_bytes(), digest)

    def test_screen_in_progress_unknown_metrics_and_api_error(self):
        self._start()
        self.publish()
        screen = self._screen()
        for key in ("database", "service", "asset", "finding", "remediation", "verification"):
            self._select_screen(screen, key)
        self.assertIn("verification_in_progress", [item.value for item in screen.metric])
        self.assertTrue(any("진행 중" in item.value for item in screen.info))
        frames = [item.value for item in screen.dataframe]
        self.assertTrue(any("After" in frame and "미확인" in frame["After"].values for frame in frames))
        with patch.object(DashboardClient, "get", side_effect=DashboardAPIError("API unavailable")):
            screen.run()
            self.assertFalse(screen.exception)
            self.assertEqual(screen.error[0].value, "API unavailable")


if __name__ == "__main__":
    unittest.main()
