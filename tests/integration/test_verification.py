"""Offline Phase 9 workflow, provenance, immutable history and database tests."""

import json
import sqlite3
import unittest
from dataclasses import replace
from datetime import timedelta

from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom
from core.verification.service import VerificationInputError, VerificationService
from core.vulnerability.matcher import match_component_to_cves
from database.database import DatabaseMigrationRequiredError, connect_database, initialize_database
from database.models.finding import FindingStatus
from database.models.verification import FunctionalEvidence, FunctionalStatus, ScannerEvidence, ScannerStatus, VerificationStatus
from database.repositories.remediation_repository import SQLiteRemediationRepository
from database.repositories.sbom_repository import SQLiteSBOMRepository
from database.repositories.verification_repository import SQLiteVerificationRepository, VerificationRepositoryError
from tests.integration import test_remediation as preparation
from tests.unit.test_vulnerability import StubTransport, clients, fixture

AFTER = preparation.NOW + timedelta(hours=1)
RECORDED = AFTER + timedelta(hours=1)


class VerificationTests(unittest.TestCase):
    _recommendation = preparation.RemediationTests._recommendation
    _plan = preparation.RemediationTests._plan

    def setUp(self):
        preparation.RemediationTests.setUp(self)
        self.verifications = SQLiteVerificationRepository(self.connection, lambda: RECORDED)
        self.verification_service = VerificationService(
            findings=self.findings, recommendations=self.recommendations, remediations=self.repository,
            matches=self.matches, verifications=self.verifications)
        self.finding, self.observation, self.recommendation = self._recommendation()
        self.plan = self._plan(self.finding, self.observation, self.recommendation)
        self.applied = self.service.record_application(self.plan.id, **preparation.APPLICATION)

    def _start(self, key="verify-1", remediation=None):
        return self.verification_service.start(
            remediation_id=(remediation or self.applied).id, asset_id=self.asset.id,
            attempt_key=key, required_functional_tests=("banking-api-smoke",))

    def _inventory(self, *, version="2.17.1", components=None, asset_id=None):
        raw = fixture("cyclonedx_log4j.json")
        if components is not None:
            raw["components"] = components
        else:
            component = raw["components"][0]
            component.update(version=version, purl=component["purl"].replace("2.14.1", version),
                             **{"bom-ref": "after-component"})
        document = json.dumps(raw)
        parsed = parse_sbom(document)
        normalized = normalize_components(parsed.components)
        repository = SQLiteSBOMRepository(self.connection)
        sbom = repository.save(asset_id=asset_id or self.asset.id, source="offline-generated-SBOM",
                               raw_document=document, parsed=parsed, normalized=normalized)
        return sbom, repository.list_components(sbom.id), normalized

    def _runs(self, components, normalized, *, osv=None, timestamp=AFTER, error=None):
        transport = StubTransport(osv={"vulns": []} if osv is None else osv,
                                  nvd=fixture("nvd_log4j_cve.json"), kev=fixture("cisa_kev_log4j.json"), error=error)
        dependencies = clients(transport)
        for client in dependencies.values():
            client.clock = lambda: timestamp
        result_ids = []
        for component, normalized_component in zip(components, normalized.components):
            result = match_component_to_cves(normalized_component, **dependencies)
            result_ids.append(self.matches.save(component_id=component.id,
                                                analysis_key=f"after-{component.id}-{len(result_ids)}",
                                                result=result).id)
        return tuple(result_ids)

    def _functional(self, sbom, **changes):
        evidence = FunctionalEvidence(self.asset.id, sbom.id, "banking-api-smoke", FunctionalStatus.PASSED,
                                      "offline functional runner", "job-9/test-results", AFTER.isoformat())
        return (replace(evidence, **changes),)

    def _scanner(self, sbom, **changes):
        evidence = ScannerEvidence(self.asset.id, sbom.id, self.finding.cve_id, ScannerStatus.NOT_DETECTED,
                                   "offline scanner", "scan-job-9", AFTER.isoformat())
        return (replace(evidence, **changes),)

    def _record(self, attempt, sbom, *, match_run_ids=(), functional_tests=None, scanner_results=(), **changes):
        data = dict(asset_id=self.asset.id, sbom_id=sbom.id, sbom_collected_at=AFTER.isoformat(),
                    sbom_reference="build-9/sbom.json", match_run_ids=match_run_ids,
                    functional_tests=self._functional(sbom) if functional_tests is None else functional_tests,
                    scanner_results=scanner_results)
        return self.verification_service.record_after(attempt.id, **{**data, **changes})

    def test_passed_matching_data_flow_and_history(self):
        attempt = self._start()
        self.assertEqual(self.findings.get(self.finding.id).status, FindingStatus.VERIFICATION_IN_PROGRESS)
        sbom, components, normalized = self._inventory()
        self._record(attempt, sbom, match_run_ids=self._runs(components, normalized))
        result = self.verification_service.complete(attempt.id)
        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertEqual(result.before, self.applied.before)
        self.assertEqual(result.application, self.applied.application)
        self.assertEqual(result.after.payload["sbom"]["source"], "offline-generated-SBOM")
        self.assertEqual(result.decision.rule_version, "verification-1.0")
        self.assertTrue(result.decision.sbom_diff["version_changes"])
        self.assertEqual([item.status for item in self.findings.get(self.finding.id).status_history],
                         [FindingStatus.OPEN, FindingStatus.RECOMMENDATION_CREATED,
                          FindingStatus.REMEDIATION_APPLIED, FindingStatus.VERIFICATION_IN_PROGRESS,
                          FindingStatus.VERIFICATION_PASSED])
        self.assertEqual(self.verification_service.list_for_remediation(self.plan.id), (result,))

    def test_component_removal_requires_independent_cve_scan(self):
        sbom, _, _ = self._inventory(components=[])
        attempt = self._start()
        self._record(attempt, sbom)
        self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)
        second = self._start("verify-2")
        self._record(second, sbom, scanner_results=self._scanner(sbom))
        result = self.verification_service.complete(second.id)
        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertTrue(result.decision.sbom_diff["removed"])

    def test_version_change_alone_and_unchanged_version_fail(self):
        for index, version in enumerate(("2.17.1", "2.14.1")):
            with self.subTest(version=version):
                attempt = self._start(f"verify-{index}")
                sbom, _, _ = self._inventory(version=version)
                self._record(attempt, sbom, scanner_results=self._scanner(sbom) if index else ())
                self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)

    def test_existing_cve_and_contradictory_scanner_fail(self):
        attempt = self._start()
        sbom, components, normalized = self._inventory()
        runs = self._runs(components, normalized, osv=fixture("osv_log4j_query.json"))
        self._record(attempt, sbom, match_run_ids=runs, scanner_results=self._scanner(sbom))
        result = self.verification_service.complete(attempt.id)
        self.assertEqual(result.status, VerificationStatus.FAILED)
        self.assertTrue(any("remains detected" in reason for reason in result.decision.reasons))

    def test_matching_error_ambiguous_and_unmatched_never_pass(self):
        for index, osv in enumerate((None, {"vulns": [{"id": "GHSA-test", "aliases": ["CVE-2021-44228", "CVE-2021-45046"]}]},
                                    {"vulns": [{"id": "GHSA-test", "aliases": []}]})):
            with self.subTest(index=index):
                attempt = self._start(f"verify-{index}")
                sbom, components, normalized = self._inventory()
                runs = self._runs(components, normalized, osv=osv, error="OSV" if index == 0 else None)
                self._record(attempt, sbom, match_run_ids=runs, scanner_results=self._scanner(sbom))
                self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)

    def test_missing_after_and_functional_evidence_fail(self):
        attempt = self._start()
        with self.assertRaises(VerificationInputError):
            self.verification_service.complete(attempt.id)
        self.verification_service.record_after(attempt.id, asset_id=self.asset.id)
        result = self.verification_service.complete(attempt.id)
        self.assertEqual(result.status, VerificationStatus.FAILED)
        self.assertTrue(any("missing" in reason for reason in result.decision.reasons))
        second = self._start("verify-2")
        sbom, _, _ = self._inventory()
        self._record(second, sbom, scanner_results=self._scanner(sbom), functional_tests=())
        self.assertEqual(self.verification_service.complete(second.id).status, VerificationStatus.FAILED)

    def test_failed_skipped_and_conflicting_functional_results_fail(self):
        for index, status in enumerate((FunctionalStatus.FAILED, FunctionalStatus.SKIPPED, FunctionalStatus.ERROR)):
            attempt = self._start(f"verify-{index}")
            sbom, _, _ = self._inventory()
            tests = self._functional(sbom) + self._functional(sbom, status=status)
            self._record(attempt, sbom, scanner_results=self._scanner(sbom), functional_tests=tests)
            self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)

    def test_provenance_missing_stale_invalid_and_future_fail(self):
        changes = ({"source": ""}, {"reference": ""}, {"collected_at": "2026-10-13"},
                   {"collected_at": (preparation.NOW - timedelta(seconds=1)).isoformat()},
                   {"collected_at": (RECORDED + timedelta(seconds=1)).isoformat()})
        for index, change in enumerate(changes):
            attempt = self._start(f"verify-{index}")
            sbom, _, _ = self._inventory()
            self._record(attempt, sbom, scanner_results=self._scanner(sbom),
                         functional_tests=self._functional(sbom, **change))
            self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)

    def test_stale_matching_and_scanner_scope_or_cve_mismatch_fail(self):
        attempt = self._start()
        sbom, components, normalized = self._inventory()
        self._record(attempt, sbom, match_run_ids=self._runs(components, normalized, timestamp=preparation.NOW))
        self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)
        for index, change in enumerate(({"scope": "component"}, {"cve_id": "CVE-2021-45046"},
                                        {"status": ScannerStatus.DETECTED}, {"status": ScannerStatus.INCONCLUSIVE},
                                        {"source": ""}, {"status": ScannerStatus.ERROR})):
            attempt = self._start(f"verify-{index + 2}")
            self._record(attempt, sbom, scanner_results=self._scanner(sbom, **change))
            self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)

    def test_other_occurrences_and_incomplete_asset_matching_fail(self):
        old = fixture("cyclonedx_log4j.json")["components"][0]
        new = {**old, "version": "2.17.1", "purl": old["purl"].replace("2.14.1", "2.17.1"), "bom-ref": "new"}
        sbom, components, normalized = self._inventory(components=[old, new])
        attempt = self._start()
        self._record(attempt, sbom, match_run_ids=self._runs(components, normalized), scanner_results=self._scanner(sbom))
        self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)
        other = {"name": "other", "type": "library", "version": "1.0", "purl": "pkg:pypi/other@1.0"}
        sbom, components, normalized = self._inventory(components=[new, other])
        attempt = self._start("verify-2")
        runs = self._runs(components, normalized)
        self._record(attempt, sbom, match_run_ids=runs[:1])
        self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)

    def test_raw_document_stored_components_and_unresolved_identity_fail(self):
        attempt = self._start()
        sbom, components, _ = self._inventory()
        self.connection.execute("UPDATE components SET version = 'different' WHERE id = ?", (components[0].id,))
        self.connection.commit()
        self._record(attempt, sbom, scanner_results=self._scanner(sbom))
        self.assertEqual(self.verification_service.complete(attempt.id).status, VerificationStatus.FAILED)
        second = self._start("verify-2")
        unknown = {"name": "unidentified", "type": "library"}
        sbom, _, _ = self._inventory(components=[unknown])
        self._record(second, sbom, scanner_results=self._scanner(sbom))
        self.assertEqual(self.verification_service.complete(second.id).status, VerificationStatus.FAILED)

    def test_relationship_and_unapplied_or_before_sbom_rejected(self):
        with self.assertRaises(VerificationInputError):
            self.verification_service.start(remediation_id=self.applied.id, asset_id=self.other_asset.id,
                                            attempt_key="wrong", required_functional_tests=("smoke",))
        other = self._plan(self.finding, self.observation, self.recommendation, key="not-applied")
        with self.assertRaises(VerificationInputError):
            self._start(remediation=other)
        attempt = self._start()
        sbom, _, _ = self._inventory(asset_id=self.other_asset.id)
        with self.assertRaises(VerificationInputError):
            self._record(attempt, sbom)
        before_id = self.verifications.sbom_id_for_component(self.applied.before.component_id)
        with self.assertRaises(VerificationInputError):
            self.verification_service.record_after(attempt.id, asset_id=self.asset.id, sbom_id=before_id)
        good, _, _ = self._inventory()
        before_run = self.observation.match_run_id
        with self.assertRaises(VerificationInputError):
            self._record(attempt, good, match_run_ids=(before_run,))
        with self.assertRaises(VerificationInputError):
            self._record(attempt, good, functional_tests=self._functional(good, asset_id=self.other_asset.id))
        with self.assertRaises(VerificationInputError):
            self._record(attempt, good, scanner_results=self._scanner(good, sbom_id=sbom.id))
        self.assertIsNone(self.verification_service.get(attempt.id).after)

    def test_before_and_recommendation_mismatch_rejected(self):
        self.connection.execute("UPDATE recommendations SET input_json = '{}' WHERE id = ?", (self.recommendation.id,))
        self.connection.commit()
        with self.assertRaises(VerificationInputError):
            self._start()
        self.assertEqual(self.verifications.list_for_remediation(self.plan.id), ())

    def test_idempotency_conflicts_and_single_active_attempt(self):
        attempt = self._start()
        self.assertEqual(self._start(), attempt)
        with self.assertRaises(VerificationRepositoryError):
            self._start("another-active")
        with self.assertRaises(VerificationRepositoryError):
            self.verification_service.start(remediation_id=self.applied.id, asset_id=self.asset.id,
                                            attempt_key="verify-1", required_functional_tests=("changed",))
        sbom, _, _ = self._inventory()
        recorded = self._record(attempt, sbom, scanner_results=self._scanner(sbom))
        self.assertEqual(self._record(attempt, sbom, scanner_results=self._scanner(sbom)), recorded)
        with self.assertRaises(VerificationRepositoryError):
            self._record(attempt, sbom, scanner_results=self._scanner(sbom), sbom_reference="different")
        complete = self.verification_service.complete(attempt.id)
        self.assertEqual(self.verification_service.complete(attempt.id), complete)
        self.assertEqual(self._start(), complete)
        self.assertEqual(len(self.findings.get(self.finding.id).status_history), 5)

    def test_repeated_verification_additional_remediation_and_detached_history(self):
        first = self._start()
        sbom, _, _ = self._inventory()
        self._record(first, sbom, functional_tests=(), scanner_results=self._scanner(sbom))
        failed = self.verification_service.complete(first.id)
        second_plan = self._plan(self.finding, self.observation, self.recommendation, key="change-2")
        applied = self.service.record_application(second_plan.id, **preparation.APPLICATION)
        second = self._start("verify-2", remediation=applied)
        self._record(second, sbom, scanner_results=self._scanner(sbom))
        passed = self.verification_service.complete(second.id)
        third = self._start("verify-3", remediation=applied)
        self._record(third, sbom, scanner_results=self._scanner(sbom))
        self.assertEqual(self.verification_service.complete(third.id).status, VerificationStatus.PASSED)
        self.connection.execute("UPDATE sboms SET source = 'changed' WHERE id = ?", (sbom.id,))
        self.connection.commit()
        self.assertEqual(self.verification_service.get(first.id), failed)
        self.assertEqual(self.verification_service.get(second.id), passed)
        passed.after.payload.clear()
        self.assertTrue(self.verification_service.get(second.id).after.payload)
        history = self.findings.get(self.finding.id).status_history
        self.assertEqual(len(history), 9)
        self.assertEqual(sum(item.status == FindingStatus.VERIFICATION_PASSED for item in history), 2)
        self.assertEqual(self.service.get(self.plan.id).before, first.before)

    def test_database_immutability_constraints_and_illegal_transitions(self):
        for status in (FindingStatus.VERIFICATION_IN_PROGRESS, FindingStatus.VERIFICATION_PASSED,
                       FindingStatus.VERIFICATION_FAILED):
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute("UPDATE findings SET status = ? WHERE id = ?", (status.value, self.finding.id))
        self.connection.rollback()
        attempt = self._start()
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("UPDATE verifications SET before_json = '{}' WHERE id = ?", (attempt.id,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("DELETE FROM verifications WHERE id = ?", (attempt.id,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("""INSERT INTO verification_results
                (verification_id,status,rule_version,reasons_json,completed_at) VALUES (?,'verification_passed','v','["x"]','now')""", (attempt.id,))
        self.connection.rollback()
        sbom, _, _ = self._inventory()
        self._record(attempt, sbom, scanner_results=self._scanner(sbom))
        for query in ("UPDATE verification_after_evidence SET payload_json = '{}' WHERE verification_id = ?",
                      "DELETE FROM verification_after_evidence WHERE verification_id = ?"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute(query, (attempt.id,))
        self.connection.rollback()
        self.verification_service.complete(attempt.id)
        for query in ("UPDATE verification_results SET status = 'verification_failed' WHERE verification_id = ?",
                      "DELETE FROM verification_results WHERE verification_id = ?"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute(query, (attempt.id,))
        self.connection.rollback()
        self.assertEqual(self.connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_atomic_start_and_completion_status_failure_rollback(self):
        self.connection.execute("""CREATE TRIGGER reject_verification_start BEFORE UPDATE OF status ON findings
            WHEN NEW.status = 'verification_in_progress' BEGIN SELECT RAISE(ABORT,'rollback'); END""")
        self.connection.commit()
        with self.assertRaises(VerificationRepositoryError):
            self._start()
        self.assertEqual(self.verifications.list_for_remediation(self.plan.id), ())
        self.assertEqual(len(self.findings.get(self.finding.id).status_history), 3)
        self.connection.execute("DROP TRIGGER reject_verification_start")
        self.connection.commit()
        attempt = self._start()
        sbom, _, _ = self._inventory()
        self._record(attempt, sbom, scanner_results=self._scanner(sbom))
        self.connection.execute("""CREATE TRIGGER reject_verification_result BEFORE UPDATE OF status ON findings
            WHEN NEW.status = 'verification_passed' BEGIN SELECT RAISE(ABORT,'rollback'); END""")
        self.connection.commit()
        with self.assertRaises(VerificationRepositoryError):
            self.verification_service.complete(attempt.id)
        current = self.verification_service.get(attempt.id)
        self.assertIsNone(current.decision)
        self.assertIsNotNone(current.after)
        self.assertEqual(self.findings.get(self.finding.id).status, FindingStatus.VERIFICATION_IN_PROGRESS)
        self.assertEqual(len(self.findings.get(self.finding.id).status_history), 4)

    def test_database_after_source_and_history_guards(self):
        attempt = self._start()
        sbom, _, _ = self._inventory()
        other, other_components, other_normalized = self._inventory(asset_id=self.other_asset.id)
        other_runs = self._runs(other_components, other_normalized)
        snapshot = self.verifications.sbom_snapshot(sbom.id)
        bad_payloads = (
            {"asset_id": self.other_asset.id, "sbom": snapshot},
            {"asset_id": self.asset.id, "sbom": {**snapshot, "asset_id": self.other_asset.id}},
            {"asset_id": self.asset.id, "sbom": snapshot, "match_runs": [
                {"id": other_runs[0], "component_id": other_components[0].id}]},
            {"asset_id": self.asset.id, "sbom": snapshot, "functional_tests": [
                {"asset_id": self.other_asset.id, "sbom_id": other.id}]},
        )
        for payload in bad_payloads:
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute("""INSERT INTO verification_after_evidence
                    (verification_id,sbom_id,payload_json,payload_digest,recorded_at) VALUES (?,?,?,?,?)""",
                    (attempt.id, sbom.id, json.dumps(payload), "a" * 64, RECORDED.isoformat()))
            self.connection.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("""INSERT INTO finding_status_history
                (finding_id,status,recorded_at) VALUES (?,'verification_passed',?)""",
                (self.finding.id, RECORDED.isoformat()))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("DELETE FROM finding_status_history WHERE finding_id = ?", (self.finding.id,))
        self.connection.rollback()
        self.assertIsNone(self.verification_service.get(attempt.id).after)

    def test_required_tests_invalid_input_and_reinitialization(self):
        for required in ((), ("",), ("smoke", "smoke"), ["smoke"]):
            with self.assertRaises(VerificationInputError):
                self.verification_service.start(remediation_id=self.applied.id, asset_id=self.asset.id,
                                                attempt_key="invalid", required_functional_tests=required)
        attempt = self._start()
        sbom, _, _ = self._inventory()
        with self.assertRaises(VerificationInputError):
            self._record(attempt, sbom, functional_tests=self._functional(sbom, status="passed"))
        self._record(attempt, sbom, scanner_results=self._scanner(sbom))
        completed = self.verification_service.complete(attempt.id)
        before_history = self.findings.get(self.finding.id).status_history
        initialize_database(self.connection)
        self.assertEqual(self.verification_service.get(attempt.id), completed)
        self.assertEqual(self.findings.get(self.finding.id).status_history, before_history)

    def test_reanalysis_new_before_snapshot_preserves_previous_verification(self):
        first = self._start()
        self.verification_service.record_after(first.id, asset_id=self.asset.id)
        original = self.verification_service.complete(first.id)
        _, components, normalized = self._inventory(version="2.15.0")
        runs = self._runs(components, normalized, osv=fixture("osv_log4j_query.json"),
                          timestamp=preparation.NOW - timedelta(hours=1))
        finding = self.finding_service.create_from_match_run(asset_id=self.asset.id, match_run_id=runs[0])[0]
        self.mapping_service.map_finding(finding.id)
        observation = finding.observations[-1]
        recommendation = self.recommendation_service.create_for_observation(observation.id)
        plan = self._plan(finding, observation, recommendation, key="change-after-reanalysis")
        applied = self.service.record_application(plan.id, **preparation.APPLICATION)
        second = self._start("verification-after-reanalysis", remediation=applied)
        sbom, _, _ = self._inventory()
        self._record(second, sbom, scanner_results=self._scanner(sbom))
        result = self.verification_service.complete(second.id)
        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertEqual(result.before.component_version, "2.15.0")
        self.assertNotEqual(result.before.observation_id, original.before.observation_id)
        self.assertEqual(self.verification_service.get(first.id), original)
        self.assertEqual(self.service.get(self.plan.id).before.component_version, "2.14.1")

    def test_phase9_migration_preserves_phase8_snapshots_and_history(self):
        legacy = connect_database()
        self.addCleanup(legacy.close)
        folder = preparation.ROOT / "database" / "migrations"
        for path in sorted(folder.glob("000[1-6]_*.sql")):
            legacy.executescript(path.read_text(encoding="utf-8"))
        # Copy a populated Phase 8 graph in dependency order; migration must preserve every row.
        tables = ("business_services", "assets", "sboms", "components", "vulnerability_match_runs",
                  "vulnerability_match_evidence", "findings", "finding_observations", "finding_status_history",
                  "finding_control_mappings", "recommendations", "remediations", "remediation_applications")
        legacy.execute("PRAGMA foreign_keys = OFF")
        # Disable guards only while loading historical rows into this test database.
        triggers = legacy.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
        for trigger in triggers:
            legacy.execute(f"DROP TRIGGER {trigger['name']}")
        for table in tables:
            for row in self.connection.execute(f"SELECT * FROM {table}").fetchall():
                data = dict(row)
                data.pop("verification_id", None)
                columns = ','.join(data)
                placeholders = ','.join('?' for _ in data)
                legacy.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(data.values()))
        legacy.commit()
        # Restore Phase 8 guards before testing the real migration.
        import re
        phase8 = (folder / "0006_remediations.sql").read_text(encoding="utf-8")
        for trigger in re.findall(r"CREATE TRIGGER .*?END;", phase8, re.DOTALL):
            legacy.executescript(trigger)
        previous = {table: [tuple(row) for row in legacy.execute(f"SELECT * FROM {table}")]
                    for table in tables}
        with self.assertRaises(DatabaseMigrationRequiredError):
            initialize_database(legacy)
        self.assertIsNone(legacy.execute("SELECT name FROM sqlite_master WHERE name='verifications'").fetchone())
        legacy.executescript((folder / "0007_verifications.sql").read_text(encoding="utf-8"))
        initialize_database(legacy)
        for table in tables:
            rows = [tuple(row) for row in legacy.execute(f"SELECT * FROM {table}")]
            if table == "finding_status_history":
                rows = [row[:-1] for row in rows]
            self.assertEqual(rows, previous[table], table)
        self.assertEqual(legacy.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(legacy.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        repository = SQLiteVerificationRepository(legacy, lambda: RECORDED)
        record = SQLiteRemediationRepository(legacy).get(self.plan.id)
        started = repository.start(record, asset_id=self.asset.id, attempt_key="migrated",
                                   required_tests=("smoke",), before_sbom=self.verifications.sbom_snapshot(
                                       self.verifications.sbom_id_for_component(record.before.component_id)))
        self.assertEqual(started.before, record.before)


if __name__ == "__main__":
    unittest.main()
