"""Offline Phase 4 -> Phase 5 -> Phase 6 persistence and failure cases."""

import sqlite3
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from core.assets.asset_service import AssetService
from core.findings.service import FindingInputError, FindingService
from core.risk.engine import calculate_risk_priorities
from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom_file
from core.vulnerability.matcher import MatchStatus, match_component_to_cves
from database.database import connect_database, initialize_database
from database.models.finding import FindingStatus
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.finding_repository import FindingRepositoryError, SQLiteFindingRepository
from database.repositories.sbom_repository import SQLiteSBOMRepository
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository
from tests.unit.test_asset_context import VALID
from tests.unit.test_vulnerability import StubTransport, clients, fixture

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.connection = connect_database()
        self.addCleanup(self.connection.close)
        initialize_database(self.connection)
        self.assets = SQLiteAssetRepository(self.connection)
        self.asset_service = AssetService(self.assets)
        business = self.asset_service.register_business_service("Banking")
        self.asset = self.asset_service.register_asset(business.id, **VALID)
        self.other_asset = self.asset_service.register_asset(
            business.id, **{**VALID, "name": "Other API"})
        path = ROOT / "tests" / "fixtures" / "cyclonedx_log4j.json"
        parsed = parse_sbom_file(path)
        self.normalized = normalize_components(parsed.components)
        self.sboms = SQLiteSBOMRepository(self.connection)
        self.component_id = self._component(self.asset.id, path, parsed)
        self.other_component_id = self._component(self.other_asset.id, path, parsed)
        self.matches = SQLiteVulnerabilityRepository(self.connection, lambda: NOW)
        self.findings = SQLiteFindingRepository(self.connection, lambda: NOW)
        self.service = FindingService(self.findings, self.matches, self.assets)
        self.match = match_component_to_cves(
            self.normalized.components[0], **clients(StubTransport(
                osv=fixture("osv_log4j_query.json"),
                nvd=fixture("nvd_log4j_cve.json"),
                kev=fixture("cisa_kev_log4j.json"))))

    def _component(self, asset_id, path, parsed):
        sbom = self.sboms.save(
            asset_id=asset_id, source=str(path), raw_document=path.read_text(encoding="utf-8"),
            parsed=parsed, normalized=self.normalized)
        return self.sboms.list_components(sbom.id)[0].id

    def _run(self, result=None, key="scan-1", component_id=None):
        return self.matches.save(
            component_id=component_id or self.component_id, analysis_key=key,
            result=self.match if result is None else result)

    def _alternate_cve(self):
        new_id = "CVE-2021-45046"
        old = self.match.matches[0]
        new_match = replace(old, cve=replace(old.cve, cve_id=new_id), kev=False,
                            kev_entry=None)
        candidate = self.match.osv_query.candidates[0]
        query = replace(self.match.osv_query,
                        candidates=(replace(candidate, cve_ids=(new_id,)),))
        return replace(self.match, matches=(new_match,), osv_query=query)

    def test_create_read_idempotent_reanalysis_and_status_history(self):
        run = self._run()
        first = self.service.create_from_match_run(asset_id=self.asset.id, match_run_id=run.id)[0]
        self.assertEqual(first.status, FindingStatus.OPEN)
        self.assertEqual(len(first.status_history), 1)
        self.assertEqual(first.status_history[0].status, FindingStatus.OPEN)
        self.assertEqual(first.observations[0].risk.priority, "P1")
        self.assertEqual(first.observations[0].risk.score, 100)
        self.assertEqual(first.observations[0].asset_context, self.asset.context)
        self.assertEqual(first.observations[0].match_run_id, run.id)
        self.assertEqual(self.matches.get(first.observations[0].match_run_id).result, self.match)
        self.assertEqual(self.service.create_from_match_run(
            asset_id=self.asset.id, match_run_id=run.id)[0], first)
        second_run = self._run(key="scan-2")
        second = self.service.create_from_match_run(
            asset_id=self.asset.id, match_run_id=second_run.id)[0]
        self.assertEqual(second.id, first.id)
        self.assertEqual([item.match_run_id for item in second.observations],
                         [run.id, second_run.id])
        self.assertEqual(len(second.status_history), 1)
        self.assertEqual(self.service.get(first.id), second)
        self.assertEqual(self.service.get_by_asset_cve(self.asset.id, first.cve_id), second)
        self.assertEqual(self.service.list_for_asset(self.asset.id), (second,))

    def test_different_asset_and_cve_have_distinct_findings(self):
        first = self.service.create_from_match_run(
            asset_id=self.asset.id, match_run_id=self._run().id)[0]
        second = self.service.create_from_match_run(
            asset_id=self.other_asset.id,
            match_run_id=self._run(component_id=self.other_component_id).id)[0]
        third = self.service.create_from_match_run(
            asset_id=self.asset.id,
            match_run_id=self._run(result=self._alternate_cve(), key="other-cve").id)[0]
        self.assertEqual(len({first.id, second.id, third.id}), 3)
        self.assertEqual(len(self.service.list_for_asset(self.asset.id)), 2)

    def test_same_asset_cve_from_another_component_keeps_both_sources(self):
        path = ROOT / "tests" / "fixtures" / "cyclonedx_log4j.json"
        parsed = parse_sbom_file(path)
        another_component = self._component(self.asset.id, path, parsed)
        first_run = self._run()
        second_run = self._run(component_id=another_component)
        first = self.service.create_from_match_run(
            asset_id=self.asset.id, match_run_id=first_run.id)[0]
        second = self.service.create_from_match_run(
            asset_id=self.asset.id, match_run_id=second_run.id)[0]
        self.assertEqual(first.id, second.id)
        self.assertEqual({item.component_id for item in second.observations},
                         {self.component_id, another_component})

    def test_failed_match_risk_and_mismatched_asset_create_nothing(self):
        empty = replace(self.match, status=MatchStatus.NO_MATCH, matches=(),
                        osv_query=replace(self.match.osv_query, candidates=()))
        run = self._run(result=empty)
        with self.assertRaises(FindingInputError):
            self.service.create_from_match_run(asset_id=self.asset.id, match_run_id=run.id)
        errored = self._run(result=replace(self.match, status=MatchStatus.ERROR,
                                           matches=()), key="error")
        with self.assertRaises(FindingInputError):
            self.service.create_from_match_run(asset_id=self.asset.id,
                                               match_run_id=errored.id)
        no_cvss = replace(self.match, matches=(replace(
            self.match.matches[0], cve=replace(self.match.matches[0].cve, cvss=None)),))
        unscorable = self._run(result=no_cvss, key="no-cvss")
        with self.assertRaises(FindingInputError):
            self.service.create_from_match_run(asset_id=self.asset.id, match_run_id=unscorable.id)
        good = self._run(key="good")
        with self.assertRaises(FindingInputError):
            self.service.create_from_match_run(asset_id=self.other_asset.id, match_run_id=good.id)
        with self.assertRaises(FindingInputError):
            self.service.create_from_match_run(asset_id=True, match_run_id=good.id)
        self.assertEqual(self.service.list_for_asset(self.asset.id), ())

    def test_mismatched_component_purl_is_rejected(self):
        changed = replace(self.match, component_purl="pkg:maven/other/component@1.0")
        run = self._run(result=changed)
        with self.assertRaises(FindingRepositoryError):
            self.service.create_from_match_run(asset_id=self.asset.id, match_run_id=run.id)
        self.assertEqual(self.service.list_for_asset(self.asset.id), ())

    def test_conflicting_same_run_and_database_constraints(self):
        run = self._run()
        saved = self.service.create_from_match_run(asset_id=self.asset.id, match_run_id=run.id)[0]
        changed = replace(self.asset.context, patch_status="overdue")
        risks = calculate_risk_priorities(run.result, changed)
        with self.assertRaises(FindingRepositoryError):
            self.findings.save(asset_id=self.asset.id, run=run, risks=risks, context=changed)
        self.assertEqual(self.service.get(saved.id), saved)
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO findings (asset_id,cve_id,status,created_at) VALUES (?,?,?,?)",
                (self.asset.id, saved.cve_id, "open", NOW.isoformat()))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO findings (asset_id,cve_id,status,created_at) VALUES (?,?,?,?)",
                (9999, "CVE-2021-45046", "open", NOW.isoformat()))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE findings SET status = 'verification_passed' WHERE id = ?", (saved.id,))
        wrong_asset = self.connection.execute(
            "INSERT INTO findings (asset_id,cve_id,status,created_at) VALUES (?,?,?,?)",
            (self.other_asset.id, saved.cve_id, "open", NOW.isoformat()),
        ).lastrowid
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """INSERT INTO finding_observations
                (finding_id,match_evidence_id,risk_json,asset_context_json,recorded_at)
                VALUES (?,?,?,?,?)""",
                (wrong_asset, saved.observations[0].match_evidence_id, "{}", "{}",
                 NOW.isoformat()),
            )

    def test_transaction_rolls_back_partial_multi_cve_write(self):
        first = self.match.matches[0]
        alternate = self._alternate_cve()
        query = replace(self.match.osv_query,
                        candidates=self.match.osv_query.candidates + alternate.osv_query.candidates)
        result = replace(self.match, matches=(first, alternate.matches[0]), osv_query=query)
        run = self._run(result=result)
        self.connection.execute("""CREATE TRIGGER fail_second_observation
            BEFORE INSERT ON finding_observations
            WHEN (SELECT COUNT(*) FROM finding_observations) = 1
            BEGIN SELECT RAISE(ABORT, 'test rollback'); END""")
        self.connection.commit()
        with self.assertRaises(FindingRepositoryError):
            self.service.create_from_match_run(asset_id=self.asset.id, match_run_id=run.id)
        for table in ("findings", "finding_observations", "finding_status_history"):
            self.assertEqual(self.connection.execute(
                f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)

    def test_incremental_migration(self):
        legacy = connect_database()
        self.addCleanup(legacy.close)
        folder = ROOT / "database" / "migrations"
        for number in ("0001_asset_and_sbom", "0002_vulnerability_matches", "0003_findings"):
            legacy.executescript((folder / f"{number}.sql").read_text(encoding="utf-8"))
        legacy.executescript((folder / "0003_findings.sql").read_text(encoding="utf-8"))
        self.assertEqual(legacy.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertIsNotNone(legacy.execute(
            "SELECT name FROM sqlite_master WHERE name='findings'").fetchone())


if __name__ == "__main__":
    unittest.main()
