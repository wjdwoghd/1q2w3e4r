"""Offline Phase 6 Finding to Phase 7.1 reference control mapping."""

import sqlite3
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from core.assets.asset_service import AssetService
from core.compliance.controls import ControlType, SecurityControl, load_controls
from core.compliance.mapper import map_observation
from core.compliance.service import ControlMappingService
from core.findings.service import FindingService
from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom_file
from core.vulnerability.matcher import match_component_to_cves
from database.database import connect_database, initialize_database
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.control_mapping_repository import (
    ControlMappingRepositoryError, SQLiteControlMappingRepository,
)
from database.repositories.finding_repository import FindingNotFoundError, SQLiteFindingRepository
from database.repositories.sbom_repository import SQLiteSBOMRepository
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository
from tests.unit.test_asset_context import VALID
from tests.unit.test_vulnerability import StubTransport, clients, fixture


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)


class ControlMappingTests(unittest.TestCase):
    def setUp(self):
        self.connection = connect_database()
        self.addCleanup(self.connection.close)
        initialize_database(self.connection)
        assets = SQLiteAssetRepository(self.connection)
        asset_service = AssetService(assets)
        business = asset_service.register_business_service("Banking")
        self.asset = asset_service.register_asset(business.id, **VALID)
        self.other_asset = asset_service.register_asset(
            business.id, **{**VALID, "name": "Other API"})
        path = ROOT / "tests" / "fixtures" / "cyclonedx_log4j.json"
        parsed = parse_sbom_file(path)
        normalized = normalize_components(parsed.components)
        sboms = SQLiteSBOMRepository(self.connection)
        self.component_id = sboms.list_components(sboms.save(
            asset_id=self.asset.id, source=str(path),
            raw_document=path.read_text(encoding="utf-8"),
            parsed=parsed, normalized=normalized).id)[0].id
        self.matches = SQLiteVulnerabilityRepository(self.connection, lambda: NOW)
        self.findings = SQLiteFindingRepository(self.connection, lambda: NOW)
        self.finding_service = FindingService(self.findings, self.matches, assets)
        self.repository = SQLiteControlMappingRepository(self.connection, lambda: NOW)
        self.service = ControlMappingService(self.findings, self.repository)
        self.match = match_component_to_cves(
            normalized.components[0], **clients(StubTransport(
                osv=fixture("osv_log4j_query.json"),
                nvd=fixture("nvd_log4j_cve.json"),
                kev=fixture("cisa_kev_log4j.json"))))

    def _finding(self, key="scan-1"):
        run = self.matches.save(component_id=self.component_id,
                                analysis_key=key, result=self.match)
        return self.finding_service.create_from_match_run(
            asset_id=self.asset.id, match_run_id=run.id)[0]

    def test_catalog_provenance_types_and_reference_only_mapping(self):
        catalog = load_controls()
        self.assertEqual(set(catalog), {"FIN-37-2-5-1", "FIN-37-2-5",
                                        "ISMS-P-2.10", "ISMS-P-1.2"})
        for control in catalog.values():
            self.assertTrue(control.document_title and control.issuer and control.edition)
            self.assertTrue(control.publication_date and control.identifier)
            self.assertTrue(control.source_url.startswith("https://"))
        self.assertEqual(catalog["ISMS-P-2.10"].granularity, "category")
        with self.assertRaises(ValueError):
            SecurityControl.from_record({"key": "unverified"})
        with self.assertRaises(ValueError):
            map_observation(self._finding().observations[0], controls={})
        finding = self.finding_service.list_for_asset(self.asset.id)[0]
        mapped = self.service.map_finding(finding.id)
        self.assertEqual({m.control.key for m in mapped},
                         {"FIN-37-2-5-1", "ISMS-P-2.10", "ISMS-P-1.2"})
        self.assertEqual({m.control.control_type for m in mapped},
                         {ControlType.TECHNICAL, ControlType.ADMINISTRATIVE})
        for mapping in mapped:
            self.assertEqual(mapping.observation_id, finding.observations[0].id)
            self.assertEqual(dict(mapping.observed_facts)["cve_id"], finding.cve_id)
            self.assertEqual(dict(mapping.observed_facts)["match_evidence_id"],
                             str(finding.observations[0].match_evidence_id))
            self.assertTrue(mapping.reason and mapping.rule_id and mapping.rule_version)
        self.assertEqual(self.service.list_for_finding(finding.id), mapped)

    def test_idempotence_reanalysis_and_historical_evidence(self):
        finding = self._finding()
        first = self.service.map_finding(finding.id)
        self.assertEqual(self.service.map_finding(finding.id), first)
        self.connection.execute("UPDATE assets SET patch_status = 'overdue' WHERE id = ?",
                                (self.asset.id,))
        self.connection.commit()
        updated = self._finding(key="scan-2")
        self.assertEqual(updated.id, finding.id)
        all_mappings = self.service.map_finding(finding.id)
        self.assertEqual(len(all_mappings), 7)
        self.assertEqual(tuple(m for m in all_mappings
                               if m.observation_id == finding.observations[0].id), first)
        latest = tuple(m for m in all_mappings
                       if m.observation_id == updated.observations[-1].id)
        self.assertEqual({m.control.key for m in latest},
                         {"FIN-37-2-5-1", "FIN-37-2-5", "ISMS-P-2.10", "ISMS-P-1.2"})
        self.assertEqual(dict(next(m for m in latest if m.control.key == "FIN-37-2-5")
                              .observed_facts)["patch_status"], "overdue")
        self.assertEqual(self.service.map_finding(finding.id), all_mappings)

    def test_missing_and_mismatched_input_rejected(self):
        finding = self._finding()
        candidate = map_observation(finding.observations[0])[0]
        for invalid in (0, True, -1):
            with self.assertRaises(ValueError):
                self.service.map_finding(invalid)
        with self.assertRaises(FindingNotFoundError):
            self.service.list_for_finding(9999)
        with self.assertRaises(ControlMappingRepositoryError):
            self.repository.save_for_finding(self.other_asset.id,
                                             (candidate,))
        wrong = replace(candidate, observed_facts=(("cve_id", "CVE-2020-0000"),) +
                        candidate.observed_facts[1:])
        with self.assertRaises(ControlMappingRepositoryError):
            self.repository.save_for_finding(finding.id, (wrong,))
        self.assertEqual(self.service.list_for_finding(finding.id), ())

    def test_conflicting_replay_and_batch_rollback(self):
        finding = self._finding()
        candidates = map_observation(finding.observations[0])
        self.repository.save_for_finding(finding.id, candidates)
        changed = replace(candidates[0], reason="changed reason")
        with self.assertRaises(ControlMappingRepositoryError):
            self.repository.save_for_finding(finding.id, (changed,))
        changed_source = replace(candidates[0],
                                 control=replace(candidates[0].control,
                                                 edition="unverified later edition"))
        with self.assertRaises(ControlMappingRepositoryError):
            self.repository.save_for_finding(finding.id, (changed_source,))
        self.assertEqual(len(self.service.list_for_finding(finding.id)), 3)
        self.connection.execute("DELETE FROM finding_control_mappings")
        self.connection.commit()
        self.connection.execute("""CREATE TRIGGER fail_second_control
            BEFORE INSERT ON finding_control_mappings
            WHEN (SELECT COUNT(*) FROM finding_control_mappings) = 1
            BEGIN SELECT RAISE(ABORT, 'test rollback'); END""")
        self.connection.commit()
        with self.assertRaises(ControlMappingRepositoryError):
            self.repository.save_for_finding(finding.id, candidates)
        self.assertEqual(self.service.list_for_finding(finding.id), ())

    def test_database_constraints_and_incremental_migration(self):
        finding = self._finding()
        candidate = map_observation(finding.observations[0])[0]
        self.repository.save_for_finding(finding.id, (candidate,))
        row = self.connection.execute("SELECT * FROM finding_control_mappings").fetchone()
        values = (row["observation_id"], row["control_key"], row["control_type"],
                  row["control_snapshot_json"], row["rule_id"], row["rule_version"],
                  row["reason"], row["observed_facts_json"], row["payload_digest"],
                  row["recorded_at"])
        columns = """(observation_id,control_key,control_type,control_snapshot_json,
                     rule_id,rule_version,reason,observed_facts_json,payload_digest,recorded_at)"""
        for override in ({}, {"observation_id": 9999}, {"control_type": "invalid"},
                         {"control_snapshot_json": "not-json"}, {"reason": " "}):
            data = list(values)
            indices = {"observation_id": 0, "control_type": 2,
                       "control_snapshot_json": 3, "reason": 6}
            for key, value in override.items():
                data[indices[key]] = value
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute(
                    f"INSERT INTO finding_control_mappings {columns} VALUES (?,?,?,?,?,?,?,?,?,?)",
                    data)
        legacy = connect_database()
        self.addCleanup(legacy.close)
        folder = ROOT / "database" / "migrations"
        for number in ("0001_asset_and_sbom", "0002_vulnerability_matches",
                       "0003_findings", "0004_finding_control_mappings"):
            legacy.executescript((folder / f"{number}.sql").read_text(encoding="utf-8"))
        legacy.executescript((folder / "0004_finding_control_mappings.sql")
                             .read_text(encoding="utf-8"))
        self.assertEqual(legacy.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertIsNotNone(legacy.execute("""SELECT name FROM sqlite_master
            WHERE name = 'finding_control_mappings'""").fetchone())


if __name__ == "__main__":
    unittest.main()
