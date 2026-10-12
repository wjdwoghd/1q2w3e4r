"""Offline recommendation generation, provenance and persistence tests."""

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.assets.asset_service import AssetService
from core.compliance.service import ControlMappingService
from core.consulting.analyzer import RecommendationInputError, build_recommendation_input
from core.consulting.recommender import RecommendationOutputError, RecommendationService
from core.findings.service import FindingService
from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom_file
from core.vulnerability.matcher import match_component_to_cves
from database.database import connect_database, initialize_database
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.control_mapping_repository import SQLiteControlMappingRepository
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.recommendation_repository import (
    RecommendationRepositoryError, SQLiteRecommendationRepository,
)
from database.repositories.sbom_repository import SQLiteSBOMRepository
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository
from tests.unit.test_asset_context import VALID
from tests.unit.test_vulnerability import StubTransport, clients, fixture

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
GOOD_ACTIONS = {
    "technical_recommendations": ["Review vendor guidance and plan a supported upgrade."],
    "administrative_recommendations": ["Assign an owner and track change approval."],
    "temporary_mitigations": ["Restrict exposure pending the approved change."],
    "verification_plan": ["Regenerate the SBOM, rematch the vulnerability, and run functional checks."],
}


class StubGenerator:
    model = "offline-stub"

    def __init__(self, result=None, error=None):
        self.result = GOOD_ACTIONS if result is None else result
        self.error = error
        self.calls = 0

    def generate(self, input_data):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result


class RecommendationTests(unittest.TestCase):
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
        self.mappings = SQLiteControlMappingRepository(self.connection, lambda: NOW)
        self.mapping_service = ControlMappingService(self.findings, self.mappings)
        self.recommendations = SQLiteRecommendationRepository(self.connection, lambda: NOW)
        self.generator = StubGenerator()
        self.service = RecommendationService(
            findings=self.findings, mappings=self.mappings, matches=self.matches,
            recommendations=self.recommendations, generator=self.generator)
        self.match = match_component_to_cves(
            normalized.components[0], **clients(StubTransport(
                osv=fixture("osv_log4j_query.json"),
                nvd=fixture("nvd_log4j_cve.json"),
                kev=fixture("cisa_kev_log4j.json"))))

    def _finding(self, key="scan-1", map_controls=True):
        run = self.matches.save(component_id=self.component_id,
                                analysis_key=key, result=self.match)
        finding = self.finding_service.create_from_match_run(
            asset_id=self.asset.id, match_run_id=run.id)[0]
        if map_controls:
            self.mapping_service.map_finding(finding.id)
        return finding

    def test_generation_lookup_and_verified_input(self):
        finding = self._finding()
        observation_id = finding.observations[0].id
        saved = self.service.create_for_observation(observation_id)
        self.assertEqual(saved.finding_id, finding.id)
        self.assertEqual(saved.content["technical_recommendations"], GOOD_ACTIONS["technical_recommendations"])
        self.assertEqual(saved.content["related_controls"], saved.input_data["controls"])
        self.assertEqual(saved.input_data["eol"], "unknown")
        self.assertEqual(saved.input_data["cve"], finding.cve_id)
        self.assertEqual(saved.input_data["risk_priority"], finding.observations[0].risk.priority)
        self.assertEqual(self.service.get_for_observation(observation_id), saved)
        self.assertEqual(self.service.list_for_finding(finding.id), (saved,))
        self.assertEqual(self.generator.calls, 1)

    def test_missing_and_mismatched_input_does_not_call_ai(self):
        finding = self._finding(map_controls=False)
        with self.assertRaises(RecommendationInputError):
            self.service.create_for_observation(finding.observations[0].id)
        with self.assertRaises(RecommendationInputError):
            self.service.create_for_observation(0)
        self.mapping_service.map_finding(finding.id)
        self.connection.execute(
            "UPDATE finding_control_mappings SET observed_facts_json = ?",
            (json.dumps({"cve_id": "CVE-2020-0000"}),))
        self.connection.commit()
        with self.assertRaises(RecommendationInputError):
            self.service.create_for_observation(finding.observations[0].id)
        self.assertEqual(self.generator.calls, 0)
        self.assertEqual(self.service.list_for_finding(finding.id), ())

    def test_prior_observation_controls_cannot_supply_new_observation(self):
        finding = self._finding()
        run = self.matches.save(component_id=self.component_id,
                                analysis_key="scan-2", result=self.match)
        updated = self.finding_service.create_from_match_run(
            asset_id=self.asset.id, match_run_id=run.id)[0]
        with self.assertRaises(RecommendationInputError):
            self.service.create_for_observation(updated.observations[-1].id)
        self.assertEqual(self.generator.calls, 0)

    def test_unverified_ai_facts_and_api_failure_not_saved(self):
        finding = self._finding()
        observation_id = finding.observations[0].id
        for text in ("Upgrade to version 9.9.", "CVE-2099-9999 was found.",
                     "The patch was completed.", "ISMS-P-9.9 applies.",
                     "PCI applies.", "검증 통과했습니다."):
            self.generator.result = {**GOOD_ACTIONS, "technical_recommendations": [text]}
            with self.assertRaises(RecommendationOutputError):
                self.service.create_for_observation(observation_id)
            self.assertIsNone(self.service.get_for_observation(observation_id))
        self.generator.error = RuntimeError("API unavailable")
        with self.assertRaises(RuntimeError):
            self.service.create_for_observation(observation_id)
        self.assertIsNone(self.service.get_for_observation(observation_id))
        self.generator.error = None
        self.generator.result = {"technical_recommendations": ["Review vendor guidance."]}
        with self.assertRaises(RecommendationOutputError):
            self.service.create_for_observation(observation_id)
        self.assertIsNone(self.service.get_for_observation(observation_id))

    def test_generator_cannot_mutate_verified_facts(self):
        finding = self._finding()

        class MutatingGenerator(StubGenerator):
            def generate(self, input_data):
                input_data["cve"] = "CVE-2099-9999"
                input_data["controls"].clear()
                return GOOD_ACTIONS

        self.service.generator = MutatingGenerator()
        saved = self.service.create_for_observation(finding.observations[0].id)
        self.assertEqual(saved.input_data["cve"], finding.cve_id)
        self.assertTrue(saved.input_data["controls"])

    def test_idempotence_and_reanalysis_history(self):
        finding = self._finding()
        first = self.service.create_for_observation(finding.observations[0].id)
        self.assertEqual(self.service.create_for_observation(finding.observations[0].id), first)
        self.assertEqual(self.generator.calls, 1)
        self.connection.execute("UPDATE assets SET patch_status = 'overdue' WHERE id = ?",
                                (self.asset.id,))
        self.connection.commit()
        updated = self._finding(key="scan-2")
        second = self.service.create_for_observation(updated.observations[-1].id)
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(first.input_data["patch_status"], VALID["patch_status"])
        self.assertEqual(second.input_data["patch_status"], "overdue")
        self.assertEqual(self.service.list_for_finding(finding.id), (first, second))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """INSERT INTO recommendations
                   (observation_id,input_digest,model_name,input_json,content_json,created_at)
                   VALUES (?,?,?,?,?,?)""",
                (first.observation_id, first.input_digest, first.model_name,
                 json.dumps(first.input_data), json.dumps(first.content), NOW.isoformat()))
        with self.assertRaises(RecommendationRepositoryError):
            self.recommendations.save(observation_id=first.observation_id,
                                      input_data={"changed": True},
                                      content=first.content, model_name="offline-stub")

    def test_database_constraints_rollback_and_migration(self):
        finding = self._finding()
        observation_id = finding.observations[0].id
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """INSERT INTO recommendations
                   (observation_id,input_digest,model_name,input_json,content_json,created_at)
                   VALUES (?,?,?,?,?,?)""",
                (9999, "a" * 64, "stub", "{}", "{}", NOW.isoformat()))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """INSERT INTO recommendations
                   (observation_id,input_digest,model_name,input_json,content_json,created_at)
                   VALUES (?,?,?,?,?,?)""",
                (observation_id, "a" * 64, "stub", "bad-json", "{}", NOW.isoformat()))
        self.connection.execute("""CREATE TRIGGER reject_recommendation BEFORE INSERT ON recommendations
            BEGIN SELECT RAISE(ABORT, 'test rollback'); END""")
        self.connection.commit()
        with self.assertRaises(RecommendationRepositoryError):
            self.service.create_for_observation(observation_id)
        self.assertIsNone(self.service.get_for_observation(observation_id))
        legacy = connect_database()
        self.addCleanup(legacy.close)
        folder = ROOT / "database" / "migrations"
        for number in ("0001_asset_and_sbom", "0002_vulnerability_matches", "0003_findings",
                       "0004_finding_control_mappings", "0005_recommendations"):
            legacy.executescript((folder / f"{number}.sql").read_text(encoding="utf-8"))
        legacy.executescript((folder / "0005_recommendations.sql").read_text(encoding="utf-8"))
        self.assertEqual(legacy.execute("PRAGMA foreign_key_check").fetchall(), [])


if __name__ == "__main__":
    unittest.main()
