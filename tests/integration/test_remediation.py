"""Offline Phase 8 provenance, history, constraints and migration tests."""

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.assets.asset_service import AssetService
from core.compliance.service import ControlMappingService
from core.consulting.recommender import RecommendationService
from core.findings.service import FindingService
from core.remediation.service import RemediationInputError, RemediationService
from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom_file
from core.vulnerability.matcher import match_component_to_cves
from database.database import connect_database, initialize_database
from database.models.finding import FindingStatus
from database.models.remediation import RemediationStatus
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.control_mapping_repository import SQLiteControlMappingRepository
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.finding_repository import FindingNotFoundError
from database.repositories.recommendation_repository import SQLiteRecommendationRepository
from database.repositories.remediation_repository import (
    RemediationNotFoundError, RemediationRepositoryError, SQLiteRemediationRepository,
)
from database.repositories.sbom_repository import SQLiteSBOMRepository
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository
from tests.integration.test_recommendation import StubGenerator
from tests.unit.test_asset_context import VALID
from tests.unit.test_vulnerability import StubTransport, clients, fixture

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)
APPLICATION = dict(action="Deployed approved dependency upgrade", actor="Release owner",
                   applied_at=NOW.isoformat(), evidence_type="deployment_record",
                   evidence_reference="release-42/job-7", evidence_source="internal CI")


class RemediationTests(unittest.TestCase):
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
        mappings = SQLiteControlMappingRepository(self.connection, lambda: NOW)
        self.mapping_service = ControlMappingService(self.findings, mappings)
        self.recommendations = SQLiteRecommendationRepository(self.connection, lambda: NOW)
        self.recommendation_service = RecommendationService(
            findings=self.findings, mappings=mappings, matches=self.matches,
            recommendations=self.recommendations, generator=StubGenerator())
        self.repository = SQLiteRemediationRepository(self.connection, lambda: NOW)
        self.service = RemediationService(findings=self.findings,
                                          recommendations=self.recommendations,
                                          remediations=self.repository)
        self.match = match_component_to_cves(normalized.components[0], **clients(
            StubTransport(osv=fixture("osv_log4j_query.json"),
                          nvd=fixture("nvd_log4j_cve.json"),
                          kev=fixture("cisa_kev_log4j.json"))))

    def _recommendation(self, key="scan-1"):
        run = self.matches.save(component_id=self.component_id, analysis_key=key,
                                result=self.match)
        finding = self.finding_service.create_from_match_run(
            asset_id=self.asset.id, match_run_id=run.id)[0]
        self.mapping_service.map_finding(finding.id)
        observation = finding.observations[-1]
        recommendation = self.recommendation_service.create_for_observation(observation.id)
        return finding, observation, recommendation

    def _plan(self, finding, observation, recommendation, key="change-1"):
        return self.service.create_plan(
            finding_id=finding.id, observation_id=observation.id,
            recommendation_id=recommendation.id, action_key=key,
            planned_action="Upgrade the component in the next release", owner="Release owner")

    def test_plan_and_application_are_distinct_with_before_snapshot_and_history(self):
        finding, observation, recommendation = self._recommendation()
        plan = self._plan(finding, observation, recommendation)
        self.assertEqual(plan.status, RemediationStatus.PLANNED)
        self.assertIsNone(plan.application)
        self.assertEqual(plan.before.component_version, recommendation.input_data["version"])
        self.assertEqual(plan.before.component_name, recommendation.input_data["component"])
        self.assertEqual(plan.before.cve_id, finding.cve_id)
        self.assertEqual(plan.before.risk_priority, observation.risk.priority)
        self.assertEqual(plan.before.risk_reasons, observation.risk.reasons)
        self.assertEqual(self.service.get(plan.id), plan)
        self.assertEqual(self.service.list_for_finding(finding.id), (plan,))
        self.assertEqual([event.status for event in self.findings.get(finding.id).status_history],
                         [FindingStatus.OPEN, FindingStatus.RECOMMENDATION_CREATED])
        applied = self.service.record_application(plan.id, **APPLICATION)
        self.assertEqual(applied.status, RemediationStatus.APPLIED)
        self.assertEqual(applied.application.evidence_reference, "release-42/job-7")
        self.assertEqual(applied.before, plan.before)
        self.assertEqual(self.findings.get(finding.id).status, FindingStatus.REMEDIATION_APPLIED)
        self.assertEqual([event.status for event in self.findings.get(finding.id).status_history],
                         [FindingStatus.OPEN, FindingStatus.RECOMMENDATION_CREATED,
                          FindingStatus.REMEDIATION_APPLIED])

    def test_missing_mismatched_and_unverified_application_rejected(self):
        finding, observation, recommendation = self._recommendation()
        with self.assertRaises(RemediationNotFoundError):
            self.service.get(9999)
        with self.assertRaises(RemediationInputError):
            self._plan(finding, observation, recommendation, key=" ")
        with self.assertRaises(RemediationInputError):
            self.service.create_plan(finding_id=finding.id, observation_id=9999,
                                     recommendation_id=recommendation.id, action_key="x",
                                     planned_action="Upgrade", owner="Owner")
        second_finding = self.finding_service.get_by_asset_cve(self.asset.id, finding.cve_id)
        with self.assertRaises(FindingNotFoundError):
            self.service.create_plan(finding_id=self.other_asset.id,
                                     observation_id=observation.id,
                                     recommendation_id=recommendation.id,
                                     action_key="x", planned_action="Upgrade", owner="Owner")
        _, other_observation, other_recommendation = self._recommendation("scan-2")
        with self.assertRaises(RemediationInputError):
            self.service.create_plan(finding_id=finding.id,
                                     observation_id=other_observation.id,
                                     recommendation_id=recommendation.id,
                                     action_key="x", planned_action="Upgrade", owner="Owner")
        with self.assertRaises(RemediationInputError):
            self.service.create_plan(finding_id=finding.id,
                                     observation_id=observation.id,
                                     recommendation_id=other_recommendation.id,
                                     action_key="x", planned_action="Upgrade", owner="Owner")
        self.assertEqual(second_finding.status, FindingStatus.OPEN)
        plan = self._plan(finding, observation, recommendation)
        for bad in ({"evidence_reference": ""}, {"evidence_type": "ai_generated"},
                    {"evidence_type": "commit"},
                    {"applied_at": "2026-10-13"}, {"actor": " "}):
            with self.assertRaises(RemediationInputError):
                self.service.record_application(plan.id, **{**APPLICATION, **bad})
        self.assertIsNone(self.service.get(plan.id).application)
        self.assertEqual(self.findings.get(finding.id).status,
                         FindingStatus.RECOMMENDATION_CREATED)

    def test_plan_status_failure_rolls_back_insert(self):
        finding, observation, recommendation = self._recommendation()
        self.connection.execute("""CREATE TRIGGER reject_plan_status
            BEFORE UPDATE OF status ON findings WHEN NEW.status = 'recommendation_created'
            BEGIN SELECT RAISE(ABORT, 'test rollback'); END""")
        self.connection.commit()
        with self.assertRaises(RemediationRepositoryError):
            self._plan(finding, observation, recommendation)
        self.assertEqual(self.service.list_for_finding(finding.id), ())
        self.assertEqual(self.findings.get(finding.id).status, FindingStatus.OPEN)

    def test_idempotence_multiple_actions_and_reanalysis_preserve_snapshots(self):
        finding, observation, recommendation = self._recommendation()
        first = self._plan(finding, observation, recommendation)
        self.assertEqual(self._plan(finding, observation, recommendation), first)
        with self.assertRaises(RemediationRepositoryError):
            self.service.create_plan(finding_id=finding.id, observation_id=observation.id,
                                     recommendation_id=recommendation.id, action_key="change-1",
                                     planned_action="Different action", owner="Release owner")
        second = self._plan(finding, observation, recommendation, key="change-2")
        applied = self.service.record_application(first.id, **APPLICATION)
        self.assertEqual(self.service.record_application(first.id, **APPLICATION), applied)
        with self.assertRaises(RemediationRepositoryError):
            self.service.record_application(first.id,
                                            **{**APPLICATION, "evidence_reference": "changed"})
        self.connection.execute("UPDATE assets SET patch_status = 'overdue' WHERE id = ?",
                                (self.asset.id,))
        self.connection.commit()
        _, next_observation, next_recommendation = self._recommendation("scan-2")
        third = self._plan(finding, next_observation, next_recommendation)
        self.assertNotEqual(third.before.observation_id, first.before.observation_id)
        self.assertEqual(self.service.list_for_finding(finding.id), (applied, second, third))
        self.assertEqual(self.service.get(first.id).before, first.before)
        self.assertEqual(len(self.findings.get(finding.id).status_history), 3)

    def test_database_constraints_immutability_and_transaction_rollback(self):
        finding, observation, recommendation = self._recommendation()
        plan = self._plan(finding, observation, recommendation)
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("UPDATE remediations SET before_json = '{}' WHERE id = ?",
                                    (plan.id,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("UPDATE findings SET status = 'remediation_applied' WHERE id = ?",
                                    (finding.id,))
        for unsupported in ("verification_passed", "verification_failed", "risk_accepted"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute("UPDATE findings SET status = ? WHERE id = ?",
                                        (unsupported, finding.id))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("""INSERT INTO remediation_applications VALUES
                (?, ?, ?, ?, ?, ?, ?, ?)""",
                (plan.id, "action", "actor", NOW.isoformat(), "deployment_record", "", "source",
                 NOW.isoformat()))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("""INSERT INTO remediations
                (finding_id,recommendation_id,observation_id,action_key,planned_action,owner,before_json,created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (finding.id, recommendation.id, 9999, "bad", "action", "owner",
                 json.dumps({}), NOW.isoformat()))
        self.connection.execute("""CREATE TRIGGER reject_application_status
            BEFORE UPDATE OF status ON findings WHEN NEW.status = 'remediation_applied'
            BEGIN SELECT RAISE(ABORT, 'test rollback'); END""")
        self.connection.commit()
        with self.assertRaises(RemediationRepositoryError):
            self.service.record_application(plan.id, **APPLICATION)
        self.assertIsNone(self.service.get(plan.id).application)
        self.assertEqual(self.findings.get(finding.id).status,
                         FindingStatus.RECOMMENDATION_CREATED)

    def test_incremental_migration_preserves_open_rows(self):
        legacy = connect_database()
        self.addCleanup(legacy.close)
        folder = ROOT / "database" / "migrations"
        for name in ("0001_asset_and_sbom", "0002_vulnerability_matches",
                     "0003_findings", "0004_finding_control_mappings", "0005_recommendations"):
            legacy.executescript((folder / f"{name}.sql").read_text(encoding="utf-8"))
        legacy.execute("INSERT INTO business_services (name) VALUES ('Legacy')")
        legacy.execute("""INSERT INTO assets
            (business_service_id,name,environment,internet_exposed,business_criticality,
             customer_information,credit_information,patch_status,vendor,owner)
            VALUES (1,'API','production',1,'critical',0,0,'unknown','vendor','owner')""")
        legacy.execute("""INSERT INTO findings (asset_id,cve_id,status,created_at)
            VALUES (1,'CVE-2021-44228','open',?)""", (NOW.isoformat(),))
        legacy.execute("""INSERT INTO finding_status_history (finding_id,status,recorded_at)
            VALUES (1,'open',?)""", (NOW.isoformat(),))
        legacy.execute("""INSERT INTO sboms
            (asset_id,source,bom_format,spec_version,raw_document)
            VALUES (1,'fixture','CycloneDX','1.5','{}')""")
        legacy.execute("""INSERT INTO components
            (sbom_id,position,name,version,purl,issues_json)
            VALUES (1,0,'log4j-core','2.14.1','pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1','[]')""")
        legacy.execute("""INSERT INTO vulnerability_match_runs
            (component_id,analysis_key,status,component_purl,reasons_json,
             recorded_at,payload_digest) VALUES (1,'old','matched',?,'[]',?,'digest')""",
            ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", NOW.isoformat()))
        legacy.execute("""INSERT INTO vulnerability_match_evidence
            (run_id,cve_id,evidence_json) VALUES (1,'CVE-2021-44228','{}')""")
        legacy.execute("""INSERT INTO finding_observations
            (finding_id,match_evidence_id,risk_json,asset_context_json,recorded_at)
            VALUES (1,1,'{}','{}',?)""", (NOW.isoformat(),))
        legacy.execute("""INSERT INTO recommendations
            (observation_id,input_digest,model_name,input_json,content_json,created_at)
            VALUES (1,?,'stub','{}','{}',?)""", ("a" * 64, NOW.isoformat()))
        legacy.commit()
        legacy.executescript((folder / "0006_remediations.sql").read_text(encoding="utf-8"))
        self.assertEqual(legacy.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(legacy.execute("SELECT status FROM findings WHERE id=1").fetchone()[0],
                         "open")
        self.assertEqual(legacy.execute("SELECT status FROM finding_status_history WHERE id=1")
                         .fetchone()[0], "open")
        self.assertEqual(legacy.execute("SELECT observation_id FROM recommendations WHERE id=1")
                         .fetchone()[0], 1)
        self.assertEqual(legacy.execute("SELECT finding_id FROM finding_observations WHERE id=1")
                         .fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
