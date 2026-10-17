"""Read facade: reuse persisted services and attempt-specific Phase 10 comparison."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict

from core.assets.asset_service import AssetService
from core.consulting.recommender import RecommendationService
from core.findings.service import FindingService
from core.remediation.service import RemediationService
from core.verification.comparison import ComparisonService
from core.verification.service import VerificationService
from database.models.finding import Finding
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.comparison_repository import SQLiteComparisonRepository
from database.repositories.control_mapping_repository import SQLiteControlMappingRepository
from database.repositories.dashboard_repository import SQLiteDashboardRepository
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.recommendation_repository import SQLiteRecommendationRepository
from database.repositories.remediation_repository import SQLiteRemediationRepository
from database.repositories.verification_repository import SQLiteVerificationRepository
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository


class DashboardSelectionError(ValueError):
    """An explicit ID is absent from its selected parent."""


class _DisabledGenerator:
    model = "disabled-read-only"

    def generate(self, input_data: dict) -> dict:
        raise RuntimeError("Dashboard is read-only")


class DashboardService:
    def __init__(self, connection: sqlite3.Connection) -> None:
        assets = SQLiteAssetRepository(connection)
        findings = SQLiteFindingRepository(connection)
        recommendations = SQLiteRecommendationRepository(connection)
        remediations = SQLiteRemediationRepository(connection)
        self.matches = SQLiteVulnerabilityRepository(connection)
        self.verifications = SQLiteVerificationRepository(connection)
        self.inventory = SQLiteDashboardRepository(connection)
        self.mappings = SQLiteControlMappingRepository(connection)
        self.assets = AssetService(assets)
        self.findings = FindingService(findings, self.matches, assets)
        self.recommendations = RecommendationService(
            findings=findings, mappings=self.mappings, matches=self.matches,
            recommendations=recommendations, generator=_DisabledGenerator())
        self.remediations = RemediationService(
            findings=findings, recommendations=recommendations, remediations=remediations)
        self.verification = VerificationService(
            findings=findings, recommendations=recommendations, remediations=remediations,
            matches=self.matches, verifications=self.verifications)
        self.comparison = ComparisonService(SQLiteComparisonRepository(connection))

    def services(self) -> list[dict]:
        return [asdict(item) for item in self.assets.list_business_services()]

    def asset_list(self, service_id: int | None = None) -> list[dict]:
        if service_id is not None:
            self.assets.get_business_service(service_id)
        return [asdict(item) for item in self.assets.list_assets(service_id)]

    def asset(self, asset_id: int) -> dict:
        return asdict(self.assets.get_asset(asset_id))

    def sboms(self, asset_id: int) -> list[dict]:
        self.asset(asset_id)
        return self.inventory.list_sboms(asset_id)

    def sbom(self, asset_id: int, sbom_id: int) -> dict:
        self.asset(asset_id)
        result = self.verifications.sbom_snapshot(sbom_id)
        if result["asset_id"] != asset_id:
            raise DashboardSelectionError("SBOM belongs to another asset")
        return result

    def finding_list(self, asset_id: int) -> list[dict]:
        self.asset(asset_id)
        return [{"id": item.id, "asset_id": item.asset_id, "cve_id": item.cve_id,
                 "status": item.status.value, "observation_count": len(item.observations)}
                for item in self.findings.list_for_asset(asset_id)]

    def _finding_record(self, asset_id: int, finding_id: int) -> Finding:
        self.asset(asset_id)
        finding = self.findings.get(finding_id)
        if finding.asset_id != asset_id:
            raise DashboardSelectionError("Finding belongs to another asset")
        return finding

    def finding(self, asset_id: int, finding_id: int) -> dict:
        finding = self._finding_record(asset_id, finding_id)
        result = asdict(finding)
        # Every observation remains separate. Never silently pick the newest risk/analysis.
        result["observations"] = [
            {**asdict(item), "match_run": asdict(self.matches.get(item.match_run_id)),
             "risk_reasons": list(item.risk.reasons)} for item in finding.observations]
        result["control_mappings"] = [asdict(item) for item in self.mappings.list_for_finding(finding_id)]
        return result

    def recommendation_list(self, asset_id: int, finding_id: int) -> list[dict]:
        self._finding_record(asset_id, finding_id)
        return [asdict(item) for item in self.recommendations.list_for_finding(finding_id)]

    def remediation_list(self, asset_id: int, finding_id: int) -> list[dict]:
        self._finding_record(asset_id, finding_id)
        return [{**asdict(item), "status": item.status.value}
                for item in self.remediations.list_for_finding(finding_id)]

    def remediation(self, asset_id: int, finding_id: int, remediation_id: int) -> dict:
        self._finding_record(asset_id, finding_id)
        result = self.remediations.get(remediation_id)
        if result.finding_id != finding_id:
            raise DashboardSelectionError("Remediation belongs to another Finding")
        return {**asdict(result), "status": result.status.value}

    def attempts(self, asset_id: int, finding_id: int, remediation_id: int) -> list[dict]:
        self.remediation(asset_id, finding_id, remediation_id)
        return [{"id": item.id, "remediation_id": item.remediation_id, "finding_id": item.finding_id,
                 "attempt_key": item.attempt_key, "status": item.status.value,
                 "started_at": item.started_at, "completed_at": item.completed_at,
                 "has_after_evidence": item.after is not None}
                for item in self.verification.list_for_remediation(remediation_id)]

    def attempt(self, asset_id: int, finding_id: int, remediation_id: int, verification_id: int) -> dict:
        self.remediation(asset_id, finding_id, remediation_id)
        selection = dict(asset_id=asset_id, finding_id=finding_id,
                         remediation_id=remediation_id, verification_id=verification_id)
        comparison = self.comparison.compare_finding(**selection)
        attempt = self.verification.get(verification_id)
        return {"selection": comparison["selection"], "status": attempt.status.value,
                "required_functional_tests": list(attempt.required_functional_tests),
                "functional_tests": attempt.after.payload.get("functional_tests", []) if attempt.after else None,
                "functional_unknown_reason": "After Evidence missing" if attempt.after is None else None,
                "comparison": comparison,
                "asset_comparison": self.comparison.compare_asset(
                    asset_id=asset_id, selections=((finding_id, remediation_id, verification_id),))}
