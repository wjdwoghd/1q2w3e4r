"""Connect persisted matching, asset context and deterministic risk to Findings."""

from __future__ import annotations

import logging

from core.risk.engine import RiskInputError, calculate_risk_priorities
from core.vulnerability.matcher import MatchStatus
from database.models.finding import Finding
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository

logger = logging.getLogger(__name__)


class FindingInputError(ValueError):
    pass


class FindingService:
    def __init__(self, findings: SQLiteFindingRepository,
                 matches: SQLiteVulnerabilityRepository,
                 assets: SQLiteAssetRepository) -> None:
        self.findings = findings
        self.matches = matches
        self.assets = assets

    def create_from_match_run(self, *, asset_id: int, match_run_id: int) -> tuple[Finding, ...]:
        if (not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0
                or not isinstance(match_run_id, int) or isinstance(match_run_id, bool)
                or match_run_id <= 0):
            raise FindingInputError("positive asset and match run IDs are required")
        run = self.matches.get(match_run_id)
        if run.result.status is not MatchStatus.MATCHED:
            raise FindingInputError("only a successful MATCHED run can create Findings")
        if self.findings.asset_id_for_component(run.component_id) != asset_id:
            raise FindingInputError("match component belongs to another asset")
        asset = self.assets.get_asset(asset_id)
        try:
            risks = calculate_risk_priorities(run.result, asset.context)
        except RiskInputError as exc:
            raise FindingInputError("risk calculation failed") from exc
        result = self.findings.save(asset_id=asset_id, run=run, risks=risks,
                                    context=asset.context)
        logger.info("Findings recorded: asset_id=%d run_id=%d count=%d",
                    asset_id, match_run_id, len(result))
        return result

    def get(self, finding_id: int) -> Finding:
        return self.findings.get(finding_id)

    def get_by_asset_cve(self, asset_id: int, cve_id: str) -> Finding:
        return self.findings.get_by_asset_cve(asset_id, cve_id)

    def list_for_asset(self, asset_id: int) -> tuple[Finding, ...]:
        return self.findings.list_for_asset(asset_id)
