"""Application service for recording and reading reference control mappings."""

from __future__ import annotations

import logging

from core.compliance.mapper import map_observation
from database.models.control_mapping import FindingControlMapping
from database.repositories.control_mapping_repository import SQLiteControlMappingRepository
from database.repositories.finding_repository import SQLiteFindingRepository

logger = logging.getLogger(__name__)


class ControlMappingService:
    def __init__(self, findings: SQLiteFindingRepository,
                 mappings: SQLiteControlMappingRepository) -> None:
        self.findings = findings
        self.mappings = mappings

    def map_finding(self, finding_id: int) -> tuple[FindingControlMapping, ...]:
        if not isinstance(finding_id, int) or isinstance(finding_id, bool) or finding_id <= 0:
            raise ValueError("positive finding ID is required")
        finding = self.findings.get(finding_id)
        candidates = tuple(candidate for observation in finding.observations
                           for candidate in map_observation(observation))
        result = self.mappings.save_for_finding(finding.id, candidates)
        logger.info("Control mappings recorded: finding_id=%d count=%d", finding.id, len(result))
        return result

    def list_for_finding(self, finding_id: int) -> tuple[FindingControlMapping, ...]:
        if not isinstance(finding_id, int) or isinstance(finding_id, bool) or finding_id <= 0:
            raise ValueError("positive finding ID is required")
        self.findings.get(finding_id)
        return self.mappings.list_for_finding(finding_id)
