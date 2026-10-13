"""Validate provenance, capture after evidence and persist explainable decisions."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict

from core.verification.verifier import verify_remediation
from database.models.remediation import Remediation
from database.models.verification import FunctionalEvidence, FunctionalStatus, ScannerEvidence, ScannerStatus, Verification
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.recommendation_repository import SQLiteRecommendationRepository
from database.repositories.remediation_repository import SQLiteRemediationRepository
from database.repositories.verification_repository import SQLiteVerificationRepository, evidence_json
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository

logger = logging.getLogger(__name__)


class VerificationInputError(ValueError):
    pass


def _positive_id(value: object, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise VerificationInputError(f"positive {name} is required")


class VerificationService:
    def __init__(self, *, findings: SQLiteFindingRepository,
                 recommendations: SQLiteRecommendationRepository, remediations: SQLiteRemediationRepository,
                 matches: SQLiteVulnerabilityRepository, verifications: SQLiteVerificationRepository) -> None:
        self.findings, self.recommendations, self.remediations = findings, recommendations, remediations
        self.matches, self.verifications = matches, verifications

    def _source(self, remediation_id: int, asset_id: int) -> Remediation:
        remediation = self.remediations.get(remediation_id)
        if remediation.application is None:
            raise VerificationInputError("remediation application evidence is required before verification")
        finding = self.findings.get(remediation.finding_id)
        recommendation = self.recommendations.get(remediation.recommendation_id)
        source = self.recommendations.source_for_observation(remediation.observation_id)
        observation = next((item for item in finding.observations if item.id == remediation.observation_id), None)
        before = remediation.before
        if (finding.asset_id != asset_id or source["asset_id"] != asset_id
                or recommendation.finding_id != finding.id
                or recommendation.observation_id != remediation.observation_id or observation is None):
            raise VerificationInputError("remediation, recommendation, observation, Finding and asset do not belong together")
        expected = (observation.id, observation.match_evidence_id, observation.analysis_key,
                    observation.component_id, source["component_name"], source["version"], source["purl"],
                    finding.cve_id, observation.risk.score, observation.risk.priority,
                    tuple(observation.risk.reasons), observation.risk.rule_version)
        actual = tuple(asdict(before).values())
        expected_input = {"finding_id": finding.id, "observation_id": observation.id,
                          "component": before.component_name, "version": before.component_version,
                          "purl": before.component_purl, "cve": before.cve_id,
                          "risk_score": before.risk_score, "risk_priority": before.risk_priority,
                          "risk_reasons": list(before.risk_reasons), "risk_rule_version": before.risk_rule_version}
        if actual != expected or any(recommendation.input_data.get(key) != value for key, value in expected_input.items()):
            raise VerificationInputError("immutable before snapshot and stored source evidence disagree")
        if (source["finding_id"] != finding.id or source["match_evidence_id"] != observation.match_evidence_id
                or source["component_id"] != observation.component_id or source["analysis_key"] != observation.analysis_key):
            raise VerificationInputError("observation and matching source disagree")
        return remediation

    def start(self, *, remediation_id: int, asset_id: int, attempt_key: str,
              required_functional_tests: tuple[str, ...]) -> Verification:
        _positive_id(remediation_id, "remediation ID")
        _positive_id(asset_id, "asset ID")
        if not isinstance(attempt_key, str) or not attempt_key.strip():
            raise VerificationInputError("non-empty verification attempt key is required")
        if (not isinstance(required_functional_tests, tuple) or not required_functional_tests
                or any(not isinstance(item, str) or not item.strip() for item in required_functional_tests)
                or len(set(required_functional_tests)) != len(required_functional_tests)):
            raise VerificationInputError("explicit non-empty unique functional test IDs are required")
        source = self._source(remediation_id, asset_id)
        before_sbom = self.verifications.sbom_snapshot(
            self.verifications.sbom_id_for_component(source.before.component_id))
        result = self.verifications.start(source, asset_id=asset_id, attempt_key=attempt_key,
                                          required_tests=tuple(sorted(required_functional_tests)), before_sbom=before_sbom)
        logger.info("Verification started: verification_id=%d remediation_id=%d", result.id, remediation_id)
        return result

    def record_after(self, verification_id: int, *, asset_id: int, sbom_id: int | None = None,
                     sbom_collected_at: str = "", sbom_reference: str = "",
                     match_run_ids: tuple[int, ...] = (), scanner_results: tuple[ScannerEvidence, ...] = (),
                     functional_tests: tuple[FunctionalEvidence, ...] = ()) -> Verification:
        _positive_id(verification_id, "verification ID")
        _positive_id(asset_id, "asset ID")
        verification = self.verifications.get(verification_id)
        self._source(verification.remediation_id, asset_id)
        if any(not isinstance(items, tuple) for items in (match_run_ids, scanner_results, functional_tests)):
            raise VerificationInputError("evidence collections must be tuples")
        sbom = None
        if sbom_id is not None:
            _positive_id(sbom_id, "after SBOM ID")
            sbom = self.verifications.sbom_snapshot(sbom_id)
            if sbom["asset_id"] != asset_id:
                raise VerificationInputError("after SBOM belongs to another asset")
            before_sbom = self.verifications.sbom_id_for_component(verification.before.component_id)
            if sbom_id == before_sbom:
                raise VerificationInputError("a separate after SBOM is required")
            sbom.update(collected_at=sbom_collected_at, reference=sbom_reference)
        if len(set(match_run_ids)) != len(match_run_ids):
            raise VerificationInputError("duplicate match run IDs")
        runs = []
        for run_id in sorted(match_run_ids):
            _positive_id(run_id, "match run ID")
            run = self.matches.get(run_id)
            if sbom is None or self.verifications.sbom_id_for_component(run.component_id) != sbom_id:
                raise VerificationInputError("re-matching run does not belong to the after SBOM")
            runs.append(asdict(run))
        for items, expected_type, enum_type in ((scanner_results, ScannerEvidence, ScannerStatus),
                                                (functional_tests, FunctionalEvidence, FunctionalStatus)):
            for item in items:
                if not isinstance(item, expected_type) or not isinstance(item.status, enum_type):
                    raise VerificationInputError("typed scanner or functional evidence is required")
                _positive_id(item.asset_id, "evidence asset ID")
                _positive_id(item.sbom_id, "evidence SBOM ID")
                fields = (item.source, item.reference, item.collected_at,
                          item.cve_id if isinstance(item, ScannerEvidence) else item.test_id)
                if any(not isinstance(field, str) for field in fields):
                    raise VerificationInputError("evidence labels and provenance must be strings")
                if item.asset_id != asset_id or item.sbom_id != sbom_id:
                    raise VerificationInputError("test or scanner evidence belongs to another asset or after SBOM")
        payload = {"asset_id": asset_id, "sbom": sbom, "match_runs": runs,
                   "scanner_results": [asdict(item) for item in scanner_results],
                   "functional_tests": [asdict(item) for item in functional_tests]}
        # Serialize now so decision input is exactly the detached, persisted snapshot.
        payload = json.loads(evidence_json(payload))
        result = self.verifications.save_after(verification_id, payload)
        logger.info("After evidence recorded: verification_id=%d", verification_id)
        return result

    def complete(self, verification_id: int) -> Verification:
        _positive_id(verification_id, "verification ID")
        verification = self.verifications.get(verification_id)
        if verification.decision:
            return verification
        if verification.after is None:
            raise VerificationInputError("record after evidence, including missing evidence, before completing")
        self._source(verification.remediation_id, verification.after.payload["asset_id"])
        decision = verify_remediation(
            verification.before, applied_at=verification.application.applied_at,
            required_functional_tests=verification.required_functional_tests, after=verification.after.payload,
            before_components=verification.before_sbom["components"], recorded_at=verification.after.recorded_at)
        result = self.verifications.complete(verification_id, decision)
        logger.info("Verification completed: verification_id=%d status=%s", verification_id, result.status.value)
        return result

    def get(self, verification_id: int) -> Verification:
        _positive_id(verification_id, "verification ID")
        return self.verifications.get(verification_id)

    def list_for_remediation(self, remediation_id: int) -> tuple[Verification, ...]:
        _positive_id(remediation_id, "remediation ID")
        self.remediations.get(remediation_id)
        return self.verifications.list_for_remediation(remediation_id)
