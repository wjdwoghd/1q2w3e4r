"""Resumable orchestration of existing services, without new analysis policies."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import urlopen
from uuid import uuid4

from core.assets.asset_service import AssetService
from core.compliance.service import ControlMappingService
from core.consulting.prompts import ACTION_OPTIONS
from core.consulting.recommender import RecommendationService
from core.findings.service import FindingService
from core.remediation.service import RemediationService
from core.sbom.generator import SBOMGenerationError, generate_cyclonedx_json
from core.sbom.normalizer import ComponentNormalizationError, normalize_components
from core.sbom.parser import SBOMParsingError, parse_sbom
from core.verification.comparison import ComparisonService
from core.verification.run_store import RunConflict, RunStore, atomic_bytes, atomic_document
from core.verification.service import VerificationService
from core.vulnerability.cve_client import NVDClient, OSVClient
from core.vulnerability.kev_client import KEVClient
from core.vulnerability.matcher import MatchStatus, match_component_to_cves
from database.database import connect_database, initialize_database
from database.models.verification import FunctionalEvidence, FunctionalStatus
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.comparison_repository import SQLiteComparisonRepository
from database.repositories.control_mapping_repository import SQLiteControlMappingRepository
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.recommendation_repository import SQLiteRecommendationRepository
from database.repositories.remediation_repository import SQLiteRemediationRepository
from database.repositories.sbom_repository import SQLiteSBOMRepository
from database.repositories.verification_repository import SQLiteVerificationRepository, evidence_json
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository

logger = logging.getLogger(__name__)
HTTP_CONTRACTS = {
    "health-contract": ("/health", {"status": "ok"}),
    "banking-api-smoke": ("/banking/smoke", {"result": "ok", "mode": "synthetic"}),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def runtime_hashes(source: Path) -> dict[str, str]:
    if not source.is_dir():
        raise RunConflict("Runtime directory is required")
    result = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise RunConflict("Runtime symlinks require a separately reviewed scope")
        if path.is_file():
            result[path.relative_to(source).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not result:
        raise RunConflict("Runtime is empty")
    return result


def preserve_runtime(source: Path, destination: Path, expected: dict) -> None:
    if runtime_hashes(source) != expected:
        raise RunConflict("Runtime changed during this operation; start a separate analysis")
    for relative in expected:
        atomic_bytes(destination / relative, (source / relative).read_bytes())
    if runtime_hashes(destination) != expected or runtime_hashes(source) != expected:
        raise RunConflict("Runtime changed during preservation")


class LocalPlanGenerator:
    """Explicit demo mode; never presents a local choice as an AI call."""
    model = "local-plan-demo"

    def generate(self, input_data: dict) -> dict:
        return {field: [options[0]] for field, options in ACTION_OPTIONS.items()}


class VerificationWorkflow:
    def __init__(self, store: RunStore, *, db: str | Path, asset_id: int) -> None:
        self.store = store
        self.state = store.read("run.json")
        self.db = Path(db).resolve()
        if self.state["db"] != str(self.db) or self.state["asset_id"] != asset_id:
            raise RunConflict("Explicit database/asset does not match this run")
        if not self.db.is_file():
            raise RunConflict("Existing run database is required")
        self.asset_id = asset_id
        self.connection = connect_database(self.db)
        self.assets = SQLiteAssetRepository(self.connection)
        self.assets.get_asset(asset_id)
        self.sboms = SQLiteSBOMRepository(self.connection)
        self.matches = SQLiteVulnerabilityRepository(self.connection)
        self.findings = SQLiteFindingRepository(self.connection)
        self.mappings = SQLiteControlMappingRepository(self.connection)
        self.recommendations = SQLiteRecommendationRepository(self.connection)
        self.remediations = SQLiteRemediationRepository(self.connection)
        self.verifications = SQLiteVerificationRepository(self.connection)
        self.finding_service = FindingService(self.findings, self.matches, self.assets)
        self.remediation_service = RemediationService(
            findings=self.findings, recommendations=self.recommendations, remediations=self.remediations)
        self.verification_service = VerificationService(
            findings=self.findings, recommendations=self.recommendations,
            remediations=self.remediations, matches=self.matches, verifications=self.verifications)

    def close(self) -> None:
        self.connection.close()

    @staticmethod
    def initialize(store: RunStore, *, db: str | Path, asset_id: int | None = None,
                   context: dict | None = None, business_service: str | None = None) -> dict:
        db = Path(db).resolve()
        binding = {"db": str(db), "requested_asset_id": asset_id,
                   "context": context, "business_service": business_service}
        if asset_id is None and (context is None or not business_service):
            raise RunConflict("Provide an existing asset ID or explicit context and service")
        if asset_id is not None and (context is not None or not db.is_file()):
            raise RunConflict("Existing asset mode requires an existing DB and no new context")
        store.save("init.json", binding)
        if (store.directory / "run.json").exists():
            return store.read("run.json")
        db.parent.mkdir(parents=True, exist_ok=True)
        connection = connect_database(db)
        try:
            repository = SQLiteAssetRepository(connection)
            service = AssetService(repository)
            if asset_id is None:
                initialize_database(connection)
                services = [item for item in service.list_business_services() if item.name == business_service]
                business = services[0] if services else service.register_business_service(business_service)
                existing = [item for item in service.list_assets(business.id) if item.context.name == context["name"]]
                asset = existing[0] if existing else service.register_asset(business.id, **context)
                from core.assets.context import AssetContext
                if asset.context != AssetContext.create(**context):
                    raise RunConflict("Existing asset context differs; do not replace it")
                asset_id = asset.id
            else:
                service.get_asset(asset_id)
            state = {"format": 1, "run_id": uuid4().hex, "db": str(db), "asset_id": asset_id,
                     "created_at": utc_now(), "operations": {}}
            store.save("run.json", state)
            logger.info("E2E run initialized: asset_id=%d", asset_id)
            return state
        finally:
            connection.close()

    def _capture(self, key: str, op: dict, *, directory: str, source: Path, syft: str) -> tuple[int, str]:
        if "runtime_hashes" not in op:
            op["runtime_hashes"] = runtime_hashes(source)
            self.store.checkpoint(key, op)
        preserve_runtime(source, self.store.directory / directory / "runtime", op["runtime_hashes"])
        capture_file = self.store.directory / directory / "capture.json"
        if not capture_file.exists():
            generated = generate_cyclonedx_json(source, executable=syft)
            self.store.save(f"{directory}/capture.json", {
                "content": generated.content, "source": generated.source,
                "tool": generated.tool, "collected_at": utc_now(),
            })
        capture = self.store.read(f"{directory}/capture.json")
        capture_digest = hashlib.sha256(capture_file.read_bytes()).hexdigest()
        if op.get("capture_digest", capture_digest) != capture_digest:
            raise RunConflict("Captured SBOM evidence changed during recovery")
        op["capture_digest"] = capture_digest
        self.store.checkpoint(key, op)
        atomic_document(self.store.directory / directory / "sbom.json", capture["content"])
        parsed = parse_sbom(capture["content"])
        normalized = normalize_components(parsed.components)
        candidates = self.sboms.find_by_document(asset_id=self.asset_id, source=capture["source"],
                                                 raw_document=capture["content"])
        if len(candidates) > 1:
            raise RunConflict("Multiple exact SBOM imports exist; refusing to select the latest")
        sbom = candidates[0] if candidates else self.sboms.save(
            asset_id=self.asset_id, source=capture["source"], raw_document=capture["content"],
            parsed=parsed, normalized=normalized)
        op["sbom_id"], op["collected_at"] = sbom.id, capture["collected_at"]
        self.store.checkpoint(key, op)
        return sbom.id, capture["collected_at"]

    def _match(self, *, sbom_id: int, analysis_key: str, directory: str) -> tuple:
        snapshot = self.verifications.sbom_snapshot(sbom_id)
        normalized = normalize_components(parse_sbom(snapshot["raw_document"]).components)
        runs = []
        for component, item in zip(self.sboms.list_components(sbom_id), normalized.components):
            existing = [run for run in self.matches.list_for_component(component.id)
                        if run.analysis_key == analysis_key]
            if existing:
                run = existing[0]
            else:
                logger.info("Matching component: id=%d name=%s", component.id, component.name)
                result = match_component_to_cves(item, osv=OSVClient(), nvd=NVDClient(), kev=KEVClient())
                run = self.matches.save(component_id=component.id, analysis_key=analysis_key, result=result)
            self.store.save(f"{directory}/match-{run.id}.json", asdict(run))
            runs.append(run)
        self.store.save(f"{directory}/matches.json", [asdict(run) for run in runs])
        return tuple(runs)

    @staticmethod
    def _base_url(value: str) -> str:
        parsed = urlsplit(value)
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"} or parsed.port is None):
            raise RunConflict("Functional checks require an explicit loopback HTTP address and port")
        return value.rstrip("/")

    def _functional(self, *, sbom_id: int, base_url: str, directory: str,
                    required: tuple[str, ...]) -> tuple[FunctionalEvidence, ...]:
        address = self._base_url(base_url)
        if not required or any(item not in HTTP_CONTRACTS for item in required):
            raise RunConflict("The Lab collector supports only the explicitly selected HTTP contracts")
        evidence = []
        for test_id in required:
            filename = f"{directory}/functional-{test_id}.json"
            path = self.store.directory / filename
            if not path.exists():
                route, expected = HTTP_CONTRACTS[test_id]
                try:
                    with urlopen(address + route, timeout=10) as response:
                        body = json.load(response)
                        status = FunctionalStatus.PASSED if response.status == 200 and body == expected else FunctionalStatus.FAILED
                        detail = {"http_status": response.status, "response": body, "expected": expected}
                except HTTPError as exc:
                    status, detail = FunctionalStatus.FAILED, {"http_status": exc.code}
                except (URLError, TimeoutError, OSError) as exc:
                    status, detail = FunctionalStatus.ERROR, {"error_type": type(exc).__name__}
                except (ValueError, UnicodeError) as exc:
                    status, detail = FunctionalStatus.FAILED, {"error_type": type(exc).__name__}
                self.store.save(filename, {
                    "asset_id": self.asset_id, "sbom_id": sbom_id, "test_id": test_id,
                    "status": status.value, "source": "actual local HTTP contract check",
                    "reference": str(path), "collected_at": utc_now(), "url": address + route, **detail,
                })
            record = self.store.read(filename)
            evidence.append(FunctionalEvidence(**{
                name: FunctionalStatus(record[name]) if name == "status" else record[name]
                for name in FunctionalEvidence.__dataclass_fields__}))
        return tuple(evidence)

    def before(self, *, source: str, syft: str, syft_config: str, base_url: str) -> dict:
        config = Path(syft_config).resolve()
        parameters = {"source": str(Path(source).resolve()), "syft": syft,
                      "syft_config": str(config), "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
                      "base_url": self._base_url(base_url)}
        key = "before"
        op = self.store.operation(key, parameters)
        if "result" in op:
            return op["result"]
        os.environ["SYFT_CONFIG"] = str(config)
        sbom_id, collected = self._capture(key, op, directory="before", source=Path(parameters["source"]), syft=syft)
        runs = self._match(sbom_id=sbom_id, analysis_key=self.state["run_id"] + ":before", directory="before")
        if not runs or any(run.result.status not in (MatchStatus.MATCHED, MatchStatus.NO_MATCH) for run in runs):
            raise RunConflict("Before analysis incomplete; evidence retained. Use a new run for a fresh lookup")
        for run in runs:
            if run.result.status is MatchStatus.MATCHED:
                self.finding_service.create_from_match_run(asset_id=self.asset_id, match_run_id=run.id)
        functional = self._functional(sbom_id=sbom_id, base_url=base_url, directory="before",
                                      required=tuple(HTTP_CONTRACTS))
        if any(item.status is not FunctionalStatus.PASSED for item in functional):
            raise RunConflict("Before functional baseline failed; actual evidence retained")
        if runtime_hashes(Path(parameters["source"])) != op["runtime_hashes"]:
            raise RunConflict("Before runtime changed during analysis")
        op["result"] = {"asset_id": self.asset_id, "sbom_id": sbom_id,
                        "collected_at": collected, "match_run_ids": [run.id for run in runs],
                        "matches": [{"match_run_id": run.id, "component_id": run.component_id,
                                     "purl": run.result.component_purl, "status": run.result.status.value,
                                     "cve_ids": [match.cve.cve_id for match in run.result.matches]}
                                    for run in runs]}
        self.store.checkpoint(key, op)
        return op["result"]

    def plan(self, *, match_run_id: int, cve_id: str, action_key: str,
             planned_action: str, owner: str, mode: str) -> dict:
        if mode not in {"local-plan-demo", "live-openai"}:
            raise RunConflict("Explicit Recommendation mode required")
        parameters = locals().copy()
        parameters.pop("self")
        key = "plan-" + hashlib.sha256(action_key.encode()).hexdigest()
        op = self.store.operation(key, parameters)
        if "result" in op:
            return op["result"]
        run = self.matches.get(match_run_id)
        self.finding_service.create_from_match_run(asset_id=self.asset_id, match_run_id=run.id)
        finding = self.findings.get_by_asset_cve(self.asset_id, cve_id)
        observations = [item for item in finding.observations if item.match_run_id == run.id]
        if len(observations) != 1:
            raise RunConflict("Exactly one explicitly selected observation is required")
        observation = observations[0]
        ControlMappingService(self.findings, self.mappings).map_finding(finding.id)
        if mode == "local-plan-demo":
            generator = LocalPlanGenerator()
        elif mode == "live-openai":
            from core.consulting.openai_client import OpenAIRecommendationClient
            generator = OpenAIRecommendationClient()
        else:
            raise RunConflict("Explicit Recommendation mode required")
        recommendation = RecommendationService(
            findings=self.findings, mappings=self.mappings, matches=self.matches,
            recommendations=self.recommendations, generator=generator).create_for_observation(observation.id)
        if recommendation.model_name != generator.model:
            raise RunConflict("Stored Recommendation mode/model differs; select another observation")
        plan = self.remediation_service.create_plan(
            finding_id=finding.id, observation_id=observation.id, recommendation_id=recommendation.id,
            action_key=action_key, planned_action=planned_action, owner=owner)
        result = {"asset_id": self.asset_id, "finding_id": finding.id, "observation_id": observation.id,
                  "remediation_id": plan.id, "recommendation_id": recommendation.id,
                  "recommendation_mode": mode, "before": asdict(plan.before)}
        self.store.save(f"plans/{plan.id}.json", result)
        op["result"] = result
        self.store.checkpoint(key, op)
        return result

    def plan_source(self, remediation_id: int) -> tuple:
        plan = self.remediations.get(remediation_id)
        if self.findings.get(plan.finding_id).asset_id != self.asset_id:
            raise RunConflict("Remediation belongs to another asset")
        sbom = self.verifications.sbom_snapshot(self.verifications.sbom_id_for_component(plan.before.component_id))
        return plan, sbom

    def apply(self, *, remediation_id: int, evidence: dict) -> dict:
        self.plan_source(remediation_id)
        result = self.remediation_service.record_application(remediation_id, **evidence)
        return {"remediation_id": result.id, "status": result.status.value}

    def start(self, *, remediation_id: int, attempt_key: str, required_tests: tuple[str, ...]) -> dict:
        self.plan_source(remediation_id)
        attempt = self.verification_service.start(remediation_id=remediation_id, asset_id=self.asset_id,
                                                 attempt_key=attempt_key, required_functional_tests=required_tests)
        result = {"asset_id": self.asset_id, "finding_id": attempt.finding_id,
                  "remediation_id": remediation_id, "verification_id": attempt.id,
                  "attempt_key": attempt.attempt_key, "status": attempt.status.value}
        self.store.save(f"attempts/{attempt.id}/selection.json", {key: value for key, value in result.items() if key != "status"})
        return result

    def after(self, *, remediation_id: int, verification_id: int, source: str,
              syft: str, syft_config: str, base_url: str,
              validate_source: Callable[[], None] | None = None) -> dict:
        plan, _ = self.plan_source(remediation_id)
        attempt = self.verification_service.get(verification_id)
        if attempt.remediation_id != plan.id:
            raise RunConflict("Verification belongs to another Remediation")
        config = Path(syft_config).resolve()
        parameters = {"remediation_id": remediation_id, "verification_id": verification_id,
                      "source": str(Path(source).resolve()), "syft": syft, "base_url": self._base_url(base_url),
                      "syft_config": str(config), "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest()}
        key, directory = f"after-{verification_id}", f"attempts/{verification_id}/after"
        op = self.store.operation(key, parameters)
        if attempt.after is None:
            lab_operation = self.store.read("run.json")["operations"].get(f"lab-switch-{remediation_id}")
            if lab_operation:
                expected_source = Path(lab_operation["parameters"]["root"]) / "labs/log4shell/patched/target/runtime"
                if (Path(parameters["source"]) != expected_source.resolve()
                        or urlsplit(base_url).port != lab_operation["parameters"]["port"]
                        or runtime_hashes(expected_source) != lab_operation["target_hashes"]):
                    raise RunConflict("After source differs from the recorded Lab application")
            if validate_source:
                validate_source()
            os.environ["SYFT_CONFIG"] = str(config)
            sbom_id, collected, runs, functional = None, "", (), ()
            error_file = self.store.directory / directory / "generation-error.json"
            if not error_file.exists():
                try:
                    sbom_id, collected = self._capture(key, op, directory=directory, source=Path(parameters["source"]), syft=syft)
                except (SBOMGenerationError, SBOMParsingError, ComponentNormalizationError) as exc:
                    self.store.save(f"{directory}/generation-error.json", {"error_type": type(exc).__name__,
                                                                           "reason": str(exc), "recorded_at": utc_now()})
            if sbom_id is not None:
                runs = self._match(sbom_id=sbom_id, analysis_key=self.state["run_id"] + f":after:{verification_id}", directory=directory)
                functional = self._functional(sbom_id=sbom_id, base_url=base_url, directory=directory,
                                              required=attempt.required_functional_tests)
                if runtime_hashes(Path(parameters["source"])) != op["runtime_hashes"]:
                    raise RunConflict("After runtime changed during collection; retain evidence and review")
            if validate_source:
                validate_source()
            self.verification_service.record_after(
                verification_id, asset_id=self.asset_id, sbom_id=sbom_id,
                sbom_collected_at=collected, sbom_reference=str(self.store.directory / directory / "sbom.json") if sbom_id else "",
                match_run_ids=tuple(run.id for run in runs), scanner_results=(), functional_tests=functional)
        completed = self.verification_service.complete(verification_id)
        self.store.save(f"attempts/{verification_id}/result.json", asdict(completed))
        result = self.compare(remediation_id=remediation_id, verification_id=verification_id)
        op["result"] = result
        self.store.checkpoint(key, op)
        return result

    def compare(self, *, remediation_id: int, verification_id: int) -> dict:
        plan, _ = self.plan_source(remediation_id)
        service = ComparisonService(SQLiteComparisonRepository(self.connection))
        parameters = {"asset_id": self.asset_id, "finding_id": plan.finding_id,
                      "remediation_id": remediation_id, "verification_id": verification_id}
        first = service.compare_finding(**parameters)
        second = service.compare_finding(**parameters)
        if first != second:
            raise RunConflict("Comparison is not deterministic")
        asset = service.compare_asset(asset_id=self.asset_id, selections=((plan.finding_id, remediation_id, verification_id),))
        directory = f"attempts/{verification_id}"
        if first["verification"]["decision"] is None:
            attempt = self.verifications.get(verification_id)
            directory += "/previews/" + (attempt.after.digest if attempt.after else "no-after")
        self.store.save(f"{directory}/comparison.json", first)
        self.store.save(f"{directory}/asset-comparison.json", asset)
        return {"selection": parameters, "status": first["verification"]["status"],
                "decision": first["verification"]["decision"],
                "finding_cve_count": first["finding"]["cve_count"],
                "asset_cve_count": first["asset"]["cve_count"],
                "comparison": str(self.store.directory / directory / "comparison.json")}
