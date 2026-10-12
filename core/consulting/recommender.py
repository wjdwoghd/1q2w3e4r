"""Generate and validate observation-bound recommendations."""

from __future__ import annotations

import hashlib
import logging
import re
from copy import deepcopy
from typing import Protocol

from core.consulting.analyzer import build_recommendation_input
from core.consulting.prompts import ACTION_OPTIONS
from database.models.recommendation import Recommendation
from database.repositories.control_mapping_repository import SQLiteControlMappingRepository
from database.repositories.finding_repository import SQLiteFindingRepository
from database.repositories.recommendation_repository import (
    SQLiteRecommendationRepository, canonical_json,
)
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository

logger = logging.getLogger(__name__)
ACTION_FIELDS = tuple(ACTION_OPTIONS)
FORBIDDEN_STATUS = re.compile(
    r"\b(?:already|completed|confirmed|verified|resolved|fixed|patched|remediated|"
    r"passed|failed|not vulnerable|end.of.life|eol|scanner found|scan found)\b|"
    r"\b(?:PCI|NIST|ISO|SOC|CIS|OWASP|ISMS|FIN)\b|"
    r"(?:적용되었|완료되었|확인되었|해결되었|검증\s*통과|검증\s*실패|"
    r"취약점\s*제거|패치\s*완료|지원\s*종료)", re.IGNORECASE)


class RecommendationOutputError(ValueError):
    pass


class ActionGenerator(Protocol):
    model: str

    def generate(self, input_data: dict) -> dict: ...


def validate_actions(value: object) -> dict:
    """Fail closed on identifiers, numbers and completed-state claims in AI prose."""
    if not isinstance(value, dict) or set(value) != set(ACTION_FIELDS):
        raise RecommendationOutputError("recommendation output fields are invalid")
    for field in ACTION_FIELDS:
        items = value[field]
        if (not isinstance(items, list) or not items
                or any(not isinstance(item, str) or not item.strip() for item in items)):
            raise RecommendationOutputError(f"{field} must contain non-empty action text")
        for item in items:
            if (item not in ACTION_OPTIONS[field] or re.search(r"\d", item)
                    or FORBIDDEN_STATUS.search(item)):
                raise RecommendationOutputError("AI action is not an approved fact-free proposal")
    return value


def assemble_content(input_data: dict, actions: dict) -> dict:
    """All observed facts are rendered by code; AI only supplies future actions."""
    return {
        "finding": (f"{input_data['asset']} uses {input_data['component']} "
                    f"{input_data['version'] or 'version unknown'}; "
                    f"{input_data['cve']} was matched in this observation."),
        "financial_service_impact": (
            f"{input_data['business_service']} includes {input_data['asset']} "
            f"({input_data['environment']}, internet exposed: "
            f"{input_data['internet_exposed']}). Review the service impact."),
        "priority_reason": (f"{input_data['risk_priority']} (score {input_data['risk_score']}): "
                            + "; ".join(input_data["risk_reasons"])),
        "related_controls": input_data["controls"],
        **actions,
    }


class RecommendationService:
    def __init__(self, *, findings: SQLiteFindingRepository,
                 mappings: SQLiteControlMappingRepository,
                 matches: SQLiteVulnerabilityRepository,
                 recommendations: SQLiteRecommendationRepository,
                 generator: ActionGenerator) -> None:
        self.findings = findings
        self.mappings = mappings
        self.matches = matches
        self.recommendations = recommendations
        self.generator = generator

    def create_for_observation(self, observation_id: int) -> Recommendation:
        input_data = build_recommendation_input(
            observation_id, findings=self.findings, mappings=self.mappings,
            matches=self.matches, recommendations=self.recommendations)
        digest = hashlib.sha256(canonical_json(input_data).encode("utf-8")).hexdigest()
        prior = self.recommendations.get_for_observation(observation_id)
        if prior is not None:
            if prior.input_digest != digest:
                raise RecommendationOutputError("stored recommendation has different input evidence")
            return prior
        actions = validate_actions(self.generator.generate(deepcopy(input_data)))
        content = assemble_content(input_data, actions)
        result = self.recommendations.save(
            observation_id=observation_id, input_data=input_data, content=content,
            model_name=self.generator.model)
        logger.info("Recommendation created: observation_id=%d", observation_id)
        return result

    def get_for_observation(self, observation_id: int) -> Recommendation | None:
        return self.recommendations.get_for_observation(observation_id)

    def list_for_finding(self, finding_id: int) -> tuple[Recommendation, ...]:
        self.findings.get(finding_id)
        return self.recommendations.list_for_finding(finding_id)
