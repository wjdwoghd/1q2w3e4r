"""Persisted, observation-scoped reference control mapping snapshot."""

from __future__ import annotations

from dataclasses import dataclass

from core.compliance.controls import SecurityControl


@dataclass(frozen=True)
class FindingControlMapping:
    id: int
    finding_id: int
    observation_id: int
    control: SecurityControl
    rule_id: str
    rule_version: str
    reason: str
    observed_facts: tuple[tuple[str, str], ...]
    recorded_at: str
