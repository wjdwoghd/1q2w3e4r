"""Map a non-negative rule score to a remediation priority."""

from __future__ import annotations

from core.risk.rules import PRIORITY_THRESHOLDS


def priority_for_score(score: int) -> str:
    if isinstance(score, bool) or not isinstance(score, int) or score < 0:
        raise ValueError("score must be a non-negative integer")
    for minimum, priority in PRIORITY_THRESHOLDS:
        if score >= minimum:
            return priority
    raise AssertionError("priority thresholds must include zero")
