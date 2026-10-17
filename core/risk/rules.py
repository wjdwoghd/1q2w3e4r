"""Versioned, deterministic financial-service remediation priority rules."""

from __future__ import annotations

RULE_VERSION = "1.0"

# These are remediation-priority points, not CVSS scores or probabilities.
CVSS_BANDS: tuple[tuple[float, int, str], ...] = (
    (9.0, 30, "CVSS >= 9.0"),
    (7.0, 20, "CVSS >= 7.0"),
    (4.0, 10, "CVSS >= 4.0"),
    (0.0, 0, "CVSS < 4.0"),
)

RISK_WEIGHTS = {
    "kev": 30,
    "internet_exposure": 15,
    "production": 10,
    "critical_service": 10,
    "high_criticality": 5,
    "patch_overdue": 5,
    "credit_information": 5,
}

PRIORITY_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (80, "P1"),
    (50, "P2"),
    (20, "P3"),
    (0, "P4"),
)
