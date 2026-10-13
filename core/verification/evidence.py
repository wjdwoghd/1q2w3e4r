"""Shared deterministic evidence provenance checks."""

from datetime import datetime


def evidence_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        return None
    return result if result.tzinfo is not None and result.utcoffset() is not None else None


def provenance_errors(item: dict, applied_at: str, label: str) -> list[str]:
    errors = []
    for field in ("source", "reference"):
        if not isinstance(item.get(field), str) or not item[field].strip():
            errors.append(f"{label}: missing {field}")
    collected, applied = evidence_time(item.get("collected_at")), evidence_time(applied_at)
    if collected is None:
        errors.append(f"{label}: missing or invalid collection time")
    elif applied is None or collected < applied:
        errors.append(f"{label}: evidence predates remediation application")
    return errors
