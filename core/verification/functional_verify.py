"""Require all operator-selected functional checks to have passing evidence."""

from core.verification.evidence import provenance_errors
from database.models.verification import FunctionalStatus


def verify_functional_tests(required: tuple[str, ...], after: dict,
                            applied_at: str) -> tuple[list[str], list[str]]:
    errors, reasons = [], []
    tests = after["functional_tests"]
    for item in tests:
        errors.extend(provenance_errors(item, applied_at, f"Functional test {item['test_id']}"))
        if item["status"] != FunctionalStatus.PASSED.value:
            errors.append(f"Functional test {item['test_id']}: {item['status']}")
    for test_id in required:
        matching = [item for item in tests if item["test_id"] == test_id]
        if not matching:
            errors.append(f"Functional test {test_id}: required evidence missing")
        elif all(item["status"] == FunctionalStatus.PASSED.value for item in matching):
            reasons.append(f"Functional test {test_id}: passed evidence recorded")
    return errors, reasons
