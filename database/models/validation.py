"""Shared inventory field validation."""


def require_text(field: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be non-empty text without surrounding whitespace")
