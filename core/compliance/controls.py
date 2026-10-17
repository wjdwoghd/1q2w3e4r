"""Small, source-checked reference catalog for Phase 7.1."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ControlType(str, Enum):
    TECHNICAL = "technical"
    ADMINISTRATIVE = "administrative"


@dataclass(frozen=True)
class SecurityControl:
    key: str
    document_title: str
    issuer: str
    edition: str
    publication_date: str
    identifier: str
    title: str
    control_type: ControlType
    source_url: str
    granularity: str

    @classmethod
    def from_record(cls, record: dict[str, str]) -> SecurityControl:
        expected = set(cls.__dataclass_fields__)
        if set(record) != expected or any(not isinstance(v, str) or not v.strip()
                                              for v in record.values()):
            raise ValueError("control record has missing, empty, or unexpected fields")
        if not record["source_url"].startswith("https://"):
            raise ValueError("control source must be an HTTPS URL")
        if record["granularity"] not in {"clause", "category"}:
            raise ValueError("control granularity must be clause or category")
        return cls(**{**record, "control_type": ControlType(record["control_type"])})


def load_controls() -> dict[str, SecurityControl]:
    """Load only verified entries; an unverified guide is deliberately absent."""
    folder = Path(__file__).resolve().parent / "standards"
    controls: dict[str, SecurityControl] = {}
    for filename in ("financial.json", "isms_p.json"):
        records = json.loads((folder / filename).read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ValueError("control catalog must be a list")
        for record in records:
            control = SecurityControl.from_record(record)
            if control.key in controls:
                raise ValueError(f"duplicate control key: {control.key}")
            controls[control.key] = control
    return controls
