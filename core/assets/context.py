"""Validated asset context used by later deterministic risk rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AssetContextError(ValueError):
    """Asset context is missing or contains an unsupported value."""


class Environment(str, Enum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"


class BusinessCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PatchStatus(str, Enum):
    CURRENT = "current"
    PENDING = "pending"
    OVERDUE = "overdue"
    UNKNOWN = "unknown"


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AssetContextError(f"{field} must be a non-empty string")
    return value.strip()


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise AssetContextError(f"{field} must be a boolean")
    return value


def _enum(value: object, enum_type: type[Enum], field: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise AssetContextError(f"{field} has an unsupported value")
    try:
        return enum_type(value.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise AssetContextError(f"{field} must be one of: {allowed}") from exc


@dataclass(frozen=True)
class AssetContext:
    name: str
    environment: Environment
    internet_exposed: bool
    business_criticality: BusinessCriticality
    customer_information: bool
    credit_information: bool
    patch_status: PatchStatus
    vendor: str
    owner: str

    def __post_init__(self) -> None:
        # Direct dataclass construction must obey the same contract as create().
        object.__setattr__(self, "name", _required_text(self.name, "name"))
        object.__setattr__(self, "environment", _enum(self.environment, Environment, "environment"))
        object.__setattr__(self, "internet_exposed", _boolean(self.internet_exposed, "internet_exposed"))
        object.__setattr__(
            self, "business_criticality",
            _enum(self.business_criticality, BusinessCriticality, "business_criticality"),
        )
        object.__setattr__(self, "customer_information", _boolean(self.customer_information, "customer_information"))
        object.__setattr__(self, "credit_information", _boolean(self.credit_information, "credit_information"))
        object.__setattr__(self, "patch_status", _enum(self.patch_status, PatchStatus, "patch_status"))
        object.__setattr__(self, "vendor", _required_text(self.vendor, "vendor"))
        object.__setattr__(self, "owner", _required_text(self.owner, "owner"))

    @classmethod
    def create(cls, **values: object) -> "AssetContext":
        required = set(cls.__dataclass_fields__)
        missing = required - values.keys()
        if missing:
            raise AssetContextError(f"missing asset context fields: {', '.join(sorted(missing))}")
        unknown = values.keys() - required
        if unknown:
            raise AssetContextError(f"unknown asset context fields: {', '.join(sorted(unknown))}")
        return cls(**values)

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION
