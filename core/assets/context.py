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

    @classmethod
    def create(
        cls,
        *,
        name: object,
        environment: object,
        internet_exposed: object,
        business_criticality: object,
        customer_information: object,
        credit_information: object,
        patch_status: object,
        vendor: object,
        owner: object,
    ) -> "AssetContext":
        return cls(
            name=_required_text(name, "name"),
            environment=_enum(environment, Environment, "environment"),
            internet_exposed=_boolean(internet_exposed, "internet_exposed"),
            business_criticality=_enum(
                business_criticality, BusinessCriticality, "business_criticality"
            ),
            customer_information=_boolean(
                customer_information, "customer_information"
            ),
            credit_information=_boolean(credit_information, "credit_information"),
            patch_status=_enum(patch_status, PatchStatus, "patch_status"),
            vendor=_required_text(vendor, "vendor"),
            owner=_required_text(owner, "owner"),
        )

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION
