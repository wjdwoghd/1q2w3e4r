"""Validated asset inventory entities."""

from dataclasses import dataclass
from enum import StrEnum

from database.models.validation import require_text


class Environment(StrEnum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"


class BusinessCriticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PatchStatus(StrEnum):
    UNKNOWN = "unknown"
    PENDING = "pending"
    APPLIED = "applied"
    DEFERRED = "deferred"


@dataclass(frozen=True)
class Asset:
    asset_id: str
    name: str
    business_service_id: str
    environment: Environment
    internet_exposed: bool
    business_criticality: BusinessCriticality
    customer_information: bool
    credit_information: bool
    vendor: str
    owner: str
    patch_status: PatchStatus = PatchStatus.UNKNOWN

    def __post_init__(self) -> None:
        for field in ("asset_id", "name", "business_service_id", "vendor", "owner"):
            require_text(field, getattr(self, field))
        for field in ("internet_exposed", "customer_information", "credit_information"):
            if type(getattr(self, field)) is not bool:
                raise ValueError(f"{field} must be a boolean")
        for field, enum_type in (
            ("environment", Environment),
            ("business_criticality", BusinessCriticality),
            ("patch_status", PatchStatus),
        ):
            try:
                value = enum_type(getattr(self, field))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid {field}") from exc
            object.__setattr__(self, field, value)
