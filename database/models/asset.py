"""Persistence-neutral records for financial services and assets."""

from dataclasses import dataclass

from core.assets.context import AssetContext


@dataclass(frozen=True)
class BusinessService:
    id: int
    name: str
    description: str | None = None


@dataclass(frozen=True)
class Asset:
    id: int
    business_service_id: int
    context: AssetContext
