"""Structured inventory context without inferred security facts."""

from dataclasses import asdict
from enum import Enum

from database.models.asset import Asset
from database.models.business_service import BusinessService


def build_asset_context(asset: Asset, service: BusinessService) -> dict[str, str | bool]:
    if asset.business_service_id != service.service_id:
        raise ValueError("Asset and business service do not match")
    context = {
        key: value.value if isinstance(value, Enum) else value
        for key, value in asdict(asset).items()
    }
    context["business_service_name"] = service.name
    return context
