"""Thin API-call layer; validation and persistence live below app/."""

from dataclasses import asdict
from typing import Any

from core.assets.asset_service import AssetService


def register_business_service(service: AssetService, payload: dict[str, Any]) -> dict[str, Any]:
    return asdict(service.register_business_service(payload.get("name"), payload.get("description")))


def register_asset(service: AssetService, payload: dict[str, Any]) -> dict[str, Any]:
    values = dict(payload)
    service_id = values.pop("business_service_id", None)
    return asdict(service.register_asset(service_id, **values))


def list_assets(service: AssetService, business_service_id: int | None = None) -> list[dict[str, Any]]:
    return [asdict(asset) for asset in service.list_assets(business_service_id)]
