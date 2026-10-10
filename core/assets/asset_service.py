"""Application-independent orchestration for asset registration and lookup."""

from __future__ import annotations

from typing import Any

from core.assets.context import AssetContext, AssetContextError
from database.models.asset import Asset, BusinessService
from database.repositories.asset_repository import SQLiteAssetRepository


class AssetService:
    def __init__(self, repository: SQLiteAssetRepository) -> None:
        self.repository = repository

    def register_business_service(
        self, name: object, description: object = None
    ) -> BusinessService:
        if not isinstance(name, str) or not name.strip():
            raise AssetContextError("business service name must be a non-empty string")
        if description is not None and not isinstance(description, str):
            raise AssetContextError("description must be a string or null")
        return self.repository.create_business_service(
            name.strip(), description.strip() if description else None
        )

    def register_asset(self, business_service_id: int, **values: Any) -> Asset:
        if not isinstance(business_service_id, int) or isinstance(business_service_id, bool):
            raise AssetContextError("business_service_id must be an integer")
        context = AssetContext.create(**values)
        return self.repository.create_asset(business_service_id, context)

    def get_business_service(self, service_id: int) -> BusinessService:
        return self.repository.get_business_service(service_id)

    def list_business_services(self) -> tuple[BusinessService, ...]:
        return self.repository.list_business_services()

    def get_asset(self, asset_id: int) -> Asset:
        return self.repository.get_asset(asset_id)

    def list_assets(self, business_service_id: int | None = None) -> tuple[Asset, ...]:
        return self.repository.list_assets(business_service_id)
