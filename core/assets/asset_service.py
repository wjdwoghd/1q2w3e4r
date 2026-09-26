"""Inventory registration and lookup, independent of UI and SQL."""

import logging

from core.assets.context import build_asset_context
from database.models.asset import Asset
from database.models.business_service import BusinessService
from database.models.validation import require_text
from database.repositories.assets import AssetRepository

logger = logging.getLogger(__name__)


class InventoryNotFoundError(LookupError):
    """Requested inventory entity does not exist."""


class AssetService:
    def __init__(self, repository: AssetRepository) -> None:
        self.repository = repository

    def register_business_service(self, service: BusinessService) -> BusinessService:
        if not isinstance(service, BusinessService):
            raise ValueError("Expected a validated BusinessService")
        self.repository.add_business_service(service)
        logger.info("Business service registered")
        return service

    def get_business_service(self, service_id: str) -> BusinessService:
        require_text("service_id", service_id)
        service = self.repository.get_business_service(service_id)
        if service is None:
            raise InventoryNotFoundError("Business service not found")
        return service

    def list_business_services(self) -> list[BusinessService]:
        return self.repository.list_business_services()

    def register_asset(self, asset: Asset) -> Asset:
        if not isinstance(asset, Asset):
            raise ValueError("Expected a validated Asset")
        self.get_business_service(asset.business_service_id)
        self.repository.add_asset(asset)
        logger.info("Asset registered")
        return asset

    def get_asset(self, asset_id: str) -> Asset:
        require_text("asset_id", asset_id)
        asset = self.repository.get_asset(asset_id)
        if asset is None:
            raise InventoryNotFoundError("Asset not found")
        return asset

    def list_assets(self, business_service_id: str | None = None) -> list[Asset]:
        if business_service_id is not None:
            self.get_business_service(business_service_id)
        return self.repository.list_assets(business_service_id)

    def get_asset_context(self, asset_id: str) -> dict[str, str | bool]:
        asset = self.get_asset(asset_id)
        return build_asset_context(asset, self.get_business_service(asset.business_service_id))
