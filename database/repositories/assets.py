"""Parameterized persistence operations for services and assets."""

from dataclasses import asdict
import sqlite3

from database.database import Database
from database.models.asset import Asset
from database.models.business_service import BusinessService


class InventoryConflictError(ValueError):
    """Duplicate identifier or missing related business service."""


class AssetRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add_business_service(self, service: BusinessService) -> None:
        try:
            with self.database.connection() as connection:
                connection.execute(
                    "INSERT INTO business_services (service_id, name) VALUES (?, ?)",
                    (service.service_id, service.name),
                )
        except sqlite3.IntegrityError as exc:
            raise InventoryConflictError("Business service ID already exists or data is invalid") from exc

    def get_business_service(self, service_id: str) -> BusinessService | None:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT service_id, name FROM business_services WHERE service_id = ?", (service_id,)
            ).fetchone()
        return BusinessService(**dict(row)) if row else None

    def list_business_services(self) -> list[BusinessService]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT service_id, name FROM business_services ORDER BY service_id"
            ).fetchall()
        return [BusinessService(**dict(row)) for row in rows]

    def add_asset(self, asset: Asset) -> None:
        try:
            with self.database.connection() as connection:
                connection.execute(
                    """INSERT INTO assets (
                        asset_id, name, business_service_id, environment, internet_exposed,
                        business_criticality, customer_information, credit_information,
                        vendor, owner, patch_status
                    ) VALUES (
                        :asset_id, :name, :business_service_id, :environment, :internet_exposed,
                        :business_criticality, :customer_information, :credit_information,
                        :vendor, :owner, :patch_status
                    )""", asdict(asset),
                )
        except sqlite3.IntegrityError as exc:
            raise InventoryConflictError(
                "Asset ID already exists, business service is missing, or data is invalid"
            ) from exc

    def get_asset(self, asset_id: str) -> Asset | None:
        with self.database.connection() as connection:
            row = connection.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        return self._to_asset(row) if row else None

    def list_assets(self, business_service_id: str | None = None) -> list[Asset]:
        with self.database.connection() as connection:
            if business_service_id is None:
                rows = connection.execute("SELECT * FROM assets ORDER BY asset_id").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM assets WHERE business_service_id = ? ORDER BY asset_id",
                    (business_service_id,),
                ).fetchall()
        return [self._to_asset(row) for row in rows]

    @staticmethod
    def _to_asset(row: sqlite3.Row) -> Asset:
        values = dict(row)
        for field in ("internet_exposed", "customer_information", "credit_information"):
            values[field] = bool(values[field])
        return Asset(**values)
