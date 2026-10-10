"""SQLite repository for Phase 1 asset registration and lookup."""

from __future__ import annotations

import sqlite3

from core.assets.context import AssetContext
from database.models.asset import Asset, BusinessService


class AssetRepositoryError(RuntimeError):
    pass


class AssetNotFoundError(AssetRepositoryError):
    pass


class SQLiteAssetRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def create_business_service(
        self, name: str, description: str | None = None
    ) -> BusinessService:
        try:
            cursor = self.connection.execute(
                "INSERT INTO business_services (name, description) VALUES (?, ?)",
                (name, description),
            )
            self.connection.commit()
        except sqlite3.IntegrityError as exc:
            raise AssetRepositoryError("business service already exists") from exc
        return BusinessService(cursor.lastrowid, name, description)

    def get_business_service(self, service_id: int) -> BusinessService:
        row = self.connection.execute(
            "SELECT id, name, description FROM business_services WHERE id = ?",
            (service_id,),
        ).fetchone()
        if row is None:
            raise AssetNotFoundError("business service not found")
        return BusinessService(row["id"], row["name"], row["description"])

    def list_business_services(self) -> tuple[BusinessService, ...]:
        rows = self.connection.execute(
            "SELECT id, name, description FROM business_services ORDER BY id"
        ).fetchall()
        return tuple(BusinessService(row["id"], row["name"], row["description"]) for row in rows)

    def create_asset(self, service_id: int, context: AssetContext) -> Asset:
        try:
            cursor = self.connection.execute(
                """INSERT INTO assets (
                    business_service_id, name, environment, internet_exposed,
                    business_criticality, customer_information, credit_information,
                    patch_status, vendor, owner
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    service_id, context.name, context.environment.value,
                    context.internet_exposed, context.business_criticality.value,
                    context.customer_information, context.credit_information,
                    context.patch_status.value, context.vendor, context.owner,
                ),
            )
            self.connection.commit()
        except sqlite3.IntegrityError as exc:
            raise AssetRepositoryError("asset relationship or uniqueness is invalid") from exc
        return Asset(cursor.lastrowid, service_id, context)

    def get_asset(self, asset_id: int) -> Asset:
        row = self.connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if row is None:
            raise AssetNotFoundError("asset not found")
        return self._to_asset(row)

    def list_assets(self, service_id: int | None = None) -> tuple[Asset, ...]:
        if service_id is None:
            rows = self.connection.execute("SELECT * FROM assets ORDER BY id").fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM assets WHERE business_service_id = ? ORDER BY id",
                (service_id,),
            ).fetchall()
        return tuple(self._to_asset(row) for row in rows)

    @staticmethod
    def _to_asset(row: sqlite3.Row) -> Asset:
        context = AssetContext.create(
            name=row["name"], environment=row["environment"],
            internet_exposed=bool(row["internet_exposed"]),
            business_criticality=row["business_criticality"],
            customer_information=bool(row["customer_information"]),
            credit_information=bool(row["credit_information"]),
            patch_status=row["patch_status"], vendor=row["vendor"], owner=row["owner"],
        )
        return Asset(row["id"], row["business_service_id"], context)
