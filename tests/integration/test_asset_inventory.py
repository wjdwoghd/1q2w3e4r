"""Actual SQLite persistence, referential integrity and service workflows."""

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from core.assets.asset_service import AssetService, InventoryNotFoundError
from database.database import Database, StorageError
from database.models.asset import Asset
from database.models.business_service import BusinessService
from database.repositories.assets import AssetRepository, InventoryConflictError
from tests.unit.test_assets import sample_asset


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.url = "sqlite:///" + (Path(self.directory.name) / "inventory.db").as_posix()
        self.database = Database(self.url)
        self.database.initialize()
        self.repository = AssetRepository(self.database)
        self.service = AssetService(self.repository)
        self.service.register_business_service(BusinessService("SVC-001", "Demo Banking"))

    def test_persists_across_new_database_instances(self):
        asset = sample_asset()
        self.service.register_asset(asset)
        reopened = AssetService(AssetRepository(Database(self.url)))
        self.assertEqual(reopened.get_asset(asset.asset_id), asset)
        self.assertIs(reopened.get_asset_context(asset.asset_id)["credit_information"], False)

    def test_duplicate_service_does_not_overwrite(self):
        with self.assertRaises(InventoryConflictError):
            self.service.register_business_service(BusinessService("SVC-001", "Replacement"))
        self.assertEqual(self.service.get_business_service("SVC-001").name, "Demo Banking")

    def test_duplicate_asset_does_not_overwrite(self):
        self.service.register_asset(sample_asset())
        with self.assertRaises(InventoryConflictError):
            self.service.register_asset(sample_asset(name="Replacement"))
        self.assertEqual(self.service.get_asset("AST-001").name, "Demo API")

    def test_missing_service_rejected_by_service_and_database(self):
        asset = sample_asset(business_service_id="MISSING")
        with self.assertRaises(InventoryNotFoundError):
            self.service.register_asset(asset)
        with self.assertRaises(InventoryConflictError):
            self.repository.add_asset(asset)
        self.assertEqual(self.service.list_assets(), [])

    def test_not_found(self):
        for operation in (
            lambda: self.service.get_asset("MISSING"),
            lambda: self.service.get_business_service("MISSING"),
            lambda: self.service.get_asset_context("MISSING"),
            lambda: self.service.list_assets("MISSING"),
        ):
            with self.assertRaises(InventoryNotFoundError):
                operation()

    def test_filter_and_stable_order(self):
        self.service.register_business_service(BusinessService("SVC-002", "Demo Cards"))
        self.service.register_asset(sample_asset(asset_id="Z", business_service_id="SVC-002"))
        self.service.register_asset(sample_asset(asset_id="A"))
        self.assertEqual([a.asset_id for a in self.service.list_assets()], ["A", "Z"])
        self.assertEqual([a.asset_id for a in self.service.list_assets("SVC-001")], ["A"])
        self.assertEqual([s.service_id for s in self.service.list_business_services()],
                         ["SVC-001", "SVC-002"])

    def test_sql_metacharacters_are_data(self):
        name = "Demo'); DROP TABLE assets; --"
        self.service.register_asset(sample_asset(name=name))
        self.assertEqual(self.service.get_asset("AST-001").name, name)
        self.assertEqual(len(self.service.list_assets()), 1)

    def test_reinitialize_preserves_records(self):
        self.service.register_asset(sample_asset())
        self.database.initialize()
        self.assertEqual(self.service.get_asset("AST-001"), sample_asset())

    def test_unknown_schema_rejected(self):
        with self.database.connection() as connection:
            connection.execute("PRAGMA user_version = 2")
        with self.assertRaises(StorageError):
            self.database.initialize()

    def test_db_boolean_constraint(self):
        self.service.register_asset(sample_asset())
        with self.assertRaises(sqlite3.IntegrityError):
            with self.database.connection() as connection:
                connection.execute("UPDATE assets SET internet_exposed = 2")
        self.assertTrue(self.service.get_asset("AST-001").internet_exposed)

    def test_storage_failure_is_understandable(self):
        bad = Database("sqlite:///" + str(Path(self.directory.name) / "absent" / "db.sqlite"))
        with self.assertRaises(StorageError):
            bad.initialize()

    def test_invalid_database_urls(self):
        for url in ("", "postgres://host/db", "sqlite:///", "sqlite:///:memory:"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Database(url)

    def test_sample_inventory_is_valid_and_persistent(self):
        path = Path(__file__).resolve().parents[2] / "data/assets/sample_assets.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        sample_db = Database("sqlite:///" + str(Path(self.directory.name) / "sample.db"))
        sample_db.initialize()
        service = AssetService(AssetRepository(sample_db))
        for item in payload["business_services"]:
            service.register_business_service(BusinessService(**item))
        for item in payload["assets"]:
            service.register_asset(Asset(**item))
        self.assertEqual(len(service.list_business_services()), 3)
        self.assertEqual(len(service.list_assets()), 3)
        self.assertTrue(all(a.patch_status == "unknown" for a in service.list_assets()))
