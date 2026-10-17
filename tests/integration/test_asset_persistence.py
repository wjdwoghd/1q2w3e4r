import unittest

from core.assets.asset_service import AssetService
from database.database import connect_database, initialize_database
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.asset_repository import AssetRepositoryError
from tests.unit.test_asset_context import VALID


class AssetPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.connection = connect_database()
        initialize_database(self.connection)
        self.service = AssetService(SQLiteAssetRepository(self.connection))

    def tearDown(self):
        self.connection.close()

    def test_register_and_query_service_asset_relationship(self):
        banking = self.service.register_business_service("Internet Banking")
        trading = self.service.register_business_service("Securities Trading")
        asset = self.service.register_asset(banking.id, **VALID)
        self.assertEqual(self.service.get_asset(asset.id), asset)
        self.assertEqual(self.service.list_assets(banking.id), (asset,))
        self.assertEqual(self.service.list_assets(trading.id), ())
        self.assertEqual(len(self.service.list_business_services()), 2)

    def test_asset_requires_existing_business_service(self):
        with self.assertRaises(AssetRepositoryError):
            self.service.register_asset(999, **VALID)
