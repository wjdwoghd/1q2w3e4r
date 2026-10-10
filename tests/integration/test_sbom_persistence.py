import unittest
from pathlib import Path

from core.assets.asset_service import AssetService
from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom_file
from database.database import connect_database, initialize_database
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.sbom_repository import SQLiteSBOMRepository
from tests.unit.test_asset_context import VALID


class SBOMPersistenceTests(unittest.TestCase):
    def test_asset_parser_normalizer_storage_chain(self):
        connection = connect_database()
        self.addCleanup(connection.close)
        initialize_database(connection)
        assets = AssetService(SQLiteAssetRepository(connection))
        service = assets.register_business_service("Internet Banking")
        asset = assets.register_asset(service.id, **VALID)
        fixture = Path(__file__).resolve().parents[1] / "fixtures" / "cyclonedx.json"
        raw = fixture.read_text(encoding="utf-8")
        parsed = parse_sbom_file(fixture)
        normalized = normalize_components(parsed.components)
        repository = SQLiteSBOMRepository(connection)
        sbom = repository.save(asset_id=asset.id, source=str(fixture),
                               raw_document=raw, parsed=parsed, normalized=normalized)
        components = repository.list_components(sbom.id)
        self.assertEqual(sbom.asset_id, asset.id)
        self.assertEqual(len(components), len(parsed.components))
        self.assertEqual(components[0].source_bom_ref, parsed.components[0].bom_ref)
