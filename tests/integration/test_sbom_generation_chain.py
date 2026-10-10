"""Offline generator-to-storage contract; Syft process output is mocked."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.assets.asset_service import AssetService
from core.sbom.generator import generate_cyclonedx_json
from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom
from database.database import connect_database, initialize_database
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.sbom_repository import SQLiteSBOMRepository
from tests.unit.test_asset_context import VALID


class GenerationChainTests(unittest.TestCase):
    def test_mocked_syft_parser_normalizer_storage(self):
        raw = (Path(__file__).resolve().parents[1] / "fixtures" / "cyclonedx.json").read_text(
            encoding="utf-8")
        connection = connect_database()
        self.addCleanup(connection.close)
        initialize_database(connection)
        service = AssetService(SQLiteAssetRepository(connection)).register_business_service(
            "SBOM fixture service")
        asset = AssetService(SQLiteAssetRepository(connection)).register_asset(
            service.id, **VALID)
        with tempfile.TemporaryDirectory() as directory, patch(
            "core.sbom.generator.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, raw, ""),
        ) as run:
            generated = generate_cyclonedx_json(directory)
            self.assertEqual(run.call_args.args[0][0], "syft")
            parsed = parse_sbom(generated.content)
            normalized = normalize_components(parsed.components)
            repository = SQLiteSBOMRepository(connection)
            saved = repository.save(asset_id=asset.id, source=generated.source,
                                    raw_document=generated.content, parsed=parsed,
                                    normalized=normalized)
            self.assertEqual(len(repository.list_components(saved.id)),
                             len(parsed.components))
            self.assertEqual(connection.execute(
                "SELECT raw_document FROM sboms WHERE id = ?", (saved.id,)
            ).fetchone()[0], raw)
