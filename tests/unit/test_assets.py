"""Model, configuration and context validation."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.config.settings import get_database_url
from core.assets.context import build_asset_context
from database.models.asset import Asset, Environment, PatchStatus
from database.models.business_service import BusinessService


def sample_asset(**changes: object) -> Asset:
    values = dict(
        asset_id="AST-001", name="Demo API", business_service_id="SVC-001",
        environment="production", internet_exposed=True, business_criticality="critical",
        customer_information=True, credit_information=False, vendor="Demo Vendor", owner="Demo Team",
    )
    values.update(changes)
    return Asset(**values)


class AssetValidationTests(unittest.TestCase):
    def test_valid_context_preserves_explicit_values(self):
        asset = sample_asset()
        context = build_asset_context(asset, BusinessService("SVC-001", "Demo Banking"))
        self.assertEqual(context["environment"], "production")
        self.assertIs(context["internet_exposed"], True)
        self.assertIs(context["credit_information"], False)
        self.assertEqual(context["business_service_name"], "Demo Banking")
        self.assertEqual(context["patch_status"], "unknown")
        self.assertNotIn("risk_score", context)

    def test_missing_required_field(self):
        with self.assertRaises(TypeError):
            Asset(asset_id="AST-001")

    def test_invalid_required_text(self):
        for field in ("asset_id", "name", "business_service_id", "vendor", "owner"):
            for value in ("", " ", " padded ", None, 123):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    sample_asset(**{field: value})

    def test_business_service_required_fields(self):
        for service_id, name in (("", "Demo"), ("SVC", ""), (None, "Demo")):
            with self.subTest(service_id=service_id, name=name), self.assertRaises(ValueError):
                BusinessService(service_id, name)

    def test_strict_booleans(self):
        for field in ("internet_exposed", "customer_information", "credit_information"):
            for value in ("false", "true", 0, 1, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    sample_asset(**{field: value})

    def test_false_boolean_is_preserved(self):
        self.assertIs(sample_asset(internet_exposed=False).internet_exposed, False)

    def test_invalid_enums(self):
        for field in ("environment", "business_criticality", "patch_status"):
            for value in ("", "INVALID", None, []):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    sample_asset(**{field: value})

    def test_environments_remain_distinct(self):
        for environment in Environment:
            self.assertEqual(sample_asset(environment=environment.value).environment, environment)
        self.assertNotEqual(Environment.PRODUCTION, Environment.DEVELOPMENT)

    def test_patch_status_is_explicit(self):
        self.assertEqual(sample_asset().patch_status, PatchStatus.UNKNOWN)
        self.assertEqual(sample_asset(patch_status="applied").patch_status, PatchStatus.APPLIED)

    def test_context_rejects_unrelated_service(self):
        with self.assertRaises(ValueError):
            build_asset_context(sample_asset(), BusinessService("OTHER", "Other"))

    def test_context_is_detached_from_asset(self):
        asset = sample_asset()
        context = build_asset_context(asset, BusinessService("SVC-001", "Demo"))
        context["internet_exposed"] = False
        self.assertTrue(asset.internet_exposed)


class SettingsTests(unittest.TestCase):
    def test_env_file_and_environment_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text('# comment\nDATABASE_URL="sqlite:///demo.db"\n', encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(get_database_url(path), "sqlite:///demo.db")
            with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///override.db"}, clear=True):
                self.assertEqual(get_database_url(path), "sqlite:///override.db")

    def test_missing_blank_and_malformed_configuration(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            path = Path(directory) / ".env"
            with self.assertRaises(ValueError):
                get_database_url(path)
            for content in ("DATABASE_URL=", 'DATABASE_URL="unterminated'):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    get_database_url(path)
