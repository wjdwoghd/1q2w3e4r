import unittest

from core.assets.context import AssetContext, AssetContextError, Environment


VALID = {
    "name": "Internet Banking API",
    "environment": "production",
    "internet_exposed": True,
    "business_criticality": "critical",
    "customer_information": True,
    "credit_information": True,
    "patch_status": "current",
    "vendor": "Internal",
    "owner": "Digital Banking",
}


class AssetContextTests(unittest.TestCase):
    def test_required_fields(self):
        for field in ("name", "vendor", "owner"):
            with self.subTest(field=field), self.assertRaises(AssetContextError):
                AssetContext.create(**{**VALID, field: " "})

    def test_invalid_criticality(self):
        with self.assertRaisesRegex(AssetContextError, "business_criticality"):
            AssetContext.create(**{**VALID, "business_criticality": "urgent"})

    def test_environment_distinguishes_production_and_development(self):
        production = AssetContext.create(**VALID)
        development = AssetContext.create(**{**VALID, "environment": "development"})
        self.assertTrue(production.is_production)
        self.assertFalse(development.is_production)
        self.assertEqual(development.environment, Environment.DEVELOPMENT)
        with self.assertRaises(AssetContextError):
            AssetContext.create(**{**VALID, "environment": "staging"})

    def test_internet_exposure_requires_boolean(self):
        self.assertTrue(AssetContext.create(**VALID).internet_exposed)
        self.assertFalse(AssetContext.create(**{**VALID, "internet_exposed": False}).internet_exposed)
        for invalid in (1, "yes", None):
            with self.subTest(invalid=invalid), self.assertRaises(AssetContextError):
                AssetContext.create(**{**VALID, "internet_exposed": invalid})
