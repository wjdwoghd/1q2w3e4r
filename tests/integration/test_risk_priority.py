"""Offline Phase 4 matching to Phase 5 priority contract."""

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.assets.context import AssetContext
from core.risk.engine import calculate_risk_priorities
from core.sbom.normalizer import normalize_component
from core.sbom.parser import ParsedComponent
from core.vulnerability.cve_client import NVDClient, OSVClient
from core.vulnerability.kev_client import KEVClient
from core.vulnerability.matcher import match_component_to_cves

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


class FixtureTransport:
    def __init__(self):
        self.responses = {
            "OSV": "osv_log4j_query.json",
            "NVD": "nvd_log4j_cve.json",
            "CISA KEV": "cisa_kev_log4j.json",
        }

    def request(self, source, url, payload=None):
        return json.loads((FIXTURES / self.responses[source]).read_text(encoding="utf-8"))


class RiskPriorityIntegrationTests(unittest.TestCase):
    def test_verified_match_to_financial_priority(self):
        component = normalize_component(ParsedComponent(
            "log4j-core", "library", "2.14.1",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            None, "org.apache.logging.log4j", None, (), (), None))
        transport = FixtureTransport()
        matched = match_component_to_cves(
            component, osv=OSVClient(transport, lambda: NOW),
            nvd=NVDClient(transport, lambda: NOW),
            kev=KEVClient(transport, lambda: NOW))
        asset = AssetContext.create(
            name="Internet Banking API", environment="production",
            internet_exposed=True, business_criticality="critical",
            customer_information=True, credit_information=False,
            patch_status="current", vendor="Internal", owner="Digital Banking")
        risks = calculate_risk_priorities(matched, asset)
        self.assertEqual(len(risks), 1)
        self.assertEqual((risks[0].cve_id, risks[0].cvss_score, risks[0].score, risks[0].priority),
                         ("CVE-2021-44228", 10.0, 95, "P1"))
