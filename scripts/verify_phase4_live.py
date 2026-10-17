"""One-shot live Phase 4 check using a verified local Log4j SBOM sample.

Run from the repository root: python -m scripts.verify_phase4_live
No result is written to disk. A failed external lookup is reported as ERROR.
"""

from __future__ import annotations

from pathlib import Path

from core.assets.asset_service import AssetService
from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom_file
from core.vulnerability.cve_client import NVDClient, OSVClient
from core.vulnerability.kev_client import KEVClient
from core.vulnerability.matcher import MatchStatus, match_component_to_cves
from database.database import connect_database, initialize_database
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.sbom_repository import SQLiteSBOMRepository
from database.repositories.vulnerability_repository import SQLiteVulnerabilityRepository


def main() -> int:
    path = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "cyclonedx_log4j.json"
    connection = connect_database()
    try:
        initialize_database(connection)
        assets = AssetService(SQLiteAssetRepository(connection))
        service = assets.register_business_service("Local Phase 4 sample")
        asset = assets.register_asset(
            service.id, name="Local Log4j sample", environment="development",
            internet_exposed=False, business_criticality="low",
            customer_information=False, credit_information=False,
            patch_status="unknown", vendor="Local sample", owner="Local sample",
        )
        parsed = parse_sbom_file(path)
        normalized = normalize_components(parsed.components)
        sbom = SQLiteSBOMRepository(connection).save(
            asset_id=asset.id, source=str(path), raw_document=path.read_text(encoding="utf-8"),
            parsed=parsed, normalized=normalized,
        )
        component = SQLiteSBOMRepository(connection).list_components(sbom.id)[0]
        result = match_component_to_cves(normalized.components[0],
                                         osv=OSVClient(), nvd=NVDClient(), kev=KEVClient())
        repository = SQLiteVulnerabilityRepository(connection)
        saved = repository.save(component_id=component.id, analysis_key="live-1", result=result)
        loaded = repository.get(saved.id)
        if loaded.result != result:
            raise RuntimeError("persisted matcher result differs from source")
        if loaded.result.status is MatchStatus.MATCHED:
            before = tuple(match.cve.cve_id for match in result.matches)
            after = tuple(match.cve.cve_id for match in loaded.result.matches)
            if before != after:
                raise RuntimeError("persisted CVE identifiers differ from source")
        print(f"status={loaded.result.status.value} component_id={component.id} "
              f"matches={len(loaded.result.matches)}")
        for match in loaded.result.matches:
            print(f"cve={match.cve.cve_id} kev={match.kev} "
                  f"cvss={match.cve.cvss.score if match.cve.cvss else None}")
        if loaded.result.status is MatchStatus.ERROR:
            print(f"error={loaded.result.reasons[0]}")
            return 1
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
