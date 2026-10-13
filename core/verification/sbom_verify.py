"""Check persisted SBOM consistency and the target component change."""

from core.sbom.diff import package_identity
from core.sbom.normalizer import normalize_components
from core.sbom.parser import SBOMParsingError, parse_sbom
from core.verification.evidence import provenance_errors
from database.models.remediation import BeforeSnapshot


def verify_sbom(before: BeforeSnapshot, after: dict, applied_at: str) -> tuple[list[str], list[str]]:
    errors, reasons = [], []
    sbom = after.get("sbom")
    if sbom is None:
        return ["SBOM: after evidence missing"], reasons
    errors.extend(provenance_errors(sbom, applied_at, "SBOM"))
    try:
        normalized = normalize_components(parse_sbom(sbom["raw_document"]).components)
    except (SBOMParsingError, ValueError, TypeError, KeyError) as exc:
        return errors + [f"SBOM: invalid raw document ({type(exc).__name__})"], reasons
    expected = [(item.name, item.version, item.purl, list(item.issues)) for item in normalized.components]
    actual = [(item["name"], item["version"], item["purl"], item["issues"]) for item in sbom["components"]]
    if expected != actual:
        errors.append("SBOM: raw document and stored component occurrences disagree")
    if any(item.package_key is None for item in normalized.components):
        errors.append("SBOM: unresolved component identity or version prevents complete coverage")
    identity = package_identity(before.component_purl)
    if identity is None or before.component_version is None:
        errors.append("SBOM: before component identity or version is missing")
        return errors, reasons
    remaining = [item for item in sbom["components"] if package_identity(item["purl"]) == identity]
    if not remaining:
        reasons.append("SBOM: target package removed from the after inventory")
    elif any(item["version"] == before.component_version for item in remaining):
        errors.append("SBOM: before component version still exists in the after inventory")
    else:
        reasons.append("SBOM: every remaining target package occurrence has a changed version")
    return errors, reasons
