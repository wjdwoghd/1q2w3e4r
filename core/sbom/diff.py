"""Occurrence-preserving inventory differences using versionless PURL identity."""

from collections import defaultdict
from packageurl import PackageURL


def package_identity(purl: str | None) -> str | None:
    if not purl:
        return None
    try:
        package = PackageURL.from_string(purl)
        return PackageURL(package.type, package.namespace, package.name,
                          qualifiers=package.qualifiers, subpath=package.subpath).to_string()
    except ValueError:
        return None


def compare_sbom_versions(before: list[dict], after: list[dict]) -> dict:
    """Group occurrences; do not guess which installation became another one."""
    def groups(items: list[dict]) -> dict:
        result = defaultdict(list)
        for item in items:
            identity = package_identity(item.get("purl"))
            if identity is not None:
                result[identity].append(item)
        return result

    old, new = groups(before), groups(after)
    return {
        "added": [item for key in sorted(new.keys() - old.keys()) for item in new[key]],
        "removed": [item for key in sorted(old.keys() - new.keys()) for item in old[key]],
        "version_changes": [
            {"package": key, "before": old[key], "after": new[key]}
            for key in sorted(old.keys() & new.keys())
            if {item.get("version") for item in old[key]}
            != {item.get("version") for item in new[key]}
        ],
        "occurrence_count_changes": [
            {"package": key, "before_count": len(old[key]), "after_count": len(new[key])}
            for key in sorted(old.keys() & new.keys()) if len(old[key]) != len(new[key])
        ],
        "unresolved_before": [item for item in before if package_identity(item.get("purl")) is None],
        "unresolved_after": [item for item in after if package_identity(item.get("purl")) is None],
    }
