"""Deterministic normalization without inventing inventory evidence."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from urllib.parse import unquote

from packageurl import PackageURL, ValidationSeverity

from core.sbom.parser import ParsedComponent

logger = logging.getLogger(__name__)
SUPPORTED_PACKAGE_TYPES = frozenset({'maven', 'npm', 'pypi', 'generic'})


class ComponentNormalizationError(ValueError):
    """The caller supplied an invalid component or collection."""


class PURLStatus(str, Enum):
    VALID = 'valid'
    MISSING = 'missing'
    INVALID = 'invalid'
    UNSUPPORTED = 'unsupported'


@dataclass(frozen=True)
class PackageIdentity:
    package_type: str
    namespace: str | None
    name: str
    version: str | None
    qualifiers: tuple[tuple[str, str], ...]
    subpath: str | None


@dataclass(frozen=True)
class NormalizedComponent:
    source: ParsedComponent
    name: str
    component_type: str
    version: str | None
    group: str | None
    supplier_name: str | None
    purl: str | None
    purl_status: PURLStatus
    package: PackageIdentity | None
    reasons: tuple[str, ...]
    issues: tuple[str, ...]

    @property
    def package_key(self) -> str | None:
        """Versioned, conflict-free identity; never an installation identifier."""
        if self.package is None or self.issues or self.package.version is None:
            return None
        return self.purl


@dataclass(frozen=True)
class DuplicateGroup:
    package_key: str
    component_indices: tuple[int, ...]


@dataclass(frozen=True)
class NormalizationResult:
    components: tuple[NormalizedComponent, ...]
    duplicate_groups: tuple[DuplicateGroup, ...]


def _clean_text(value: str | None, field: str, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ComponentNormalizationError(f'{field} must be a non-empty string')
    return value.strip()


def _validate_purl_text(value: str) -> None:
    """Reject ambiguous input that the upstream parser would silently repair."""
    if any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError('Whitespace in PURL')
    if re.search(r'%(?![0-9a-fA-F]{2})', value):
        raise ValueError('Invalid percent encoding')
    decoded = unquote(value, errors='strict')
    if any(ord(char) < 32 or ord(char) == 127 for char in decoded):
        raise ValueError('Control character in PURL')
    path, fragment_separator, fragment = value.partition('#')
    if fragment_separator and (not fragment or '#' in fragment):
        raise ValueError('Invalid subpath')
    if any(part == '..' for part in unquote(fragment).split('/')):
        raise ValueError('Parent segment in subpath')
    path, query_separator, query = path.partition('?')
    if path.endswith('@'):
        raise ValueError('Empty PURL version')
    if query_separator:
        keys = set()
        for qualifier in query.split('&'):
            key, separator, content = qualifier.partition('=')
            key = unquote(key).lower()
            if not separator or not content or key in keys:
                raise ValueError('Empty or duplicate qualifier')
            keys.add(key)


def _parse_purl(value: str | None) -> tuple[PackageURL | None, PURLStatus]:
    if value is None:
        return None, PURLStatus.MISSING
    try:
        _validate_purl_text(value)
        package = PackageURL.from_string(value)
        if package.type not in SUPPORTED_PACKAGE_TYPES:
            return None, PURLStatus.UNSUPPORTED
        if any(message.severity == ValidationSeverity.ERROR
               for message in package.validate()):
            return None, PURLStatus.INVALID
    except (ValueError, UnicodeError):
        return None, PURLStatus.INVALID
    return package, PURLStatus.VALID


def _package_name(name: str, package_type: str) -> str:
    if package_type == 'pypi':
        return re.sub(r'[-_.]+', '-', name).lower()
    if package_type == 'npm':
        return name.lower()
    return name


def _normalize_package(package: PackageURL) -> PackageURL:
    """Apply the explicitly supported ecosystem naming rules to PURL fields."""
    namespace = package.namespace
    name = _package_name(package.name, package.type)
    if package.type == 'npm':
        namespace = namespace.lower() if namespace is not None else None
    return PackageURL(
        type=package.type,
        namespace=namespace,
        name=name,
        version=package.version,
        qualifiers=package.qualifiers,
        subpath=package.subpath,
    )


def normalize_component(component: ParsedComponent) -> NormalizedComponent:
    """Keep source evidence separate; report bad PURLs without dropping records.

    Only supplied strings are normalized. Missing component versions and groups
    remain missing even when the separately returned PURL contains these fields.
    Invalid component field types raise ComponentNormalizationError.
    """
    if not isinstance(component, ParsedComponent):
        raise ComponentNormalizationError('Expected ParsedComponent')
    name = _clean_text(component.name, 'name', required=True)
    component_type = _clean_text(component.component_type, 'component_type', True)
    version = _clean_text(component.version, 'version')
    group = _clean_text(component.group, 'group')
    purl_text = _clean_text(component.purl, 'purl')
    supplier_name = None
    if component.supplier is not None:
        if not isinstance(component.supplier, dict):
            raise ComponentNormalizationError('supplier must be an object')
        if 'name' in component.supplier:
            supplier_name = _clean_text(component.supplier['name'], 'supplier.name', True)

    reasons = []
    issues = []
    for field, value in (('name', name), ('component_type', component_type),
                         ('version', version), ('group', group), ('purl', purl_text)):
        if getattr(component, field) != value:
            reasons.append(f'{field}: trimmed surrounding whitespace')
    if component.supplier and component.supplier.get('name') != supplier_name:
        reasons.append('supplier.name: trimmed surrounding whitespace')

    package, status = _parse_purl(purl_text)
    identity = None
    canonical = None
    if package is not None:
        package = _normalize_package(package)
        normalized_name = _package_name(name, package.type)
        if name != normalized_name:
            reasons.append(f'name: applied {package.type} naming rules')
        name = normalized_name
        canonical = package.to_string()
        if canonical != purl_text:
            reasons.append('purl: canonicalized with packageurl-python 0.17.6')
        identity = PackageIdentity(
            package.type, package.namespace, package.name, package.version,
            tuple(sorted(package.qualifiers.items())), package.subpath,
        )
        accepted_names = {package.name}
        if package.type == 'npm' and package.namespace:
            accepted_names.add(f'{package.namespace}/{package.name}')
        if name not in accepted_names:
            issues.append('name_purl_conflict')
        if version is not None and package.version is not None and version != package.version:
            issues.append('version_purl_conflict')
        if group is not None and package.type in {'maven', 'npm'}:
            comparable_group = group.lower() if package.type == 'npm' else group
            if comparable_group != package.namespace:
                issues.append('group_purl_conflict')
        if package.version is None:
            issues.append('purl_version_missing')
    else:
        issues.append(f'purl_{status.value}')

    return NormalizedComponent(
        deepcopy(component), name, component_type, version, group, supplier_name,
        canonical, status, identity, tuple(reasons), tuple(issues),
    )


def normalize_components(components: Iterable[ParsedComponent]) -> NormalizationResult:
    """Preserve order and occurrences; group only complete, unambiguous PURLs.

    Duplicate groups are package identity candidates, not permission to merge
    installation evidence. Indices refer to the returned component tuple.
    """
    if isinstance(components, (str, bytes, dict)) or not isinstance(components, Iterable):
        raise ComponentNormalizationError('Expected an iterable of ParsedComponent')
    normalized = tuple(normalize_component(component) for component in components)
    indices: dict[str, list[int]] = {}
    for index, component in enumerate(normalized):
        if component.package_key is not None:
            indices.setdefault(component.package_key, []).append(index)
    groups = tuple(DuplicateGroup(key, tuple(positions))
                   for key, positions in indices.items() if len(positions) > 1)
    logger.info('Components normalized: component_count=%d duplicate_group_count=%d',
                len(normalized), len(groups))
    return NormalizationResult(normalized, groups)
