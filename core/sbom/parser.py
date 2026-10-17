"""CycloneDX JSON extraction; no normalization or security inference."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
SUPPORTED_VERSIONS = frozenset({'1.4', '1.5', '1.6'})


class SBOMParsingError(ValueError):
    """Unreadable SBOM or invalid extracted field."""


class UnsupportedSBOMFormat(SBOMParsingError):
    """Unsupported format or specification version."""


@dataclass(frozen=True)
class ParsedComponent:
    name: str
    component_type: str
    version: str | None
    purl: str | None
    bom_ref: str | None
    group: str | None
    supplier: dict[str, Any] | None
    hashes: tuple[dict[str, Any], ...]
    licenses: tuple[dict[str, Any], ...]
    parent_ref: str | None


@dataclass(frozen=True)
class ParsedSBOM:
    spec_version: str
    components: tuple[ParsedComponent, ...]
    metadata_component: ParsedComponent | None
    dependencies: dict[str, tuple[str, ...]] | None


def _text(data: dict, key: str, required: bool = False) -> str | None:
    if key not in data and not required:
        return None
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SBOMParsingError(f'{key} must be a non-empty string')
    return value


def _objects(data: dict, key: str) -> list[dict]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise SBOMParsingError(f'{key} must be an array of objects')
    return value


def _component(data: dict, parent: str | None) -> ParsedComponent:
    supplier = data.get('supplier')
    if 'supplier' in data and not isinstance(supplier, dict):
        raise SBOMParsingError('supplier must be an object')
    if supplier is not None and 'name' in supplier:
        _text(supplier, 'name', True)
    hashes = _objects(data, 'hashes')
    for item in hashes:
        _text(item, 'alg', True)
        _text(item, 'content', True)
    licenses = _objects(data, 'licenses')
    for item in licenses:
        if ('license' in item) == ('expression' in item):
            raise SBOMParsingError('license entry needs license or expression')
        if 'expression' in item:
            _text(item, 'expression', True)
        else:
            value = item['license']
            if not isinstance(value, dict) or not ({'id', 'name'} & value.keys()):
                raise SBOMParsingError('license needs id or name')
            for key in ('id', 'name'):
                if key in value:
                    _text(value, key, True)
    return ParsedComponent(
        name=_text(data, 'name', True),
        component_type=_text(data, 'type', True),
        version=_text(data, 'version'), purl=_text(data, 'purl'),
        bom_ref=_text(data, 'bom-ref'), group=_text(data, 'group'),
        supplier=supplier, hashes=tuple(hashes), licenses=tuple(licenses),
        parent_ref=parent,
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SBOMParsingError('Duplicate JSON object key')
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise SBOMParsingError('Non-standard JSON constant')


def parse_sbom(content: str) -> ParsedSBOM:
    """Parse CycloneDX 1.4-1.6 JSON text or raise SBOMParsingError.

    Preserves source values and order. Validates extracted fields, not the
    complete schema. No dependency reference resolution or PURL validation.
    """
    if not isinstance(content, str):
        raise SBOMParsingError('SBOM content must be text')
    if content.lstrip('\ufeff \t\r\n').startswith('<'):
        raise UnsupportedSBOMFormat('XML unsupported; supply CycloneDX JSON')
    try:
        data = json.loads(content.lstrip('\ufeff'),
                          object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, SBOMParsingError):
            raise
        raise SBOMParsingError('Invalid SBOM JSON') from exc
    if not isinstance(data, dict):
        raise SBOMParsingError('SBOM root must be an object')
    if data.get('bomFormat') != 'CycloneDX':
        raise UnsupportedSBOMFormat('Expected CycloneDX JSON')
    version = _text(data, 'specVersion', True)
    if version not in SUPPORTED_VERSIONS:
        raise UnsupportedSBOMFormat('Supported versions: 1.4, 1.5, 1.6')
    metadata = data.get('metadata', {})
    if not isinstance(metadata, dict):
        raise SBOMParsingError('metadata must be an object')
    root = metadata.get('component')
    if 'component' in metadata and not isinstance(root, dict):
        raise SBOMParsingError('metadata.component must be an object')
    root_component = _component(root, None) if root is not None else None
    refs = set()
    if root_component and root_component.bom_ref:
        refs.add(root_component.bom_ref)
    pending = [(item, None) for item in _objects(data, 'components')]
    if root is not None:
        pending = [(item, root_component.bom_ref)
                   for item in _objects(root, 'components')] + pending
    components = []
    stack = list(reversed(pending))
    while stack:
        item, parent = stack.pop()
        component = _component(item, parent)
        if component.bom_ref is not None:
            if component.bom_ref in refs:
                raise SBOMParsingError('Duplicate component bom-ref')
            refs.add(component.bom_ref)
        components.append(component)
        stack.extend((child, component.bom_ref)
                     for child in reversed(_objects(item, 'components')))
    dependencies = None
    if 'dependencies' in data:
        dependencies = {}
        for item in _objects(data, 'dependencies'):
            ref = _text(item, 'ref', True)
            targets = item.get('dependsOn', [])
            if not isinstance(targets, list) or any(
                not isinstance(x, str) or not x.strip() for x in targets
            ):
                raise SBOMParsingError('dependsOn must be an array of strings')
            if ref in dependencies:
                raise SBOMParsingError('Duplicate dependency ref')
            dependencies[ref] = tuple(targets)
    logger.info('SBOM parsed: component_count=%d', len(components))
    return ParsedSBOM(version, tuple(components), root_component, dependencies)


def parse_sbom_file(path: str | Path) -> ParsedSBOM:
    """Read UTF-8 JSON; translate filesystem and encoding errors."""
    try:
        content = Path(path).read_text(encoding='utf-8-sig')
    except (OSError, UnicodeError, ValueError) as exc:
        raise SBOMParsingError('Unable to read UTF-8 SBOM file') from exc
    return parse_sbom(content)
