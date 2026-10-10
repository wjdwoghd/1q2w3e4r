"""Parser to normalizer contract, including installation provenance."""

import json
import unittest
from pathlib import Path

from core.sbom.normalizer import normalize_component, normalize_components
from core.sbom.parser import parse_sbom, parse_sbom_file


class SBOMNormalizationTests(unittest.TestCase):
    def test_existing_fixture_preserves_parser_contract(self):
        fixture = Path(__file__).resolve().parents[1] / 'fixtures' / 'cyclonedx.json'
        parsed = parse_sbom_file(fixture)
        result = normalize_components(parsed.components)
        self.assertEqual(len(result.components), len(parsed.components))
        self.assertEqual(result.components[0].source, parsed.components[0])
        self.assertEqual(result.components[0].package_key, 'pkg:pypi/sample-library@01.2.0')
        self.assertEqual(parsed.dependencies, {'app': ('lib',), 'lib': ()})
        root = normalize_component(parsed.metadata_component)
        self.assertEqual(root.source.bom_ref, 'app')

    def test_nested_and_duplicate_occurrences_keep_relations(self):
        child = {'type': 'library', 'name': 'demo', 'version': '1',
                 'purl': 'pkg:pypi/demo@1', 'bom-ref': 'child'}
        parent = {**child, 'bom-ref': 'parent', 'components': [child]}
        parsed = parse_sbom(json.dumps({
            'bomFormat': 'CycloneDX', 'specVersion': '1.6',
            'components': [parent],
            'dependencies': [{'ref': 'parent', 'dependsOn': ['child', 'external']}],
        }))
        result = normalize_components(parsed.components)
        self.assertEqual(result.duplicate_groups[0].component_indices, (0, 1))
        self.assertEqual(result.components[1].source.parent_ref, 'parent')
        self.assertEqual(parsed.dependencies['parent'], ('child', 'external'))

    def test_bad_purl_does_not_discard_other_components(self):
        parsed = parse_sbom(json.dumps({
            'bomFormat': 'CycloneDX', 'specVersion': '1.6',
            'components': [
                {'type': 'library', 'name': 'demo', 'purl': 'bad'},
                {'type': 'library', 'name': 'demo', 'purl': 'pkg:pypi/demo@1'},
            ],
        }))
        result = normalize_components(parsed.components)
        self.assertEqual(result.components[0].issues, ('purl_invalid',))
        self.assertEqual(result.components[1].package_key, 'pkg:pypi/demo@1')
