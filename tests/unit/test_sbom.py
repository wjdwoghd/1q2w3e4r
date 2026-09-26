"""Synthetic inventory fixtures; no scanner or vulnerability claims."""

import json
import tempfile
import unittest
from pathlib import Path

from core.sbom.parser import (
    SBOMParsingError, UnsupportedSBOMFormat, parse_sbom, parse_sbom_file,
)

FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures' / 'cyclonedx.json'


def document(**fields):
    return json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', **fields})


class SBOMParserTests(unittest.TestCase):
    def test_fixture_fields_and_dependencies(self):
        result = parse_sbom_file(FIXTURE)
        component = result.components[0]
        self.assertEqual(component.name, 'sample-library')
        self.assertEqual(component.component_type, 'library')
        self.assertEqual(component.version, '01.2.0')
        self.assertEqual(component.purl, 'pkg:pypi/sample-library@01.2.0')
        self.assertEqual(component.group, 'example')
        self.assertEqual(component.supplier['name'], 'Example Supplier')
        self.assertEqual(component.hashes[0]['content'], 'a' * 64)
        self.assertEqual(component.licenses[0]['license']['id'], 'MIT')
        self.assertEqual(result.metadata_component.bom_ref, 'app')
        self.assertEqual(result.dependencies, {'app': ('lib',), 'lib': ()})

    def test_missing_optional_fields_are_not_inferred(self):
        component = parse_sbom(document(components=[
            {'type': 'library', 'name': 'sample'},
        ])).components[0]
        for key in ('version', 'purl', 'bom_ref', 'supplier', 'group'):
            self.assertIsNone(getattr(component, key))
        self.assertEqual(component.hashes, ())
        self.assertEqual(component.licenses, ())

    def test_empty_inventory_and_dependency_evidence(self):
        self.assertEqual(parse_sbom(document()).components, ())
        self.assertIsNone(parse_sbom(document()).dependencies)
        self.assertEqual(parse_sbom(document(dependencies=[])).dependencies, {})

    def test_supported_versions_and_determinism(self):
        for version in ('1.4', '1.5', '1.6'):
            with self.subTest(version=version):
                content = document(specVersion=version)
                self.assertEqual(parse_sbom(content), parse_sbom(content))
                self.assertEqual(parse_sbom(content).spec_version, version)

    def test_nested_inventory_preserves_order(self):
        child = {'type': 'library', 'name': 'child', 'bom-ref': 'child'}
        parent = {'type': 'library', 'name': 'parent', 'bom-ref': 'parent',
                  'components': [child]}
        root = {'type': 'application', 'name': 'root', 'bom-ref': 'root',
                'components': [parent]}
        result = parse_sbom(document(metadata={'component': root}))
        self.assertEqual([x.name for x in result.components], ['parent', 'child'])
        self.assertEqual([x.parent_ref for x in result.components], ['root', 'parent'])
        self.assertIsNone(result.dependencies)  # Nesting is not dependency evidence.

    def test_same_name_different_refs_are_preserved(self):
        items = [{'name': 'same', 'type': 'library', 'bom-ref': ref}
                 for ref in ('a', 'b')]
        self.assertEqual(len(parse_sbom(document(components=items)).components), 2)

    def test_duplicate_component_refs_fail(self):
        item = {'name': 'same', 'type': 'library', 'bom-ref': 'a'}
        for fields in ({'components': [item, item]},
                       {'metadata': {'component': item}, 'components': [item]}):
            with self.subTest(fields=fields), self.assertRaises(SBOMParsingError):
                parse_sbom(document(**fields))

    def test_invalid_component_fields(self):
        changes = [{'name': ''}, {'name': None}, {'version': 12}, {'purl': []},
                   {'supplier': 'vendor'}, {'hashes': [{}]}, {'licenses': [{}]},
                   {'components': None}, {'licenses': [{'license': {}}]},
                   {'licenses': [{'expression': 3}]}, {'bom-ref': ''}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(SBOMParsingError):
                parse_sbom(document(components=[
                    {'type': 'library', 'name': 'sample', **change},
                ]))
        with self.assertRaises(SBOMParsingError):
            parse_sbom(document(components=[{'name': 'missing-type'}]))

    def test_invalid_document_structure(self):
        for fields in ({'components': {}}, {'components': [None]},
                       {'metadata': None}, {'metadata': {'component': None}},
                       {'dependencies': None}, {'specVersion': []}):
            with self.subTest(fields=fields), self.assertRaises(SBOMParsingError):
                parse_sbom(document(**fields))

    def test_dependency_validation_and_unresolved_refs(self):
        for deps in ([{}], [{'ref': 'a', 'dependsOn': 'b'}],
                     [{'ref': 'a', 'dependsOn': [None]}],
                     [{'ref': 'a'}, {'ref': 'a'}]):
            with self.subTest(deps=deps), self.assertRaises(SBOMParsingError):
                parse_sbom(document(dependencies=deps))
        result = parse_sbom(document(dependencies=[{'ref': 'external',
                                                   'dependsOn': ['unknown']}]))
        self.assertEqual(result.dependencies, {'external': ('unknown',)})

    def test_license_expression_and_named_license(self):
        licenses = [{'expression': 'MIT OR Apache-2.0'},
                    {'license': {'name': 'Example License'}}]
        result = parse_sbom(document(components=[
            {'name': 'sample', 'type': 'library', 'licenses': licenses},
        ]))
        self.assertEqual(result.components[0].licenses, tuple(licenses))

    def test_invalid_json(self):
        for content in ('', '{', '[]', 'null', '{"a":1,"a":2}',
                        '{"a":NaN}', '[' * 2000, None):
            with self.subTest(content=str(content)[:30]):
                with self.assertRaises(SBOMParsingError):
                    parse_sbom(content)

    def test_unsupported_formats(self):
        for content in ('<bom/>', document(bomFormat='SPDX'),
                        document(specVersion='9.0')):
            with self.subTest(content=content):
                with self.assertRaises(UnsupportedSBOMFormat):
                    parse_sbom(content)

    def test_file_errors_and_utf8_bom(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.json'
            with self.assertRaises(SBOMParsingError):
                parse_sbom_file(path)
            path.write_bytes(b'\xff')
            with self.assertRaises(SBOMParsingError):
                parse_sbom_file(path)
            path.write_text(document(), encoding='utf-8-sig')
            self.assertEqual(parse_sbom_file(path).components, ())
            with self.assertRaises(SBOMParsingError):
                parse_sbom_file(directory)
