"""Synthetic package data; these tests make no vulnerability claims."""

import unittest
from dataclasses import replace

from core.sbom.normalizer import (
    ComponentNormalizationError, PURLStatus,
    normalize_component, normalize_components,
)
from core.sbom.parser import ParsedComponent


def component(**changes):
    values = dict(name='demo', component_type='library', version='1.0',
                  purl='pkg:pypi/demo@1.0', bom_ref='lib', group=None,
                  supplier=None, hashes=(), licenses=(), parent_ref=None)
    values.update(changes)
    return ParsedComponent(**values)


class NormalizerTests(unittest.TestCase):
    def test_whitespace_and_evidence_preservation(self):
        original = component(name=' Demo_Package ', version=' 01.2.0 ',
                             purl=' pkg:pypi/Demo_Package@01.2.0 ',
                             supplier={'name': ' Example Supplier ', 'url': ['https://example.test']},
                             group=' Example ', bom_ref=' ref ', parent_ref=' parent ')
        result = normalize_component(original)
        self.assertEqual(result.name, 'demo-package')
        self.assertEqual(result.version, '01.2.0')
        self.assertEqual(result.supplier_name, 'Example Supplier')
        self.assertEqual(result.group, 'Example')
        self.assertEqual(result.purl, 'pkg:pypi/demo-package@01.2.0')
        self.assertEqual(result.source, original)
        self.assertEqual(result.source.bom_ref, ' ref ')
        self.assertEqual(result.source.parent_ref, ' parent ')
        self.assertIn('version: trimmed surrounding whitespace', result.reasons)

    def test_source_snapshot_is_detached(self):
        original = component(supplier={'name': 'Vendor', 'url': ['https://example.test']},
                             hashes=({'alg': 'SHA-256', 'content': 'synthetic'},),
                             licenses=({'license': {'id': 'MIT'}},))
        result = normalize_component(original)
        original.supplier['url'].append('https://other.test')
        original.hashes[0]['content'] = 'changed'
        original.licenses[0]['license']['id'] = 'changed'
        self.assertEqual(result.source.supplier['url'], ['https://example.test'])
        self.assertEqual(result.source.hashes[0]['content'], 'synthetic')
        self.assertEqual(result.source.licenses[0]['license']['id'], 'MIT')

    def test_versions_are_not_reinterpreted(self):
        for version in ('v1.0', '01.2.0', '1.0-SNAPSHOT', '1.0+Build', '1.0rc1'):
            with self.subTest(version=version):
                result = normalize_component(component(version=version, purl=None))
                self.assertEqual(result.version, version)

    def test_missing_values_are_not_generated(self):
        result = normalize_component(component(version=None, purl=None))
        self.assertIsNone(result.version)
        self.assertIsNone(result.purl)
        self.assertIsNone(result.package)
        self.assertIsNone(result.supplier_name)
        self.assertIsNone(result.package_key)
        self.assertEqual(result.purl_status, PURLStatus.MISSING)

    def test_purl_fields_do_not_fill_component_fields(self):
        result = normalize_component(component(version=None))
        self.assertIsNone(result.version)
        self.assertEqual(result.package.version, '1.0')
        self.assertEqual(result.package_key, 'pkg:pypi/demo@1.0')

    def test_pypi_name_separators(self):
        result = normalize_component(component(name='Demo..__Package',
                                               purl='pkg:PyPI/Demo..__Package@1.0'))
        self.assertEqual(result.name, 'demo-package')
        self.assertEqual(result.package.name, 'demo-package')
        self.assertFalse(result.issues)

    def test_maven_case_and_namespace_are_preserved(self):
        result = normalize_component(component(name='Demo', group='org.Example',
                                               purl='pkg:maven/org.Example/Demo@1.0'))
        self.assertEqual(result.name, 'Demo')
        self.assertEqual(result.package.namespace, 'org.Example')
        self.assertFalse(result.issues)

    def test_scoped_npm_name_forms(self):
        for name in ('Demo', '@Scope/Demo'):
            with self.subTest(name=name):
                result = normalize_component(component(
                    name=name, group='@Scope', purl='pkg:npm/%40Scope/Demo@1.0'))
                self.assertEqual(result.package.namespace, '@scope')
                self.assertFalse(result.issues)

    def test_generic_names_remain_case_sensitive(self):
        result = normalize_component(component(name='Demo_Lib',
                                               purl='pkg:generic/Demo_Lib@1.0'))
        self.assertEqual(result.name, 'Demo_Lib')
        self.assertFalse(result.issues)

    def test_qualifiers_subpath_and_encoding(self):
        result = normalize_component(component(
            purl='pkg:pypi/demo@1.0?repository_url=https%3a%2f%2fexample.test&arch=x86#src/lib'))
        self.assertEqual(result.package.qualifiers,
                         (('arch', 'x86'), ('repository_url', 'https://example.test')))
        self.assertEqual(result.package.subpath, 'src/lib')
        self.assertIn('?arch=x86&repository_url=', result.purl)

    def test_plus_is_not_decoded_as_space(self):
        result = normalize_component(component(
            name='Demo', version='1.0+Build', purl='pkg:generic/Demo@1.0%2BBuild'))
        self.assertEqual(result.package.version, '1.0+Build')
        self.assertFalse(result.issues)

    def test_invalid_purls_are_retained_as_issues(self):
        invalid = (
            'https://example.test/demo', 'pkg:pypi/', 'pkg:1bad/demo',
            'pkg:maven/demo@1.0', 'pkg:pypi/namespace/demo@1.0',
            'pkg:pypi/demo@', 'pkg:pypi/demo@1.0?arch=',
            'pkg:pypi/demo@1.0?arch=x&ARCH=y', 'pkg:pypi/demo@1.0?',
            'pkg:pypi/demo%GG@1.0', 'pkg:pypi/demo%FF@1.0',
            'pkg:pypi/demo%00@1.0', 'pkg:pypi/de mo@1.0',
            'pkg:pypi/demo@1.0#../src', 'pkg:pypi/demo@1.0#',
        )
        for purl in invalid:
            with self.subTest(purl=purl):
                result = normalize_component(component(purl=purl))
                self.assertEqual(result.purl_status, PURLStatus.INVALID)
                self.assertIsNone(result.package_key)
                self.assertIsNone(result.purl)
                self.assertEqual(result.source.purl, purl)

    def test_unsupported_type_is_not_guessed(self):
        result = normalize_component(component(name='Demo_Lib',
                                               purl='pkg:future/Demo_Lib@1.0'))
        self.assertEqual(result.purl_status, PURLStatus.UNSUPPORTED)
        self.assertEqual(result.name, 'Demo_Lib')
        self.assertIsNone(result.package_key)

    def test_field_conflicts_are_not_overwritten(self):
        cases = (
            (component(name='different'), 'name_purl_conflict'),
            (component(version='2.0'), 'version_purl_conflict'),
            (component(group='org.other', purl='pkg:maven/org.example/demo@1.0'),
             'group_purl_conflict'),
        )
        for original, issue in cases:
            with self.subTest(issue=issue):
                result = normalize_component(original)
                self.assertIn(issue, result.issues)
                self.assertEqual(result.source, original)
                self.assertIsNone(result.package_key)

    def test_unversioned_purl_is_not_completed(self):
        result = normalize_component(component(purl='pkg:pypi/demo'))
        self.assertEqual(result.purl, 'pkg:pypi/demo')
        self.assertIsNone(result.package.version)
        self.assertIsNone(result.package_key)
        self.assertIn('purl_version_missing', result.issues)

    def test_invalid_component_input_is_explicit(self):
        for changes in ({'name': ''}, {'version': 3}, {'component_type': None},
                        {'supplier': []}, {'supplier': {'name': None}},
                        {'purl': []}, {'group': False}):
            with self.subTest(changes=changes):
                with self.assertRaises(ComponentNormalizationError):
                    normalize_component(component(**changes))
        with self.assertRaises(ComponentNormalizationError):
            normalize_component({})

    def test_supplier_without_name_is_not_inferred(self):
        result = normalize_component(component(supplier={'url': ['https://example.test']}))
        self.assertIsNone(result.supplier_name)
        self.assertFalse(result.reasons)

    def test_duplicates_keep_every_occurrence_and_evidence(self):
        first = component(bom_ref='first', hashes=({'content': 'one'},))
        second = component(bom_ref='second', parent_ref='parent',
                           hashes=({'content': 'two'},), supplier={'name': 'Other'})
        result = normalize_components([first, second])
        self.assertEqual(len(result.components), 2)
        self.assertEqual(result.duplicate_groups[0].component_indices, (0, 1))
        self.assertEqual(result.components[1].source, second)
        self.assertEqual(result.components[0].source, first)

    def test_equivalent_purl_encodings_group_together(self):
        result = normalize_components([
            component(name='Demo_Package', purl='pkg:PyPI/Demo_Package@1.0?b=2&a=1'),
            component(name='demo-package', purl='pkg:pypi/demo-package@1.0?a=1&b=2'),
        ])
        self.assertEqual(len(result.duplicate_groups), 1)

    def test_different_identity_parts_do_not_group(self):
        purls = ('pkg:pypi/demo@1.0', 'pkg:pypi/demo@2.0',
                 'pkg:pypi/demo@1.0?arch=x86', 'pkg:pypi/demo@1.0#src',
                 'pkg:generic/demo@1.0',
                 'pkg:maven/org.one/demo@1.0', 'pkg:maven/org.two/demo@1.0')
        result = normalize_components([component(purl=purl, version=None) for purl in purls])
        self.assertFalse(result.duplicate_groups)

    def test_missing_invalid_conflicting_records_do_not_group(self):
        for original in (component(purl=None), component(purl='invalid'),
                         component(purl='pkg:pypi/demo'), component(version='2.0'),
                         component(purl='pkg:future/demo@1.0')):
            with self.subTest(original=original):
                result = normalize_components([original, original])
                self.assertFalse(result.duplicate_groups)
                self.assertEqual(len(result.components), 2)

    def test_deterministic_order_and_generator_input(self):
        records = [component(), component(name='other', purl='pkg:pypi/other@1.0'),
                   component(bom_ref=None), component(name='other', purl='pkg:pypi/other@1.0')]
        first = normalize_components(records)
        self.assertEqual(first, normalize_components(iter(records)))
        self.assertEqual([group.component_indices for group in first.duplicate_groups],
                         [(0, 2), (1, 3)])

    def test_normalized_values_are_idempotent(self):
        result = normalize_component(component(name=' Demo_Package ',
                                               purl='pkg:pypi/Demo_Package@1.0'))
        again = normalize_component(replace(result.source, name=result.name, purl=result.purl))
        self.assertEqual(result.name, again.name)
        self.assertEqual(result.package, again.package)
        self.assertFalse(again.reasons)

    def test_empty_and_invalid_collections(self):
        self.assertEqual(normalize_components([]).components, ())
        for value in (None, 'demo', {}, [None]):
            with self.subTest(value=value), self.assertRaises(ComponentNormalizationError):
                normalize_components(value)

    def test_logs_only_counts(self):
        with self.assertLogs('core.sbom.normalizer', level='INFO') as captured:
            normalize_components([component(supplier={'name': 'private-vendor'})])
        self.assertIn('component_count=1', captured.output[0])
        self.assertNotIn('private-vendor', captured.output[0])
