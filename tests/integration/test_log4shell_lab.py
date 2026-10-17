"""Offline Java runtime contracts; no exploit payloads or vulnerability API calls."""

import json
import os
from pathlib import Path
from queue import Queue, Empty
import shutil
import subprocess
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

from core.assets.asset_service import AssetService
from core.sbom.diff import compare_sbom_versions
from core.sbom.generator import generate_cyclonedx_json
from core.sbom.normalizer import normalize_components
from core.sbom.parser import parse_sbom
from database.database import connect_database, initialize_database
from database.repositories.asset_repository import SQLiteAssetRepository
from database.repositories.sbom_repository import SQLiteSBOMRepository

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / 'labs' / 'log4shell'
NS = {'m': 'http://maven.apache.org/POM/4.0.0'}


def java_executable():
    home = os.environ.get('LAB_JAVA_HOME') or os.environ.get('JAVA_HOME')
    config = ROOT / 'data' / 'output' / 'lab-tooling' / 'toolchain.json'
    if not home and config.is_file():
        home = json.loads(config.read_text(encoding='utf-8-sig')).get('java_home')
    executable = str(Path(home) / 'bin' / ('java.exe' if os.name == 'nt' else 'java')) if home else shutil.which('java')
    return executable if executable and Path(executable).is_file() else None


def classpath(variant):
    runtime = LAB / variant / 'target' / 'runtime'
    return os.pathsep.join((str(runtime / 'classes'), str(runtime / 'lib' / '*')))


def declared_version(variant):
    return ET.parse(LAB / variant / 'pom.xml').findtext('m:properties/m:log4j.version', namespaces=NS)


class LabDefinitionTests(unittest.TestCase):
    def test_variants_use_same_source_and_only_two_runtime_dependencies(self):
        parent = ET.parse(LAB / 'pom.xml')
        self.assertIn('/../common/src/main/java', parent.findtext('m:build/m:sourceDirectory', namespaces=NS))
        self.assertTrue(parent.findtext('m:build/m:outputDirectory', namespaces=NS).endswith('/runtime/classes'))
        for variant in ('vulnerable', 'patched'):
            child = ET.parse(LAB / variant / 'pom.xml')
            dependencies = child.findall('m:dependencies/m:dependency', NS)
            self.assertEqual({item.findtext('m:artifactId', namespaces=NS) for item in dependencies},
                             {'log4j-api', 'log4j-core'})
            self.assertIsNone(child.find('m:build', NS))
        self.assertEqual(declared_version('vulnerable'), '2.14.1')
        self.assertNotEqual(declared_version('vulnerable'), declared_version('patched'))

    @unittest.skipUnless(shutil.which('docker'), 'Docker CLI required for offline Compose validation')
    def test_compose_is_loopback_only_and_separate_from_platform(self):
        environment = os.environ.copy()
        environment.pop('LAB_PORT', None)
        result = subprocess.run(
            ['docker', 'compose', '-f', str(LAB / 'docker-compose.yml'), '--profile', 'before',
             '--profile', 'after', 'config', '--format', 'json'], capture_output=True, text=True,
            encoding='utf-8', timeout=30, check=True, env=environment,
        )
        config = json.loads(result.stdout)
        self.assertEqual(set(config['services']), {'vulnerable', 'patched'})
        self.assertTrue(config['networks']['isolated']['internal'])
        for service in config['services'].values():
            self.assertEqual(service['ports'][0]['host_ip'], '127.0.0.1')
            self.assertEqual(str(service['ports'][0]['published']), '18080')
            self.assertTrue(service['read_only'])
            self.assertIn('ALL', service['cap_drop'])
            self.assertEqual(set(service['environment']), {'JAVA_TOOL_OPTIONS'})
            self.assertFalse(service.get('privileged', False))
            self.assertFalse(service.get('volumes'))


class JavaRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = java_executable()
        if cls.java is None:
            raise unittest.SkipTest('Prepare JDK using the Lab guide before actual runtime tests')
        for variant in ('vulnerable', 'patched'):
            if not (LAB / variant / 'target/runtime/classes/com/example/sbomlab/BankingLab.class').is_file():
                raise unittest.SkipTest('Build both Lab variants before actual runtime tests')

    def _environment(self):
        environment = os.environ.copy()
        environment.pop('LAB_CONTAINER', None)
        return environment

    def _run(self, variant, *arguments):
        return subprocess.run([self.java, '-cp', classpath(variant), 'com.example.sbomlab.BankingLab', *arguments],
                              capture_output=True, text=True, encoding='utf-8', timeout=15,
                              env=self._environment())

    def _server(self, variant):
        process = subprocess.Popen(
            [self.java, '-cp', classpath(variant), 'com.example.sbomlab.BankingLab',
             '--host', '127.0.0.1', '--port', '0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8', env=self._environment(),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        )

        def stop():
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        self.addCleanup(stop)
        ready = Queue()
        Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
        try:
            marker = json.loads(ready.get(timeout=10))
        except (Empty, ValueError) as error:
            self.fail(f'Lab did not publish a valid startup marker: {type(error).__name__}')
        self.assertEqual(marker['host'], '127.0.0.1')
        self.assertGreater(marker['port'], 0)
        return f"http://127.0.0.1:{marker['port']}"

    def test_both_actual_jars_report_their_declared_versions(self):
        for variant in ('vulnerable', 'patched'):
            with self.subTest(variant=variant):
                result = self._run(variant, '--self-test')
                self.assertEqual(result.returncode, 0, result.stderr)
                inventory = json.loads(result.stdout)
                self.assertEqual(inventory['log4j_api_version'], declared_version(variant))
                self.assertEqual(inventory['log4j_core_version'], declared_version(variant))

    def test_same_real_health_and_business_contract_before_and_after(self):
        for variant in ('vulnerable', 'patched'):
            with self.subTest(variant=variant):
                address = self._server(variant)
                for path, expected in (('/health', {'status': 'ok'}),
                                       ('/banking/smoke', {'result': 'ok', 'mode': 'synthetic'})):
                    with urlopen(address + path, timeout=5) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(json.load(response), expected)
                with urlopen(address + '/runtime', timeout=5) as response:
                    self.assertEqual(json.load(response)['log4j_core_version'], declared_version(variant))

    def test_unknown_routes_and_non_get_methods_fail(self):
        address = self._server('vulnerable')
        with self.assertRaises(HTTPError) as unknown:
            urlopen(address + '/unknown', timeout=5)
        self.assertEqual(unknown.exception.code, 404)
        unknown.exception.close()
        with self.assertRaises(HTTPError) as method:
            urlopen(Request(address + '/banking/smoke', data=b'{}', method='POST'), timeout=5)
        self.assertEqual(method.exception.code, 405)
        self.assertEqual(method.exception.headers['Allow'], 'GET')
        method.exception.close()

    def test_host_mode_refuses_non_loopback_binding_and_invalid_ports(self):
        for arguments in (('--host', '0.0.0.0'), ('--port', '-1'), ('--port', '65536'), ('--unknown', '1')):
            with self.subTest(arguments=arguments):
                result = self._run('vulnerable', *arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(result.stdout)


class LabSBOMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = ROOT / 'data/output/lab-tooling/toolchain.json'
        data = json.loads(config.read_text(encoding='utf-8-sig')) if config.is_file() else {}
        cls.syft = os.environ.get('LAB_SYFT_EXECUTABLE') or data.get('syft_executable') or shutil.which('syft')
        if not cls.syft or not Path(cls.syft).is_file():
            raise unittest.SkipTest('Prepare Syft for actual Lab SBOM generation')
        if any(not (LAB / variant / 'target/runtime/lib').is_dir() for variant in ('vulnerable', 'patched')):
            raise unittest.SkipTest('Build both Lab runtimes before SBOM generation')

    def test_actual_runtime_sbom_parser_normalizer_storage_and_diff(self):
        connection = connect_database()
        self.addCleanup(connection.close)
        initialize_database(connection)
        assets = AssetService(SQLiteAssetRepository(connection))
        business = assets.register_business_service('Offline actual Lab inventory test')
        asset = assets.register_asset(business.id, name='Local Log4j test', environment='development',
                                      internet_exposed=False, business_criticality='low',
                                      customer_information=False, credit_information=False,
                                      patch_status='unknown', vendor='Lab', owner='Test')
        sboms = SQLiteSBOMRepository(connection)
        inventories = {}
        with patch.dict(os.environ, {'SYFT_CONFIG': str(LAB / 'syft.yaml'), 'SYFT_CHECK_FOR_APP_UPDATE': 'false'}):
            for variant in ('vulnerable', 'patched'):
                generated = generate_cyclonedx_json(LAB / variant / 'target/runtime', executable=self.syft)
                parsed = parse_sbom(generated.content)
                normalized = normalize_components(parsed.components)
                self.assertEqual(parsed.spec_version, '1.6')
                self.assertEqual({item.name for item in normalized.components}, {'log4j-api', 'log4j-core'})
                self.assertEqual(len(normalized.components), 2)
                self.assertTrue(all(item.package_key and not item.issues for item in normalized.components))
                self.assertTrue(all(item.version == declared_version(variant) for item in normalized.components))
                saved = sboms.save(asset_id=asset.id, source=generated.source, raw_document=generated.content,
                                   parsed=parsed, normalized=normalized)
                inventories[variant] = [dict(name=item.name, version=item.version, purl=item.purl)
                                        for item in sboms.list_components(saved.id)]
        diff = compare_sbom_versions(inventories['vulnerable'], inventories['patched'])
        self.assertEqual(len(diff['version_changes']), 2)
        self.assertFalse(diff['added'] or diff['removed'] or diff['unresolved_before'] or diff['unresolved_after'])


if __name__ == '__main__':
    unittest.main()
