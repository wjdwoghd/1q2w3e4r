import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.sbom.generator import SBOMGenerationError, generate_cyclonedx_json


class SBOMGeneratorTests(unittest.TestCase):
    def test_successful_wrapper(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "core.sbom.generator.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess([], 0, '{"bomFormat":"CycloneDX"}', "")
            result = generate_cyclonedx_json(Path(directory), timeout_seconds=5)
            self.assertEqual(result.tool, "syft")
            self.assertIn("CycloneDX", result.content)
            self.assertEqual(run.call_args.args[0][-2:], ["-o", "cyclonedx-json@1.6"])

    def test_missing_source_and_timeout(self):
        with self.assertRaises(SBOMGenerationError):
            generate_cyclonedx_json("missing-path")
        with tempfile.TemporaryDirectory() as directory, patch(
            "core.sbom.generator.subprocess.run", side_effect=subprocess.TimeoutExpired([], 1)
        ), self.assertRaisesRegex(SBOMGenerationError, "timed out"):
            generate_cyclonedx_json(directory)
