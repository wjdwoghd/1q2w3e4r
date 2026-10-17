"""External SBOM generation wrapper with explicit failure modes."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


class SBOMGenerationError(RuntimeError):
    pass


@dataclass(frozen=True)
class GeneratedSBOM:
    content: str
    source: str
    tool: str


def generate_cyclonedx_json(
    source: str | Path,
    *,
    executable: str = "syft",
    timeout_seconds: float = 120.0,
) -> GeneratedSBOM:
    source_path = Path(source)
    if not source_path.exists():
        raise SBOMGenerationError(f"SBOM source does not exist: {source_path}")
    if timeout_seconds <= 0:
        raise SBOMGenerationError("timeout_seconds must be positive")
    # Pin to the parser's supported schema; Syft's default advances over time.
    command = [executable, str(source_path), "-o", "cyclonedx-json@1.6"]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout_seconds, check=False,
        )
    except FileNotFoundError as exc:
        raise SBOMGenerationError(f"SBOM generator not found: {executable}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SBOMGenerationError("SBOM generation timed out") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or "no diagnostic output"
        raise SBOMGenerationError(
            f"SBOM generator failed with exit code {result.returncode}: {detail}"
        )
    if not result.stdout.strip():
        raise SBOMGenerationError("SBOM generator returned empty output")
    return GeneratedSBOM(result.stdout, str(source_path), executable)
