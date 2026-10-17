"""Stored SBOM snapshot metadata."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SBOM:
    id: int
    asset_id: int
    source: str
    bom_format: str
    spec_version: str
    component_count: int
