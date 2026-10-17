"""Stored component occurrence linked to a specific SBOM snapshot."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Component:
    id: int
    sbom_id: int
    position: int
    name: str
    version: str | None
    purl: str | None
    source_bom_ref: str | None
