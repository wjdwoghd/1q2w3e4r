"""Atomic persistence for parsed and normalized SBOM snapshots."""

from __future__ import annotations

import json
import sqlite3

from core.sbom.normalizer import NormalizationResult
from core.sbom.parser import ParsedSBOM
from database.models.component import Component
from database.models.sbom import SBOM


class SBOMRepositoryError(RuntimeError):
    pass


class SQLiteSBOMRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def save(
        self,
        *,
        asset_id: int,
        source: str,
        raw_document: str,
        parsed: ParsedSBOM,
        normalized: NormalizationResult,
    ) -> SBOM:
        if len(parsed.components) != len(normalized.components):
            raise SBOMRepositoryError("parsed and normalized component counts differ")
        if any(item.source != original for item, original in
               zip(normalized.components, parsed.components)):
            raise SBOMRepositoryError("normalized components do not match parsed source")
        try:
            with self.connection:
                cursor = self.connection.execute(
                    """INSERT INTO sboms
                    (asset_id, source, bom_format, spec_version, serial_number, raw_document)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (asset_id, source, "CycloneDX", parsed.spec_version,
                     None, raw_document),
                )
                sbom_id = cursor.lastrowid
                self.connection.executemany(
                    """INSERT INTO components
                    (sbom_id, position, name, version, purl, source_bom_ref, issues_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    [
                        (sbom_id, index, item.name, item.version, item.purl,
                         item.source.bom_ref, json.dumps(item.issues))
                        for index, item in enumerate(normalized.components)
                    ],
                )
        except sqlite3.IntegrityError as exc:
            raise SBOMRepositoryError("SBOM asset relationship is invalid") from exc
        return SBOM(sbom_id, asset_id, source, "CycloneDX",
                    parsed.spec_version, len(normalized.components))

    def list_components(self, sbom_id: int) -> tuple[Component, ...]:
        rows = self.connection.execute(
            "SELECT * FROM components WHERE sbom_id = ? ORDER BY position", (sbom_id,)
        ).fetchall()
        return tuple(Component(row["id"], row["sbom_id"], row["position"],
                               row["name"], row["version"], row["purl"],
                               row["source_bom_ref"]) for row in rows)

    def find_by_document(self, *, asset_id: int, source: str,
                         raw_document: str) -> tuple[SBOM, ...]:
        """Recover a committed import after a caller checkpoint was interrupted.

        Return all exact matches; callers must reject ambiguity rather than pick
        the newest SBOM. Component occurrence rows are never deduplicated.
        """
        rows = self.connection.execute(
            """SELECT s.*, COUNT(c.id) AS component_count FROM sboms s
               LEFT JOIN components c ON c.sbom_id = s.id
               WHERE s.asset_id = ? AND s.source = ? AND s.raw_document = ?
               GROUP BY s.id ORDER BY s.id""",
            (asset_id, source, raw_document),
        ).fetchall()
        return tuple(SBOM(row["id"], row["asset_id"], row["source"],
                          row["bom_format"], row["spec_version"], row["component_count"])
                     for row in rows)
