"""Read-only database sessions and the missing SBOM inventory lookup."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class DashboardDatabaseError(RuntimeError):
    """A configured execution database cannot be read with the MVP schema."""


@contextmanager
def open_dashboard_database(path: Path) -> Iterator[sqlite3.Connection]:
    # mode=ro prevents accidental creation; query_only also rejects writes to attached DBs.
    connection = None
    try:
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")  # One consistent read snapshot per API request.
        required = {
            "business_services", "assets", "sboms", "components", "findings",
            "finding_observations", "finding_status_history", "finding_control_mappings",
            "vulnerability_match_runs", "vulnerability_match_evidence", "recommendations",
            "remediations", "remediation_applications", "verifications",
            "verification_after_evidence", "verification_results",
        }
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if required - tables:
            raise DashboardDatabaseError("Phase 9 schema required; missing tables: " + ", ".join(sorted(required - tables)))
        yield connection
    finally:
        if connection is not None:
            connection.close()  # No schema initialization, migrations or commits.


class SQLiteDashboardRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def list_sboms(self, asset_id: int) -> list[dict]:
        rows = self.connection.execute(
            """SELECT s.id, s.asset_id, s.source, s.bom_format, s.spec_version,
                      COUNT(c.id) AS component_count
               FROM sboms s LEFT JOIN components c ON c.sbom_id = s.id
               WHERE s.asset_id = ? GROUP BY s.id ORDER BY s.id""", (asset_id,)
        ).fetchall()
        return [dict(row) for row in rows]
