"""Atomic Finding persistence and read-only analysis provenance lookup."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Callable

from core.assets.context import AssetContext
from core.risk.engine import AppliedRule, RiskResult
from database.models.finding import Finding, FindingObservation, FindingStatus, FindingStatusEvent
from database.models.vulnerability import VulnerabilityMatchRun


class FindingRepositoryError(RuntimeError):
    pass


class FindingNotFoundError(FindingRepositoryError):
    pass


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class SQLiteFindingRepository:
    def __init__(self, connection: sqlite3.Connection,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.connection = connection
        self.clock = clock

    def asset_id_for_component(self, component_id: int) -> int:
        row = self.connection.execute(
            """SELECT s.asset_id FROM components AS c
            JOIN sboms AS s ON s.id = c.sbom_id WHERE c.id = ?""", (component_id,)
        ).fetchone()
        if row is None:
            raise FindingRepositoryError("match component does not exist")
        return row["asset_id"]

    def save(self, *, asset_id: int, run: VulnerabilityMatchRun,
             risks: tuple[RiskResult, ...], context: AssetContext) -> tuple[Finding, ...]:
        """One Finding per asset/CVE; one immutable observation per match evidence row."""
        if self.asset_id_for_component(run.component_id) != asset_id:
            raise FindingRepositoryError("match component belongs to another asset")
        source = self.connection.execute(
            """SELECT r.component_id, r.component_purl, c.purl
            FROM vulnerability_match_runs AS r JOIN components AS c ON c.id = r.component_id
            WHERE r.id = ?""", (run.id,),
        ).fetchone()
        if (source is None or source["component_id"] != run.component_id
                or source["component_purl"] != source["purl"]
                or run.result.component_purl != source["purl"]):
            raise FindingRepositoryError("match run and component identity disagree")
        rows = self.connection.execute(
            "SELECT id, cve_id FROM vulnerability_match_evidence WHERE run_id = ? ORDER BY id",
            (run.id,),
        ).fetchall()
        if (len(rows) != len(risks) or len(rows) != len(run.result.matches)
                or len({risk.cve_id for risk in risks}) != len(risks)
                or {row["cve_id"] for row in rows} != {risk.cve_id for risk in risks}):
            raise FindingRepositoryError("risk results do not match stored CVE evidence")
        risk_by_cve = {risk.cve_id: risk for risk in risks}
        context_json = _json(asdict(context))
        timestamp = self.clock().isoformat()
        try:
            with self.connection:
                for row in rows:
                    risk = risk_by_cve[row["cve_id"]]
                    risk_json = _json(asdict(risk))
                    self.connection.execute(
                        """INSERT INTO findings (asset_id, cve_id, status, created_at)
                        VALUES (?, ?, ?, ?) ON CONFLICT(asset_id, cve_id) DO NOTHING""",
                        (asset_id, risk.cve_id, FindingStatus.OPEN.value, timestamp),
                    )
                    finding_id = self.connection.execute(
                        "SELECT id FROM findings WHERE asset_id = ? AND cve_id = ?",
                        (asset_id, risk.cve_id),
                    ).fetchone()["id"]
                    self.connection.execute(
                        """INSERT INTO finding_status_history (finding_id, status, recorded_at)
                        VALUES (?, ?, ?) ON CONFLICT DO NOTHING""",
                        (finding_id, FindingStatus.OPEN.value, timestamp),
                    )
                    prior = self.connection.execute(
                        """SELECT finding_id, risk_json, asset_context_json
                        FROM finding_observations WHERE match_evidence_id = ?""",
                        (row["id"],),
                    ).fetchone()
                    if prior is not None:
                        if (prior["finding_id"] != finding_id or prior["risk_json"] != risk_json
                                or prior["asset_context_json"] != context_json):
                            raise FindingRepositoryError("analysis evidence already has different risk or context")
                        continue
                    self.connection.execute(
                        """INSERT INTO finding_observations
                        (finding_id, match_evidence_id, risk_json, asset_context_json, recorded_at)
                        VALUES (?, ?, ?, ?, ?)""",
                        (finding_id, row["id"], risk_json, context_json, timestamp),
                    )
        except sqlite3.IntegrityError as exc:
            raise FindingRepositoryError("finding relationship or constraint is invalid") from exc
        return tuple(self.get_by_asset_cve(asset_id, risk.cve_id) for risk in risks)

    def get(self, finding_id: int) -> Finding:
        row = self.connection.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row is None:
            raise FindingNotFoundError("finding not found")
        observations = self.connection.execute(
            """SELECT o.*, e.run_id, r.component_id, r.analysis_key
            FROM finding_observations AS o
            JOIN vulnerability_match_evidence AS e ON e.id = o.match_evidence_id
            JOIN vulnerability_match_runs AS r ON r.id = e.run_id
            WHERE o.finding_id = ? ORDER BY o.id""", (finding_id,)
        ).fetchall()
        history = self.connection.execute(
            "SELECT * FROM finding_status_history WHERE finding_id = ? ORDER BY id",
            (finding_id,),
        ).fetchall()
        def observation(item: sqlite3.Row) -> FindingObservation:
            risk = json.loads(item["risk_json"])
            risk["applied_rules"] = tuple(AppliedRule(**rule) for rule in risk["applied_rules"])
            risk["unassessed_factors"] = tuple(risk["unassessed_factors"])
            return FindingObservation(
                item["id"], item["match_evidence_id"], item["run_id"],
                item["component_id"], item["analysis_key"], RiskResult(**risk),
                AssetContext.create(**json.loads(item["asset_context_json"])), item["recorded_at"],
            )
        return Finding(
            row["id"], row["asset_id"], row["cve_id"], FindingStatus(row["status"]),
            row["created_at"], tuple(observation(item) for item in observations),
            tuple(FindingStatusEvent(item["id"], FindingStatus(item["status"]),
                                     item["recorded_at"]) for item in history),
        )

    def get_by_asset_cve(self, asset_id: int, cve_id: str) -> Finding:
        row = self.connection.execute(
            "SELECT id FROM findings WHERE asset_id = ? AND cve_id = ?", (asset_id, cve_id)
        ).fetchone()
        if row is None:
            raise FindingNotFoundError("finding not found")
        return self.get(row["id"])

    def list_for_asset(self, asset_id: int) -> tuple[Finding, ...]:
        rows = self.connection.execute(
            "SELECT id FROM findings WHERE asset_id = ? ORDER BY id", (asset_id,)
        ).fetchall()
        return tuple(self.get(row["id"]) for row in rows)
