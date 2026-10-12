"""Atomic, immutable reference-control mapping persistence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Callable

from core.compliance.controls import SecurityControl
from core.compliance.mapper import ControlMappingCandidate
from database.models.control_mapping import FindingControlMapping


class ControlMappingRepositoryError(RuntimeError):
    pass


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class SQLiteControlMappingRepository:
    def __init__(self, connection: sqlite3.Connection,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.connection = connection
        self.clock = clock

    def save_for_finding(self, finding_id: int,
                         candidates: tuple[ControlMappingCandidate, ...]
                         ) -> tuple[FindingControlMapping, ...]:
        """Reject conflicting replay and roll back the whole mapping batch."""
        if not isinstance(finding_id, int) or isinstance(finding_id, bool) or finding_id <= 0:
            raise ValueError("positive finding ID is required")
        if not isinstance(candidates, tuple):
            raise ValueError("mapping candidates must be a tuple")
        timestamp = self.clock().isoformat()
        try:
            with self.connection:
                for candidate in candidates:
                    if not isinstance(candidate, ControlMappingCandidate):
                        raise ValueError("invalid mapping candidate")
                    owner = self.connection.execute(
                        """SELECT o.finding_id, o.match_evidence_id, o.risk_json,
                               o.asset_context_json, f.cve_id, r.analysis_key
                        FROM finding_observations AS o
                        JOIN findings AS f ON f.id = o.finding_id
                        JOIN vulnerability_match_evidence AS e ON e.id = o.match_evidence_id
                        JOIN vulnerability_match_runs AS r ON r.id = e.run_id
                        WHERE o.id = ?""",
                        (candidate.observation_id,),
                    ).fetchone()
                    if owner is None or owner["finding_id"] != finding_id:
                        raise ControlMappingRepositoryError(
                            "mapping observation does not belong to Finding")
                    facts = dict(candidate.observed_facts)
                    if len(facts) != len(candidate.observed_facts) or any(
                        facts.get(key) != value for key, value in (
                            ("cve_id", owner["cve_id"]),
                            ("match_evidence_id", str(owner["match_evidence_id"])),
                            ("analysis_key", owner["analysis_key"]),
                        )
                    ):
                        raise ControlMappingRepositoryError(
                            "mapping facts disagree with stored observation evidence")
                    risk = json.loads(owner["risk_json"])
                    context = json.loads(owner["asset_context_json"])
                    for key, actual in (("priority", risk["priority"]),
                                        ("risk_rule_version", risk["rule_version"]),
                                        ("patch_status", context["patch_status"])):
                        if key in facts and facts[key] != actual:
                            raise ControlMappingRepositoryError(
                                "mapping facts disagree with stored observation snapshot")
                    control_json = _json(asdict(candidate.control))
                    facts_json = _json(facts)
                    payload = _json({"control": json.loads(control_json),
                                     "rule_id": candidate.rule_id,
                                     "rule_version": candidate.rule_version,
                                     "reason": candidate.reason,
                                     "facts": json.loads(facts_json)})
                    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                    prior = self.connection.execute(
                        """SELECT payload_digest FROM finding_control_mappings
                        WHERE observation_id = ? AND control_key = ?""",
                        (candidate.observation_id, candidate.control.key),
                    ).fetchone()
                    if prior is not None:
                        if prior["payload_digest"] != digest:
                            raise ControlMappingRepositoryError(
                                "observation and control already have different mapping evidence")
                        continue
                    self.connection.execute(
                        """INSERT INTO finding_control_mappings
                        (observation_id, control_key, control_type, control_snapshot_json,
                         rule_id, rule_version, reason, observed_facts_json, payload_digest,
                         recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (candidate.observation_id, candidate.control.key,
                         candidate.control.control_type.value, control_json,
                         candidate.rule_id, candidate.rule_version, candidate.reason,
                         facts_json, digest, timestamp),
                    )
        except sqlite3.IntegrityError as exc:
            raise ControlMappingRepositoryError("mapping relationship or constraint is invalid") from exc
        return self.list_for_finding(finding_id)

    def list_for_finding(self, finding_id: int) -> tuple[FindingControlMapping, ...]:
        rows = self.connection.execute(
            """SELECT m.*, o.finding_id FROM finding_control_mappings AS m
            JOIN finding_observations AS o ON o.id = m.observation_id
            WHERE o.finding_id = ? ORDER BY m.observation_id, m.control_key""",
            (finding_id,),
        ).fetchall()
        return tuple(FindingControlMapping(
            row["id"], row["finding_id"], row["observation_id"],
            SecurityControl.from_record(json.loads(row["control_snapshot_json"])),
            row["rule_id"], row["rule_version"], row["reason"],
            tuple(sorted(json.loads(row["observed_facts_json"]).items())),
            row["recorded_at"],
        ) for row in rows)
