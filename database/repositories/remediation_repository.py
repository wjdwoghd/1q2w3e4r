"""Atomic, append-only remediation plans and application evidence."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Callable

from database.models.finding import FindingStatus
from database.models.remediation import BeforeSnapshot, Remediation, RemediationApplication
from database.repositories.recommendation_repository import canonical_json


class RemediationRepositoryError(RuntimeError):
    pass


class RemediationNotFoundError(RemediationRepositoryError):
    pass


class SQLiteRemediationRepository:
    def __init__(self, connection: sqlite3.Connection,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.connection = connection
        self.clock = clock

    def get(self, remediation_id: int) -> Remediation:
        row = self.connection.execute(
            """SELECT r.*, a.action AS applied_action, a.actor, a.applied_at,
                      a.evidence_type, a.evidence_reference, a.evidence_source,
                      a.recorded_at AS application_recorded_at
               FROM remediations AS r LEFT JOIN remediation_applications AS a
               ON a.remediation_id = r.id WHERE r.id = ?""", (remediation_id,)
        ).fetchone()
        if row is None:
            raise RemediationNotFoundError("remediation not found")
        before = json.loads(row["before_json"])
        before["risk_reasons"] = tuple(before["risk_reasons"])
        application = None
        if row["applied_action"] is not None:
            application = RemediationApplication(
                row["applied_action"], row["actor"], row["applied_at"],
                row["evidence_type"], row["evidence_reference"],
                row["evidence_source"], row["application_recorded_at"])
        return Remediation(row["id"], row["finding_id"], row["recommendation_id"],
                           row["observation_id"], row["action_key"],
                           row["planned_action"], row["owner"],
                           BeforeSnapshot(**before), row["created_at"], application)

    def list_for_finding(self, finding_id: int) -> tuple[Remediation, ...]:
        rows = self.connection.execute(
            "SELECT id FROM remediations WHERE finding_id = ? ORDER BY id", (finding_id,)
        ).fetchall()
        return tuple(self.get(row["id"]) for row in rows)

    def get_by_action_key(self, recommendation_id: int, action_key: str) -> Remediation | None:
        row = self.connection.execute(
            "SELECT id FROM remediations WHERE recommendation_id = ? AND action_key = ?",
            (recommendation_id, action_key),
        ).fetchone()
        return self.get(row["id"]) if row else None

    def create(self, *, finding_id: int, recommendation_id: int, observation_id: int,
               action_key: str, planned_action: str, owner: str,
               before: BeforeSnapshot) -> Remediation:
        prior = self.get_by_action_key(recommendation_id, action_key)
        if prior is not None:
            if (prior.finding_id, prior.observation_id, prior.planned_action,
                    prior.owner, prior.before) != (finding_id, observation_id,
                                                   planned_action, owner, before):
                raise RemediationRepositoryError("action key already has different plan or evidence")
            return prior
        timestamp = self.clock().isoformat()
        try:
            with self.connection:
                cursor = self.connection.execute(
                    """INSERT INTO remediations
                       (finding_id, recommendation_id, observation_id, action_key,
                        planned_action, owner, before_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (finding_id, recommendation_id, observation_id, action_key,
                     planned_action, owner, canonical_json(asdict(before)), timestamp),
                )
                self._advance(finding_id, FindingStatus.OPEN,
                              FindingStatus.RECOMMENDATION_CREATED, timestamp)
                remediation_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise RemediationRepositoryError("remediation relationship or constraint failed") from exc
        return self.get(remediation_id)

    def apply(self, remediation_id: int, *, action: str, actor: str, applied_at: str,
              evidence_type: str, evidence_reference: str,
              evidence_source: str) -> Remediation:
        prior = self.get(remediation_id)
        data = (action, actor, applied_at, evidence_type,
                evidence_reference, evidence_source)
        if prior.application is not None:
            existing = prior.application
            if data != (existing.action, existing.actor, existing.applied_at,
                        existing.evidence_type, existing.evidence_reference,
                        existing.evidence_source):
                raise RemediationRepositoryError("application already has different evidence")
            return prior
        timestamp = self.clock().isoformat()
        try:
            with self.connection:
                self.connection.execute(
                    """INSERT INTO remediation_applications
                       (remediation_id, action, actor, applied_at, evidence_type,
                        evidence_reference, evidence_source, recorded_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (remediation_id, *data, timestamp),
                )
                self._advance(prior.finding_id, FindingStatus.RECOMMENDATION_CREATED,
                              FindingStatus.REMEDIATION_APPLIED, timestamp)
        except sqlite3.IntegrityError as exc:
            raise RemediationRepositoryError("remediation application constraint failed") from exc
        return self.get(remediation_id)

    def _advance(self, finding_id: int, old: FindingStatus,
                 new: FindingStatus, timestamp: str) -> None:
        cursor = self.connection.execute(
            "UPDATE findings SET status = ? WHERE id = ? AND status = ?",
            (new.value, finding_id, old.value),
        )
        if cursor.rowcount:
            self.connection.execute(
                """INSERT INTO finding_status_history (finding_id, status, recorded_at)
                   VALUES (?, ?, ?)""", (finding_id, new.value, timestamp),
            )
