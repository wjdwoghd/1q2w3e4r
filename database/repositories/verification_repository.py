"""Append-only attempts, detached after snapshots and atomic workflow updates."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from dataclasses import asdict
from typing import Callable

from database.models.finding import FindingStatus
from database.models.remediation import BeforeSnapshot, Remediation, RemediationApplication
from database.models.verification import (
    AfterEvidence, Verification, VerificationDecision, VerificationStatus,
)
from database.repositories.recommendation_repository import canonical_json


class VerificationRepositoryError(RuntimeError):
    pass


class VerificationNotFoundError(VerificationRepositoryError):
    pass


def evidence_json(value: object) -> str:
    def encode(item: object) -> str:
        if isinstance(item, datetime):
            return item.isoformat()
        raise TypeError(f"unsupported evidence type: {type(item).__name__}")
    return json.dumps(value, default=encode, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class SQLiteVerificationRepository:
    def __init__(self, connection: sqlite3.Connection,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.connection = connection
        self.clock = clock

    def get(self, verification_id: int) -> Verification:
        row = self.connection.execute("SELECT * FROM verifications WHERE id = ?", (verification_id,)).fetchone()
        if row is None:
            raise VerificationNotFoundError("verification not found")
        after = self.connection.execute("SELECT * FROM verification_after_evidence WHERE verification_id = ?",
                                        (verification_id,)).fetchone()
        result = self.connection.execute("SELECT * FROM verification_results WHERE verification_id = ?",
                                         (verification_id,)).fetchone()
        before = json.loads(row["before_json"])
        before["risk_reasons"] = tuple(before["risk_reasons"])
        return Verification(
            row["id"], row["remediation_id"], row["finding_id"], row["attempt_key"],
            BeforeSnapshot(**before), json.loads(row["before_sbom_json"]),
            RemediationApplication(**json.loads(row["application_json"])),
            tuple(json.loads(row["required_tests_json"])), row["started_at"],
            AfterEvidence(json.loads(after["payload_json"]), after["payload_digest"], after["recorded_at"])
            if after else None,
            VerificationDecision(VerificationStatus(result["status"]), result["rule_version"],
                                 tuple(json.loads(result["reasons_json"])),
                                 json.loads(result["sbom_diff_json"]) if result["sbom_diff_json"] else None)
            if result else None,
            result["completed_at"] if result else None,
        )

    def list_for_remediation(self, remediation_id: int) -> tuple[Verification, ...]:
        rows = self.connection.execute("SELECT id FROM verifications WHERE remediation_id = ? ORDER BY id",
                                        (remediation_id,)).fetchall()
        return tuple(self.get(row["id"]) for row in rows)

    def start(self, remediation: Remediation, *, asset_id: int, attempt_key: str,
              required_tests: tuple[str, ...], before_sbom: dict) -> Verification:
        prior = self.connection.execute(
            "SELECT id FROM verifications WHERE remediation_id = ? AND attempt_key = ?",
            (remediation.id, attempt_key)).fetchone()
        if prior:
            existing = self.get(prior["id"])
            if (existing.before != remediation.before or existing.application != remediation.application
                    or existing.required_functional_tests != required_tests or existing.before_sbom != before_sbom):
                raise VerificationRepositoryError("attempt key already has different requirements or source")
            return existing
        timestamp = self.clock().isoformat()
        try:
            with self.connection:
                cursor = self.connection.execute(
                    """INSERT INTO verifications
                       (remediation_id,finding_id,asset_id,attempt_key,before_json,before_sbom_json,application_json,
                        required_tests_json,started_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                    (remediation.id, remediation.finding_id, asset_id, attempt_key,
                     canonical_json(asdict(remediation.before)), canonical_json(before_sbom),
                     canonical_json(asdict(remediation.application)),
                     canonical_json(required_tests), timestamp))
                verification_id = cursor.lastrowid
                self._transition(remediation.finding_id, FindingStatus.VERIFICATION_IN_PROGRESS,
                                 verification_id, timestamp)
        except sqlite3.IntegrityError as exc:
            raise VerificationRepositoryError("verification source, active attempt or status constraint failed") from exc
        return self.get(verification_id)

    def save_after(self, verification_id: int, payload: dict) -> Verification:
        prior = self.get(verification_id)
        document = evidence_json(payload)
        digest = hashlib.sha256(document.encode("utf-8")).hexdigest()
        if prior.after:
            if prior.after.digest != digest:
                raise VerificationRepositoryError("attempt already has different after evidence; start a new attempt")
            return prior
        sbom = payload.get("sbom")
        try:
            with self.connection:
                self.connection.execute(
                    """INSERT INTO verification_after_evidence
                       (verification_id,sbom_id,payload_json,payload_digest,recorded_at) VALUES (?,?,?,?,?)""",
                    (verification_id, sbom["id"] if sbom else None, document, digest, self.clock().isoformat()))
        except sqlite3.IntegrityError as exc:
            raise VerificationRepositoryError("after evidence constraint failed") from exc
        return self.get(verification_id)

    def complete(self, verification_id: int, decision: VerificationDecision) -> Verification:
        prior = self.get(verification_id)
        if prior.decision:
            if prior.decision != decision:
                raise VerificationRepositoryError("verification decision is immutable")
            return prior
        timestamp = self.clock().isoformat()
        try:
            with self.connection:
                self.connection.execute(
                    """INSERT INTO verification_results
                       (verification_id,status,rule_version,reasons_json,sbom_diff_json,completed_at) VALUES (?,?,?,?,?,?)""",
                    (verification_id, decision.status.value, decision.rule_version,
                     canonical_json(decision.reasons),
                     canonical_json(decision.sbom_diff) if decision.sbom_diff is not None else None, timestamp))
                self._transition(prior.finding_id, FindingStatus(decision.status.value), verification_id, timestamp)
        except sqlite3.IntegrityError as exc:
            raise VerificationRepositoryError("verification result or status constraint failed") from exc
        return self.get(verification_id)

    def _transition(self, finding_id: int, status: FindingStatus, verification_id: int, timestamp: str) -> None:
        self.connection.execute("UPDATE findings SET status = ? WHERE id = ?", (status.value, finding_id))
        self.connection.execute(
            """INSERT INTO finding_status_history (finding_id,status,recorded_at,verification_id)
               VALUES (?,?,?,?)""", (finding_id, status.value, timestamp, verification_id))

    def sbom_snapshot(self, sbom_id: int) -> dict:
        row = self.connection.execute("SELECT * FROM sboms WHERE id = ?", (sbom_id,)).fetchone()
        if row is None:
            raise VerificationNotFoundError("after SBOM not found")
        result = dict(row)
        components = self.connection.execute("SELECT * FROM components WHERE sbom_id = ? ORDER BY position",
                                              (sbom_id,)).fetchall()
        result["components"] = []
        for component in components:
            item = dict(component)
            item["issues"] = json.loads(item.pop("issues_json"))
            result["components"].append(item)
        return result

    def sbom_id_for_component(self, component_id: int) -> int:
        row = self.connection.execute("SELECT sbom_id FROM components WHERE id = ?", (component_id,)).fetchone()
        if row is None:
            raise VerificationNotFoundError("component not found")
        return row["sbom_id"]
