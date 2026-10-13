"""Observation provenance lookup and immutable Recommendation persistence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Callable

from database.models.recommendation import Recommendation


class RecommendationRepositoryError(RuntimeError):
    pass


class RecommendationNotFoundError(RecommendationRepositoryError):
    pass


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class SQLiteRecommendationRepository:
    def __init__(self, connection: sqlite3.Connection,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.connection = connection
        self.clock = clock

    def source_for_observation(self, observation_id: int) -> sqlite3.Row:
        row = self.connection.execute(
            """SELECT o.id AS observation_id, o.finding_id, o.match_evidence_id,
                      f.cve_id, f.asset_id, a.name AS asset_name,
                      b.name AS business_service, c.id AS component_id,
                      c.name AS component_name, c.version, c.purl,
                      r.id AS run_id, r.analysis_key, e.cve_id AS evidence_cve_id
               FROM finding_observations AS o
               JOIN findings AS f ON f.id = o.finding_id
               JOIN assets AS a ON a.id = f.asset_id
               JOIN business_services AS b ON b.id = a.business_service_id
               JOIN vulnerability_match_evidence AS e ON e.id = o.match_evidence_id
               JOIN vulnerability_match_runs AS r ON r.id = e.run_id
               JOIN components AS c ON c.id = r.component_id
               JOIN sboms AS s ON s.id = c.sbom_id AND s.asset_id = f.asset_id
               WHERE o.id = ? AND r.status = 'matched'
                 AND r.component_purl = c.purl AND e.cve_id = f.cve_id""",
            (observation_id,),
        ).fetchone()
        if row is None:
            raise RecommendationNotFoundError("verified observation source not found")
        return row

    def get_for_observation(self, observation_id: int) -> Recommendation | None:
        row = self.connection.execute(
            """SELECT p.*, o.finding_id FROM recommendations AS p
               JOIN finding_observations AS o ON o.id = p.observation_id
               WHERE p.observation_id = ?""", (observation_id,)
        ).fetchone()
        return self._record(row) if row else None

    def get(self, recommendation_id: int) -> Recommendation:
        row = self.connection.execute(
            """SELECT p.*, o.finding_id FROM recommendations AS p
               JOIN finding_observations AS o ON o.id = p.observation_id
               WHERE p.id = ?""", (recommendation_id,)
        ).fetchone()
        if row is None:
            raise RecommendationNotFoundError("recommendation not found")
        return self._record(row)

    def list_for_finding(self, finding_id: int) -> tuple[Recommendation, ...]:
        rows = self.connection.execute(
            """SELECT p.*, o.finding_id FROM recommendations AS p
               JOIN finding_observations AS o ON o.id = p.observation_id
               WHERE o.finding_id = ? ORDER BY o.id""", (finding_id,)
        ).fetchall()
        return tuple(self._record(row) for row in rows)

    def save(self, *, observation_id: int, input_data: dict,
             content: dict, model_name: str) -> Recommendation:
        input_json = canonical_json(input_data)
        digest = hashlib.sha256(input_json.encode("utf-8")).hexdigest()
        prior = self.get_for_observation(observation_id)
        if prior is not None:
            if prior.input_digest != digest:
                raise RecommendationRepositoryError("observation already has different input evidence")
            return prior
        try:
            with self.connection:
                self.connection.execute(
                    """INSERT INTO recommendations
                       (observation_id, input_digest, model_name, input_json,
                        content_json, created_at) VALUES (?, ?, ?, ?, ?, ?)""",
                    (observation_id, digest, model_name, input_json,
                     canonical_json(content), self.clock().isoformat()),
                )
        except sqlite3.IntegrityError as exc:
            concurrent = self.get_for_observation(observation_id)
            if concurrent is not None and concurrent.input_digest == digest:
                return concurrent
            raise RecommendationRepositoryError("recommendation constraint failed") from exc
        return self.get_for_observation(observation_id)

    @staticmethod
    def _record(row: sqlite3.Row) -> Recommendation:
        return Recommendation(row["id"], row["finding_id"], row["observation_id"],
                              row["input_digest"], row["model_name"],
                              json.loads(row["input_json"]), json.loads(row["content_json"]),
                              row["created_at"])
