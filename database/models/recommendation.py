"""Immutable recommendation for one Finding analysis observation."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Recommendation:
    id: int
    finding_id: int
    observation_id: int
    input_digest: str
    model_name: str
    input_data: dict
    content: dict
    created_at: str
