"""Financial business service inventory entity."""

from dataclasses import dataclass

from database.models.validation import require_text


@dataclass(frozen=True)
class BusinessService:
    service_id: str
    name: str

    def __post_init__(self) -> None:
        require_text("service_id", self.service_id)
        require_text("name", self.name)
