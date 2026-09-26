"""Read only the Phase 1 database setting; do not load unrelated secrets."""

import os
from pathlib import Path


def get_database_url(env_file: str | Path = ".env") -> str:
    """Environment wins; .env supports plain or quoted DATABASE_URL values."""
    value = os.environ.get("DATABASE_URL")
    if value is None:
        try:
            lines = Path(env_file).read_text(encoding="utf-8-sig").splitlines()
        except FileNotFoundError:
            lines = []
        for line in lines:
            key, separator, candidate = line.partition("=")
            if separator and key.strip() == "DATABASE_URL":
                value = candidate.strip()
                if value.startswith(("'", '"')):
                    if len(value) < 2 or value[-1] != value[0]:
                        raise ValueError("Invalid quoted DATABASE_URL")
                    value = value[1:-1]
    if value is None or not value.strip():
        raise ValueError("Set DATABASE_URL in the environment or .env")
    return value
