"""Local configuration: server-owned database aliases, never client file paths."""

from __future__ import annotations

import json
import os
from pathlib import Path


def load_local_env(path: Path = Path(".env")) -> None:
    """Read simple KEY=value lines without expanding or executing their content."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


def database_paths() -> dict[str, Path]:
    load_local_env()
    values = json.loads(os.getenv("DASHBOARD_DATABASES", "{}"))
    if not isinstance(values, dict) or any(
        not isinstance(key, str) or not key.strip() or not isinstance(value, str) or not value.strip()
        for key, value in values.items()
    ):
        raise ValueError("DASHBOARD_DATABASES must be a JSON object of alias: database path")
    return {key: Path(value).resolve() for key, value in values.items()}
