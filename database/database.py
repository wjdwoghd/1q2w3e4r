"""SQLite connection lifecycle and schema migration."""

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator


class StorageError(RuntimeError):
    """An inventory storage operation failed."""


class Database:
    def __init__(self, database_url: str) -> None:
        prefix = "sqlite:///"
        if not isinstance(database_url, str) or not database_url.startswith(prefix):
            raise ValueError("DATABASE_URL must use sqlite:/// followed by a file path")
        path = database_url[len(prefix):]
        if not path or path == ":memory:" or "?" in path or "#" in path:
            raise ValueError("DATABASE_URL must identify a persistent SQLite file")
        self.path = Path(path)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            connection = sqlite3.connect(self.path, timeout=5)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            with connection:
                yield connection
        except sqlite3.IntegrityError:
            raise
        except sqlite3.Error as exc:
            raise StorageError("Inventory database operation failed") from exc
        finally:
            if connection is not None:
                connection.close()

    def initialize(self) -> None:
        migration = Path(__file__).parent / "migrations" / "001_asset_inventory.sql"
        with self.connection() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                connection.executescript(migration.read_text(encoding="utf-8"))
            elif version != 1:
                raise StorageError("Unsupported inventory schema version")
