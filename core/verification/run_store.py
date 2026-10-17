"""Local execution checkpoints, separate from immutable platform evidence."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
from typing import Iterator

from database.repositories.verification_repository import evidence_json


class RunConflict(ValueError):
    pass


def atomic_document(path: Path, content: str, *, replace: bool = False) -> None:
    """Publish complete UTF-8 documents; immutable artifacts are never overwritten."""
    atomic_bytes(path, content.encode("utf-8"), replace=replace)


def atomic_bytes(path: Path, content: bytes, *, replace: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not replace and path.exists():
        if path.read_bytes() != content:
            raise RunConflict(f"Existing evidence differs: {path}")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if replace:
            os.replace(temporary_path, path)
        else:
            try:
                os.link(temporary_path, path)
            except FileExistsError:
                if path.read_bytes() != content:
                    raise RunConflict(f"Existing evidence differs: {path}")
    finally:
        temporary_path.unlink(missing_ok=True)


class RunStore:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory).resolve()

    @contextmanager
    def locked(self) -> Iterator[None]:
        """OS-owned advisory lock is released even when the CLI process dies."""
        self.directory.mkdir(parents=True, exist_ok=True)
        with (self.directory / ".run.lock").open("a+b") as lock:
            lock.seek(0, os.SEEK_END)
            if lock.tell() == 0:
                lock.write(b"0")
                lock.flush()
            lock.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RunConflict("Another command owns this run; wait for it to finish") from exc
            try:
                yield
            finally:
                lock.seek(0)
                if os.name == "nt":
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def read(self, name: str) -> dict:
        value = json.loads((self.directory / name).read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict):
            raise RunConflict(f"Expected a structured run document: {name}")
        return value

    def save(self, name: str, value: object, *, replace: bool = False) -> None:
        atomic_document(self.directory / name, evidence_json(value), replace=replace)

    def operation(self, key: str, parameters: dict) -> dict:
        state = self.read("run.json")
        operation = state["operations"].get(key)
        if operation is None:
            operation = {"parameters": parameters}
            state["operations"][key] = operation
            self.save("run.json", state, replace=True)
        elif operation["parameters"] != parameters:
            raise RunConflict("Operation parameters changed; use a new run or explicit attempt key")
        return operation

    def checkpoint(self, key: str, operation: dict) -> None:
        state = self.read("run.json")
        state["operations"][key] = operation
        self.save("run.json", state, replace=True)
