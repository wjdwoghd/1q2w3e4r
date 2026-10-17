"""Windows host adapter; process policy stays in the existing Lab PowerShell tool."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from uuid import uuid4

from core.verification.run_store import RunConflict, RunStore, atomic_document
from core.verification.workflow import preserve_runtime, runtime_hashes


class LabOperationError(RuntimeError):
    pass


class Log4ShellRunner:
    def __init__(self, *, root: Path, logs: Path, port: int) -> None:
        if not 1024 <= port <= 65535:
            raise ValueError("Lab port must be between 1024 and 65535")
        self.root, self.logs, self.port = root.resolve(), logs.resolve(), port

    def call(self, action: str, variant: str) -> str:
        if action not in {"Start", "Stop", "Status", "Smoke"} or variant not in {"vulnerable", "patched"}:
            raise ValueError("Unsupported Lab action or variant")
        self.logs.mkdir(parents=True, exist_ok=True)
        identifier = uuid4().hex
        output_path = self.logs / f"{identifier}.stdout.log"
        error_path = self.logs / f"{identifier}.stderr.log"
        command = ["powershell.exe", "-NoProfile", "-File",
                   str(self.root / "labs/log4shell/host.ps1"),
                   "-Action", action, "-Variant", variant]
        if action == "Start":
            command += ["-Port", str(self.port)]
        event = {"command": command, "started_at": datetime.now(timezone.utc).isoformat(),
                 "stdout": str(output_path), "stderr": str(error_path)}
        atomic_document(self.logs / f"{identifier}.json", json.dumps(event))
        # A long-lived Java child can inherit PIPE handles from PowerShell. Even
        # TimeoutExpired.communicate() can then wait indefinitely on Windows.
        # Regular files permit bounded process wait without waiting for pipe EOF.
        try:
            with output_path.open("x", encoding="utf-8") as output, error_path.open("x", encoding="utf-8") as error:
                completed = subprocess.run(
                    command, stdin=subprocess.DEVNULL, stdout=output, stderr=error,
                    timeout=50, check=False,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
        except subprocess.TimeoutExpired as exc:
            raise LabOperationError(f"Lab command timed out; retain logs and resume: {self.logs}") from exc
        if completed.returncode:
            raise LabOperationError(f"Lab command failed ({completed.returncode}); logs: {self.logs}")
        return output_path.read_text(encoding="utf-8-sig").strip()

    def status(self, variant: str) -> dict | None:
        result = self.call("Status", variant)
        if result == f"Lab not running: {variant}":
            return None
        return json.loads(result)

    def smoke(self, variant: str) -> dict:
        return json.loads(self.call("Smoke", variant))

    def validate_applied(self, *, store: RunStore, remediation_id: int) -> None:
        saved = store.read(f"applications/{remediation_id}/host.json")
        current = self.status("patched")
        if current != saved["state"] or runtime_hashes(Path(saved["state"]["runtime"])) != saved["files_sha256"]:
            raise RunConflict("Owned service changed after this recorded application")

    def switch(self, *, store: RunStore, remediation_id: int, before_sbom: dict,
               expected_before_version: str | None) -> dict:
        """Resume the same owned change; never restart an already recorded target."""
        key = f"lab-switch-{remediation_id}"
        op = store.operation(key, {"remediation_id": remediation_id, "port": self.port,
                                   "root": str(self.root), "before_sbom_id": before_sbom["id"]})
        if "result" in op:
            return op["result"]
        old_runtime = (self.root / "labs/log4shell/vulnerable/target/runtime").resolve()
        new_runtime = (self.root / "labs/log4shell/patched/target/runtime").resolve()
        if Path(before_sbom["source"]).resolve() != old_runtime:
            raise RunConflict("Selected Before SBOM was not collected from this Lab runtime")
        namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
        target_version = ET.parse(self.root / "labs/log4shell/patched/pom.xml").findtext(
            "m:properties/m:log4j.version", namespaces=namespace)
        if not target_version:
            raise LabOperationError("Patched version is not declared")
        if "before_state" not in op:
            before = self.status("vulnerable")
            if before is None or self.status("patched") is not None:
                raise RunConflict("Start the owned Before service and stop other Lab variants first")
            smoke = self.smoke("vulnerable")
            if (before["port"] != self.port or Path(before["runtime"]).resolve() != old_runtime
                    or smoke["pid"] != before["pid"]
                    or smoke["runtime"]["log4j_core_version"] != expected_before_version):
                raise RunConflict("Actual Before service differs from the selected remediation")
            op.update(before_state=before, before_smoke=smoke,
                      before_hashes=runtime_hashes(old_runtime), target_hashes=runtime_hashes(new_runtime),
                      target_version=target_version, requested_at=datetime.now(timezone.utc).isoformat())
            store.checkpoint(key, op)
        if op["target_version"] != target_version or runtime_hashes(new_runtime) != op["target_hashes"]:
            raise RunConflict("Prepared target changed during this operation")
        directory = f"applications/{remediation_id}"
        preserve_runtime(old_runtime, store.directory / directory / "before-runtime", op["before_hashes"])
        store.save(f"{directory}/before-sbom.json", before_sbom)
        old, target = self.status("vulnerable"), self.status("patched")
        if old is not None:
            if old != op["before_state"] or target is not None:
                raise RunConflict("Owned processes changed; refusing to stop another process")
            self.call("Stop", "vulnerable")
        if target is None:
            # If this times out after Java starts, a repeated command reads the
            # owned host state and resumes below instead of starting Java again.
            self.call("Start", "patched")
            target = self.status("patched")
        if (target is None or target["port"] != self.port
                or Path(target["runtime"]).resolve() != new_runtime
                or datetime.fromisoformat(target["started_at"]) < datetime.fromisoformat(op["requested_at"])):
            raise RunConflict("Existing target is not attributable to this change operation")
        smoke = self.smoke("patched")
        if (smoke["pid"] != target["pid"]
                or smoke["runtime"] != {"log4j_api_version": target_version, "log4j_core_version": target_version}
                or runtime_hashes(new_runtime) != op["target_hashes"]):
            raise RunConflict("Actual target version or files disagree with the prepared runtime")
        store.save(f"{directory}/host.json", {"state": target, "smoke": smoke,
                                              "files_sha256": op["target_hashes"]})
        evidence = {
            "action": f"Stopped owned Before and started patched Lab on 127.0.0.1:{self.port}; observed Log4j API/Core {target_version}.",
            "actor": "Local Lab operator (manual CLI execution)",
            "applied_at": target["ready_at"], "evidence_type": "change_execution_log",
            "evidence_reference": str(self.logs),
            "evidence_source": "host.ps1 command files, owned process readiness event and actual Smoke",
        }
        store.save(f"{directory}/application.json", evidence)
        op["result"] = evidence
        store.checkpoint(key, op)
        return evidence
