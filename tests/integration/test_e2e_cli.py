"""Offline CLI recovery uses real services/repositories and existing intelligence fixtures."""

from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from core.sbom.generator import GeneratedSBOM, SBOMGenerationError
from core.verification.run_store import RunConflict, RunStore, atomic_document
from core.verification.workflow import VerificationWorkflow
from core.vulnerability.matcher import match_component_to_cves
from database.models.verification import VerificationStatus
from database.repositories.remediation_repository import RemediationNotFoundError
from labs.log4shell.runner import LabOperationError, Log4ShellRunner
from scripts.e2e import main
from tests.unit.test_asset_context import VALID
from tests.unit.test_vulnerability import StubTransport, clients, fixture


class Interrupted(BaseException):
    """Represent abrupt process death, not a recoverable analysis result."""


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = RunStore(self.root / "run")
        self.db = self.root / "records.db"
        self.context = {**VALID, "name": "Offline CLI test"}
        with self.store.locked():
            state = VerificationWorkflow.initialize(self.store, db=self.db, context=self.context,
                                                     business_service="Synthetic service")
        self.workflow = VerificationWorkflow(self.store, db=self.db, asset_id=state["asset_id"])
        self.addCleanup(self.workflow.close)
        self.before_source, self.after_source = self.root / "old", self.root / "new"
        for source, version in ((self.before_source, "2.14.1"), (self.after_source, "2.17.1")):
            source.mkdir()
            (source / "version.txt").write_text(version, encoding="utf-8")
        self.config = self.root / "syft.yaml"
        self.config.write_text("check-for-app-update: false", encoding="utf-8")
        self.generator = patch("core.verification.workflow.generate_cyclonedx_json", side_effect=self.generate).start()
        self.matcher = patch("core.verification.workflow.match_component_to_cves", side_effect=self.match).start()
        self.http = patch("core.verification.workflow.urlopen", side_effect=self.response).start()
        self.addCleanup(patch.stopall)
        self.bad_http = False

    def generate(self, source, *, executable):
        version = (Path(source) / "version.txt").read_text(encoding="utf-8")
        document = fixture("cyclonedx_log4j.json")
        component = document["components"][0]
        component["purl"] = component["purl"].replace(component["version"], version)
        component["version"] = version
        return GeneratedSBOM(json.dumps(document), str(source), executable)

    def match(self, component, **unused):
        transport = StubTransport(osv=fixture("osv_log4j_query.json") if component.version == "2.14.1" else {"vulns": []},
                                  nvd=fixture("nvd_log4j_cve.json"), kev=fixture("cisa_kev_log4j.json"))
        dependencies = clients(transport)
        for client in dependencies.values():
            client.clock = lambda: datetime.now(timezone.utc)
        return match_component_to_cves(component, **dependencies)

    def response(self, url, **unused):
        body = {"status": "ok"} if url.endswith("/health") else {"result": "ok", "mode": "synthetic"}
        if self.bad_http:
            body = {"status": "broken"}
        stream = io.StringIO(json.dumps(body))
        stream.status = 200
        return stream

    def before(self):
        return self.workflow.before(source=str(self.before_source), syft="offline-syft",
                                    syft_config=str(self.config), base_url="http://127.0.0.1:18081")

    def plan(self):
        before = self.before()
        return self.workflow.plan(match_run_id=before["match_run_ids"][0], cve_id="CVE-2021-44228",
                                  action_key="upgrade", planned_action="Offline upgrade and rollback plan",
                                  owner="Test operator", mode="local-plan-demo")

    def start(self):
        plan = self.plan()
        self.workflow.apply(remediation_id=plan["remediation_id"], evidence={
            "action": "Offline execution fixture", "actor": "Test operator",
            "applied_at": datetime.now(timezone.utc).isoformat(), "evidence_type": "change_execution_log",
            "evidence_reference": "offline/execution.log", "evidence_source": "offline test",
        })
        return self.workflow.start(remediation_id=plan["remediation_id"], attempt_key="try-1",
                                   required_tests=("health-contract", "banking-api-smoke"))

    def after(self, selected):
        return self.workflow.after(remediation_id=selected["remediation_id"], verification_id=selected["verification_id"],
                                   source=str(self.after_source), syft="offline-syft",
                                   syft_config=str(self.config), base_url="http://127.0.0.1:18081")

    def test_end_to_end_and_completed_retry_use_same_evidence(self):
        selected = self.start()
        first = self.after(selected)
        calls = self.generator.call_count, self.matcher.call_count, self.http.call_count
        second = self.after(selected)
        self.assertEqual(first, second)
        self.assertEqual(calls, (self.generator.call_count, self.matcher.call_count, self.http.call_count))
        self.assertEqual(first["status"], "verification_passed")
        result = self.workflow.verification_service.get(selected["verification_id"])
        self.assertEqual(result.before.component_version, "2.14.1")
        self.assertEqual(first["finding_cve_count"]["delta"], -1)
        snapshot = self.store.read("attempts/1/comparison.json")
        self.assertIsNone(snapshot["finding"]["risk_score"]["after"]["value"])
        self.assertIsNone(snapshot["asset"]["eol_component_count"]["after"]["value"])

    def test_resume_after_committed_sbom_before_checkpoint(self):
        original = self.workflow.sboms.save
        def commit_and_interrupt(**kwargs):
            original(**kwargs)
            raise Interrupted()
        with patch.object(self.workflow.sboms, "save", side_effect=commit_and_interrupt):
            with self.assertRaises(Interrupted):
                self.before()
        result = self.before()
        self.assertEqual(result["sbom_id"], 1)
        self.assertEqual(self.generator.call_count, 1)

    def test_changed_capture_is_rejected_after_interruption(self):
        original = self.workflow.sboms.save
        def commit_and_interrupt(**kwargs):
            original(**kwargs)
            raise Interrupted()
        with patch.object(self.workflow.sboms, "save", side_effect=commit_and_interrupt):
            with self.assertRaises(Interrupted):
                self.before()
        path = self.store.directory / "before/capture.json"
        capture = json.loads(path.read_text(encoding="utf-8"))
        capture["content"] += " "
        path.write_text(json.dumps(capture), encoding="utf-8")
        with self.assertRaisesRegex(RunConflict, "evidence changed"):
            self.before()

    def test_source_change_prevents_attaching_misattributed_evidence(self):
        selected = self.start()
        checks = iter((None, RunConflict("Owned source changed")))
        def validate():
            error = next(checks)
            if error:
                raise error
        with self.assertRaises(RunConflict):
            self.workflow.after(remediation_id=selected["remediation_id"], verification_id=selected["verification_id"],
                                 source=str(self.after_source), syft="offline-syft", syft_config=str(self.config),
                                 base_url="http://127.0.0.1:18081", validate_source=validate)
        self.assertIsNone(self.workflow.verification_service.get(selected["verification_id"]).after)

    def test_resume_after_committed_matching_before_export(self):
        original = self.workflow.matches.save
        def commit_and_interrupt(**kwargs):
            original(**kwargs)
            raise Interrupted()
        with patch.object(self.workflow.matches, "save", side_effect=commit_and_interrupt):
            with self.assertRaises(Interrupted):
                self.before()
        self.before()
        self.assertEqual(self.matcher.call_count, 1)

    def test_resume_after_decision_commit_does_not_rejudge(self):
        selected = self.start()
        original = self.workflow.verification_service.complete
        def commit_and_interrupt(identifier):
            original(identifier)
            raise Interrupted()
        with patch.object(self.workflow.verification_service, "complete", side_effect=commit_and_interrupt):
            with self.assertRaises(Interrupted):
                self.after(selected)
        result = self.workflow.verification_service.get(selected["verification_id"])
        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.after(selected)
        self.assertEqual(self.workflow.verification_service.get(selected["verification_id"]), result)

    def test_failed_functional_result_is_preserved_on_retry_and_new_attempt(self):
        selected = self.start()
        self.bad_http = True
        failed = self.after(selected)
        self.assertEqual(failed["status"], "verification_failed")
        self.bad_http = False
        self.assertEqual(self.after(selected), failed)
        second = self.workflow.start(remediation_id=selected["remediation_id"], attempt_key="try-2",
                                     required_tests=("health-contract", "banking-api-smoke"))
        self.assertEqual(self.after(second)["status"], "verification_passed")
        self.assertEqual(self.workflow.compare(remediation_id=selected["remediation_id"],
                                               verification_id=selected["verification_id"]), failed)

    def test_generation_error_records_failed_and_is_not_retried_as_success(self):
        selected = self.start()
        with patch("core.verification.workflow.generate_cyclonedx_json", side_effect=SBOMGenerationError("offline missing tool")):
            failed = self.after(selected)
        self.assertEqual(failed["status"], "verification_failed")
        self.assertEqual(self.after(selected), failed)

    def test_same_operation_refuses_changed_analysis_scope(self):
        self.before()
        with self.assertRaises(RunConflict):
            self.workflow.before(source=str(self.after_source), syft="offline-syft",
                                 syft_config=str(self.config), base_url="http://127.0.0.1:18081")

    def test_wrong_asset_and_wrong_remediation_are_rejected(self):
        with self.assertRaises(RunConflict):
            VerificationWorkflow(self.store, db=self.db, asset_id=999)
        selected = self.start()
        with self.assertRaises(RemediationNotFoundError):
            self.workflow.after(remediation_id=999, verification_id=selected["verification_id"],
                                 source=str(self.after_source), syft="offline-syft",
                                 syft_config=str(self.config), base_url="http://127.0.0.1:18081")
        self.assertIsNone(self.workflow.verification_service.get(selected["verification_id"]).after)

    def test_compare_does_not_write_finding_or_verification(self):
        selected = self.start()
        self.after(selected)
        changes = self.workflow.connection.total_changes
        self.workflow.compare(remediation_id=selected["remediation_id"], verification_id=selected["verification_id"])
        self.assertEqual(self.workflow.connection.total_changes, changes)

    def test_ambiguous_exact_import_recovery_is_rejected(self):
        self.before()
        snapshot = self.workflow.verifications.sbom_snapshot(1)
        from core.sbom.normalizer import normalize_components
        from core.sbom.parser import parse_sbom
        parsed = parse_sbom(snapshot["raw_document"])
        self.workflow.sboms.save(asset_id=self.workflow.asset_id, source=snapshot["source"],
                                  raw_document=snapshot["raw_document"], parsed=parsed,
                                  normalized=normalize_components(parsed.components))
        state = self.store.read("run.json")
        del state["operations"]["before"]["result"]
        self.store.save("run.json", state, replace=True)
        with self.assertRaisesRegex(RunConflict, "Multiple exact"):
            self.before()

    def test_local_mode_is_explicit_and_artifacts_are_immutable(self):
        plan = self.plan()
        self.assertEqual(plan["recommendation_mode"], "local-plan-demo")
        self.assertEqual(self.workflow.recommendations.get(plan["recommendation_id"]).model_name, "local-plan-demo")
        with self.assertRaises(RunConflict):
            atomic_document(self.store.directory / "plans/1.json", "changed")

    def test_lock_is_released_after_interruption_and_init_is_idempotent(self):
        with self.assertRaises(Interrupted):
            with self.store.locked():
                with self.assertRaises(RunConflict):
                    with self.store.locked():
                        self.fail("Concurrent acquisition should fail")
                raise Interrupted()
        with self.store.locked():
            state = VerificationWorkflow.initialize(self.store, db=self.db, context=self.context,
                                                     business_service="Synthetic service")
        self.assertEqual(state["asset_id"], self.workflow.asset_id)

    def test_cli_existing_asset_binding_and_status(self):
        run = self.root / "second-run"
        common = ["--run-dir", str(run), "--db", str(self.db), "--asset-id", str(self.workflow.asset_id)]
        with patch("scripts.e2e.logging.basicConfig"), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["init", *common]), 0)
            self.assertEqual(main(["status", *common]), 0)
        self.assertIn('"asset_id"', output.getvalue())

    def test_in_progress_preview_does_not_conflict_with_final_comparison(self):
        selected = self.start()
        preview = self.workflow.compare(remediation_id=selected["remediation_id"],
                                         verification_id=selected["verification_id"])
        self.assertIn("previews", preview["comparison"])
        self.assertEqual(self.after(selected)["status"], "verification_passed")
        self.assertTrue(Path(preview["comparison"]).is_file())

    def test_after_lookup_error_is_failed_and_asset_count_is_unknown(self):
        selected = self.start()
        def failed(component, **unused):
            return match_component_to_cves(component, **clients(StubTransport(error="OSV")))
        with patch("core.verification.workflow.match_component_to_cves", side_effect=failed):
            result = self.after(selected)
        self.assertEqual(result["status"], "verification_failed")
        self.assertIsNone(result["asset_cve_count"]["after"]["value"])

    def test_duplicate_occurrences_keep_one_finding_and_multiple_observations(self):
        original = self.generate
        def duplicate(source, *, executable):
            generated = original(source, executable=executable)
            document = json.loads(generated.content)
            document["components"].append({**document["components"][0], "bom-ref": "duplicate-occurrence"})
            return GeneratedSBOM(json.dumps(document), generated.source, generated.tool)
        with patch("core.verification.workflow.generate_cyclonedx_json", side_effect=duplicate):
            before = self.before()
        self.assertEqual(len(before["match_run_ids"]), 2)
        findings = self.workflow.findings.list_for_asset(self.workflow.asset_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].observations), 2)

    def test_cli_failed_verification_returns_nonzero_exit(self):
        arguments = ["after", "--run-dir", str(self.store.directory), "--db", str(self.db),
                     "--asset-id", "1", "--remediation-id", "1", "--verification-id", "1",
                     "--source", str(self.after_source), "--syft", "offline", "--syft-config", str(self.config),
                     "--base-url", "http://127.0.0.1:18081"]
        with patch("scripts.e2e.execute", return_value={"status": "verification_failed"}), \
                patch("scripts.e2e.logging.basicConfig"), redirect_stdout(io.StringIO()):
            self.assertEqual(main(arguments), 1)


class LabProcessTests(unittest.TestCase):
    def test_resume_after_start_timeout_does_not_restart_live_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "labs/log4shell/vulnerable/target/runtime"
            new = root / "labs/log4shell/patched/target/runtime"
            for source in (old, new):
                source.mkdir(parents=True)
                (source / "component.jar").write_bytes(b"offline fixture")
            (new.parents[1] / "pom.xml").write_text(
                '<project xmlns="http://maven.apache.org/POM/4.0.0"><properties>'
                '<log4j.version>2.25.5</log4j.version></properties></project>', encoding="utf-8")
            store = RunStore(root / "run")
            store.save("run.json", {"operations": {}})
            runner = Log4ShellRunner(root=root, logs=root / "logs", port=18081)
            physical = {"vulnerable": {"pid": 10, "port": 18081, "runtime": str(old)}, "patched": None}
            starts = []
            def call(action, variant):
                if action == "Status":
                    return json.dumps(physical[variant]) if physical[variant] else f"Lab not running: {variant}"
                if action == "Smoke":
                    version = "2.14.1" if variant == "vulnerable" else "2.25.5"
                    return json.dumps({"pid": physical[variant]["pid"], "runtime": {
                        "log4j_api_version": version, "log4j_core_version": version}})
                if action == "Stop":
                    physical[variant] = None
                    return "Stopped"
                starts.append(variant)
                physical[variant] = {"pid": 20, "port": 18081, "runtime": str(new),
                                     "started_at": datetime.now(timezone.utc).isoformat(),
                                     "ready_at": datetime.now(timezone.utc).isoformat()}
                raise LabOperationError("simulated timeout after the actual start")
            arguments = {"store": store, "remediation_id": 1, "before_sbom": {"id": 1, "source": str(old)},
                         "expected_before_version": "2.14.1"}
            with patch.object(runner, "call", side_effect=call):
                with self.assertRaises(LabOperationError):
                    runner.switch(**arguments)
                evidence = runner.switch(**arguments)
                self.assertEqual(runner.switch(**arguments), evidence)
            self.assertEqual(starts, ["patched"])
            self.assertEqual(evidence["applied_at"], physical["patched"]["ready_at"])

    def test_regular_files_prevent_wait_for_child_pipe_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = Log4ShellRunner(root=root, logs=root / "logs", port=18081)
            def invoke(command, **kwargs):
                self.assertNotEqual(kwargs["stdout"], subprocess.PIPE)
                self.assertNotEqual(kwargs["stderr"], subprocess.PIPE)
                self.assertEqual(kwargs["timeout"], 50)
                kwargs["stdout"].write('Lab not running: patched')
                return subprocess.CompletedProcess(command, 0)
            with patch("labs.log4shell.runner.subprocess.run", side_effect=invoke):
                self.assertIsNone(runner.status("patched"))
            self.assertEqual(len(list((root / "logs").glob("*.stdout.log"))), 1)

    def test_timeout_preserves_command_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = Log4ShellRunner(root=root, logs=root / "logs", port=18081)
            with patch("labs.log4shell.runner.subprocess.run", side_effect=subprocess.TimeoutExpired("powershell", 50)):
                with self.assertRaises(LabOperationError):
                    runner.call("Start", "patched")
            self.assertTrue(list((root / "logs").glob("*.json")))


if __name__ == "__main__":
    unittest.main()
