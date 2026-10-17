"""Run with python -m scripts.e2e; no analysis rules or direct SQL here."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sqlite3
import sys

from core.verification.run_store import RunStore
from core.verification.workflow import VerificationWorkflow
from database.repositories.verification_repository import evidence_json


def positive_id(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("ID must be positive")
    return number


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Resumable SBOM remediation E2E commands")
    commands = result.add_subparsers(dest="command", required=True)
    names = ("init", "before", "plan", "lab-switch", "apply", "start", "after", "compare", "status")
    for name in names:
        command = commands.add_parser(name)
        command.add_argument("--run-dir", required=True, type=Path)
        command.add_argument("--db", required=True, type=Path)
        command.add_argument("--asset-id", type=positive_id, required=name != "init")
        if name == "init":
            command.add_argument("--asset-context", type=Path)
            command.add_argument("--business-service")
        if name in {"before", "after"}:
            command.add_argument("--source", required=True, type=Path)
            command.add_argument("--syft", required=True)
            command.add_argument("--syft-config", required=True, type=Path)
            command.add_argument("--base-url", required=True)
        if name == "plan":
            command.add_argument("--match-run-id", required=True, type=positive_id)
            command.add_argument("--cve", required=True)
            command.add_argument("--action-key", required=True)
            command.add_argument("--planned-action", required=True)
            command.add_argument("--owner", required=True)
            command.add_argument("--recommendation-mode", required=True,
                                 choices=("local-plan-demo", "live-openai"))
        if name in {"lab-switch", "apply", "start", "after", "compare"}:
            command.add_argument("--remediation-id", required=True, type=positive_id)
        if name == "lab-switch":
            command.add_argument("--port", required=True, type=int)
        if name == "apply":
            command.add_argument("--evidence", required=True, type=Path)
        if name == "start":
            command.add_argument("--attempt-key", required=True)
            command.add_argument("--required-test", required=True, action="append")
        if name in {"after", "compare"}:
            command.add_argument("--verification-id", required=True, type=positive_id)
    return result


def execute(args: argparse.Namespace) -> dict:
    store = RunStore(args.run_dir)
    with store.locked():
        if args.command == "init":
            context = json.loads(args.asset_context.read_text(encoding="utf-8-sig")) if args.asset_context else None
            return VerificationWorkflow.initialize(store, db=args.db, asset_id=args.asset_id,
                                                   context=context, business_service=args.business_service)
        workflow = VerificationWorkflow(store, db=args.db, asset_id=args.asset_id)
        try:
            if args.command == "status":
                return store.read("run.json")
            if args.command == "before":
                return workflow.before(source=str(args.source), syft=args.syft,
                                       syft_config=str(args.syft_config), base_url=args.base_url)
            if args.command == "plan":
                return workflow.plan(match_run_id=args.match_run_id, cve_id=args.cve,
                                     action_key=args.action_key, planned_action=args.planned_action,
                                     owner=args.owner, mode=args.recommendation_mode)
            if args.command == "lab-switch":
                from labs.log4shell.runner import Log4ShellRunner
                plan, before_sbom = workflow.plan_source(args.remediation_id)
                runner = Log4ShellRunner(root=Path(__file__).resolve().parents[1],
                                         logs=store.directory / f"applications/{plan.id}/commands", port=args.port)
                evidence = runner.switch(store=store, remediation_id=plan.id,
                                         before_sbom=before_sbom, expected_before_version=plan.before.component_version)
                return workflow.apply(remediation_id=plan.id, evidence=evidence)
            if args.command == "apply":
                return workflow.apply(remediation_id=args.remediation_id,
                                      evidence=json.loads(args.evidence.read_text(encoding="utf-8-sig")))
            if args.command == "start":
                return workflow.start(remediation_id=args.remediation_id, attempt_key=args.attempt_key,
                                      required_tests=tuple(args.required_test))
            if args.command == "after":
                validate_source = None
                operation = store.read("run.json")["operations"].get(f"lab-switch-{args.remediation_id}")
                if operation:
                    from labs.log4shell.runner import Log4ShellRunner
                    runner = Log4ShellRunner(root=Path(operation["parameters"]["root"]),
                                             logs=store.directory / f"applications/{args.remediation_id}/checks",
                                             port=operation["parameters"]["port"])
                    validate_source = lambda: runner.validate_applied(store=store, remediation_id=args.remediation_id)
                return workflow.after(remediation_id=args.remediation_id, verification_id=args.verification_id,
                                      source=str(args.source), syft=args.syft,
                                      syft_config=str(args.syft_config), base_url=args.base_url,
                                      validate_source=validate_source)
            return workflow.compare(remediation_id=args.remediation_id, verification_id=args.verification_id)
        finally:
            workflow.close()


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = execute(args)
    except (ValueError, RuntimeError, OSError, sqlite3.Error) as exc:
        logging.error("Command stopped; preserve this run and resume the same command: %s", exc)
        return 2
    print(evidence_json(result))
    if args.command == "after" and result.get("status") == "verification_failed":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
