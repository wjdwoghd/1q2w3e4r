"""GET-only API. Validation, service dispatch and JSON presentation only."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from core.dashboard.service import DashboardService
from database.repositories.dashboard_repository import open_dashboard_database

dashboard_api = Blueprint("dashboard", __name__, url_prefix="/api")


def positive_id(name: str, *, optional: bool = False) -> int | None:
    values = request.args.getlist(name)
    if not values and optional:
        return None
    if (len(values) != 1 or len(values[0]) > 19 or not values[0].isascii()
            or not values[0].isdigit() or not 0 < int(values[0]) <= 2**63 - 1):
        raise ValueError(f"{name}: explicit positive ID required")
    return int(values[0])


@contextmanager
def selected_service():
    aliases: dict[str, Path] = current_app.config["DASHBOARD_DATABASES"]
    names = request.args.getlist("database")
    if len(names) != 1 or names[0] not in aliases:
        raise ValueError("database: select one configured execution DB alias")
    with open_dashboard_database(Path(aliases[names[0]])) as connection:
        yield DashboardService(connection)


def selection(*names: str) -> dict:
    return {name: positive_id(name) for name in names}


@dashboard_api.get("/databases")
def databases():
    return jsonify([{"name": key, "path": str(value)}
                    for key, value in current_app.config["DASHBOARD_DATABASES"].items()])


@dashboard_api.get("/<resource>")
def read_resource(resource: str):
    # Explicit dispatch prevents access to write methods of the underlying services.
    with selected_service() as service:
        if resource == "services":
            result = service.services()
        elif resource == "assets":
            result = service.asset_list(positive_id("service_id", optional=True))
        elif resource in ("asset", "sboms", "findings"):
            args = selection("asset_id")
            result = {"asset": service.asset, "sboms": service.sboms,
                      "findings": service.finding_list}[resource](**args)
        elif resource == "sbom":
            result = service.sbom(**selection("asset_id", "sbom_id"))
        elif resource in ("finding", "recommendations", "remediations"):
            args = selection("asset_id", "finding_id")
            result = {"finding": service.finding, "recommendations": service.recommendation_list,
                      "remediations": service.remediation_list}[resource](**args)
        elif resource in ("remediation", "attempts"):
            args = selection("asset_id", "finding_id", "remediation_id")
            result = {"remediation": service.remediation, "attempts": service.attempts}[resource](**args)
        elif resource == "attempt":
            result = service.attempt(**selection("asset_id", "finding_id", "remediation_id", "verification_id"))
        else:
            return jsonify(error={"code": "not_found", "message": "Unknown read resource"}), 404
    return jsonify(result)


def register_errors(app) -> None:
    from database.repositories.asset_repository import AssetNotFoundError
    from database.repositories.finding_repository import FindingNotFoundError
    from database.repositories.recommendation_repository import RecommendationNotFoundError
    from database.repositories.remediation_repository import RemediationNotFoundError
    from database.repositories.verification_repository import VerificationNotFoundError
    from database.repositories.vulnerability_repository import VulnerabilityMatchNotFoundError
    from database.repositories.dashboard_repository import DashboardDatabaseError
    from werkzeug.exceptions import HTTPException

    def missing(exc):
        return jsonify(error={"code": "not_found", "message": str(exc)}), 404

    for error in (AssetNotFoundError, FindingNotFoundError, RecommendationNotFoundError,
                  RemediationNotFoundError, VerificationNotFoundError, VulnerabilityMatchNotFoundError):
        app.register_error_handler(error, missing)

    @app.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(error={"code": "invalid_selection_or_evidence", "message": str(exc)}), 400

    @app.errorhandler(DashboardDatabaseError)
    @app.errorhandler(sqlite3.Error)
    def unavailable(exc):
        message = str(exc) if isinstance(exc, DashboardDatabaseError) else "Execution DB unavailable, locked, damaged or schema incompatible"
        return jsonify(error={"code": "database_unavailable", "message": message}), 503

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error={"code": exc.name, "message": exc.description}), exc.code
