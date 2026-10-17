"""Run the local read-only API with python -m app.main."""

from flask import Flask

from app.api.dashboard import dashboard_api, register_errors
from app.config.dashboard import database_paths


def create_app(databases: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config["DASHBOARD_DATABASES"] = database_paths() if databases is None else databases
    app.json.ensure_ascii = False
    app.register_blueprint(dashboard_api)
    register_errors(app)
    return app


if __name__ == "__main__":
    import os

    application = create_app()
    application.run(host=os.getenv("FLASK_HOST", "127.0.0.1"),
                    port=int(os.getenv("FLASK_PORT", "5000")), debug=False)
