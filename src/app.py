"""Flask application factory for Network Recon."""

from flask import Flask, jsonify, render_template, request

from config import Config
from routes import main


def create_app(config_object: type = Config) -> Flask:
    """Create and configure the Flask application.

    Templates and static assets live alongside this module under ``src/``.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_object)

    app.register_blueprint(main)
    _register_error_handlers(app)

    return app


def _wants_json(req) -> bool:
    return req.path.startswith(("/scan", "/healthz")) or "application/json" in (
        req.headers.get("Accept", "")
    )


def _register_error_handlers(app: Flask) -> None:
    """Return friendly pages/JSON instead of raw tracebacks."""

    @app.errorhandler(404)
    def not_found(_error):
        if _wants_json(request):
            return jsonify({"status": "error", "message": "Not found."}), 404
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(_error):
        if _wants_json(request):
            return (
                jsonify({"status": "error", "message": "Internal server error."}),
                500,
            )
        return render_template("500.html"), 500
