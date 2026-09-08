"""HTTP routes for Network Recon.

Milestone 1 provides only the web application skeleton. The scan endpoint is a
placeholder: it performs no network activity and returns a fixed "not
implemented" response. Discovery and port-check logic arrive in later
milestones.
"""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request

import config

main = Blueprint("main", __name__)

# Field labels shown in the (currently empty) results area. These mirror the
# fields described in the PRD so the interface communicates intent before any
# scanning exists.
RESULT_FIELDS = [
    "IP Address",
    "Hostname",
    "MAC Address",
    "Status",
    "Open Common Ports",
    "Scan Time",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@main.route("/")
def index():
    """Render the reconnaissance dashboard."""
    return render_template(
        "index.html",
        app_name=config.APP_NAME,
        app_description=config.APP_DESCRIPTION,
        result_fields=RESULT_FIELDS,
    )


@main.route("/scan", methods=["POST"])
def scan():
    """Placeholder scan endpoint.

    Requires the caller to confirm authorization, then returns a fixed
    "not implemented" payload. No network activity is performed.
    """
    confirmed = request.form.get("authorized", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not confirmed:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": (
                        "You must confirm that you are authorized to scan this "
                        "network before starting a scan."
                    ),
                }
            ),
            400,
        )

    return jsonify(
        {
            "status": "not_implemented",
            "message": "Scan functionality is not yet implemented (Milestone 1).",
            "devices": [],
            "scan_time": _now_iso(),
        }
    )


@main.route("/healthz")
def healthz():
    """Lightweight liveness check."""
    return jsonify({"status": "ok"})
