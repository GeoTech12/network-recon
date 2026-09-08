"""HTTP routes for Network Recon.

The ``/scan`` endpoint determines the authorised local subnet (auto-detected, or
the validated ``RECON_SUBNET`` override), sends a single ICMP echo request to
each address, then enriches the responsive hosts with a MAC address from the
local ARP cache and -- only when ``RECON_RESOLVE_HOSTNAMES`` is enabled -- a
reverse-DNS hostname. When ``RECON_CHECK_PORTS`` is enabled it also checks a
small fixed list of common TCP ports. Missing hostnames, MAC addresses and open
ports are all normal. Reporting is a later milestone.
"""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request

import config
from recon.discovery import discover_hosts
from recon.enrichment import enrich_hosts
from recon.errors import ReconError, TargetNotAllowed
from recon.localnet import detect_local_network, ensure_allowed_network
from recon.portscan import check_ports

main = Blueprint("main", __name__)

# Field labels shown in the results area. These mirror the fields described in
# the PRD; later milestones fill in the columns that are empty in Milestone 2.
RESULT_FIELDS = [
    "IP Address",
    "Hostname",
    "MAC Address",
    "Status",
    "Open Common Ports",
    "Scan Time",
]

_TRUTHY = {"1", "true", "yes", "on"}


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
    """Discover responsive hosts on the authorised local network."""
    confirmed = request.form.get("authorized", "").strip().lower() in _TRUTHY
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

    try:
        if config.RECON_SUBNET:
            network = ensure_allowed_network(config.RECON_SUBNET)
        else:
            network = ensure_allowed_network(detect_local_network())
        hosts = discover_hosts(network)
        # Best-effort enrichment. Never raises; hostname resolution only happens
        # when RECON_RESOLVE_HOSTNAMES is enabled.
        hosts = enrich_hosts(hosts, resolve_hostnames=config.RECON_RESOLVE_HOSTNAMES)
        # Opt-in TCP port checks. check_ports re-validates `network` as defence
        # in depth and only probes hosts contained in it.
        hosts = check_ports(hosts, network, enabled=config.RECON_CHECK_PORTS)
    except TargetNotAllowed as exc:
        # The requested scope is not permitted: a client-correctable request.
        return jsonify({"status": "error", "message": str(exc)}), 400
    except ReconError as exc:
        # Includes NetworkDetectionError. Failure to determine the server's own
        # local network (or to run discovery) is a server-side condition.
        return jsonify({"status": "error", "message": str(exc)}), 500

    devices = [host.to_dict() for host in hosts]
    count = len(devices)
    if count:
        noun = "host" if count == 1 else "hosts"
        message = f"Discovered {count} responsive {noun} on {network}."
    else:
        message = f"No responsive hosts found on {network}."

    return jsonify(
        {
            "status": "ok",
            "message": message,
            "scan_time": _now_iso(),
            "network": str(network),
            "devices": devices,
        }
    )


@main.route("/healthz")
def healthz():
    """Lightweight liveness check."""
    return jsonify({"status": "ok"})
