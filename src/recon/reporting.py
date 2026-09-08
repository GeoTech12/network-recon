"""Local HTML report generation.

A report is written only when the user explicitly asks for one (the dashboard's
"Save report" button -> ``POST /report``). Reports are plain, self-contained
HTML files placed in the repository's ``reports/`` directory, which is
git-ignored.

A report contains real infrastructure data (IP / MAC / hostname / open ports),
so this module never uploads it, never logs its contents, and only ever writes
inside ``reports/``. Filenames are server-generated from a fixed timestamp
pattern; no part of a request influences the path.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

# reporting.py -> recon -> src -> <repo>; reports/ sits at the repo root.
REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports"

_TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"

_FILENAME_RE = re.compile(r"network-recon-\d{8}-\d{6}(?:-\d+)?\.html")

# A /24 holds at most 254 hosts; cap well above that but keep the work bounded.
_MAX_DEVICES = 4096
_MAX_PORTS_PER_DEVICE = 64
_MAX_COLLISION_SUFFIX = 1000

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


class ReportError(Exception):
    """Report generation failed. The scan result itself is unaffected."""


def _as_text(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _clean_ports(raw) -> list:
    if not isinstance(raw, list):
        return []
    cleaned = []
    for entry in raw[:_MAX_PORTS_PER_DEVICE]:
        if not isinstance(entry, dict):
            continue
        try:
            port_num = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        if not 1 <= port_num <= 65535:
            continue
        cleaned.append({"port": port_num, "service": _as_text(entry.get("service")) or ""})
    return cleaned


def _clean_device(raw) -> dict:
    if not isinstance(raw, dict):
        raw = {}
    return {
        "ip": _as_text(raw.get("ip")) or "",
        "hostname": _as_text(raw.get("hostname")),
        "mac": _as_text(raw.get("mac")),
        "status": _as_text(raw.get("status")) or "unknown",
        "open_ports": _clean_ports(raw.get("open_ports")),
    }


def build_report_model(payload) -> dict:
    """Turn an untrusted ``/scan``-style payload into a sanitized report model.

    Only known keys are kept; values are coerced; lists are size-capped. Raises
    :class:`ReportError` if the payload is not a usable scan result.
    """
    if not isinstance(payload, dict):
        raise ReportError("Report data must be a scan result object.")

    devices_raw = payload.get("devices")
    if not isinstance(devices_raw, list):
        raise ReportError("Report data is missing the list of devices.")

    network = _as_text(payload.get("network"))
    if not network:
        raise ReportError("Report data is missing the scanned network.")

    features_raw = payload.get("features")
    if not isinstance(features_raw, dict):
        features_raw = {}

    devices = [_clean_device(device) for device in devices_raw[:_MAX_DEVICES]]

    return {
        "network": network,
        "scan_time": _as_text(payload.get("scan_time")) or "unknown",
        # Derived from the sanitized list, never taken from the payload.
        "device_count": len(devices),
        "features": {
            "hostname_resolution": bool(features_raw.get("hostname_resolution")),
            "port_check": bool(features_raw.get("port_check")),
        },
        "devices": devices,
        "generated_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
    }


def _safe_target(reports_dir: Path, filename: str) -> Path:
    """Resolve ``filename`` inside ``reports_dir``, refusing anything else."""
    if not _FILENAME_RE.fullmatch(filename):
        raise ReportError("Refusing to write a report with an unexpected filename.")
    base = reports_dir.resolve()
    target = (base / filename).resolve()
    if target.parent != base:
        raise ReportError("Refusing to write a report outside the reports directory.")
    return target


def generate_report(model: dict, *, reports_dir: Optional[Path] = None) -> Path:
    """Render ``model`` to a self-contained HTML file inside ``reports_dir``.

    Returns the path written. Raises :class:`ReportError` on any failure; a
    failed write leaves no partial file.
    """
    reports_dir = Path(reports_dir) if reports_dir is not None else REPORTS_DIR

    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportError("Could not create the reports directory.") from exc

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = None
    for suffix in range(_MAX_COLLISION_SUFFIX):
        name = (
            f"network-recon-{stamp}.html"
            if suffix == 0
            else f"network-recon-{stamp}-{suffix + 1}.html"
        )
        candidate = _safe_target(reports_dir, name)
        if not candidate.exists():
            target = candidate
            break
    if target is None:
        raise ReportError("Too many reports generated in the same second.")

    try:
        html = _env.get_template("report.html").render(**model)
    except Exception as exc:
        raise ReportError("Could not render the report.") from exc

    partial = target.parent / (target.name + ".part")
    try:
        partial.write_text(html, encoding="utf-8")
        partial.replace(target)
    except OSError as exc:
        try:
            partial.unlink(missing_ok=True)
        except OSError:
            pass
        raise ReportError("Could not write the report file.") from exc

    return target
