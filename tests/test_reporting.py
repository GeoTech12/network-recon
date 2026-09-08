"""Tests for local HTML report generation.

All data is fictional (RFC 5737 documentation addresses). Every file is written
under pytest's ``tmp_path`` or a monkeypatched reports directory, never the real
``reports/`` folder. No network activity.
"""

import datetime as _dt
import re

import pytest

import recon.reporting as reporting
import routes
from recon.reporting import (
    ReportError,
    _safe_target,
    build_report_model,
    generate_report,
)

FILENAME_RE = re.compile(r"^network-recon-\d{8}-\d{6}(-\d+)?\.html$")


class _FrozenDatetime:
    @staticmethod
    def now(tz=None):
        return _dt.datetime(2026, 9, 8, 14, 32, 0, tzinfo=tz or _dt.timezone.utc)


def sample_payload(**overrides):
    payload = {
        "status": "ok",
        "message": "Discovered 2 responsive hosts on 192.0.2.0/24.",
        "scan_time": "2026-09-08T14:32:00+00:00",
        "network": "192.0.2.0/24",
        "device_count": 2,
        "features": {"hostname_resolution": True, "port_check": True},
        "devices": [
            {
                "ip": "192.0.2.10",
                "status": "up",
                "discovery_method": "icmp",
                "hostname": "desktop-lab",
                "mac": "52:54:00:11:22:33",
                "open_ports": [{"port": 22, "service": "ssh"}],
            },
            {
                "ip": "192.0.2.11",
                "status": "up",
                "discovery_method": "icmp",
                "hostname": None,
                "mac": None,
                "open_ports": [],
            },
        ],
    }
    payload.update(overrides)
    return payload


class TestBuildReportModel:
    def test_keeps_known_keys_and_drops_unknown(self):
        model = build_report_model(sample_payload(secret="drop me"))
        assert "secret" not in model
        assert model["network"] == "192.0.2.0/24"
        assert model["device_count"] == 2
        assert model["features"] == {"hostname_resolution": True, "port_check": True}
        assert set(model["devices"][0]) == {
            "ip",
            "hostname",
            "mac",
            "status",
            "open_ports",
        }
        assert model["devices"][0]["open_ports"] == [{"port": 22, "service": "ssh"}]
        assert "generated_at" in model

    def test_rejects_non_dict(self):
        with pytest.raises(ReportError):
            build_report_model(["not", "a", "dict"])

    def test_rejects_missing_devices(self):
        payload = sample_payload()
        del payload["devices"]
        with pytest.raises(ReportError):
            build_report_model(payload)

    def test_rejects_missing_network(self):
        with pytest.raises(ReportError):
            build_report_model(sample_payload(network=None))

    def test_device_count_is_derived_from_sanitized_devices_not_payload(self):
        payload = sample_payload(device_count=999)  # attacker-supplied, ignored
        model = build_report_model(payload)
        assert model["device_count"] == 2
        assert model["device_count"] == len(model["devices"])

    def test_device_count_ignores_non_numeric_payload_value(self):
        model = build_report_model(sample_payload(device_count="bogus"))
        assert model["device_count"] == 2

    def test_coerces_and_filters_ports(self):
        payload = sample_payload()
        payload["devices"][0]["open_ports"] = [
            {"port": "80", "service": "http"},
            {"port": None},
            "garbage",
        ]
        model = build_report_model(payload)
        assert model["devices"][0]["open_ports"] == [{"port": 80, "service": "http"}]

    def test_rejects_ports_outside_1_to_65535(self):
        payload = sample_payload()
        payload["devices"][0]["open_ports"] = [
            {"port": 0},
            {"port": -1},
            {"port": 65536},
            {"port": 100000},
            {"port": 443, "service": "https"},
        ]
        model = build_report_model(payload)
        assert model["devices"][0]["open_ports"] == [{"port": 443, "service": "https"}]


class TestSafeTarget:
    def test_rejects_path_traversal(self, tmp_path):
        with pytest.raises(ReportError):
            _safe_target(tmp_path, "../evil.html")

    def test_rejects_unexpected_filename(self, tmp_path):
        with pytest.raises(ReportError):
            _safe_target(tmp_path, "network-recon-oops.html")

    def test_accepts_generated_pattern(self, tmp_path):
        target = _safe_target(tmp_path, "network-recon-20260908-143200.html")
        assert target.parent == tmp_path.resolve()


class TestGenerateReport:
    def test_writes_safe_html_inside_reports_dir(self, tmp_path):
        path = generate_report(build_report_model(sample_payload()), reports_dir=tmp_path)
        assert path.parent == tmp_path.resolve()
        assert FILENAME_RE.match(path.name)
        assert path.read_text(encoding="utf-8").startswith("<!doctype html>")
        assert list(tmp_path.glob("*.part")) == []

    def test_contains_fictional_values(self, tmp_path):
        html = generate_report(
            build_report_model(sample_payload()), reports_dir=tmp_path
        ).read_text(encoding="utf-8")
        assert "192.0.2.10" in html
        assert "desktop-lab" in html
        assert "52:54:00:11:22:33" in html
        assert "22 (ssh)" in html

    def test_four_state_strings_render(self, tmp_path):
        off = generate_report(
            build_report_model(
                sample_payload(
                    features={"hostname_resolution": False, "port_check": False}
                )
            ),
            reports_dir=tmp_path,
        ).read_text(encoding="utf-8")
        assert "Not resolved" in off
        assert "Not checked" in off

        on = generate_report(
            build_report_model(sample_payload()), reports_dir=tmp_path
        ).read_text(encoding="utf-8")
        assert "Unknown" in on
        assert "None found" in on
        assert "Not available" in on

    def test_escapes_hostile_hostname(self, tmp_path):
        payload = sample_payload()
        payload["devices"][0]["hostname"] = "<script>alert(1)</script>"
        html = generate_report(
            build_report_model(payload), reports_dir=tmp_path
        ).read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_zero_devices(self, tmp_path):
        html = generate_report(
            build_report_model(sample_payload(devices=[], device_count=0)),
            reports_dir=tmp_path,
        ).read_text(encoding="utf-8")
        assert "No responsive hosts were found" in html

    def test_collision_gets_numbered_suffix(self, tmp_path, monkeypatch):
        monkeypatch.setattr(reporting, "datetime", _FrozenDatetime)
        model = build_report_model(sample_payload())
        first = generate_report(model, reports_dir=tmp_path)
        second = generate_report(model, reports_dir=tmp_path)
        assert first.name != second.name
        assert second.name.endswith("-2.html")

    def test_write_failure_raises_and_leaves_no_file(self, tmp_path, monkeypatch):
        from pathlib import Path

        def failing_write(self, *args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(Path, "write_text", failing_write)
        with pytest.raises(ReportError):
            generate_report(
                build_report_model(sample_payload()), reports_dir=tmp_path
            )
        assert list(tmp_path.glob("*.html")) == []
        assert list(tmp_path.glob("*.part")) == []

    def test_default_reports_dir_is_repo_reports_folder(self):
        assert reporting.REPORTS_DIR.name == "reports"
        assert (reporting.REPORTS_DIR.parent / "src").is_dir()


class TestReportRoute:
    @pytest.fixture(autouse=True)
    def _redirect_reports_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(reporting, "REPORTS_DIR", tmp_path)
        self.reports_dir = tmp_path

    def test_writes_file_and_returns_relative_path(self, client):
        response = client.post("/report", json=sample_payload())
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"
        assert data["path"].startswith("reports/")
        assert FILENAME_RE.match(data["filename"])
        assert "192.0.2.10" not in response.get_data(as_text=True)
        assert len(list(self.reports_dir.glob("*.html"))) == 1

    def test_rejects_non_json_body(self, client):
        response = client.post("/report", data="nope", content_type="text/plain")
        assert response.status_code == 400
        assert response.get_json()["status"] == "error"

    def test_rejects_empty_object(self, client):
        response = client.post("/report", json={})
        assert response.status_code == 400

    def test_generation_failure_is_a_friendly_500(self, client, monkeypatch):
        def boom(_model):
            raise ReportError("the disk is on fire")

        monkeypatch.setattr(routes, "generate_report", boom)
        response = client.post("/report", json=sample_payload())
        assert response.status_code == 500
        body = response.get_json()
        assert body["status"] == "error"
        assert "Traceback" not in body["message"]
