"""Tests for the /scan route with discovery wired in.

Discovery and local-network detection are monkeypatched, so the route is
exercised end to end without any real network I/O.
"""

import ipaddress

import pytest

import config
import routes
from recon.discovery import DiscoveredHost
from recon.errors import NetworkDetectionError


def _fail_if_called(*_args, **_kwargs):
    raise AssertionError("discover_hosts should not run in this scenario")


@pytest.fixture(autouse=True)
def _no_recon_subnet(monkeypatch):
    """Default to auto-detection unless a test opts into RECON_SUBNET."""
    monkeypatch.setattr(config, "RECON_SUBNET", None)


@pytest.fixture(autouse=True)
def _stub_enrichment(monkeypatch):
    """No test should reach real hostname/ARP enrichment; identity by default."""
    monkeypatch.setattr(routes, "enrich_hosts", lambda hosts, **_kwargs: hosts)


def test_scan_returns_discovered_hosts(client, monkeypatch):
    monkeypatch.setattr(
        routes, "detect_local_network", lambda: ipaddress.ip_network("192.168.1.0/24")
    )
    monkeypatch.setattr(
        routes,
        "discover_hosts",
        lambda network: [
            DiscoveredHost(ip="192.168.1.10"),
            DiscoveredHost(ip="192.168.1.20"),
        ],
    )

    response = client.post("/scan", data={"authorized": "on"})

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["network"] == "192.168.1.0/24"
    assert "host_count_probed" not in data
    assert [d["ip"] for d in data["devices"]] == ["192.168.1.10", "192.168.1.20"]
    assert data["devices"][0]["hostname"] is None
    assert data["devices"][0]["mac"] is None
    assert data["devices"][0]["open_ports"] == []
    assert "2 responsive hosts on 192.168.1.0/24" in data["message"]


def test_scan_reports_when_no_hosts_found(client, monkeypatch):
    monkeypatch.setattr(
        routes, "detect_local_network", lambda: ipaddress.ip_network("192.168.1.0/24")
    )
    monkeypatch.setattr(routes, "discover_hosts", lambda network: [])

    response = client.post("/scan", data={"authorized": "on"})

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["devices"] == []
    assert "No responsive hosts found" in data["message"]


def test_scan_still_requires_authorization_confirmation(client, monkeypatch):
    monkeypatch.setattr(routes, "detect_local_network", _fail_if_called)
    monkeypatch.setattr(routes, "discover_hosts", _fail_if_called)

    response = client.post("/scan")

    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_scan_handles_network_detection_failure(client, monkeypatch):
    def raise_detection_error():
        raise NetworkDetectionError("Could not determine your local network.")

    monkeypatch.setattr(routes, "detect_local_network", raise_detection_error)
    monkeypatch.setattr(routes, "discover_hosts", _fail_if_called)

    response = client.post("/scan", data={"authorized": "on"})

    # Detection failure is a server-side condition, not a bad request.
    assert response.status_code == 500
    body = response.get_json()
    assert body["status"] == "error"
    assert "local network" in body["message"].lower()
    assert "Traceback" not in body["message"]


def test_scan_rejects_public_recon_subnet(client, monkeypatch):
    monkeypatch.setattr(config, "RECON_SUBNET", "8.8.8.0/24")
    monkeypatch.setattr(routes, "discover_hosts", _fail_if_called)

    response = client.post("/scan", data={"authorized": "on"})

    assert response.status_code == 400
    assert "private address ranges" in response.get_json()["message"]


def test_scan_rejects_oversized_recon_subnet(client, monkeypatch):
    monkeypatch.setattr(config, "RECON_SUBNET", "10.0.0.0/16")
    monkeypatch.setattr(routes, "discover_hosts", _fail_if_called)

    response = client.post("/scan", data={"authorized": "on"})

    assert response.status_code == 400
    assert "256" in response.get_json()["message"]


def test_scan_accepts_valid_recon_subnet(client, monkeypatch):
    monkeypatch.setattr(config, "RECON_SUBNET", "192.168.5.0/28")
    monkeypatch.setattr(routes, "detect_local_network", _fail_if_called)
    monkeypatch.setattr(
        routes, "discover_hosts", lambda network: [DiscoveredHost(ip="192.168.5.2")]
    )

    response = client.post("/scan", data={"authorized": "on"})

    assert response.status_code == 200
    data = response.get_json()
    assert data["network"] == "192.168.5.0/28"
    assert [d["ip"] for d in data["devices"]] == ["192.168.5.2"]


def test_scan_includes_hostname_and_mac_when_enrichment_provides_them(client, monkeypatch):
    monkeypatch.setattr(
        routes, "detect_local_network", lambda: ipaddress.ip_network("192.168.1.0/24")
    )
    monkeypatch.setattr(
        routes, "discover_hosts", lambda network: [DiscoveredHost(ip="192.168.1.10")]
    )

    def fake_enrich(hosts, **_kwargs):
        hosts[0].hostname = "desktop-lab"
        hosts[0].mac = "52:54:00:1a:2b:3c"
        return hosts

    monkeypatch.setattr(routes, "enrich_hosts", fake_enrich)

    response = client.post("/scan", data={"authorized": "on"})

    assert response.status_code == 200
    device = response.get_json()["devices"][0]
    assert device["hostname"] == "desktop-lab"
    assert device["mac"] == "52:54:00:1a:2b:3c"


def test_scan_succeeds_when_enrichment_yields_nothing(client, monkeypatch):
    monkeypatch.setattr(
        routes, "detect_local_network", lambda: ipaddress.ip_network("192.168.1.0/24")
    )
    monkeypatch.setattr(
        routes, "discover_hosts", lambda network: [DiscoveredHost(ip="192.168.1.10")]
    )

    response = client.post("/scan", data={"authorized": "on"})

    assert response.status_code == 200
    device = response.get_json()["devices"][0]
    assert device["hostname"] is None
    assert device["mac"] is None


def test_scan_passes_hostname_flag_from_config_to_enrichment(client, monkeypatch):
    monkeypatch.setattr(
        routes, "detect_local_network", lambda: ipaddress.ip_network("192.168.1.0/24")
    )
    monkeypatch.setattr(
        routes, "discover_hosts", lambda network: [DiscoveredHost(ip="192.168.1.10")]
    )
    monkeypatch.setattr(config, "RECON_RESOLVE_HOSTNAMES", True)

    seen = {}

    def fake_enrich(hosts, *, resolve_hostnames=False, **_kwargs):
        seen["resolve_hostnames"] = resolve_hostnames
        return hosts

    monkeypatch.setattr(routes, "enrich_hosts", fake_enrich)

    client.post("/scan", data={"authorized": "on"})

    assert seen["resolve_hostnames"] is True
