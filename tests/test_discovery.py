"""Tests for ICMP host discovery.

A fake ``runner`` is always injected, so these tests never spawn ``ping`` or
touch the network.
"""

import ipaddress

import pytest

from recon.discovery import DiscoveredHost, discover_hosts
from recon.errors import TargetNotAllowed


def responder(up_ips):
    """Return a runner that reports the given IPs as up and all others as down."""
    up = set(up_ips)
    return lambda ip: ip in up


def _forbidden_runner(_ip):
    raise AssertionError("runner must not be invoked for an out-of-scope network")


def test_returns_only_responsive_hosts_sorted_by_address():
    network = ipaddress.ip_network("192.168.99.0/29")  # .1 .. .6
    runner = responder({"192.168.99.4", "192.168.99.1"})

    hosts = discover_hosts(network, runner=runner)

    assert [host.ip for host in hosts] == ["192.168.99.1", "192.168.99.4"]
    assert all(h.status == "up" and h.discovery_method == "icmp" for h in hosts)


def test_result_dict_has_enrichment_placeholders():
    network = ipaddress.ip_network("10.0.0.0/30")  # .1, .2
    (host,) = discover_hosts(network, runner=responder({"10.0.0.1"}))

    assert host.to_dict() == {
        "ip": "10.0.0.1",
        "status": "up",
        "discovery_method": "icmp",
        "hostname": None,
        "mac": None,
        "open_ports": [],
    }


def test_runner_exceptions_are_treated_as_down():
    network = ipaddress.ip_network("192.168.50.0/30")

    def broken_runner(_ip):
        raise RuntimeError("boom")

    assert discover_hosts(network, runner=broken_runner) == []


def test_no_responsive_hosts_returns_empty_list():
    network = ipaddress.ip_network("192.168.1.0/24")
    assert discover_hosts(network, runner=lambda _ip: False) == []


@pytest.mark.parametrize(
    "cidr",
    [
        "8.8.8.0/24",  # public
        "1.1.1.0/30",  # public
        "169.254.0.0/24",  # link-local, not RFC1918
        "172.32.0.0/28",  # just outside 172.16/12
    ],
)
def test_rejects_non_rfc1918_network_without_probing(cidr):
    with pytest.raises(TargetNotAllowed):
        discover_hosts(ipaddress.ip_network(cidr), runner=_forbidden_runner)


@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "192.168.0.0/16", "10.1.0.0/23"])
def test_rejects_oversized_network_without_probing(cidr):
    with pytest.raises(TargetNotAllowed):
        discover_hosts(ipaddress.ip_network(cidr), runner=_forbidden_runner)


def test_rejects_unsafe_network_before_checking_ping_availability(monkeypatch):
    import shutil

    def fail(_name):
        raise AssertionError("ping availability must not be checked first")

    monkeypatch.setattr(shutil, "which", fail)
    with pytest.raises(TargetNotAllowed):
        discover_hosts(ipaddress.ip_network("8.8.8.0/24"))


def test_larger_sweep_orders_addresses_numerically():
    network = ipaddress.ip_network("192.168.1.0/24")
    runner = responder({"192.168.1.100", "192.168.1.3", "192.168.1.20"})

    hosts = discover_hosts(network, runner=runner)

    assert [h.ip for h in hosts] == [
        "192.168.1.3",
        "192.168.1.20",
        "192.168.1.100",
    ]
    assert all(isinstance(h, DiscoveredHost) for h in hosts)
