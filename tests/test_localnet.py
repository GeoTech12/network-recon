"""Tests for local subnet detection and target-network validation.

No real network I/O: the routing table is a fixture file and the primary-IP
helper is monkeypatched.
"""

import ipaddress

import pytest

from recon import localnet
from recon.errors import NetworkDetectionError, TargetNotAllowed

# A synthetic /proc/net/route: a default route (via gateway), a connected
# 192.168.1.0/24, and a loopback route.
FAKE_ROUTE_TABLE = (
    "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
    "lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n"
)


class TestEnsureAllowedNetwork:
    @pytest.mark.parametrize(
        "cidr",
        [
            "192.168.1.0/24",
            "10.0.0.0/24",
            "172.16.5.0/25",
            "192.168.1.128/26",
            "10.1.2.3/32",
        ],
    )
    def test_accepts_small_private_subnets(self, cidr):
        network = localnet.ensure_allowed_network(cidr)
        assert isinstance(network, ipaddress.IPv4Network)

    def test_accepts_ipv4network_instance(self):
        given = ipaddress.ip_network("192.168.7.0/24")
        assert localnet.ensure_allowed_network(given) == given

    @pytest.mark.parametrize(
        "cidr",
        [
            "8.8.8.0/24",  # public
            "1.1.1.0/24",  # public
            "172.32.0.0/24",  # just outside 172.16/12
            "192.169.0.0/24",  # just outside 192.168/16
            "169.254.0.0/24",  # link-local (is_private is True, but not RFC1918)
            "127.0.0.0/24",  # loopback
            "100.64.0.0/24",  # CGNAT
        ],
    )
    def test_rejects_non_rfc1918(self, cidr):
        with pytest.raises(TargetNotAllowed):
            localnet.ensure_allowed_network(cidr)

    @pytest.mark.parametrize(
        "cidr",
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/23"],
    )
    def test_rejects_subnets_larger_than_256_addresses(self, cidr):
        with pytest.raises(TargetNotAllowed):
            localnet.ensure_allowed_network(cidr)

    @pytest.mark.parametrize(
        "value", ["", "garbage", "192.168.1.0/33", "10.0.0.0 10.0.0.1", "::1/128"]
    )
    def test_rejects_invalid_or_non_ipv4(self, value):
        with pytest.raises(TargetNotAllowed):
            localnet.ensure_allowed_network(value)


class TestIterConnectedNetworks:
    def test_parses_connected_route_and_skips_default(self, tmp_path, monkeypatch):
        route_file = tmp_path / "route"
        route_file.write_text(FAKE_ROUTE_TABLE)
        monkeypatch.setattr(localnet, "_ROUTE_TABLE", str(route_file))

        networks = [network for _iface, network in localnet._iter_connected_networks()]

        assert ipaddress.ip_network("192.168.1.0/24") in networks
        assert all(network.prefixlen != 0 for network in networks)  # no default route


class TestDetectLocalNetwork:
    def test_picks_network_containing_primary_ip(self, monkeypatch):
        candidates = [
            ("eth0", ipaddress.ip_network("192.168.1.0/24")),
            ("eth1", ipaddress.ip_network("10.0.5.0/24")),
        ]
        monkeypatch.setattr(
            localnet, "_iter_connected_networks", lambda: iter(candidates)
        )
        monkeypatch.setattr(localnet, "primary_ipv4", lambda: "10.0.5.42")

        assert localnet.detect_local_network() == ipaddress.ip_network("10.0.5.0/24")

    def test_single_candidate_is_used(self, monkeypatch):
        monkeypatch.setattr(
            localnet,
            "_iter_connected_networks",
            lambda: iter([("eth0", ipaddress.ip_network("192.168.1.0/24"))]),
        )
        monkeypatch.setattr(localnet, "primary_ipv4", lambda: None)

        assert localnet.detect_local_network() == ipaddress.ip_network("192.168.1.0/24")

    def test_no_candidates_raises(self, monkeypatch):
        monkeypatch.setattr(localnet, "_iter_connected_networks", lambda: iter([]))
        monkeypatch.setattr(localnet, "primary_ipv4", lambda: None)

        with pytest.raises(NetworkDetectionError):
            localnet.detect_local_network()

    def test_ambiguous_candidates_raise_instead_of_guessing(self, monkeypatch):
        candidates = [
            ("eth0", ipaddress.ip_network("192.168.1.0/24")),
            ("eth1", ipaddress.ip_network("192.168.2.0/24")),
        ]
        monkeypatch.setattr(
            localnet, "_iter_connected_networks", lambda: iter(candidates)
        )
        monkeypatch.setattr(localnet, "primary_ipv4", lambda: "10.9.9.9")

        with pytest.raises(NetworkDetectionError):
            localnet.detect_local_network()

    def test_unreadable_route_table_raises(self, monkeypatch):
        def raise_oserror():
            raise OSError("permission denied")

        monkeypatch.setattr(
            localnet, "_iter_connected_networks", lambda: raise_oserror()
        )

        with pytest.raises(NetworkDetectionError):
            localnet.detect_local_network()
