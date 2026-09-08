"""Tests for opt-in TCP port checks.

Every test injects a fake connector, and ``socket.create_connection`` is
monkeypatched to fail the test if it is ever called. Zero real socket or network
activity.
"""

import ipaddress
import socket
import threading

import pytest

from recon import portscan
from recon.discovery import DiscoveredHost
from recon.errors import TargetNotAllowed
from recon.portscan import COMMON_TCP_PORTS, check_ports

NET = ipaddress.ip_network("192.168.1.0/24")


@pytest.fixture(autouse=True)
def _forbid_real_sockets(monkeypatch):
    def explode(*_args, **_kwargs):
        raise AssertionError("no real socket connection may be attempted")

    monkeypatch.setattr(socket, "create_connection", explode)


def _host(ip, status="up"):
    return DiscoveredHost(ip=ip, status=status)


def open_ports_on(mapping):
    """``mapping``: {ip: {port, ...}} -> a connector reporting those ports open."""

    def connector(ip, port):
        return port in mapping.get(ip, set())

    return connector


class TestPortList:
    def test_is_exactly_the_seven_documented_ports(self):
        assert COMMON_TCP_PORTS == (
            (21, "ftp"),
            (22, "ssh"),
            (53, "dns"),
            (80, "http"),
            (443, "https"),
            (445, "smb"),
            (3389, "rdp"),
        )


class TestDisabled:
    def test_disabled_opens_nothing_and_leaves_open_ports_empty(self):
        hosts = [_host("192.168.1.10")]

        def connector(_ip, _port):
            raise AssertionError("connector must not run when disabled")

        result = check_ports(hosts, NET, enabled=False, connector=connector)

        assert result is hosts
        assert hosts[0].open_ports == []

    def test_disabled_is_the_default(self):
        hosts = [_host("192.168.1.10")]
        check_ports(hosts, NET, connector=lambda _ip, _port: True)
        assert hosts[0].open_ports == []


class TestEnabled:
    def test_records_open_ports_sorted_with_service_labels(self):
        hosts = [_host("192.168.1.10")]
        check_ports(
            hosts,
            NET,
            enabled=True,
            connector=open_ports_on({"192.168.1.10": {80, 22}}),
        )
        assert hosts[0].open_ports == [
            {"port": 22, "service": "ssh"},
            {"port": 80, "service": "http"},
        ]

    def test_host_with_no_open_ports_gets_empty_list(self):
        hosts = [_host("192.168.1.10")]
        check_ports(hosts, NET, enabled=True, connector=lambda _ip, _port: False)
        assert hosts[0].open_ports == []

    def test_connector_called_only_with_known_ports_and_host_ips(self):
        hosts = [_host("192.168.1.10"), _host("192.168.1.11")]
        seen = []

        def connector(ip, port):
            seen.append((ip, port))
            return False

        check_ports(hosts, NET, enabled=True, connector=connector)

        assert {ip for ip, _ in seen} == {"192.168.1.10", "192.168.1.11"}
        assert {port for _, port in seen} == {p for p, _ in COMMON_TCP_PORTS}
        assert len(seen) == 2 * len(COMMON_TCP_PORTS)

    def test_connector_exception_counts_as_closed(self):
        def connector(ip, port):
            if port == 22:
                raise RuntimeError("boom")
            return port == 80

        hosts = [_host("192.168.1.10")]
        check_ports(hosts, NET, enabled=True, connector=connector)

        assert hosts[0].open_ports == [{"port": 80, "service": "http"}]

    def test_returns_same_list_object(self):
        hosts = [_host("192.168.1.10")]
        assert (
            check_ports(hosts, NET, enabled=True, connector=lambda _i, _p: False)
            is hosts
        )

    def test_empty_host_list(self):
        assert check_ports([], NET, enabled=True, connector=lambda _i, _p: True) == []

    def test_overall_deadline_bounds_the_wait(self):
        release = threading.Event()

        def connector(ip, port):
            if ip == "192.168.1.10" and port == 22:
                release.wait(timeout=5)
                return True
            return False

        hosts = [_host("192.168.1.10"), _host("192.168.1.11")]
        try:
            check_ports(
                hosts, NET, enabled=True, connector=connector, deadline_s=0.5
            )
            assert {"port": 22, "service": "ssh"} not in hosts[0].open_ports
        finally:
            release.set()


class TestScopeEnforcement:
    def test_revalidates_network_and_rejects_public(self):
        with pytest.raises(TargetNotAllowed):
            check_ports(
                [_host("8.8.8.8")],
                ipaddress.ip_network("8.8.8.0/24"),
                enabled=True,
                connector=lambda _i, _p: True,
            )

    def test_revalidates_network_and_rejects_oversized(self):
        with pytest.raises(TargetNotAllowed):
            check_ports(
                [_host("10.0.0.5")],
                ipaddress.ip_network("10.0.0.0/16"),
                enabled=True,
                connector=lambda _i, _p: True,
            )

    def test_only_hosts_inside_the_exact_network_are_probed(self):
        hosts = [
            _host("192.168.1.10"),  # in NET
            _host("192.168.2.10"),  # RFC1918 but NOT in NET
            _host("10.0.0.5"),  # RFC1918 but NOT in NET
        ]
        seen = []

        def connector(ip, port):
            seen.append(ip)
            return False

        check_ports(hosts, NET, enabled=True, connector=connector)

        assert set(seen) == {"192.168.1.10"}
        assert hosts[1].open_ports == []
        assert hosts[2].open_ports == []

    def test_hosts_not_up_are_skipped(self):
        host = _host("192.168.1.10", status="down")
        seen = []

        def connector(ip, port):
            seen.append(ip)
            return True

        check_ports([host], NET, enabled=True, connector=connector)

        assert seen == []
        assert host.open_ports == []


class TestTcpConnect:
    def test_open_when_connection_succeeds_and_socket_is_closed_not_read(self, monkeypatch):
        events = []

        class FakeSock:
            def close(self):
                events.append("close")

            def recv(self, *_a):
                events.append("recv")

        monkeypatch.setattr(
            socket, "create_connection", lambda _addr, timeout: FakeSock()
        )

        assert portscan._tcp_connect("192.168.1.10", 80) is True
        assert events == ["close"]

    @pytest.mark.parametrize(
        "exc", [ConnectionRefusedError(), socket.timeout(), OSError("unreachable")]
    )
    def test_not_open_when_connection_fails(self, monkeypatch, exc):
        def raise_it(_addr, timeout):
            raise exc

        monkeypatch.setattr(socket, "create_connection", raise_it)

        assert portscan._tcp_connect("192.168.1.10", 22) is False
