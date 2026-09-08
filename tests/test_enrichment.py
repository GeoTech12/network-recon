"""Tests for hostname / MAC enrichment.

No real DNS queries and no reads of the machine's real ARP table: a fake
resolver and a fake ARP reader are injected in every test.
"""

import socket
import threading

import pytest

from recon.discovery import DiscoveredHost
from recon.enrichment import enrich_hosts, read_arp_table, resolve_hostname

# Fictional data only.
FAKE_ARP_TABLE = (
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.1.1      0x1         0x2         52:54:00:11:22:33     *        eth0\n"
    "192.168.1.50     0x1         0x2         52:54:00:AA:BB:CC     *        eth0\n"
    "192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
    "192.168.1.99     0x1         0x2         00:00:00:00:00:00     *        eth0\n"
    "192.168.1.42     0x1         0x2         not-a-mac            *        eth0\n"
    "192.168.1.255    0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0\n"
    "192.168.1.30     0x1         0x2         01:00:5e:01:02:03     *        eth0\n"
    "192.168.1.31     0x1         0x2         33:33:00:00:00:01     *        eth0\n"
    "malformed line without enough fields\n"
)


class TestReadArpTable:
    def test_keeps_only_complete_valid_entries_lowercased(self, tmp_path):
        path = tmp_path / "arp"
        path.write_text(FAKE_ARP_TABLE)

        assert read_arp_table(str(path)) == {
            "192.168.1.1": "52:54:00:11:22:33",
            "192.168.1.50": "52:54:00:aa:bb:cc",
        }

    def test_missing_file_returns_empty_mapping(self, tmp_path):
        assert read_arp_table(str(tmp_path / "does-not-exist")) == {}

    @pytest.mark.parametrize(
        "mac",
        [
            "ff:ff:ff:ff:ff:ff",  # broadcast
            "01:00:5e:01:02:03",  # IPv4 multicast
            "33:33:00:00:00:01",  # IPv6 multicast
            "03:00:00:00:00:01",  # locally administered, group bit set
        ],
    )
    def test_rejects_broadcast_and_multicast_macs(self, tmp_path, mac):
        path = tmp_path / "arp"
        path.write_text(
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            f"192.168.1.5      0x1         0x2         {mac}     *        eth0\n"
        )

        assert read_arp_table(str(path)) == {}

    def test_fixture_table_excludes_group_addresses(self, tmp_path):
        path = tmp_path / "arp"
        path.write_text(FAKE_ARP_TABLE)

        table = read_arp_table(str(path))

        assert "192.168.1.255" not in table  # broadcast
        assert "192.168.1.30" not in table  # multicast
        assert "192.168.1.31" not in table  # multicast


class TestResolveHostname:
    def test_returns_normalised_name(self):
        result = resolve_hostname("192.0.2.10", lookup=lambda _ip: "Desktop-Lab.local.")
        assert result == "Desktop-Lab.local"

    def test_result_equal_to_ip_is_not_a_name(self):
        assert resolve_hostname("192.0.2.10", lookup=lambda _ip: "192.0.2.10") is None

    def test_empty_result_is_none(self):
        assert resolve_hostname("192.0.2.10", lookup=lambda _ip: "") is None

    @pytest.mark.parametrize(
        "exc",
        [socket.herror(), socket.gaierror(), TimeoutError(), OSError("boom")],
    )
    def test_resolver_errors_become_none(self, exc):
        def raise_it(_ip):
            raise exc

        assert resolve_hostname("192.0.2.10", lookup=raise_it) is None


class TestEnrichHosts:
    @staticmethod
    def _hosts():
        return [DiscoveredHost(ip="192.168.1.1"), DiscoveredHost(ip="192.168.1.50")]

    def test_returns_same_list_and_sets_mac_from_arp(self):
        hosts = self._hosts() + [DiscoveredHost(ip="192.168.1.60")]

        result = enrich_hosts(
            hosts,
            resolve_hostnames=False,
            arp_reader=lambda: {"192.168.1.1": "52:54:00:11:22:33"},
        )

        assert result is hosts
        assert hosts[0].mac == "52:54:00:11:22:33"
        assert hosts[1].mac is None  # not in the cache -> stays None
        assert hosts[2].mac is None

    def test_no_name_resolution_happens_when_disabled(self):
        called = []

        def resolver(ip):
            called.append(ip)
            return "should-not-be-used"

        hosts = self._hosts()
        enrich_hosts(
            hosts,
            resolve_hostnames=False,
            arp_reader=lambda: {},
            hostname_resolver=resolver,
        )

        assert called == []
        assert all(host.hostname is None for host in hosts)

    def test_resolves_hostnames_when_enabled(self):
        names = {"192.168.1.1": "router-demo", "192.168.1.50": "printer-demo"}
        hosts = self._hosts()

        enrich_hosts(
            hosts,
            resolve_hostnames=True,
            arp_reader=lambda: {},
            hostname_resolver=lambda ip: names.get(ip),
        )

        assert [host.hostname for host in hosts] == ["router-demo", "printer-demo"]

    def test_one_resolver_failure_does_not_affect_other_hosts(self):
        def resolver(ip):
            if ip == "192.168.1.1":
                raise RuntimeError("resolver blew up")
            return "printer-demo"

        hosts = self._hosts()
        enrich_hosts(
            hosts,
            resolve_hostnames=True,
            arp_reader=lambda: {},
            hostname_resolver=resolver,
        )

        assert hosts[0].hostname is None
        assert hosts[1].hostname == "printer-demo"

    def test_unreadable_arp_table_leaves_macs_none(self):
        def boom():
            raise OSError("cannot read")

        hosts = self._hosts()
        enrich_hosts(hosts, resolve_hostnames=False, arp_reader=boom)

        assert all(host.mac is None for host in hosts)

    def test_deadline_bounds_wait_and_leaves_slow_lookup_incomplete(self):
        release = threading.Event()

        def resolver(ip):
            if ip == "192.168.1.1":
                release.wait(timeout=5)  # simulate a blocking resolver call
                return "eventually.local"
            return "fast-host"

        hosts = self._hosts()
        try:
            enrich_hosts(
                hosts,
                resolve_hostnames=True,
                arp_reader=lambda: {},
                hostname_resolver=resolver,
                deadline_s=0.5,
            )
            # The blocking lookup is not waited for; its host keeps hostname=None.
            assert hosts[0].hostname is None
            assert hosts[1].hostname == "fast-host"
        finally:
            release.set()

    def test_empty_host_list_is_returned_unchanged(self):
        assert enrich_hosts([], resolve_hostnames=True) == []
