"""Best-effort device information: MAC address and (optionally) hostname.

This step runs *after* host discovery and only on the hosts discovery already
found. It sends nothing to those hosts:

* **MAC addresses** are read from the kernel's existing ARP cache
  (``/proc/net/arp``). Only complete, valid entries are accepted. A missing or
  incomplete entry leaves ``mac`` as ``None`` -- nothing is inferred,
  manufactured, or actively probed.
* **Hostnames** come from a reverse-DNS (PTR) lookup, and only when explicitly
  enabled (``resolve_hostnames=True``, driven by ``RECON_RESOLVE_HOSTNAMES``).
  When disabled -- the default -- no name resolution of any kind is attempted
  and ``hostname`` stays ``None``.

Neither step raises for per-host failures, and neither writes to disk or logs
device information.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

from .discovery import DiscoveredHost

# Reverse-DNS pass limits (only used when hostname resolution is enabled).
HOSTNAME_MAX_WORKERS = 16
HOSTNAME_DEADLINE_S = 20.0

# ATF_COM: the ARP entry is complete / resolved.
_ARP_FLAG_COMPLETE = 0x2
_ZERO_MAC = "00:00:00:00:00:00"

# Overridable in tests; the real path is never read by the test suite.
_ARP_TABLE = "/proc/net/arp"

PtrLookup = Callable[[str], Optional[str]]
HostnameResolver = Callable[[str], Optional[str]]
ArpReader = Callable[[], Dict[str, str]]


def _is_unicast_mac(value: str) -> bool:
    """True only for a syntactically valid, individual (unicast) MAC address.

    Rejects malformed values, the all-zero address, and any group address -- the
    broadcast address ``ff:ff:ff:ff:ff:ff`` and all multicast addresses, which
    are identified by the least-significant bit of the first octet being set.
    Such addresses are never a single host's hardware address.
    """
    parts = value.split(":")
    if len(parts) != 6:
        return False
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return False
    if any(len(part) != 2 or not 0 <= octet <= 0xFF for part, octet in zip(parts, octets)):
        return False
    if octets[0] & 0x01:  # multicast / broadcast (group) bit
        return False
    return True


def read_arp_table(path: str = _ARP_TABLE) -> Dict[str, str]:
    """Return ``{ipv4: mac}`` for complete, valid entries in ``/proc/net/arp``.

    Incomplete entries, all-zero addresses, and malformed lines are skipped. A
    missing or unreadable file yields an empty mapping rather than an error.
    """
    try:
        with open(path, "r", encoding="ascii") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return {}

    table: Dict[str, str] = {}
    for line in lines[1:]:  # skip the header row
        fields = line.split()
        if len(fields) < 4:
            continue
        ip_address, _hw_type, flags_hex, mac = fields[0], fields[1], fields[2], fields[3]
        try:
            flags = int(flags_hex, 16)
        except ValueError:
            continue
        if not flags & _ARP_FLAG_COMPLETE:
            continue
        mac = mac.lower()
        if mac == _ZERO_MAC or not _is_unicast_mac(mac):
            continue
        table[ip_address] = mac
    return table


def _default_ptr_lookup(ip: str) -> Optional[str]:
    return socket.gethostbyaddr(ip)[0]


def resolve_hostname(ip: str, *, lookup: PtrLookup = _default_ptr_lookup) -> Optional[str]:
    """Reverse-resolve ``ip`` to a hostname, or ``None`` on any failure.

    ``lookup`` performs the actual PTR query and is injected in tests so no real
    DNS traffic occurs. Every resolver error (``socket.herror``,
    ``socket.gaierror``, ``TimeoutError`` and any other ``OSError``) is treated
    as "no name". A result equal to the input address, or empty, is also "no
    name".
    """
    try:
        name = lookup(ip)
    except OSError:
        return None
    if not name:
        return None
    name = name.strip().rstrip(".")
    if not name or name == ip:
        return None
    return name


def _safe_resolve(resolver: HostnameResolver, ip: str) -> Optional[str]:
    try:
        return resolver(ip)
    except Exception:
        return None


def enrich_hosts(
    hosts: List[DiscoveredHost],
    *,
    resolve_hostnames: bool = False,
    arp_reader: ArpReader = read_arp_table,
    hostname_resolver: HostnameResolver = resolve_hostname,
    max_workers: int = HOSTNAME_MAX_WORKERS,
    deadline_s: float = HOSTNAME_DEADLINE_S,
) -> List[DiscoveredHost]:
    """Populate ``mac`` (always) and ``hostname`` (only when enabled) in place.

    MAC addresses come from a single ARP-cache read via ``arp_reader``. Hostnames
    are resolved concurrently, and only when ``resolve_hostnames`` is true.

    ``max_workers`` bounds concurrency and ``deadline_s`` bounds how long this
    function *waits* for the hostname pass. Note: Python cannot forcibly cancel a
    blocking system resolver call that has already started in a worker thread.
    When the deadline is reached, hosts whose lookups have not returned keep
    ``hostname=None`` and the worker threads are left to finish on their own
    (not joined); only not-yet-started lookups are cancelled.

    Never raises for per-host failures or for an unreadable ARP table. Returns
    the same list object it was given, with order preserved.
    """
    if not hosts:
        return hosts

    try:
        arp_table = arp_reader()
    except Exception:
        arp_table = {}
    for host in hosts:
        mac = arp_table.get(host.ip)
        if mac:
            host.mac = mac

    if not resolve_hostnames:
        return hosts

    pool = ThreadPoolExecutor(max_workers=min(max_workers, len(hosts)))
    try:
        future_to_host = {
            pool.submit(_safe_resolve, hostname_resolver, host.ip): host
            for host in hosts
        }
        try:
            for future in as_completed(future_to_host, timeout=deadline_s):
                name = future.result()
                if name:
                    future_to_host[future].hostname = name
        except TimeoutError:
            # Overall deadline reached. Outstanding lookups are abandoned; any
            # already-running resolver threads cannot be cancelled and finish
            # in the background.
            pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return hosts
