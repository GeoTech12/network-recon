"""Opt-in TCP port checks for discovered hosts.

Disabled by default. When enabled (``RECON_CHECK_PORTS``) each responsive,
in-scope host is checked against a small, fixed list of common TCP ports with a
plain connect attempt:

* one connection attempt per host/port, 1-second timeout, no retries;
* on success the socket is closed immediately -- nothing is sent, nothing is
  read (no banner grabbing, no application data, no authentication);
* bounded concurrency (16 workers) and a 60-second overall deadline.

Only open ports are recorded, as ``{"port": int, "service": str}`` dicts in the
host's ``open_ports``. Closed, filtered, timed-out, errored, or past-deadline
ports are simply omitted and never fail the scan. Nothing is written to disk or
logged.

Defence in depth: ``check_ports`` re-validates the scan network with
``ensure_allowed_network`` and only probes hosts whose address is contained in
that exact network.
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Sequence, Tuple

from .discovery import DiscoveredHost
from .localnet import ensure_allowed_network

# The documented port list. Each entry is (tcp_port, short_service_label):
#   21   FTP    - legacy cleartext file transfer (NAS, routers, printers)
#   22   SSH    - remote administration (servers, Pis, NAS, managed switches)
#   53   DNS    - TCP DNS exposed by local resolvers (routers, Pi-hole/dnsmasq)
#   80   HTTP   - device and server web interfaces
#   443  HTTPS  - TLS device and server web interfaces
#   445  SMB    - Windows / Samba file sharing
#   3389 RDP    - Windows Remote Desktop
COMMON_TCP_PORTS: Tuple[Tuple[int, str], ...] = (
    (21, "ftp"),
    (22, "ssh"),
    (53, "dns"),
    (80, "http"),
    (443, "https"),
    (445, "smb"),
    (3389, "rdp"),
)

PORT_CONNECT_TIMEOUT_S = 1.0
PORT_SCAN_MAX_WORKERS = 16
PORT_SCAN_DEADLINE_S = 60.0

Connector = Callable[[str, int], bool]


def _tcp_connect(ip: str, port: int) -> bool:
    """Return ``True`` if a TCP connection to ``ip:port`` completes.

    Full unprivileged connect. On success the socket is closed immediately with
    no data read or written. Any ``OSError`` -- connection refused, timeout, host
    unreachable -- means "not open".
    """
    try:
        conn = socket.create_connection((ip, port), timeout=PORT_CONNECT_TIMEOUT_S)
    except OSError:
        return False
    conn.close()
    return True


def _safe_connect(connector: Connector, ip: str, port: int) -> bool:
    try:
        return bool(connector(ip, port))
    except Exception:
        return False


def _ip_in_network(ip: str, network: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def check_ports(
    hosts: List[DiscoveredHost],
    network: ipaddress.IPv4Network,
    *,
    enabled: bool = False,
    ports: Sequence[Tuple[int, str]] = COMMON_TCP_PORTS,
    connector: Connector = _tcp_connect,
    max_workers: int = PORT_SCAN_MAX_WORKERS,
    deadline_s: float = PORT_SCAN_DEADLINE_S,
) -> List[DiscoveredHost]:
    """Populate ``open_ports`` for in-scope, responsive hosts, in place.

    Opens no sockets at all unless ``enabled`` is true. ``network`` is
    re-validated with ``ensure_allowed_network``; only hosts whose IP is
    contained in that exact network and whose status is ``"up"`` are probed.

    Never raises for per-probe failures or the deadline. Returns the same list
    object it was given, order preserved.
    """
    if not enabled:
        return hosts

    network = ensure_allowed_network(network)

    targets = [
        host
        for host in hosts
        if host.status == "up" and _ip_in_network(host.ip, network)
    ]
    pairs = [
        (host, port, service)
        for host in targets
        for (port, service) in ports
    ]
    if not pairs:
        return hosts

    open_by_ip: Dict[str, List[dict]] = {}
    pool = ThreadPoolExecutor(max_workers=min(max_workers, len(pairs)))
    try:
        future_map = {
            pool.submit(_safe_connect, connector, host.ip, port): (host, port, service)
            for (host, port, service) in pairs
        }
        try:
            for future in as_completed(future_map, timeout=deadline_s):
                host, port, service = future_map[future]
                if future.result():
                    open_by_ip.setdefault(host.ip, []).append(
                        {"port": port, "service": service}
                    )
        except TimeoutError:
            # Overall deadline reached. Unfinished probes are abandoned; any
            # in-flight connection cannot be cancelled and finishes in the
            # background.
            pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    for host in targets:
        found = open_by_ip.get(host.ip)
        if found:
            host.open_ports = sorted(found, key=lambda entry: entry["port"])

    return hosts
