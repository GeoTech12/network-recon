"""Conservative ICMP host discovery.

For each address in a validated target network, exactly one ICMP echo request is
sent by invoking the system ``ping`` executable with a fixed argument vector and
``shell=False``. A reply means the host is up; anything else means it is treated
as down. There are no retries, no port interaction, and no privilege escalation.
"""

import ipaddress
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Callable, List, Optional

from .errors import ReconError
from .localnet import ensure_allowed_network

# ``ping -W`` reply timeout, in seconds.
PING_REPLY_TIMEOUT_S = 1
# Hard ceiling on each ping subprocess, in seconds.
PING_PROCESS_TIMEOUT_S = 3
# Conservative worker pool size for the initial implementation.
MAX_WORKERS = 16
# Wall-clock ceiling for the whole sweep, in seconds.
OVERALL_DEADLINE_S = 90

Runner = Callable[[str], bool]


@dataclass
class DiscoveredHost:
    """A responsive host.

    ``hostname``, ``mac`` and ``open_ports`` are placeholders that later
    milestones will populate; Milestone 2 always leaves them empty.
    """

    ip: str
    status: str = "up"
    discovery_method: str = "icmp"
    hostname: Optional[str] = None  # Milestone 3
    mac: Optional[str] = None  # Milestone 3
    open_ports: list = field(default_factory=list)  # Milestone 4

    def to_dict(self) -> dict:
        return asdict(self)


def _run_ping(ip: str) -> bool:
    """Send exactly one ICMP echo request to ``ip`` via the system ping.

    Returns ``True`` only if the host replied. ``ip`` is assumed to have been
    validated by the caller; it is passed as a discrete argv element with
    ``shell=False`` so no shell interpretation occurs.
    """
    try:
        completed = subprocess.run(
            [
                "ping",
                "-n",  # no reverse DNS (hostname resolution is a later milestone)
                "-q",  # quiet
                "-c",
                "1",  # exactly one echo request, no retries
                "-W",
                str(PING_REPLY_TIMEOUT_S),
                ip,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PING_PROCESS_TIMEOUT_S,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return completed.returncode == 0


def _safe_probe(runner: Runner, ip: str) -> bool:
    try:
        return bool(runner(ip))
    except Exception:
        return False


def discover_hosts(
    network: ipaddress.IPv4Network,
    *,
    runner: Optional[Runner] = None,
    max_workers: int = MAX_WORKERS,
    deadline_s: int = OVERALL_DEADLINE_S,
) -> List[DiscoveredHost]:
    """Return the responsive hosts in ``network``, sorted by address.

    ``runner`` is injected by tests so no real ICMP traffic is generated. When
    it is not supplied, the real system ``ping`` is used and its availability is
    checked first.

    The network is re-validated here with :func:`ensure_allowed_network` before
    any address list is built or any probe is scheduled. This is defence in
    depth: callers are still expected to validate, but the packet-sending layer
    refuses an out-of-scope network on its own (raising
    :class:`~recon.errors.TargetNotAllowed`).
    """
    network = ensure_allowed_network(network)

    if runner is None:
        if shutil.which("ping") is None:
            raise ReconError(
                "Host discovery is unavailable: the system 'ping' command was "
                "not found on this machine."
            )
        runner = _run_ping

    hosts = [str(host) for host in network.hosts()]
    if not hosts:
        return []

    found: List[DiscoveredHost] = []
    pool = ThreadPoolExecutor(max_workers=min(max_workers, len(hosts)))
    future_to_ip = {pool.submit(_safe_probe, runner, ip): ip for ip in hosts}
    try:
        for future in as_completed(future_to_ip, timeout=deadline_s):
            if future.result():
                found.append(DiscoveredHost(ip=future_to_ip[future]))
    except TimeoutError:
        # Overall deadline reached; return whatever has been confirmed so far.
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    found.sort(key=lambda host: ipaddress.ip_address(host.ip))
    return found
