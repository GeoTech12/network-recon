"""Local subnet detection and target-network validation.

Discovery is only ever performed against:

* the machine's own connected private subnet, detected from the kernel routing
  table, or
* an explicit ``RECON_SUBNET`` override,

and only after the network passes :func:`ensure_allowed_network`. There is no
automatic fallback guess: if the local network cannot be determined reliably,
:class:`NetworkDetectionError` is raised.
"""

import ipaddress
import socket
import struct

from .errors import NetworkDetectionError, TargetNotAllowed

# Allowed target networks must be wholly contained within one of these RFC1918
# private-use blocks. We check containment explicitly rather than relying on
# ``ipaddress.IPv4Network.is_private``, which also treats link-local, CGNAT,
# documentation and other ranges as "private".
RFC1918_BLOCKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# Scans are kept small: at most a /24 (256 total addresses).
SUBNET_MAX_ADDRESSES = 256

# Overridable in tests.
_ROUTE_TABLE = "/proc/net/route"


def _le_hex_to_ip(value: str) -> str:
    """Convert a little-endian hex word from /proc/net/route to dotted-quad."""
    return socket.inet_ntoa(struct.pack("<L", int(value, 16)))


def _iter_connected_networks():
    """Yield ``(iface, IPv4Network)`` for each directly connected IPv4 route.

    Reads ``/proc/net/route`` (world-readable on Linux). Default routes and
    gateway routes are skipped; only on-link networks are returned.
    """
    with open(_ROUTE_TABLE, "r", encoding="ascii") as handle:
        lines = handle.read().splitlines()

    for line in lines[1:]:  # skip header row
        fields = line.split()
        if len(fields) < 8:
            continue
        iface, dest_hex, _gateway_hex, flags_hex = fields[:4]
        mask_hex = fields[7]
        try:
            flags = int(flags_hex, 16)
            dest = _le_hex_to_ip(dest_hex)
            mask = _le_hex_to_ip(mask_hex)
        except (ValueError, struct.error):
            continue

        if not flags & 0x1:  # RTF_UP not set
            continue
        if flags & 0x2:  # RTF_GATEWAY -> not directly connected
            continue
        if mask == "0.0.0.0":  # default / unspecified
            continue

        try:
            network = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            yield iface, network


def primary_ipv4():
    """Return the machine's primary outbound IPv4 address, or ``None``.

    Uses a UDP socket 'connected' to a private, non-broadcast address. A UDP
    ``connect`` only records a default destination in the kernel; no packet is
    transmitted.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.254.254.254", 1))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def detect_local_network() -> ipaddress.IPv4Network:
    """Detect the machine's connected private subnet.

    Raises :class:`NetworkDetectionError` if it cannot be determined
    unambiguously.
    """
    try:
        candidates = [
            (iface, network)
            for iface, network in _iter_connected_networks()
            if not network.is_loopback
        ]
    except OSError as exc:
        raise NetworkDetectionError(
            "Could not read the system routing table to determine your local "
            "network. Set RECON_SUBNET to specify the target subnet explicitly."
        ) from exc

    if not candidates:
        raise NetworkDetectionError(
            "Could not determine your local network from the system routing "
            "table. Set RECON_SUBNET to specify the target subnet explicitly."
        )

    primary = primary_ipv4()
    if primary is not None:
        try:
            primary_addr = ipaddress.ip_address(primary)
        except ValueError:
            primary_addr = None
        if primary_addr is not None:
            for _iface, network in candidates:
                if primary_addr in network:
                    return network

    if len(candidates) == 1:
        return candidates[0][1]

    raise NetworkDetectionError(
        "Multiple local networks were found and none could be selected "
        "automatically. Set RECON_SUBNET to choose one explicitly."
    )


def _subnet_of(network: ipaddress.IPv4Network, block: ipaddress.IPv4Network) -> bool:
    try:
        return network.subnet_of(block)
    except TypeError:
        return False


def ensure_allowed_network(value) -> ipaddress.IPv4Network:
    """Validate and normalise a target network.

    ``value`` may be a string (CIDR) or an ``IPv4Network``. Returns an
    ``IPv4Network``. Raises :class:`TargetNotAllowed` unless the network is a
    valid IPv4 subnet wholly inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16
    and contains no more than :data:`SUBNET_MAX_ADDRESSES` addresses.
    """
    if isinstance(value, ipaddress.IPv4Network):
        network = value
    else:
        try:
            network = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError as exc:
            raise TargetNotAllowed(
                f"{value!r} is not a valid IPv4 network in CIDR notation."
            ) from exc

    if not isinstance(network, ipaddress.IPv4Network):
        raise TargetNotAllowed("Only IPv4 networks are supported.")

    if not any(_subnet_of(network, block) for block in RFC1918_BLOCKS):
        raise TargetNotAllowed(
            f"{network} is not within the allowed private address ranges "
            "(10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16)."
        )

    if network.num_addresses > SUBNET_MAX_ADDRESSES:
        raise TargetNotAllowed(
            f"{network} contains {network.num_addresses} addresses; this tool "
            f"scans a /24 or smaller (at most {SUBNET_MAX_ADDRESSES} addresses). "
            "Set RECON_SUBNET to a smaller subnet."
        )

    return network
