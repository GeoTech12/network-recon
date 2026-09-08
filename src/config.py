"""Application configuration for Network Recon.

Configuration is intentionally minimal for Milestone 1. No secret key is defined
here because the application does not yet use sessions, flashing, or any other
feature that requires one. When such a requirement is introduced, the value
should be read from the environment rather than hard-coded.
"""

import os

# Application metadata - single source of truth shared by routes and templates.
APP_NAME = "Network Recon"
APP_DESCRIPTION = (
    "A browser-based tool for authorized reconnaissance of your own home or lab "
    "network. It discovers active devices and presents basic information in an "
    "easy-to-read interface."
)

# Development server binding. The application is not intended to be exposed on a
# public interface, so it binds to localhost only.
HOST = "127.0.0.1"
PORT = 5000

# Optional explicit target subnet in CIDR notation (e.g. "192.168.1.0/24"). When
# unset, the local network is auto-detected from the routing table. Whatever the
# source, the value is validated against the allowed private ranges and size
# limit before any packet is sent.
RECON_SUBNET = os.environ.get("RECON_SUBNET", "").strip() or None


def _env_flag(name: str) -> bool:
    """Return True when the named environment variable holds a truthy value."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


# Reverse-DNS hostname resolution is opt-in. When false (the default) a scan
# performs no name resolution of any kind and every host's hostname stays unset.
RECON_RESOLVE_HOSTNAMES = _env_flag("RECON_RESOLVE_HOSTNAMES")


class Config:
    """Base configuration."""

    # Debug is off unless explicitly opted in for local development via the
    # FLASK_DEBUG environment variable. It must never be enabled in a public
    # deployment.
    DEBUG = _env_flag("FLASK_DEBUG")
    TESTING = False


class TestConfig(Config):
    """Configuration used by the test suite."""

    DEBUG = False
    TESTING = True
