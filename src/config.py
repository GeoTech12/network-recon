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


def _env_flag(name: str) -> bool:
    """Return True when the named environment variable holds a truthy value."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


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
