"""Shared pytest fixtures for the Network Recon test suite."""

import socket
import subprocess

import pytest

from app import create_app
from config import TestConfig


@pytest.fixture(autouse=True)
def _block_real_network(monkeypatch):
    """Fail loudly if any test attempts real network reconnaissance.

    Every low-level reconnaissance primitive is stubbed here. Tests that need
    discovery, enrichment or port-check behaviour inject their own fakes, so
    nothing in the suite should ever reach these.
    """

    def _forbidden(name):
        def guard(*_args, **_kwargs):
            raise AssertionError(
                f"{name} was called during a test; real network activity is "
                "not allowed. Inject a fake instead."
            )

        return guard

    monkeypatch.setattr(subprocess, "run", _forbidden("subprocess.run"))
    monkeypatch.setattr(
        socket, "create_connection", _forbidden("socket.create_connection")
    )
    monkeypatch.setattr(socket, "gethostbyaddr", _forbidden("socket.gethostbyaddr"))
    monkeypatch.setattr(
        socket.socket, "connect", _forbidden("socket.socket.connect")
    )


@pytest.fixture
def app():
    return create_app(TestConfig)


@pytest.fixture
def client(app):
    return app.test_client()
