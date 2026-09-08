"""Shared pytest fixtures for the Network Recon test suite."""

import pytest

from app import create_app
from config import TestConfig


@pytest.fixture
def app():
    return create_app(TestConfig)


@pytest.fixture
def client(app):
    return app.test_client()
