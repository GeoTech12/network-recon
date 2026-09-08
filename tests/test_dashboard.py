"""Rendering and response-header tests for the dashboard page (GET /).

Assertions are on static markup and headers only -- no scan is run, no network
activity occurs, and no real reconnaissance data is used.
"""

import re

import config


def _html(client):
    response = client.get("/")
    assert response.status_code == 200
    return response.get_data(as_text=True)


def test_content_security_policy_header_present(client):
    response = client.get("/")
    csp = response.headers.get("Content-Security-Policy")
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "base-uri 'none'" in csp
    assert "form-action 'self'" in csp
    assert "object-src 'none'" in csp


def test_authorization_notice_is_prominent_and_marked_as_note(client):
    html = _html(client)
    assert 'role="note"' in html
    assert "Authorization &amp; Ethical Use" in html
    assert "explicit written permission" in html


def test_confirm_checkbox_present_and_button_starts_disabled(client):
    html = _html(client)
    assert 'id="authorized"' in html
    assert 'type="checkbox"' in html
    match = re.search(r"<button[^>]*id=\"scan-button\"[^>]*>", html)
    assert match is not None
    assert "disabled" in match.group(0)


def test_skip_link_and_main_landmark_present(client):
    html = _html(client)
    assert 'class="skip-link"' in html
    assert 'href="#main-content"' in html
    assert 'id="main-content"' in html


def test_scan_state_region_starts_ready(client):
    html = _html(client)
    assert 'id="scan-status"' in html
    assert 'aria-live="polite"' in html
    assert "Ready" in html


def test_results_table_has_caption_and_scoped_headers(client):
    html = _html(client)
    assert "<caption" in html
    assert 'scope="col"' in html


def test_per_row_scan_time_column_removed(client):
    html = _html(client)
    assert "Scan Time" not in html
    assert "Scanned at" in html  # shown once in the summary instead


def test_feature_badges_default_to_off(client):
    html = _html(client)
    assert "Hostname resolution: Off" in html
    assert "Port checks: Off" in html


def test_feature_badges_reflect_enabled_config(client, monkeypatch):
    monkeypatch.setattr(config, "RECON_RESOLVE_HOSTNAMES", True)
    monkeypatch.setattr(config, "RECON_CHECK_PORTS", True)
    html = _html(client)
    assert "Hostname resolution: On" in html
    assert "Port checks: On" in html


def test_feature_notes_describe_privacy_cost(client):
    html = _html(client)
    assert "DNS resolver" in html
    assert "TCP connection to each discovered host" in html
