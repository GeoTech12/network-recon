"""Route and configuration tests for the Milestone 1 web application skeleton."""


def test_index_ok(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Network Recon" in body
    assert "Authorization" in body


def test_healthz_ok(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_scan_requires_authorization_confirmation(client):
    response = client.post("/scan")
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "error"
    assert "authorized" in data["message"].lower()


def test_scan_placeholder_response(client):
    response = client.post("/scan", data={"authorized": "on"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "not_implemented"
    assert data["devices"] == []
    assert isinstance(data["scan_time"], str) and data["scan_time"]


def test_unknown_route_returns_branded_404(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    body = response.get_data(as_text=True)
    assert "Page not found" in body
    assert "Traceback" not in body


def test_debug_disabled_by_default(app):
    assert app.config["DEBUG"] is False
