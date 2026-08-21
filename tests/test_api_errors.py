"""
Unit tests for API global exception handling, database unavailability, and CORS.
"""

from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from neo4j.exceptions import ServiceUnavailable

from src.api.app import create_app
from src.api.dependencies import get_read_repository


def test_database_unavailable_returns_503():
    """Verify database connection errors raise 503 Service Unavailable with sanitized message."""
    app = create_app()
    mock_repo = MagicMock()
    mock_repo.list_ips.side_effect = ConnectionError("Could not connect to bolt://sensitive_host:7687")

    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)

    response = client.get("/api/v1/network/ips")
    assert response.status_code == 503
    data = response.json()
    assert data["detail"] == "Database service unavailable"
    assert "sensitive_host" not in response.text


def test_neo4j_service_unavailable_returns_503():
    """Verify Neo4j ServiceUnavailable raises 503."""
    app = create_app()
    mock_repo = MagicMock()
    mock_repo.list_ips.side_effect = ServiceUnavailable("Defunct connection")

    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)

    response = client.get("/api/v1/network/ips")
    assert response.status_code == 503
    assert response.json()["detail"] == "Database service unavailable"


def test_unexpected_exception_returns_sanitized_500():
    """Verify unhandled exceptions return 500 without stack trace leaks."""
    app = create_app()
    mock_repo = MagicMock()
    mock_repo.list_ips.side_effect = RuntimeError("Sensitive internal database crash")

    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/api/v1/network/ips")
    assert response.status_code == 500
    assert response.json()["detail"] == "Internal server error"
    assert "Sensitive internal" not in response.text


def test_cors_disabled_by_default(monkeypatch):
    """Verify CORS middleware is not active when CORS_ORIGINS is unset."""
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    app = create_app()
    client = TestClient(app)

    response = client.options(
        "/health",
        headers={
            "Origin": "http://malicious-site.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in response.headers


def test_cors_enabled_when_configured(monkeypatch):
    """Verify CORS middleware allows only configured origins."""
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:3000,http://dashboard.local")
    app = create_app()
    client = TestClient(app)

    response = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
