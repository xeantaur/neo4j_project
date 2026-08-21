"""
Unit tests for API health and readiness endpoints.
"""

from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from src.api.app import create_app
from src.api.dependencies import get_read_repository


def test_health_endpoint_liveness():
    """Verify /health returns 200 OK without database connection."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "Network Traffic Analysis"


def test_ready_endpoint_connected():
    """Verify /ready returns 200 when database connectivity is verified."""
    app = create_app()
    mock_repo = MagicMock()
    mock_repo.check_connectivity.return_value = True

    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)

    response = client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"


def test_ready_endpoint_disconnected():
    """Verify /ready returns 503 when database connectivity fails."""
    app = create_app()
    mock_repo = MagicMock()
    mock_repo.check_connectivity.return_value = False

    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)

    response = client.get("/ready")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "unready"
    assert "Database service unavailable" in data["detail"]
