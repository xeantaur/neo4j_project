"""
Unit tests for security alert API endpoints.
"""

from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.dependencies import get_read_repository


@pytest.fixture
def client_and_mock_repo():
    """Create test client with mocked read repository."""
    app = create_app()
    mock_repo = MagicMock()
    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)
    return client, mock_repo


def test_list_alerts_filtered(client_and_mock_repo):
    """Verify GET /api/v1/alerts with filtering parameters."""
    client, mock_repo = client_and_mock_repo
    mock_repo.list_alert_facts.return_value = (
        [
            {
                "fact_key": "a" * 64,
                "source_ip": "192.168.1.10",
                "target_ip": "192.168.1.20",
                "sid": 2100498,
                "gid": 1,
                "rev": 7,
                "message": "GPL ATTACK_RESPONSE id check returned root",
                "priority": 1,
                "protocol": "TCP",
                "src_port": 80,
                "dst_port": 54321,
            }
        ],
        1,
    )

    response = client.get(
        "/api/v1/alerts?source_ip=192.168.1.10&target_ip=192.168.1.20&priority=1&sid=2100498&protocol=TCP&limit=25&offset=0"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["fact_key"] == "a" * 64
    assert data["items"][0]["message"] == "GPL ATTACK_RESPONSE id check returned root"
    mock_repo.list_alert_facts.assert_called_once_with(
        source_ip="192.168.1.10",
        target_ip="192.168.1.20",
        priority=1,
        sid=2100498,
        protocol="TCP",
        limit=25,
        offset=0,
    )


def test_list_alerts_validation_errors(client_and_mock_repo):
    """Verify validation errors for alert filtering parameters."""
    client, _ = client_and_mock_repo
    # invalid priority (< 1)
    r1 = client.get("/api/v1/alerts?priority=0")
    assert r1.status_code == 422

    # invalid sid (< 0)
    r2 = client.get("/api/v1/alerts?sid=-5")
    assert r2.status_code == 422


def test_get_alert_fact_by_key_success(client_and_mock_repo):
    """Verify GET /api/v1/alerts/{fact_key} returns single AlertFactResponse."""
    client, mock_repo = client_and_mock_repo
    valid_key = "56cdd351a57a389acbda4b9274f0918877ca8e3a8d4921a7f09cf17ae8d32fb2"
    mock_repo.get_alert_fact.return_value = {
        "fact_key": valid_key,
        "source_ip": "192.168.1.10",
        "target_ip": "192.168.1.20",
        "sid": 2100498,
        "gid": 1,
        "rev": 7,
        "message": "GPL ATTACK_RESPONSE id check returned root",
        "priority": 1,
        "protocol": "TCP",
        "src_port": 80,
        "dst_port": 54321,
    }

    response = client.get(f"/api/v1/alerts/{valid_key}")
    assert response.status_code == 200
    data = response.json()
    assert data["fact_key"] == valid_key
    assert data["source_ip"] == "192.168.1.10"
    assert data["priority"] == 1


def test_get_alert_fact_by_key_invalid_format(client_and_mock_repo):
    """Verify invalid fact_key format (not 64-char hex) returns 422."""
    client, _ = client_and_mock_repo
    # Short key
    r1 = client.get("/api/v1/alerts/12345")
    assert r1.status_code == 422

    # Non-hex characters
    r2 = client.get(f"/api/v1/alerts/{'g' * 64}")
    assert r2.status_code == 422


def test_get_alert_fact_by_key_not_found(client_and_mock_repo):
    """Verify unknown fact_key returns 404 Not Found."""
    client, mock_repo = client_and_mock_repo
    mock_repo.get_alert_fact.return_value = None
    missing_key = "0" * 64

    response = client.get(f"/api/v1/alerts/{missing_key}")
    assert response.status_code == 404
    assert f"Alert fact with key '{missing_key}' not found" in response.json()["detail"]


def test_alert_nullable_fields_serialization(client_and_mock_repo):
    """Verify alert facts with null optional fields serialize correctly."""
    client, mock_repo = client_and_mock_repo
    mock_repo.list_alert_facts.return_value = (
        [
            {
                "fact_key": "b" * 64,
                "source_ip": "10.0.0.1",
                "target_ip": "10.0.0.2",
                "sid": None,
                "gid": None,
                "rev": None,
                "message": None,
                "priority": None,
                "protocol": None,
                "src_port": None,
                "dst_port": None,
            }
        ],
        1,
    )

    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["sid"] is None
    assert item["priority"] is None
    assert item["message"] is None
