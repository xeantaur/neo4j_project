"""
Unit tests for cross-domain correlation API endpoints.
"""

from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.dependencies import get_read_repository


def test_list_traffic_alert_correlations_success():
    """Verify GET /api/v1/correlations/traffic-alerts returns flat paginated records."""
    app = create_app()
    mock_repo = MagicMock()
    mock_repo.list_traffic_alert_correlations.return_value = (
        [
            {
                "source_ip": "192.168.1.10",
                "target_ip": "192.168.1.20",
                "traffic_protocol": "TCP",
                "traffic_flow_key": "f" * 64,
                "traffic_src_port": 50000,
                "traffic_dst_port": 80,
                "fact_key": "c" * 64,
                "sid": 2100498,
                "message": "GPL ATTACK_RESPONSE id check returned root",
                "priority": 1,
                "alert_protocol": "TCP",
            }
        ],
        1,
    )

    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)

    response = client.get("/api/v1/correlations/traffic-alerts?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["source_ip"] == "192.168.1.10"
    assert data["items"][0]["target_ip"] == "192.168.1.20"
    assert data["items"][0]["traffic_protocol"] == "TCP"
    assert data["items"][0]["traffic_flow_key"] == "f" * 64
    assert data["items"][0]["traffic_src_port"] == 50000
    assert data["items"][0]["traffic_dst_port"] == 80
    assert data["items"][0]["fact_key"] == "c" * 64
    assert data["items"][0]["priority"] == 1


def test_correlation_route_not_captured_by_alerts_fact_key():
    """Verify /api/v1/correlations/traffic-alerts is not routed to /api/v1/alerts/{fact_key}."""
    app = create_app()
    mock_repo = MagicMock()
    mock_repo.list_traffic_alert_correlations.return_value = ([], 0)

    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)

    response = client.get("/api/v1/correlations/traffic-alerts")
    assert response.status_code == 200
    mock_repo.list_traffic_alert_correlations.assert_called_once()
    mock_repo.get_alert_fact.assert_not_called()
