"""
Unit tests for network and topology API endpoints.
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


def test_list_ips_endpoint(client_and_mock_repo):
    """Verify GET /api/v1/network/ips returns paginated response."""
    client, mock_repo = client_and_mock_repo
    mock_repo.list_ips.return_value = ([{"address": "192.168.1.10"}, {"address": "192.168.1.20"}], 2)

    response = client.get("/api/v1/network/ips?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert data["limit"] == 10
    assert data["offset"] == 0
    assert len(data["items"]) == 2
    assert data["items"][0]["address"] == "192.168.1.10"
    mock_repo.list_ips.assert_called_once_with(limit=10, offset=0)


def test_list_ips_validation_bounds(client_and_mock_repo):
    """Verify limit and offset validation bounds return 422."""
    client, _ = client_and_mock_repo
    # limit > 200
    r1 = client.get("/api/v1/network/ips?limit=250")
    assert r1.status_code == 422

    # limit < 1
    r2 = client.get("/api/v1/network/ips?limit=0")
    assert r2.status_code == 422

    # negative offset
    r3 = client.get("/api/v1/network/ips?offset=-1")
    assert r3.status_code == 422


def test_get_ip_detail_success(client_and_mock_repo):
    """Verify GET /api/v1/network/ips/{address} returns IPDetailResponse."""
    client, mock_repo = client_and_mock_repo
    mock_repo.get_ip_detail.return_value = {
        "address": "192.168.1.10",
        "layer2_identifiers": ["00:11:22:33:44:55"],
        "outbound_flows": 5,
        "inbound_flows": 2,
        "alerts_originated": 1,
        "alerts_targeted": 0,
    }

    response = client.get("/api/v1/network/ips/192.168.1.10")
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == "192.168.1.10"
    assert data["layer2_identifiers"] == ["00:11:22:33:44:55"]
    assert data["outbound_flows"] == 5
    assert data["inbound_flows"] == 2


def test_get_ip_detail_ipv6_canonicalization(client_and_mock_repo):
    """Verify equivalent IPv6 addresses canonicalize identically before repository call."""
    client, mock_repo = client_and_mock_repo
    mock_repo.get_ip_detail.return_value = {
        "address": "2001:db8::1",
        "layer2_identifiers": [],
        "outbound_flows": 0,
        "inbound_flows": 0,
        "alerts_originated": 0,
        "alerts_targeted": 0,
    }

    # Query with non-canonical expanded IPv6 form
    response = client.get("/api/v1/network/ips/2001:0db8:0000:0000:0000:0000:0000:0001")
    assert response.status_code == 200
    mock_repo.get_ip_detail.assert_called_once_with("2001:db8::1")


def test_get_ip_detail_invalid_ip_returns_422(client_and_mock_repo):
    """Verify invalid IP string format returns 422 Unprocessable Entity."""
    client, _ = client_and_mock_repo
    response = client.get("/api/v1/network/ips/999.999.999.999")
    assert response.status_code == 422
    assert "Invalid IP address format" in response.text


def test_get_ip_detail_not_found(client_and_mock_repo):
    """Verify unknown IP address returns 404 Not Found."""
    client, mock_repo = client_and_mock_repo
    mock_repo.get_ip_detail.return_value = None

    response = client.get("/api/v1/network/ips/10.0.0.99")
    assert response.status_code == 404
    assert "not found in graph" in response.json()["detail"]


def test_list_ip_peers_directions(client_and_mock_repo):
    """Verify peer querying with outbound, inbound, and all directions."""
    client, mock_repo = client_and_mock_repo
    mock_repo.list_ip_peers.return_value = (
        [
            {"peer_address": "192.168.1.20", "direction": "outbound", "protocols": ["TCP"]},
            {"peer_address": "192.168.1.20", "direction": "inbound", "protocols": ["UDP"]},
        ],
        2,
    )

    response = client.get("/api/v1/network/ips/192.168.1.10/peers?direction=all")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2
    assert data["items"][0]["direction"] == "outbound"
    assert data["items"][1]["direction"] == "inbound"
    mock_repo.list_ip_peers.assert_called_once_with("192.168.1.10", direction="all", limit=50, offset=0)


def test_list_ip_peers_invalid_direction(client_and_mock_repo):
    """Verify invalid direction parameter returns 422."""
    client, _ = client_and_mock_repo
    response = client.get("/api/v1/network/ips/192.168.1.10/peers?direction=sideways")
    assert response.status_code == 422


def test_list_ip_peers_not_found(client_and_mock_repo):
    """Verify peer lookup on unknown IP returns 404."""
    client, mock_repo = client_and_mock_repo
    mock_repo.list_ip_peers.return_value = None

    response = client.get("/api/v1/network/ips/10.0.0.99/peers")
    assert response.status_code == 404


def test_list_ip_layer2_associations(client_and_mock_repo):
    """Verify GET /api/v1/network/ips/{address}/layer2 returns paginated L2 identifiers."""
    client, mock_repo = client_and_mock_repo
    mock_repo.list_ip_layer2.return_value = ([{"identifier": "00:11:22:33:44:55"}], 1)

    response = client.get("/api/v1/network/ips/192.168.1.10/layer2?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["identifier"] == "00:11:22:33:44:55"


def test_list_layer2_identifiers(client_and_mock_repo):
    """Verify GET /api/v1/network/layer2 returns all observed Layer 2 identifiers."""
    client, mock_repo = client_and_mock_repo
    mock_repo.list_layer2_identifiers.return_value = (
        [{"identifier": "00:11:22:33:44:55"}, {"identifier": "gateway.local"}],
        2,
    )

    response = client.get("/api/v1/network/layer2")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2


def test_list_communications_filtering(client_and_mock_repo):
    """Verify GET /api/v1/network/communications with filters."""
    client, mock_repo = client_and_mock_repo
    mock_repo.list_communications.return_value = (
        [{"source_ip": "192.168.1.10", "target_ip": "192.168.1.20", "protocol": "TCP"}],
        1,
    )

    response = client.get(
        "/api/v1/network/communications?source_ip=192.168.1.10&target_ip=192.168.1.20&protocol=TCP"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["protocol"] == "TCP"
    mock_repo.list_communications.assert_called_once_with(
        source_ip="192.168.1.10",
        target_ip="192.168.1.20",
        protocol="TCP",
        limit=50,
        offset=0,
    )
