"""
Unit tests for graph traversal and reachability API endpoints.
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


def test_get_graph_neighborhood_depth_1(client_and_mock_repo):
    """Verify GET /api/v1/graph/neighborhood/{address} at depth 1."""
    client, mock_repo = client_and_mock_repo
    mock_repo.get_neighborhood.return_value = {
        "center": "192.168.1.10",
        "depth": 1,
        "nodes": [
            {"id": "ip:192.168.1.10", "type": "IPAddress", "value": "192.168.1.10"},
            {"id": "ip:192.168.1.20", "type": "IPAddress", "value": "192.168.1.20"},
            {"id": "l2:00:11:22:33:44:55", "type": "Layer2Identifier", "value": "00:11:22:33:44:55"},
        ],
        "edges": [
            {"source": "ip:192.168.1.10", "target": "ip:192.168.1.20", "type": "COMMUNICATED_TO", "protocol": "TCP"},
            {"source": "ip:192.168.1.10", "target": "l2:00:11:22:33:44:55", "type": "OBSERVED_WITH", "protocol": None},
        ],
    }

    response = client.get("/api/v1/graph/neighborhood/192.168.1.10?depth=1&max_nodes=50")
    assert response.status_code == 200
    data = response.json()
    assert data["center"] == "192.168.1.10"
    assert data["depth"] == 1
    assert len(data["nodes"]) == 3
    assert len(data["edges"]) == 2
    mock_repo.get_neighborhood.assert_called_once_with("192.168.1.10", depth=1, max_nodes=50)


def test_get_graph_neighborhood_depth_validation(client_and_mock_repo):
    """Verify invalid depth (< 1 or > 2) returns 422."""
    client, _ = client_and_mock_repo
    # depth = 0
    r1 = client.get("/api/v1/graph/neighborhood/192.168.1.10?depth=0")
    assert r1.status_code == 422

    # depth = 3
    r2 = client.get("/api/v1/graph/neighborhood/192.168.1.10?depth=3")
    assert r2.status_code == 422


def test_get_graph_neighborhood_max_nodes_validation(client_and_mock_repo):
    """Verify max_nodes bounds (< 1 or > 100) return 422."""
    client, _ = client_and_mock_repo
    # max_nodes > 100
    r1 = client.get("/api/v1/graph/neighborhood/192.168.1.10?max_nodes=150")
    assert r1.status_code == 422

    # max_nodes < 1
    r2 = client.get("/api/v1/graph/neighborhood/192.168.1.10?max_nodes=0")
    assert r2.status_code == 422


def test_get_graph_neighborhood_not_found(client_and_mock_repo):
    """Verify neighborhood on unknown IP returns 404."""
    client, mock_repo = client_and_mock_repo
    mock_repo.get_neighborhood.return_value = None

    response = client.get("/api/v1/graph/neighborhood/10.0.0.99")
    assert response.status_code == 404
    assert "not found in graph" in response.json()["detail"]


def test_get_shortest_path_success(client_and_mock_repo):
    """Verify GET /api/v1/graph/path returns shortest path details."""
    client, mock_repo = client_and_mock_repo
    mock_repo.get_shortest_path.return_value = {
        "source": "192.168.1.10",
        "target": "192.168.1.30",
        "hops": ["192.168.1.10", "192.168.1.20", "192.168.1.30"],
        "protocols": ["TCP", "UDP"],
        "length": 2,
    }

    response = client.get("/api/v1/graph/path?source=192.168.1.10&target=192.168.1.30&max_hops=5")
    assert response.status_code == 200
    data = response.json()
    assert data["source"] == "192.168.1.10"
    assert data["target"] == "192.168.1.30"
    assert data["length"] == 2
    assert data["hops"] == ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    mock_repo.get_shortest_path.assert_called_once_with("192.168.1.10", "192.168.1.30", max_hops=5)


def test_get_shortest_path_errors(client_and_mock_repo):
    """Verify 404 error cases for shortest path."""
    client, mock_repo = client_and_mock_repo

    # Source not found
    mock_repo.get_shortest_path.return_value = {"error": "source_not_found"}
    r1 = client.get("/api/v1/graph/path?source=10.0.0.1&target=10.0.0.2")
    assert r1.status_code == 404
    assert "Source IP '10.0.0.1' not found" in r1.json()["detail"]

    # Target not found
    mock_repo.get_shortest_path.return_value = {"error": "target_not_found"}
    r2 = client.get("/api/v1/graph/path?source=10.0.0.1&target=10.0.0.2")
    assert r2.status_code == 404
    assert "Target IP '10.0.0.2' not found" in r2.json()["detail"]

    # No path found within hops
    mock_repo.get_shortest_path.return_value = {"error": "no_path"}
    r3 = client.get("/api/v1/graph/path?source=10.0.0.1&target=10.0.0.2&max_hops=3")
    assert r3.status_code == 404
    assert "No communication path found" in r3.json()["detail"]


def test_get_shortest_path_max_hops_validation(client_and_mock_repo):
    """Verify max_hops parameter validation bounds (1..10)."""
    client, _ = client_and_mock_repo
    # max_hops > 10
    r1 = client.get("/api/v1/graph/path?source=10.0.0.1&target=10.0.0.2&max_hops=15")
    assert r1.status_code == 422

    # max_hops < 1
    r2 = client.get("/api/v1/graph/path?source=10.0.0.1&target=10.0.0.2&max_hops=0")
    assert r2.status_code == 422
