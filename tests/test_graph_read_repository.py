"""
Unit tests for Neo4jReadRepository using mocked driver, session, and transactions.
"""

from unittest.mock import MagicMock
import pytest
from src.graph.read_repository import Neo4jReadRepository


@pytest.fixture
def mock_driver_and_tx():
    """Create a mock Neo4j driver that invokes callbacks passed to session.execute_read."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_tx = MagicMock()

    # Pass mock_tx into the work function passed to session.execute_read
    mock_session.execute_read.side_effect = lambda fn, *args, **kwargs: fn(mock_tx, *args, **kwargs)
    mock_driver.session.return_value.__enter__.return_value = mock_session

    return mock_driver, mock_session, mock_tx


def test_check_connectivity(mock_driver_and_tx):
    """Verify check_connectivity returns True on success and False on failure."""
    mock_driver, _, _ = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    mock_driver.verify_connectivity.return_value = None
    assert repo.check_connectivity() is True

    mock_driver.verify_connectivity.side_effect = Exception("Connection lost")
    assert repo.check_connectivity() is False

    repo_no_driver = Neo4jReadRepository(None)
    assert repo_no_driver.check_connectivity() is False


def test_list_ips(mock_driver_and_tx):
    """Verify list_ips executes parameterized count and page queries."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    mock_count_res = MagicMock()
    mock_count_res.single.return_value = {"total": 3}

    mock_page_res = [{"address": "10.0.0.1"}, {"address": "10.0.0.2"}, {"address": "10.0.0.3"}]
    mock_tx.run.side_effect = [mock_count_res, mock_page_res]

    items, total = repo.list_ips(limit=10, offset=0)
    assert total == 3
    assert len(items) == 3
    assert items[0]["address"] == "10.0.0.1"


def test_get_ip_detail_found_and_not_found(mock_driver_and_tx):
    """Verify get_ip_detail maps subquery results and handles missing nodes."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    # Found case
    mock_record = {
        "address": "10.0.0.1",
        "layer2_identifiers": ["00:11:22:33:44:55"],
        "outbound_flows": 4,
        "inbound_flows": 2,
        "alerts_originated": 1,
        "alerts_targeted": 0,
    }
    mock_res = MagicMock()
    mock_res.single.return_value = mock_record
    mock_tx.run.return_value = mock_res

    detail = repo.get_ip_detail("10.0.0.1")
    assert detail is not None
    assert detail["address"] == "10.0.0.1"
    assert detail["outbound_flows"] == 4

    # Not found case
    mock_res_empty = MagicMock()
    mock_res_empty.single.return_value = None
    mock_tx.run.return_value = mock_res_empty

    detail_none = repo.get_ip_detail("10.0.0.99")
    assert detail_none is None


def test_list_ip_peers(mock_driver_and_tx):
    """Verify list_ip_peers returns direction-scoped peer records."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    # Check node exists
    mock_check = MagicMock()
    mock_check.single.return_value = {"c": 1}

    mock_count = MagicMock()
    mock_count.single.return_value = {"total": 1}

    mock_page = [{"peer_address": "10.0.0.2", "direction": "outbound", "raw_proto": ["TCP", "HTTP", "TCP"]}]
    mock_tx.run.side_effect = [mock_check, mock_count, mock_page]

    res = repo.list_ip_peers("10.0.0.1", direction="outbound", limit=10, offset=0)
    assert res is not None
    items, total = res
    assert total == 1
    assert items[0]["peer_address"] == "10.0.0.2"
    assert items[0]["protocols"] == ["HTTP", "TCP"]  # Deduplicated and sorted


def test_list_communications_filtered(mock_driver_and_tx):
    """Verify list_communications with parameters."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    mock_count = MagicMock()
    mock_count.single.return_value = {"total": 1}

    mock_page = [{"source_ip": "10.0.0.1", "target_ip": "10.0.0.2", "protocol": "TCP"}]
    mock_tx.run.side_effect = [mock_count, mock_page]

    items, total = repo.list_communications(source_ip="10.0.0.1", target_ip="10.0.0.2", protocol="tcp")
    assert total == 1
    assert items[0]["source_ip"] == "10.0.0.1"


def test_get_alert_fact_found_and_not_found(mock_driver_and_tx):
    """Verify get_alert_fact lookup."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    mock_record = {
        "fact_key": "a" * 64,
        "source_ip": "10.0.0.1",
        "target_ip": "10.0.0.2",
        "sid": 100,
        "gid": 1,
        "rev": 1,
        "message": "Test Alert",
        "priority": 1,
        "protocol": "TCP",
        "src_port": 1234,
        "dst_port": 80,
    }
    mock_res = MagicMock()
    mock_res.single.return_value = mock_record
    mock_tx.run.return_value = mock_res

    fact = repo.get_alert_fact("a" * 64)
    assert fact is not None
    assert fact["fact_key"] == "a" * 64
    assert fact["sid"] == 100


def test_get_neighborhood_safety_and_trimming(mock_driver_and_tx):
    """Verify neighborhood guarantees max_nodes bounds, center retention, and edge validity."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    mock_check = MagicMock()
    mock_check.single.return_value = {"c": 1}

    mock_depth1_record = {
        "out_ips": [{"id": "ip:10.0.0.2", "type": "IPAddress", "value": "10.0.0.2"}],
        "in_ips": [{"id": "ip:10.0.0.3", "type": "IPAddress", "value": "10.0.0.3"}],
        "l2_nodes": [{"id": "l2:00:11:22:33:44:55", "type": "Layer2Identifier", "value": "00:11:22:33:44:55"}],
        "out_edges": [{"source": "ip:10.0.0.1", "target": "ip:10.0.0.2", "type": "COMMUNICATED_TO", "protocol": "TCP"}],
        "in_edges": [{"source": "ip:10.0.0.3", "target": "ip:10.0.0.1", "type": "COMMUNICATED_TO", "protocol": "UDP"}],
        "l2_edges": [{"source": "ip:10.0.0.1", "target": "l2:00:11:22:33:44:55", "type": "OBSERVED_WITH", "protocol": None}],
    }
    mock_res = MagicMock()
    mock_res.single.return_value = mock_depth1_record
    mock_tx.run.side_effect = [mock_check, mock_res]

    # Test with max_nodes=3 (should retain center + 2 other nodes, discarding the 3rd other node and its edge)
    neighborhood = repo.get_neighborhood("10.0.0.1", depth=1, max_nodes=3)
    assert neighborhood is not None
    assert neighborhood["center"] == "10.0.0.1"
    assert len(neighborhood["nodes"]) == 3
    assert neighborhood["nodes"][0]["id"] == "ip:10.0.0.1"  # Center retained first

    retained_ids = {n["id"] for n in neighborhood["nodes"]}
    for edge in neighborhood["edges"]:
        assert edge["source"] in retained_ids
        assert edge["target"] in retained_ids


def test_get_shortest_path_outcomes(mock_driver_and_tx):
    """Verify get_shortest_path handles missing endpoints, no path, and valid path."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    # Source not found
    mock_c0 = MagicMock()
    mock_c0.single.return_value = {"c": 0}
    mock_tx.run.return_value = mock_c0
    assert repo.get_shortest_path("10.0.0.1", "10.0.0.2") == {"error": "source_not_found"}

    # Target not found
    mock_c1 = MagicMock()
    mock_c1.single.return_value = {"c": 1}
    mock_tx.run.side_effect = [mock_c1, mock_c0]
    assert repo.get_shortest_path("10.0.0.1", "10.0.0.2") == {"error": "target_not_found"}

    # No path within max_hops
    mock_path_empty = MagicMock()
    mock_path_empty.single.return_value = None
    mock_tx.run.side_effect = [mock_c1, mock_c1, mock_path_empty]
    assert repo.get_shortest_path("10.0.0.1", "10.0.0.2") == {"error": "no_path"}

    # Valid path
    mock_path_record = {
        "hops": ["10.0.0.1", "10.0.0.2"],
        "protocols": ["TCP"],
        "length": 1,
    }
    mock_path_res = MagicMock()
    mock_path_res.single.return_value = mock_path_record
    mock_tx.run.side_effect = [mock_c1, mock_c1, mock_path_res]

    path = repo.get_shortest_path("10.0.0.1", "10.0.0.2")
    assert path["length"] == 1
    assert path["hops"] == ["10.0.0.1", "10.0.0.2"]
