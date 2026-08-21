"""
Compatibility smoke test for Neo4j loader functions in src/main.py.

Verifies that load_layer2_data_to_neo4j, load_layer3_data_to_neo4j, and
load_alarm_data_to_neo4j accept TrafficRecord and AlertRecord dataclass instances,
execute the expected Cypher queries, and map all parameters without attribute errors.
Uses a mock Neo4j driver so no live server is required.
"""

from unittest.mock import MagicMock
from src.ingestion.models import TrafficRecord, AlertRecord
from src.main import (
    load_layer2_data_to_neo4j,
    load_layer3_data_to_neo4j,
    load_alarm_data_to_neo4j,
)


class MockDriver:
    """Mock Neo4j Driver and Session for query and parameter verification."""

    def __init__(self):
        self.session_mock = MagicMock()
        self.executed_calls = []

        # session.run records (query, parameters)
        def mock_run(query, parameters=None):
            self.executed_calls.append((query.strip(), parameters or {}))
            return MagicMock()

        self.session_mock.run.side_effect = mock_run

    def session(self):
        # Context manager support: with driver.session() as session:
        mock_ctx = MagicMock()
        mock_ctx.__enter__.return_value = self.session_mock
        mock_ctx.__exit__.return_value = None
        return mock_ctx


def test_load_layer2_data_compatibility():
    """Verify Layer 2 loader accepts TrafficRecord and maps parameters correctly."""
    mock_driver = MockDriver()
    record = TrafficRecord(
        eth_src_resolved="02:00:00:00:00:01",
        eth_dst_resolved="02:00:00:00:00:02",
        ip_src="192.168.1.10",
        ip_dst="192.168.1.20",
        protocol="TCP",
    )

    load_layer2_data_to_neo4j(mock_driver, [record])

    assert len(mock_driver.executed_calls) == 1
    query, params = mock_driver.executed_calls[0]

    assert "MERGE (src:MAC {address: $eth_src_resolved})" in query
    assert "MERGE (dst:MAC {address: $eth_dst_resolved})" in query
    assert "CREATE (src)-[:DESTINATION {protocol: $protocol}]->(dst)" in query

    assert params == {
        "eth_src_resolved": "02:00:00:00:00:01",
        "eth_dst_resolved": "02:00:00:00:00:02",
        "protocol": "TCP",
    }


def test_load_layer3_data_compatibility():
    """Verify Layer 3 loader accepts TrafficRecord and maps parameters correctly."""
    mock_driver = MockDriver()
    record = TrafficRecord(
        eth_src_resolved="02:00:00:00:00:01",
        eth_dst_resolved="gateway.local",
        ip_src="192.168.1.10",
        ip_dst="10.0.0.1",
        protocol="UDP",
    )

    load_layer3_data_to_neo4j(mock_driver, [record])

    assert len(mock_driver.executed_calls) == 1
    query, params = mock_driver.executed_calls[0]

    assert "MERGE (src_ip:IP {address: $ip_src})" in query
    assert "MERGE (dst_ip:IP {address: $ip_dst})" in query
    assert "MERGE (src_mac:MAC {address: $eth_src_resolved})" in query
    assert "MERGE (dst_mac:MAC {address: $eth_dst_resolved})" in query
    assert "CREATE (src_ip)-[:ASSOCIATED_WITH]->(src_mac)" in query
    assert "CREATE (dst_ip)-[:ASSOCIATED_WITH]->(dst_mac)" in query
    assert "CREATE (src_ip)-[:DESTINATION {protocol: $protocol}]->(dst_ip)" in query

    assert params == {
        "ip_src": "192.168.1.10",
        "ip_dst": "10.0.0.1",
        "eth_src_resolved": "02:00:00:00:00:01",
        "eth_dst_resolved": "gateway.local",
        "protocol": "UDP",
    }


def test_load_alarm_data_compatibility():
    """Verify Alert loader accepts AlertRecord and maps parameters correctly."""
    mock_driver = MockDriver()
    record = AlertRecord(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        sid=9000001,
        gid=1,
        rev=1,
        message="TEST-ALERT Synthetic Port Scan Simulation",
        priority=2,
        protocol="TCP",
        src_port=54321,
        dst_port=22,
    )

    load_alarm_data_to_neo4j(mock_driver, [record])

    assert len(mock_driver.executed_calls) == 1
    query, params = mock_driver.executed_calls[0]

    assert "MERGE (src_ip:IP {address: $src_ip})" in query
    assert "MERGE (dst_ip:IP {address: $dst_ip})" in query
    assert "CREATE (src_ip)-[:ALERT" in query

    assert params == {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "sid": 9000001,
        "gid": 1,
        "rev": 1,
        "message": "TEST-ALERT Synthetic Port Scan Simulation",
        "priority": 2,
        "protocol": "TCP",
        "src_port": 54321,
        "dst_port": 22,
    }
