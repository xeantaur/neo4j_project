"""
Unit tests for Neo4jRepository atomic workspace replacement and scoped cleanup.
"""

from unittest.mock import MagicMock
import pytest

from src.graph.repository import (
    Neo4jRepository,
    CYPHER_SCOPED_CLEANUP,
    CYPHER_WRITE_TRAFFIC_BATCH,
    CYPHER_WRITE_ALERT_BATCH,
)
from src.ingestion.models import TrafficRecord, AlertRecord


@pytest.fixture
def mock_driver():
    """Mock Neo4j Driver and Session."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__.return_value = session

    # Make session.execute_write execute the callable work function immediately with mock tx
    def fake_execute_write(work_fn, *args, **kwargs):
        tx = MagicMock()
        return work_fn(tx, *args, **kwargs)

    session.execute_write.side_effect = fake_execute_write
    return driver, session


def test_replace_workspace_data_traffic_only(mock_driver):
    """replace_workspace_data executes scoped cleanup and traffic batches in single transaction."""
    driver, session = mock_driver
    repo = Neo4jRepository(driver, batch_size=100)

    traffic_records = [
        TrafficRecord("00:11:22:33:44:55", "66:77:88:99:aa:bb", "192.168.1.1", "192.168.1.2", "TCP"),
        TrafficRecord("00:11:22:33:44:55", "66:77:88:99:aa:cc", "192.168.1.1", "192.168.1.3", "DNS"),
    ]

    p_traffic, p_alerts = repo.replace_workspace_data(traffic_records=traffic_records, alert_records=None)
    assert p_traffic == 2
    assert p_alerts == 0

    session.execute_write.assert_called_once()


def test_replace_workspace_data_alerts_only(mock_driver):
    """replace_workspace_data executes scoped cleanup and alert batches in single transaction."""
    driver, session = mock_driver
    repo = Neo4jRepository(driver, batch_size=100)

    alert_records = [
        AlertRecord("192.168.1.1", "192.168.1.2", sid=1001, message="Suspicious Traffic", priority=1),
    ]

    p_traffic, p_alerts = repo.replace_workspace_data(traffic_records=None, alert_records=alert_records)
    assert p_traffic == 0
    assert p_alerts == 1

    session.execute_write.assert_called_once()


def test_replace_workspace_data_combined(mock_driver):
    """replace_workspace_data executes scoped cleanup, traffic, and alerts in single transaction."""
    driver, session = mock_driver
    repo = Neo4jRepository(driver, batch_size=100)

    traffic_records = [
        TrafficRecord("00:11:22:33:44:55", "66:77:88:99:aa:bb", "192.168.1.1", "192.168.1.2", "TCP"),
    ]
    alert_records = [
        AlertRecord("192.168.1.1", "192.168.1.2", sid=1001, message="Alert 1", priority=1),
    ]

    p_traffic, p_alerts = repo.replace_workspace_data(traffic_records=traffic_records, alert_records=alert_records)
    assert p_traffic == 1
    assert p_alerts == 1


def test_cli_methods_remain_backward_compatible(mock_driver):
    """Existing CLI write methods remain functioning and invoke individual execute_write."""
    driver, session = mock_driver
    repo = Neo4jRepository(driver, batch_size=100)

    traffic_records = [
        TrafficRecord("00:11:22:33:44:55", "66:77:88:99:aa:bb", "192.168.1.1", "192.168.1.2", "TCP"),
    ]
    p_count = repo.write_traffic_records(traffic_records)
    assert p_count == 1
    session.execute_write.assert_called_once()
