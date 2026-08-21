"""
Unit tests for main application orchestrator (src/main.py).

Verifies that main() coordinates ingestion, schema initialization, and repository
persistence while properly managing the Neo4j driver lifecycle.
"""

from unittest.mock import patch, MagicMock
from src.main import main
from src.ingestion.models import TrafficRecord, AlertRecord, IngestionSummary


@patch("src.main.GraphDatabase.driver")
@patch("src.main.ensure_schema")
@patch("src.main.Neo4jRepository")
@patch("src.main.parse_traffic_file")
@patch("src.main.parse_alert_file")
def test_main_orchestration_flow(
    mock_parse_alerts,
    mock_parse_traffic,
    mock_repo_cls,
    mock_ensure_schema,
    mock_driver_factory,
):
    """Verify main orchestrator connects, ensures schema, writes records, and closes driver."""
    # Mock parser returns
    traffic_summary = IngestionSummary(total_raw_records=1, valid_records=1, skipped_records=0)
    alert_summary = IngestionSummary(total_raw_records=1, valid_records=1, skipped_records=0)
    mock_parse_traffic.return_value = (
        [TrafficRecord("02:00:00:00:00:01", "02:00:00:00:00:02", "192.168.1.10", "192.168.1.20", "TCP")],
        traffic_summary,
    )
    mock_parse_alerts.return_value = (
        [AlertRecord("192.168.1.10", "192.168.1.20", sid=9000001, priority=1)],
        alert_summary,
    )

    # Mock driver
    mock_driver = MagicMock()
    mock_driver_factory.return_value = mock_driver

    # Mock repository
    mock_repo = MagicMock()
    mock_repo.write_traffic_records.return_value = 1
    mock_repo.write_alert_records.return_value = 1
    mock_repo_cls.return_value = mock_repo

    main()

    # Verify driver creation and connectivity check
    mock_driver_factory.assert_called_once()
    mock_driver.verify_connectivity.assert_called_once()

    # Verify schema setup called with driver
    mock_ensure_schema.assert_called_once_with(mock_driver)

    # Verify repository created with driver and called with parsed records
    mock_repo_cls.assert_called_once_with(mock_driver)
    mock_repo.write_traffic_records.assert_called_once()
    mock_repo.write_alert_records.assert_called_once()

    # Verify driver cleanup in finally
    mock_driver.close.assert_called_once()
