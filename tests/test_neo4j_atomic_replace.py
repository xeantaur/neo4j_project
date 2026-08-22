"""
Live Neo4j integration tests for Phase 6.5 Atomic Workspace Replacement & Rollback.

Strictly opt-in via RUN_NEO4J_INTEGRATION=1. Uses synthetic TEST-NET-2 / RFC 5737 data only.
"""

import os
import pytest
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from src.graph.schema import ensure_schema
from src.graph.repository import Neo4jRepository, CYPHER_SCOPED_CLEANUP
from src.graph.read_repository import Neo4jReadRepository
from src.ingestion.models import TrafficRecord, AlertRecord


@pytest.fixture(scope="module")
def live_driver():
    """Connect to live test Neo4j instance when RUN_NEO4J_INTEGRATION=1 is set."""
    if os.environ.get("RUN_NEO4J_INTEGRATION") != "1":
        pytest.skip("Live Neo4j integration tests disabled (set RUN_NEO4J_INTEGRATION=1 to enable)")

    test_uri = os.environ.get("NEO4J_TEST_URI")
    test_user = os.environ.get("NEO4J_TEST_USERNAME")
    test_pass = os.environ.get("NEO4J_TEST_PASSWORD")

    if not test_uri or not test_user or not test_pass:
        pytest.skip("RUN_NEO4J_INTEGRATION=1 set but NEO4J_TEST_* environment variables are missing.")

    driver = None
    try:
        driver = GraphDatabase.driver(test_uri, auth=(test_user, test_pass))
        driver.verify_connectivity()
    except (ServiceUnavailable, AuthError, Exception) as exc:
        if driver is not None:
            driver.close()
        pytest.fail(f"Failed to connect to test Neo4j instance at {test_uri}: {exc}")

    yield driver

    # Clean up test database after all tests in module
    if driver is not None:
        with driver.session() as session:
            session.run(CYPHER_SCOPED_CLEANUP).consume()
        driver.close()


def test_live_traffic_only_replacement(live_driver):
    """replace_workspace_data with traffic-only removes prior alerts and populates traffic graph."""
    ensure_schema(live_driver)
    repo = Neo4jRepository(live_driver, batch_size=50)
    read_repo = Neo4jReadRepository(live_driver)

    # 1. Seed initial alert
    initial_alerts = [
        AlertRecord("198.51.100.1", "198.51.100.2", sid=1001, message="Initial Alert", priority=1),
    ]
    repo.write_alert_records(initial_alerts)
    alerts_items, alerts_total = read_repo.list_alert_facts()
    assert alerts_total >= 1

    # 2. Replace with traffic-only data
    traffic_records = [
        TrafficRecord("00:11:22:33:44:01", "00:11:22:33:44:02", "198.51.100.10", "198.51.100.20", "TCP"),
        TrafficRecord("00:11:22:33:44:01", "00:11:22:33:44:03", "198.51.100.10", "198.51.100.30", "DNS"),
    ]
    p_traffic, p_alerts = repo.replace_workspace_data(traffic_records=traffic_records, alert_records=None)
    assert p_traffic == 2
    assert p_alerts == 0

    # Verify previous AlertFact nodes were deleted
    _, alerts_total_after = read_repo.list_alert_facts()
    assert alerts_total_after == 0

    # Verify new traffic topology exists
    ips, total_ips = read_repo.list_ips()
    ip_addrs = [x["address"] for x in ips]
    assert "198.51.100.10" in ip_addrs
    assert "198.51.100.20" in ip_addrs


def test_live_alerts_only_replacement(live_driver):
    """replace_workspace_data with alerts-only removes prior flows and creates AlertFacts with IP context."""
    ensure_schema(live_driver)
    repo = Neo4jRepository(live_driver, batch_size=50)
    read_repo = Neo4jReadRepository(live_driver)

    # Replace with alerts-only
    alert_records = [
        AlertRecord("198.51.100.50", "198.51.100.60", sid=3001, message="Portscan Event", priority=2, protocol="TCP"),
    ]
    p_traffic, p_alerts = repo.replace_workspace_data(traffic_records=None, alert_records=alert_records)
    assert p_traffic == 0
    assert p_alerts == 1

    # Alert fact exists
    alerts_items, alerts_total = read_repo.list_alert_facts()
    assert alerts_total == 1
    assert alerts_items[0]["sid"] == 3001

    # IP context exists with alert counts
    ip_detail = read_repo.get_ip_detail("198.51.100.50")
    assert ip_detail is not None
    assert ip_detail["alerts_originated"] == 1
    assert ip_detail["outbound_flows"] == 0  # No traffic flows


def test_live_combined_replacement(live_driver):
    """replace_workspace_data with combined data creates topology, alert facts, and correlations."""
    ensure_schema(live_driver)
    repo = Neo4jRepository(live_driver, batch_size=50)
    read_repo = Neo4jReadRepository(live_driver)

    traffic_records = [
        TrafficRecord("00:aa:bb:cc:dd:01", "00:aa:bb:cc:dd:02", "198.51.100.70", "198.51.100.80", "TCP"),
    ]
    alert_records = [
        AlertRecord("198.51.100.70", "198.51.100.80", sid=4001, message="Correlated Exploit", priority=1, protocol="TCP"),
    ]

    p_traffic, p_alerts = repo.replace_workspace_data(traffic_records=traffic_records, alert_records=alert_records)
    assert p_traffic == 1
    assert p_alerts == 1

    # Check correlation query
    corrs_items, corrs_total = read_repo.list_traffic_alert_correlations()
    assert corrs_total == 1
    assert corrs_items[0]["source_ip"] == "198.51.100.70"
    assert corrs_items[0]["target_ip"] == "198.51.100.80"


def test_live_transaction_rollback_preserves_previous_workspace(live_driver, monkeypatch):
    """Calling replace_workspace_data with a mid-transaction write failure rolls back the scoped deletion."""
    ensure_schema(live_driver)
    repo = Neo4jRepository(live_driver, batch_size=50)
    read_repo = Neo4jReadRepository(live_driver)

    # 1. Establish known baseline workspace (traffic + alerts)
    baseline_traffic = [
        TrafficRecord("00:00:00:00:00:01", "00:00:00:00:00:02", "198.51.100.91", "198.51.100.92", "TCP"),
        TrafficRecord("00:00:00:00:00:01", "00:00:00:00:00:03", "198.51.100.91", "198.51.100.93", "UDP"),
    ]
    baseline_alerts = [
        AlertRecord("198.51.100.91", "198.51.100.92", sid=9001, message="Baseline Alert", priority=1, protocol="TCP"),
    ]
    repo.replace_workspace_data(traffic_records=baseline_traffic, alert_records=baseline_alerts)

    # 2. Snapshot baseline graph state using domain metrics/keys
    baseline_ips, total_ips = read_repo.list_ips()
    baseline_ip_set = {x["address"] for x in baseline_ips}
    assert "198.51.100.91" in baseline_ip_set
    assert "198.51.100.92" in baseline_ip_set

    baseline_alerts_items, total_alerts = read_repo.list_alert_facts()
    assert total_alerts == 1
    assert baseline_alerts_items[0]["sid"] == 9001
    baseline_fact_key = baseline_alerts_items[0]["fact_key"]

    baseline_corrs, total_corrs = read_repo.list_traffic_alert_correlations()
    assert total_corrs == 1

    baseline_detail = read_repo.get_ip_detail("198.51.100.91")
    assert baseline_detail is not None
    assert baseline_detail["outbound_flows"] == 2
    assert baseline_detail["alerts_originated"] == 1

    # 3. Prepare replacement traffic records
    replacement_traffic = [
        TrafficRecord("00:ff:ff:ff:ff:01", "00:ff:ff:ff:ff:02", "198.51.100.201", "198.51.100.202", "TCP"),
    ]

    # 4. Force replace_workspace_data() to fail AFTER cleanup has executed inside the managed transaction
    # We monkeypatch CYPHER_WRITE_TRAFFIC_BATCH with invalid Cypher syntax.
    monkeypatch.setattr(
        "src.graph.repository.CYPHER_WRITE_TRAFFIC_BATCH",
        "INVALID CYPHER SYNTAX THAT FAILS ON WRITE EXECUTION",
    )

    # 5. Execute the REAL replace_workspace_data method and assert failure
    with pytest.raises(Exception):
        repo.replace_workspace_data(traffic_records=replacement_traffic, alert_records=None)

    # 6. Re-query the REAL Neo4j database after the failed replacement
    post_failure_ips, post_total_ips = read_repo.list_ips()
    post_ip_set = {x["address"] for x in post_failure_ips}

    post_alerts_items, post_total_alerts = read_repo.list_alert_facts()
    post_corrs, post_total_corrs = read_repo.list_traffic_alert_correlations()
    post_detail = read_repo.get_ip_detail("198.51.100.91")

    # 7. Prove the previous baseline workspace was 100% restored / survived intact
    assert post_total_ips == total_ips
    assert post_ip_set == baseline_ip_set
    assert post_total_alerts == 1
    assert post_alerts_items[0]["fact_key"] == baseline_fact_key
    assert post_alerts_items[0]["sid"] == 9001
    assert post_total_corrs == 1
    assert post_detail is not None
    assert post_detail["outbound_flows"] == 2
    assert post_detail["alerts_originated"] == 1
    # Ensure replacement data was NOT persisted
    assert "198.51.100.201" not in post_ip_set
