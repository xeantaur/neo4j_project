"""
Live FastAPI + Neo4j integration tests (strictly opt-in via RUN_NEO4J_INTEGRATION=1).

Verifies the complete FastAPI route stack, dependency injection, and Pydantic response
serialization against a real, disposable Neo4j instance.
"""

import os
import pytest
from fastapi.testclient import TestClient
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from src.api.app import create_app
from src.api.dependencies import get_read_repository
from src.graph.schema import ensure_schema
from src.graph.repository import Neo4jRepository
from src.graph.read_repository import Neo4jReadRepository
from src.ingestion.models import TrafficRecord, AlertRecord


@pytest.fixture(scope="module")
def live_neo4j_driver():
    """Attempt connecting to live test Neo4j only when explicitly enabled via environment."""
    if os.environ.get("RUN_NEO4J_INTEGRATION") != "1":
        pytest.skip("Live Neo4j integration tests disabled (set RUN_NEO4J_INTEGRATION=1 to enable)")

    test_uri = os.environ.get("NEO4J_TEST_URI")
    test_user = os.environ.get("NEO4J_TEST_USERNAME")
    test_pass = os.environ.get("NEO4J_TEST_PASSWORD")

    if not test_uri or not test_user or not test_pass:
        pytest.skip(
            "RUN_NEO4J_INTEGRATION=1 is set but required test configuration "
            "(NEO4J_TEST_URI, NEO4J_TEST_USERNAME, NEO4J_TEST_PASSWORD) is incomplete"
        )

    driver = None
    try:
        driver = GraphDatabase.driver(test_uri, auth=(test_user, test_pass))
        driver.verify_connectivity()
    except (ServiceUnavailable, AuthError, Exception) as exc:
        if driver is not None:
            driver.close()
        pytest.fail(f"Failed to connect to test Neo4j instance at {test_uri}: {exc}")

    yield driver

    if driver is not None:
        driver.close()


@pytest.fixture(scope="module")
def api_test_client(live_neo4j_driver):
    """FastAPI TestClient wired to real Neo4jReadRepository."""
    ensure_schema(live_neo4j_driver)
    repo = Neo4jRepository(live_neo4j_driver, batch_size=100)

    # Seed scoped TEST-NET-2 data (198.51.100.0/24)
    synth_traffic = [
        TrafficRecord(
            eth_src_resolved="02:00:00:51:aa:01",
            eth_dst_resolved="02:00:00:51:aa:02",
            ip_src="198.51.100.101",
            ip_dst="198.51.100.102",
            protocol="TCP",
        ),
        TrafficRecord(
            eth_src_resolved="02:00:00:51:aa:02",
            eth_dst_resolved="02:00:00:51:aa:03",
            ip_src="198.51.100.102",
            ip_dst="198.51.100.103",
            protocol="UDP",
        ),
    ]

    synth_alerts = [
        AlertRecord(
            src_ip="198.51.100.101",
            dst_ip="198.51.100.102",
            sid=7777001,
            gid=1,
            rev=1,
            message="SYNTHETIC Live API Alert",
            priority=1,
            protocol="TCP",
            src_port=54321,
            dst_port=443,
        )
    ]

    repo.write_traffic_records(synth_traffic)
    repo.write_alert_records(synth_alerts)

    app = create_app()
    read_repo = Neo4jReadRepository(live_neo4j_driver)
    app.dependency_overrides[get_read_repository] = lambda: read_repo

    client = TestClient(app)
    yield client

    app.dependency_overrides.clear()

    # Scoped cleanup
    test_ips = ["198.51.100.101", "198.51.100.102", "198.51.100.103"]
    test_l2s = ["02:00:00:51:aa:01", "02:00:00:51:aa:02", "02:00:00:51:aa:03"]
    with live_neo4j_driver.session() as session:
        session.run("MATCH (fact:AlertFact) WHERE fact.sid = 7777001 DETACH DELETE fact").consume()
        session.run("MATCH (ip:IPAddress) WHERE ip.address IN $ips DETACH DELETE ip", ips=test_ips).consume()
        session.run("MATCH (l2:Layer2Identifier) WHERE l2.identifier IN $l2s DETACH DELETE l2", l2s=test_l2s).consume()


@pytest.mark.integration
def test_live_api_health_and_readiness(api_test_client):
    """Verify GET /health and GET /ready with real Neo4j connection."""
    r_health = api_test_client.get("/health")
    assert r_health.status_code == 200
    assert r_health.json() == {"status": "ok", "app": "Network Traffic Analysis"}

    r_ready = api_test_client.get("/ready")
    assert r_ready.status_code == 200
    assert r_ready.json() == {"status": "ready", "database": "connected"}


@pytest.mark.integration
def test_live_api_network_endpoints(api_test_client):
    """Verify all /api/v1/network/* endpoints against real Neo4j data."""
    # 1. List IPs
    r_ips = api_test_client.get("/api/v1/network/ips?limit=50&offset=0")
    assert r_ips.status_code == 200
    data_ips = r_ips.json()
    assert "items" in data_ips
    assert data_ips["total"] >= 3
    addresses = [item["address"] for item in data_ips["items"]]
    assert "198.51.100.101" in addresses

    # 2. IP Detail
    r_detail = api_test_client.get("/api/v1/network/ips/198.51.100.101")
    assert r_detail.status_code == 200
    data_detail = r_detail.json()
    assert data_detail["address"] == "198.51.100.101"
    assert data_detail["outbound_flows"] == 1
    assert data_detail["alerts_originated"] == 1
    assert "02:00:00:51:aa:01" in data_detail["layer2_identifiers"]

    # IP detail 404
    assert api_test_client.get("/api/v1/network/ips/198.51.100.254").status_code == 404

    # 3. IP Peers
    r_peers = api_test_client.get("/api/v1/network/ips/198.51.100.101/peers?direction=outbound")
    assert r_peers.status_code == 200
    data_peers = r_peers.json()
    assert data_peers["total"] == 1
    assert data_peers["items"][0]["peer_address"] == "198.51.100.102"
    assert data_peers["items"][0]["direction"] == "outbound"

    # 4. IP Layer 2
    r_ip_l2 = api_test_client.get("/api/v1/network/ips/198.51.100.101/layer2")
    assert r_ip_l2.status_code == 200
    assert r_ip_l2.json()["total"] == 1
    assert r_ip_l2.json()["items"][0]["identifier"] == "02:00:00:51:aa:01"

    # 5. List Layer 2
    r_all_l2 = api_test_client.get("/api/v1/network/layer2")
    assert r_all_l2.status_code == 200
    assert r_all_l2.json()["total"] >= 3

    # 6. List Communications
    r_comms = api_test_client.get("/api/v1/network/communications?source_ip=198.51.100.101&protocol=TCP")
    assert r_comms.status_code == 200
    assert r_comms.json()["total"] == 1
    assert r_comms.json()["items"][0]["target_ip"] == "198.51.100.102"


@pytest.mark.integration
def test_live_api_alerts_and_correlations(api_test_client):
    """Verify /api/v1/alerts and /api/v1/correlations endpoints against real Neo4j."""
    # 1. Filter Alerts by SID
    r_alerts = api_test_client.get("/api/v1/alerts?sid=7777001")
    assert r_alerts.status_code == 200
    data_alerts = r_alerts.json()
    assert data_alerts["total"] == 1
    fact_key = data_alerts["items"][0]["fact_key"]
    assert len(fact_key) == 64

    # 2. Get Alert Fact by Key
    r_fact = api_test_client.get(f"/api/v1/alerts/{fact_key}")
    assert r_fact.status_code == 200
    fact_detail = r_fact.json()
    assert fact_detail["sid"] == 7777001
    assert fact_detail["priority"] == 1
    assert fact_detail["message"] == "SYNTHETIC Live API Alert"

    # 3. Correlations
    r_corr = api_test_client.get("/api/v1/correlations/traffic-alerts")
    assert r_corr.status_code == 200
    corr_items = r_corr.json()["items"]
    matches = [c for c in corr_items if c["source_ip"] == "198.51.100.101" and c["target_ip"] == "198.51.100.102"]
    assert len(matches) == 1
    assert matches[0]["sid"] == 7777001
    assert matches[0]["traffic_protocol"] == "TCP"


@pytest.mark.integration
def test_live_api_graph_endpoints(api_test_client):
    """Verify /api/v1/graph/neighborhood and /api/v1/graph/path endpoints against real Neo4j."""
    # 1. Neighborhood Depth 1
    r_nh = api_test_client.get("/api/v1/graph/neighborhood/198.51.100.102?depth=1&max_nodes=50")
    assert r_nh.status_code == 200
    data_nh = r_nh.json()
    assert data_nh["center"] == "198.51.100.102"
    node_ids = {n["id"] for n in data_nh["nodes"]}
    assert "ip:198.51.100.101" in node_ids
    assert "ip:198.51.100.103" in node_ids

    # 2. Shortest Path (Direct: 101 -> 102)
    r_path = api_test_client.get("/api/v1/graph/path?source=198.51.100.101&target=198.51.100.102&max_hops=5")
    assert r_path.status_code == 200
    data_path = r_path.json()
    assert data_path["length"] == 1
    assert data_path["hops"] == ["198.51.100.101", "198.51.100.102"]
    assert data_path["protocols"] == ["TCP"]

    # 3. Shortest Path (Multi-hop: 101 -> 103)
    r_multi = api_test_client.get("/api/v1/graph/path?source=198.51.100.101&target=198.51.100.103&max_hops=5")
    assert r_multi.status_code == 200
    assert r_multi.json()["length"] == 2

    # 4. Shortest Path (Same source and target: 101 -> 101)
    r_same = api_test_client.get("/api/v1/graph/path?source=198.51.100.101&target=198.51.100.101")
    assert r_same.status_code == 200
    assert r_same.json()["length"] == 0
    assert r_same.json()["hops"] == ["198.51.100.101"]

    # 5. Path 404s
    assert api_test_client.get("/api/v1/graph/path?source=198.51.100.254&target=198.51.100.102").status_code == 404
    assert api_test_client.get("/api/v1/graph/path?source=198.51.100.103&target=198.51.100.101").status_code == 404


@pytest.mark.integration
def test_live_api_analytics_endpoints(api_test_client):
    """Verify /api/v1/network/analytics/summary and /api/v1/network/analytics/endpoints routes."""
    # 1. Summary
    r_sum = api_test_client.get("/api/v1/network/analytics/summary")
    assert r_sum.status_code == 200
    data_sum = r_sum.json()
    assert "traffic_metrics_mode" in data_sum
    assert data_sum["total_communication_aggregates"] >= 2
    assert "protocol_distribution" in data_sum
    assert "top_fan_out" in data_sum
    assert "top_fan_in" in data_sum

    # 2. Endpoints
    r_ep = api_test_client.get("/api/v1/network/analytics/endpoints?sort_by=fan_out&limit=10&offset=0")
    assert r_ep.status_code == 200
    data_ep = r_ep.json()
    assert "items" in data_ep
    assert data_ep["total"] >= 2
    assert len(data_ep["items"]) >= 2
    ep_addrs = [item["address"] for item in data_ep["items"]]
    assert "198.51.100.101" in ep_addrs
