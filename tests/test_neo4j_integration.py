"""
Live Neo4j integration tests (strictly opt-in via RUN_NEO4J_INTEGRATION=1).

Requires explicit test-specific environment configuration:
- RUN_NEO4J_INTEGRATION=1
- NEO4J_TEST_URI
- NEO4J_TEST_USERNAME
- NEO4J_TEST_PASSWORD

Never probes localhost or runs automatically during default pytest runs.
Uses strictly scoped synthetic identifiers and does NOT perform global database wipes.
"""

import os
import pytest
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from src.graph.schema import ensure_schema
from src.graph.repository import Neo4jRepository
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


@pytest.mark.integration
def test_live_neo4j_schema_and_idempotent_ingestion(live_neo4j_driver):
    """Verify schema creation, data persistence, and rerun idempotency on a dedicated test database."""
    # 1. Ensure Schema
    ensure_schema(live_neo4j_driver)

    # 2. Use distinct synthetic test data with unique test-only IP space (TEST-NET-3: 203.0.113.0/24)
    test_traffic = [
        TrafficRecord(
            eth_src_resolved="02:00:00:99:99:01",
            eth_dst_resolved="02:00:00:99:99:02",
            ip_src="203.0.113.10",
            ip_dst="203.0.113.20",
            protocol="TCP",
        )
    ]
    test_alerts = [
        AlertRecord(
            src_ip="203.0.113.10",
            dst_ip="203.0.113.20",
            sid=9999001,
            gid=1,
            rev=1,
            message="SYNTHETIC-INTEGRATION-TEST Alert",
            priority=1,
            protocol="TCP",
            src_port=44444,
            dst_port=80,
        )
    ]

    repo = Neo4jRepository(live_neo4j_driver, batch_size=100)

    try:
        # 3. First Ingestion Run
        repo.write_traffic_records(test_traffic)
        repo.write_alert_records(test_alerts)

        with live_neo4j_driver.session() as session:
            res_ip = session.run(
                "MATCH (n:IPAddress) WHERE n.address IN ['203.0.113.10', '203.0.113.20'] RETURN count(n) AS c"
            ).single()["c"]
            assert res_ip == 2

            res_fact = session.run(
                "MATCH (n:AlertFact) WHERE n.sid = 9999001 RETURN count(n) AS c"
            ).single()["c"]
            assert res_fact == 1

            # Verify source-of / targets pairing
            pairing = session.run(
                "MATCH (src:IPAddress {address: '203.0.113.10'})-[:SOURCE_OF]->(fact:AlertFact {sid: 9999001})-[:TARGETS]->(dst:IPAddress {address: '203.0.113.20'}) "
                "RETURN count(fact) AS c"
            ).single()["c"]
            assert pairing == 1

        # 4. Second Ingestion Run (Verify Idempotency)
        repo.write_traffic_records(test_traffic)
        repo.write_alert_records(test_alerts)

        with live_neo4j_driver.session() as session:
            res_ip2 = session.run(
                "MATCH (n:IPAddress) WHERE n.address IN ['203.0.113.10', '203.0.113.20'] RETURN count(n) AS c"
            ).single()["c"]
            assert res_ip2 == 2

            res_fact2 = session.run(
                "MATCH (n:AlertFact) WHERE n.sid = 9999001 RETURN count(n) AS c"
            ).single()["c"]
            assert res_fact2 == 1

    finally:
        # Scoped cleanup: delete only the synthetic entities created by this test
        with live_neo4j_driver.session() as session:
            session.run(
                "MATCH (fact:AlertFact) WHERE fact.sid = 9999001 DETACH DELETE fact"
            )
            session.run(
                "MATCH (ip:IPAddress) WHERE ip.address IN ['203.0.113.10', '203.0.113.20'] DETACH DELETE ip"
            )
            session.run(
                "MATCH (l2:Layer2Identifier) WHERE l2.identifier IN ['02:00:00:99:99:01', '02:00:00:99:99:02'] DETACH DELETE l2"
            )
