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

    # 2. Verify Schema Metadata (Constraints and Indexes)
    with live_neo4j_driver.session() as session:
        constraints_res = session.run("SHOW CONSTRAINTS").data()
        constraint_names = {c.get("name") for c in constraints_res}
        assert "ip_address_unique" in constraint_names
        assert "layer2_identifier_unique" in constraint_names
        assert "alert_fact_unique" in constraint_names

        indexes_res = session.run("SHOW INDEXES").data()
        index_names = {i.get("name") for i in indexes_res}
        assert "alert_fact_priority_index" in index_names
        assert "alert_fact_sid_index" in index_names

    # 3. Use distinct synthetic test data (TEST-NET-3: 203.0.113.0/24) with two distinct pairs
    test_traffic = [
        TrafficRecord(
            eth_src_resolved="02:00:00:99:99:01",
            eth_dst_resolved="02:00:00:99:99:02",
            ip_src="203.0.113.10",
            ip_dst="203.0.113.20",
            protocol="TCP",
        ),
        TrafficRecord(
            eth_src_resolved="02:00:00:99:99:03",
            eth_dst_resolved="02:00:00:99:99:04",
            ip_src="203.0.113.30",
            ip_dst="203.0.113.40",
            protocol="UDP",
        ),
    ]
    test_alerts = [
        AlertRecord(
            src_ip="203.0.113.10",
            dst_ip="203.0.113.20",
            sid=9999001,
            gid=1,
            rev=1,
            message="SYNTHETIC Alert 1",
            priority=1,
            protocol="TCP",
            src_port=44444,
            dst_port=80,
        ),
        AlertRecord(
            src_ip="203.0.113.30",
            dst_ip="203.0.113.40",
            sid=9999002,
            gid=1,
            rev=1,
            message="SYNTHETIC Alert 2",
            priority=2,
            protocol="UDP",
            src_port=55555,
            dst_port=53,
        ),
    ]

    repo = Neo4jRepository(live_neo4j_driver, batch_size=100)

    try:
        # 4. First Ingestion Run
        repo.write_traffic_records(test_traffic)
        repo.write_alert_records(test_alerts)

        with live_neo4j_driver.session() as session:
            # Check Nodes
            c_ip_1 = session.run(
                "MATCH (n:IPAddress) WHERE n.address IN ['203.0.113.10', '203.0.113.20', '203.0.113.30', '203.0.113.40'] RETURN count(n) AS c"
            ).single()["c"]
            assert c_ip_1 == 4

            c_l2_1 = session.run(
                "MATCH (n:Layer2Identifier) WHERE n.identifier IN ['02:00:00:99:99:01', '02:00:00:99:99:02', '02:00:00:99:99:03', '02:00:00:99:99:04'] RETURN count(n) AS c"
            ).single()["c"]
            assert c_l2_1 == 4

            c_fact_1 = session.run(
                "MATCH (n:AlertFact) WHERE n.sid IN [9999001, 9999002] RETURN count(n) AS c"
            ).single()["c"]
            assert c_fact_1 == 2

            # Check Relationships
            c_comm_1 = session.run(
                "MATCH (src:IPAddress)-[r:COMMUNICATED_TO]->(dst:IPAddress) "
                "WHERE src.address IN ['203.0.113.10', '203.0.113.30'] RETURN count(r) AS c"
            ).single()["c"]
            assert c_comm_1 == 2

            c_l2_comm_1 = session.run(
                "MATCH (src:Layer2Identifier)-[r:L2_COMMUNICATED_TO]->(dst:Layer2Identifier) "
                "WHERE src.identifier IN ['02:00:00:99:99:01', '02:00:00:99:99:03'] RETURN count(r) AS c"
            ).single()["c"]
            assert c_l2_comm_1 == 2

            c_obs_1 = session.run(
                "MATCH (ip:IPAddress)-[r:OBSERVED_WITH]->(l2:Layer2Identifier) "
                "WHERE ip.address IN ['203.0.113.10', '203.0.113.20', '203.0.113.30', '203.0.113.40'] RETURN count(r) AS c"
            ).single()["c"]
            assert c_obs_1 == 4

            c_src_of_1 = session.run(
                "MATCH (src:IPAddress)-[r:SOURCE_OF]->(fact:AlertFact) "
                "WHERE fact.sid IN [9999001, 9999002] RETURN count(r) AS c"
            ).single()["c"]
            assert c_src_of_1 == 2

            c_targets_1 = session.run(
                "MATCH (fact:AlertFact)-[r:TARGETS]->(dst:IPAddress) "
                "WHERE fact.sid IN [9999001, 9999002] RETURN count(r) AS c"
            ).single()["c"]
            assert c_targets_1 == 2

            # Check Source-Target Pairing Integrity (Pair 1 and Pair 2 exist, cross pairs do NOT)
            pair1 = session.run(
                "MATCH (src:IPAddress {address: '203.0.113.10'})-[:SOURCE_OF]->(fact:AlertFact {sid: 9999001})-[:TARGETS]->(dst:IPAddress {address: '203.0.113.20'}) "
                "RETURN count(fact) AS c"
            ).single()["c"]
            assert pair1 == 1

            pair2 = session.run(
                "MATCH (src:IPAddress {address: '203.0.113.30'})-[:SOURCE_OF]->(fact:AlertFact {sid: 9999002})-[:TARGETS]->(dst:IPAddress {address: '203.0.113.40'}) "
                "RETURN count(fact) AS c"
            ).single()["c"]
            assert pair2 == 1

            cross_pair = session.run(
                "MATCH (src:IPAddress {address: '203.0.113.10'})-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress {address: '203.0.113.40'}) "
                "RETURN count(fact) AS c"
            ).single()["c"]
            assert cross_pair == 0

        # 5. Second Ingestion Run (Verify Complete Idempotency)
        repo.write_traffic_records(test_traffic)
        repo.write_alert_records(test_alerts)

        with live_neo4j_driver.session() as session:
            c_ip_2 = session.run(
                "MATCH (n:IPAddress) WHERE n.address IN ['203.0.113.10', '203.0.113.20', '203.0.113.30', '203.0.113.40'] RETURN count(n) AS c"
            ).single()["c"]
            c_l2_2 = session.run(
                "MATCH (n:Layer2Identifier) WHERE n.identifier IN ['02:00:00:99:99:01', '02:00:00:99:99:02', '02:00:00:99:99:03', '02:00:00:99:99:04'] RETURN count(n) AS c"
            ).single()["c"]
            c_fact_2 = session.run(
                "MATCH (n:AlertFact) WHERE n.sid IN [9999001, 9999002] RETURN count(n) AS c"
            ).single()["c"]
            c_comm_2 = session.run(
                "MATCH (src:IPAddress)-[r:COMMUNICATED_TO]->(dst:IPAddress) "
                "WHERE src.address IN ['203.0.113.10', '203.0.113.30'] RETURN count(r) AS c"
            ).single()["c"]
            c_l2_comm_2 = session.run(
                "MATCH (src:Layer2Identifier)-[r:L2_COMMUNICATED_TO]->(dst:Layer2Identifier) "
                "WHERE src.identifier IN ['02:00:00:99:99:01', '02:00:00:99:99:03'] RETURN count(r) AS c"
            ).single()["c"]
            c_obs_2 = session.run(
                "MATCH (ip:IPAddress)-[r:OBSERVED_WITH]->(l2:Layer2Identifier) "
                "WHERE ip.address IN ['203.0.113.10', '203.0.113.20', '203.0.113.30', '203.0.113.40'] RETURN count(r) AS c"
            ).single()["c"]
            c_src_of_2 = session.run(
                "MATCH (src:IPAddress)-[r:SOURCE_OF]->(fact:AlertFact) "
                "WHERE fact.sid IN [9999001, 9999002] RETURN count(r) AS c"
            ).single()["c"]
            c_targets_2 = session.run(
                "MATCH (fact:AlertFact)-[r:TARGETS]->(dst:IPAddress) "
                "WHERE fact.sid IN [9999001, 9999002] RETURN count(r) AS c"
            ).single()["c"]

            assert c_ip_2 == c_ip_1
            assert c_l2_2 == c_l2_1
            assert c_fact_2 == c_fact_1
            assert c_comm_2 == c_comm_1
            assert c_l2_comm_2 == c_l2_comm_1
            assert c_obs_2 == c_obs_1
            assert c_src_of_2 == c_src_of_1
            assert c_targets_2 == c_targets_1

    finally:
        # Strictly test-scoped cleanup: delete only the exact synthetic entities created by this test
        with live_neo4j_driver.session() as session:
            session.run(
                "MATCH (fact:AlertFact) WHERE fact.sid IN [9999001, 9999002] DETACH DELETE fact"
            ).consume()
            session.run(
                "MATCH (ip:IPAddress) WHERE ip.address IN ['203.0.113.10', '203.0.113.20', '203.0.113.30', '203.0.113.40'] DETACH DELETE ip"
            ).consume()
            session.run(
                "MATCH (l2:Layer2Identifier) WHERE l2.identifier IN ['02:00:00:99:99:01', '02:00:00:99:99:02', '02:00:00:99:99:03', '02:00:00:99:99:04'] DETACH DELETE l2"
            ).consume()
