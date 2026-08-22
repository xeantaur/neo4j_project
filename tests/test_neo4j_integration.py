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
from src.graph.read_repository import Neo4jReadRepository
from src.ingestion.models import TrafficRecord, AlertRecord
from src.ingestion.traffic_parser import parse_traffic_file
from src.ingestion.alert_parser import parse_alert_file


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
            assert c_targets_2 == 2

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


@pytest.mark.integration
def test_live_file_ingestion_and_read_repository(live_neo4j_driver):
    """Verify end-to-end sample file parsing, graph persistence, read retrieval, and idempotency on real Neo4j."""
    ensure_schema(live_neo4j_driver)

    traffic_records, traffic_summary = parse_traffic_file("data/samples/sample_traffic.tsv")
    assert len(traffic_records) > 0
    assert traffic_summary.valid_records == len(traffic_records)

    alert_records, alert_summary = parse_alert_file("data/samples/sample_alerts.json")
    assert len(alert_records) > 0
    assert alert_summary.valid_records == len(alert_records)

    repo = Neo4jRepository(live_neo4j_driver, batch_size=100)
    read_repo = Neo4jReadRepository(live_neo4j_driver)

    # Collect sample IPs and L2s for strictly scoped teardown
    sample_ips = {r.ip_src for r in traffic_records} | {r.ip_dst for r in traffic_records} | {r.src_ip for r in alert_records} | {r.dst_ip for r in alert_records}
    sample_l2s = {r.eth_src_resolved for r in traffic_records} | {r.eth_dst_resolved for r in traffic_records}
    sample_sids = {r.sid for r in alert_records if r.sid is not None}

    try:
        # First Ingestion pass
        repo.write_traffic_records(traffic_records)
        repo.write_alert_records(alert_records)

        # Verify through Neo4jReadRepository
        assert read_repo.check_connectivity() is True

        ips_page, total_ips = read_repo.list_ips(limit=100, offset=0)
        assert total_ips >= len(sample_ips)
        observed_addresses = {item["address"] for item in ips_page}
        for ip in sample_ips:
            assert ip in observed_addresses

        alerts_page, total_alerts = read_repo.list_alert_facts(limit=100, offset=0)
        assert total_alerts >= len(alert_records)

        # Second Ingestion pass — verify complete idempotency
        repo.write_traffic_records(traffic_records)
        repo.write_alert_records(alert_records)

        _, total_ips_2 = read_repo.list_ips(limit=1, offset=0)
        _, total_alerts_2 = read_repo.list_alert_facts(limit=1, offset=0)
        assert total_ips_2 == total_ips
        assert total_alerts_2 == total_alerts

    finally:
        # Scoped cleanup
        with live_neo4j_driver.session() as session:
            session.run(
                "MATCH (fact:AlertFact) WHERE fact.sid IN $sids DETACH DELETE fact",
                sids=list(sample_sids),
            ).consume()
            session.run(
                "MATCH (ip:IPAddress) WHERE ip.address IN $ips DETACH DELETE ip",
                ips=list(sample_ips),
            ).consume()
            session.run(
                "MATCH (l2:Layer2Identifier) WHERE l2.identifier IN $l2s DETACH DELETE l2",
                l2s=list(sample_l2s),
            ).consume()


@pytest.mark.integration
def test_live_read_repository_queries(live_neo4j_driver):
    """Verify all Cypher read methods in Neo4jReadRepository against synthetic TEST-NET live graph."""
    ensure_schema(live_neo4j_driver)
    repo = Neo4jRepository(live_neo4j_driver, batch_size=100)
    read_repo = Neo4jReadRepository(live_neo4j_driver)

    # 4 IPs in a chain: A(10) -> B(20) -> C(30) -> D(40)
    # A has alert targeting B
    # A has Layer2 association
    synth_traffic = [
        TrafficRecord(
            eth_src_resolved="02:00:00:51:00:01",
            eth_dst_resolved="02:00:00:51:00:02",
            ip_src="198.51.100.10",
            ip_dst="198.51.100.20",
            protocol="TCP",
        ),
        TrafficRecord(
            eth_src_resolved="02:00:00:51:00:02",
            eth_dst_resolved="02:00:00:51:00:03",
            ip_src="198.51.100.20",
            ip_dst="198.51.100.30",
            protocol="UDP",
        ),
        TrafficRecord(
            eth_src_resolved="02:00:00:51:00:03",
            eth_dst_resolved="02:00:00:51:00:04",
            ip_src="198.51.100.30",
            ip_dst="198.51.100.40",
            protocol="TCP",
        ),
    ]

    synth_alerts = [
        AlertRecord(
            src_ip="198.51.100.10",
            dst_ip="198.51.100.20",
            sid=8888001,
            gid=1,
            rev=1,
            message="SYNTHETIC Scan Alert",
            priority=1,
            protocol="TCP",
            src_port=12345,
            dst_port=80,
        )
    ]

    test_ips = ["198.51.100.10", "198.51.100.20", "198.51.100.30", "198.51.100.40"]
    test_l2s = ["02:00:00:51:00:01", "02:00:00:51:00:02", "02:00:00:51:00:03", "02:00:00:51:00:04"]

    try:
        repo.write_traffic_records(synth_traffic)
        repo.write_alert_records(synth_alerts)

        # 1. IP Detail
        ip_a = read_repo.get_ip_detail("198.51.100.10")
        assert ip_a is not None
        assert ip_a["address"] == "198.51.100.10"
        assert ip_a["outbound_flows"] == 1
        assert ip_a["alerts_originated"] == 1
        assert "02:00:00:51:00:01" in ip_a["layer2_identifiers"]

        # IP not found
        assert read_repo.get_ip_detail("198.51.100.99") is None

        # 2. IP Peers
        peers_out, total_p = read_repo.list_ip_peers("198.51.100.10", direction="outbound")
        assert total_p == 1
        assert peers_out[0]["peer_address"] == "198.51.100.20"
        assert peers_out[0]["direction"] == "outbound"

        peers_in, _ = read_repo.list_ip_peers("198.51.100.20", direction="inbound")
        assert len(peers_in) == 1
        assert peers_in[0]["peer_address"] == "198.51.100.10"

        # 3. Layer 2 Queries
        l2_items, total_l2 = read_repo.list_ip_layer2("198.51.100.10")
        assert total_l2 == 1
        assert l2_items[0]["identifier"] == "02:00:00:51:00:01"

        all_l2, _ = read_repo.list_layer2_identifiers(limit=10, offset=0)
        assert len(all_l2) >= 4

        # 4. Communications
        comms, total_c = read_repo.list_communications(source_ip="198.51.100.10", target_ip="198.51.100.20")
        assert total_c == 1
        assert comms[0]["protocol"] == "TCP"

        # 5. Alert Facts
        facts, total_f = read_repo.list_alert_facts(sid=8888001)
        assert total_f == 1
        fact_key = facts[0]["fact_key"]
        assert len(fact_key) == 64

        single_fact = read_repo.get_alert_fact(fact_key)
        assert single_fact is not None
        assert single_fact["sid"] == 8888001
        assert single_fact["priority"] == 1

        # 6. Correlations
        corrs, total_corrs = read_repo.list_traffic_alert_correlations()
        assert total_corrs >= 1
        matching_corr = [c for c in corrs if c["source_ip"] == "198.51.100.10" and c["target_ip"] == "198.51.100.20"]
        assert len(matching_corr) == 1
        assert matching_corr[0]["traffic_protocol"] == "TCP"
        assert matching_corr[0]["sid"] == 8888001

        # 7. Neighborhood
        nh_1 = read_repo.get_neighborhood("198.51.100.20", depth=1, max_nodes=50)
        assert nh_1 is not None
        assert nh_1["center"] == "198.51.100.20"
        nh_node_ids = {n["id"] for n in nh_1["nodes"]}
        assert "ip:198.51.100.10" in nh_node_ids
        assert "ip:198.51.100.30" in nh_node_ids

        # Neighborhood not found
        assert read_repo.get_neighborhood("198.51.100.99", depth=1) is None

        # 8. Shortest Path (Direct and Multi-hop)
        # Direct: 10 -> 20 (1 hop)
        path_direct = read_repo.get_shortest_path("198.51.100.10", "198.51.100.20", max_hops=5)
        assert path_direct is not None
        assert path_direct["length"] == 1
        assert path_direct["hops"] == ["198.51.100.10", "198.51.100.20"]
        assert path_direct["protocols"] == ["TCP"]

        # Multi-hop: 10 -> 40 (3 hops: 10 -> 20 -> 30 -> 40)
        path_multi = read_repo.get_shortest_path("198.51.100.10", "198.51.100.40", max_hops=5)
        assert path_multi is not None
        assert path_multi["length"] == 3
        assert path_multi["hops"] == ["198.51.100.10", "198.51.100.20", "198.51.100.30", "198.51.100.40"]

        # Source not found
        assert read_repo.get_shortest_path("198.51.100.99", "198.51.100.20") == {"error": "source_not_found"}

        # Target not found
        assert read_repo.get_shortest_path("198.51.100.10", "198.51.100.99") == {"error": "target_not_found"}

        # No reverse path: 40 -> 10
        assert read_repo.get_shortest_path("198.51.100.40", "198.51.100.10", max_hops=5) == {"error": "no_path"}

        # Source == Target (0 hops)
        path_same = read_repo.get_shortest_path("198.51.100.10", "198.51.100.10")
        assert path_same["length"] == 0
        assert path_same["hops"] == ["198.51.100.10"]
        assert path_same["protocols"] == []

    finally:
        with live_neo4j_driver.session() as session:
            session.run(
                "MATCH (fact:AlertFact) WHERE fact.sid = 8888001 DETACH DELETE fact"
            ).consume()
            session.run(
                "MATCH (ip:IPAddress) WHERE ip.address IN $ips DETACH DELETE ip",
                ips=test_ips,
            ).consume()
            session.run(
                "MATCH (l2:Layer2Identifier) WHERE l2.identifier IN $l2s DETACH DELETE l2",
                l2s=test_l2s,
            ).consume()
