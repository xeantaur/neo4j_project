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
    """Verify get_ip_detail maps subquery results, calculates metric mode, and handles missing nodes."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    # Found case (enriched mode)
    mock_record = {
        "address": "10.0.0.1",
        "layer2_identifiers": ["00:11:22:33:44:55"],
        "outbound_aggs": 4,
        "inbound_aggs": 2,
        "distinct_outbound_peers": 3,
        "distinct_inbound_peers": 2,
        "distinct_destination_ports": 2,
        "outbound_enriched_aggs": 4,
        "inbound_enriched_aggs": 2,
        "observed_packets_sent": 40,
        "observed_packets_received": 20,
        "observed_bytes_sent": 4000,
        "observed_bytes_received": 2000,
        "first_observed": 100.0,
        "last_observed": 150.0,
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
    assert detail["inbound_flows"] == 2
    assert detail["traffic_metrics_mode"] == "enriched"
    assert detail["observed_packets_sent"] == 40
    assert detail["observed_bytes_sent"] == 4000
    assert detail["distinct_outbound_peers"] == 3

    # Not found case
    mock_res_empty = MagicMock()
    mock_res_empty.single.return_value = None
    mock_tx.run.return_value = mock_res_empty

    detail_none = repo.get_ip_detail("10.0.0.99")
    assert detail_none is None


def test_traffic_analytics_summary_modes(mock_driver_and_tx):
    """Verify get_traffic_analytics_summary correctly calculates none, basic, enriched, and mixed modes."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    # 1. None mode (0 aggregates)
    mock_s_none = MagicMock()
    mock_s_none.single.return_value = {"total_aggs": 0, "enriched_aggs": 0}
    mock_tx.run.return_value = mock_s_none

    res_none = repo.get_traffic_analytics_summary()
    assert res_none["traffic_metrics_mode"] == "none"
    assert res_none["total_communication_aggregates"] == 0
    assert res_none["total_observed_packets"] is None

    # 2. Basic mode (5 total, 0 enriched)
    mock_s_basic = MagicMock()
    mock_s_basic.single.return_value = {
        "total_aggs": 5,
        "enriched_aggs": 0,
        "total_pkts": 0,
        "total_bytes": 0,
        "first_obs": None,
        "last_obs": None,
    }
    mock_proto_res = [{"protocol": "TCP", "agg_count": 5, "enriched_count": 0, "pkts": None, "bytes": None}]
    mock_port_res = []
    mock_fan_out = [{"address": "10.0.0.1", "distinct_destination_ips": 3}]
    mock_fan_in = [{"address": "10.0.0.2", "distinct_source_ips": 2}]

    mock_tx.run.side_effect = [mock_s_basic, mock_proto_res, mock_port_res, mock_fan_out, mock_fan_in]
    res_basic = repo.get_traffic_analytics_summary()
    assert res_basic["traffic_metrics_mode"] == "basic"
    assert res_basic["total_communication_aggregates"] == 5
    assert res_basic["enriched_communication_aggregates"] == 0
    assert res_basic["basic_communication_aggregates"] == 5
    assert res_basic["total_observed_packets"] is None
    assert res_basic["total_observed_bytes"] is None
    assert res_basic["protocol_distribution"][0]["observed_packet_count"] is None

    # 3. Enriched mode (4 total, 4 enriched)
    mock_s_enr = MagicMock()
    mock_s_enr.single.return_value = {
        "total_aggs": 4,
        "enriched_aggs": 4,
        "total_pkts": 100,
        "total_bytes": 50000,
        "first_obs": 1000.0,
        "last_obs": 1050.0,
    }
    mock_proto_enr = [{"protocol": "TLS", "agg_count": 4, "enriched_count": 4, "pkts": 100, "bytes": 50000}]
    mock_port_enr = [{"dst_port": 443, "agg_count": 4, "enriched_count": 4, "pkts": 100, "bytes": 50000}]
    mock_tx.run.side_effect = [mock_s_enr, mock_proto_enr, mock_port_enr, mock_fan_out, mock_fan_in]
    res_enr = repo.get_traffic_analytics_summary()
    assert res_enr["traffic_metrics_mode"] == "enriched"
    assert res_enr["total_observed_packets"] == 100
    assert res_enr["total_observed_bytes"] == 50000
    assert res_enr["first_observed"] == 1000.0
    assert res_enr["last_observed"] == 1050.0
    assert res_enr["destination_port_distribution"][0]["dst_port"] == 443

    # 4. Mixed mode (6 total, 2 enriched)
    mock_s_mixed = MagicMock()
    mock_s_mixed.single.return_value = {
        "total_aggs": 6,
        "enriched_aggs": 2,
        "total_pkts": 40,
        "total_bytes": 20000,
        "first_obs": 2000.0,
        "last_obs": 2020.0,
    }
    mock_tx.run.side_effect = [mock_s_mixed, mock_proto_enr, mock_port_enr, mock_fan_out, mock_fan_in]
    res_mixed = repo.get_traffic_analytics_summary()
    assert res_mixed["traffic_metrics_mode"] == "mixed"
    assert res_mixed["total_communication_aggregates"] == 6
    assert res_mixed["enriched_communication_aggregates"] == 2
    assert res_mixed["basic_communication_aggregates"] == 4
    assert res_mixed["total_observed_packets"] == 40
    assert res_mixed["total_observed_bytes"] == 20000


def test_get_endpoints_analytics(mock_driver_and_tx):
    """Verify get_endpoints_analytics query, sorting, and pagination."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    mock_count = MagicMock()
    mock_count.single.return_value = {"total": 2}

    mock_page = [
        {
            "address": "10.0.0.1",
            "outbound_aggs": 3,
            "inbound_aggs": 0,
            "distinct_outbound_peers": 3,
            "distinct_inbound_peers": 0,
            "distinct_destination_ports": 2,
            "outbound_enriched_aggs": 3,
            "inbound_enriched_aggs": 0,
            "observed_packets_sent": 30,
            "observed_packets_received": None,
            "observed_bytes_sent": 3000,
            "observed_bytes_received": None,
            "first_observed": 100.0,
            "last_observed": 110.0,
        },
        {
            "address": "10.0.0.2",
            "outbound_aggs": 1,
            "inbound_aggs": 2,
            "distinct_outbound_peers": 1,
            "distinct_inbound_peers": 2,
            "distinct_destination_ports": 1,
            "outbound_enriched_aggs": 0,
            "inbound_enriched_aggs": 0,
            "observed_packets_sent": None,
            "observed_packets_received": None,
            "observed_bytes_sent": None,
            "observed_bytes_received": None,
            "first_observed": None,
            "last_observed": None,
        },
    ]

    mock_tx.run.side_effect = [mock_count, mock_page]
    items, total = repo.get_endpoints_analytics(sort_by="fan_out", limit=10, offset=0)
    assert total == 2
    assert len(items) == 2
    assert items[0]["address"] == "10.0.0.1"
    assert items[0]["traffic_metrics_mode"] == "enriched"
    assert items[0]["distinct_outbound_peers"] == 3
    assert items[1]["traffic_metrics_mode"] == "basic"


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
    """Verify list_communications with parameters and sort options."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    mock_count = MagicMock()
    mock_count.single.return_value = {"total": 1}

    mock_page = [
        {
            "source_ip": "10.0.0.1",
            "target_ip": "10.0.0.2",
            "protocol": "TLS",
            "flow_key": "f" * 64,
            "src_port": 50000,
            "dst_port": 443,
            "observed_packet_count": 10,
            "observed_bytes": 2500,
            "first_seen": 100.0,
            "last_seen": 105.0,
            "observed_window_seconds": 5.0,
        }
    ]
    mock_tx.run.side_effect = [mock_count, mock_page]

    items, total = repo.list_communications(
        source_ip="10.0.0.1",
        target_ip="10.0.0.2",
        protocol="tls",
        src_port=50000,
        dst_port=443,
        sort_by="observed_bytes",
    )
    assert total == 1
    assert items[0]["source_ip"] == "10.0.0.1"
    assert items[0]["flow_key"] == "f" * 64
    assert items[0]["src_port"] == 50000
    assert items[0]["dst_port"] == 443
    assert items[0]["observed_bytes"] == 2500


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


def test_list_traffic_alert_correlations_parallel_distinguishability(mock_driver_and_tx):
    """Verify list_traffic_alert_correlations returns traffic_flow_key and ports for parallel flows."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    mock_count = MagicMock()
    mock_count.single.return_value = {"total": 2}

    mock_page = [
        {
            "source_ip": "10.0.0.1",
            "target_ip": "10.0.0.2",
            "traffic_protocol": "TLS",
            "traffic_flow_key": "1" * 64,
            "traffic_src_port": 50001,
            "traffic_dst_port": 443,
            "fact_key": "a" * 64,
            "sid": 1001,
            "message": "TLS Alert",
            "priority": 1,
            "alert_protocol": "TCP",
        },
        {
            "source_ip": "10.0.0.1",
            "target_ip": "10.0.0.2",
            "traffic_protocol": "TLS",
            "traffic_flow_key": "2" * 64,
            "traffic_src_port": 50002,
            "traffic_dst_port": 443,
            "fact_key": "a" * 64,
            "sid": 1001,
            "message": "TLS Alert",
            "priority": 1,
            "alert_protocol": "TCP",
        },
    ]

    mock_tx.run.side_effect = [mock_count, mock_page]
    items, total = repo.list_traffic_alert_correlations(limit=10, offset=0)
    assert total == 2
    assert len(items) == 2
    assert items[0]["traffic_flow_key"] == "1" * 64
    assert items[1]["traffic_flow_key"] == "2" * 64
    assert items[0]["traffic_src_port"] == 50001
    assert items[1]["traffic_src_port"] == 50002


def test_get_neighborhood_parallel_same_protocol_edges(mock_driver_and_tx):
    """Verify get_neighborhood preserves distinct parallel COMMUNICATED_TO edges with different flow_key."""
    mock_driver, _, mock_tx = mock_driver_and_tx
    repo = Neo4jReadRepository(mock_driver)

    mock_check = MagicMock()
    mock_check.single.return_value = {"c": 1}

    mock_depth1_record = {
        "out_ips": [{"id": "ip:10.0.0.2", "type": "IPAddress", "value": "10.0.0.2"}],
        "in_ips": [],
        "l2_nodes": [],
        "out_edges": [
            {
                "source": "ip:10.0.0.1",
                "target": "ip:10.0.0.2",
                "type": "COMMUNICATED_TO",
                "protocol": "TLS",
                "flow_key": "1" * 64,
                "src_port": 50001,
                "dst_port": 443,
                "observed_packet_count": 5,
                "observed_bytes": 1000,
                "first_seen": 100.0,
                "last_seen": 102.0,
                "observed_window_seconds": 2.0,
            },
            {
                "source": "ip:10.0.0.1",
                "target": "ip:10.0.0.2",
                "type": "COMMUNICATED_TO",
                "protocol": "TLS",
                "flow_key": "2" * 64,
                "src_port": 50002,
                "dst_port": 443,
                "observed_packet_count": 8,
                "observed_bytes": 1600,
                "first_seen": 103.0,
                "last_seen": 105.0,
                "observed_window_seconds": 2.0,
            },
        ],
        "in_edges": [],
        "l2_edges": [],
    }
    mock_res = MagicMock()
    mock_res.single.return_value = mock_depth1_record
    mock_tx.run.side_effect = [mock_check, mock_res]

    neighborhood = repo.get_neighborhood("10.0.0.1", depth=1, max_nodes=10)
    assert neighborhood is not None
    assert len(neighborhood["edges"]) == 2
    assert neighborhood["edges"][0]["flow_key"] == "1" * 64
    assert neighborhood["edges"][1]["flow_key"] == "2" * 64


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
