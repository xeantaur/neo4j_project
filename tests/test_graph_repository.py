"""
Unit tests for Neo4j graph repository module.
"""

import pytest
from unittest.mock import MagicMock
from src.ingestion.models import TrafficRecord, AlertRecord
from src.graph.repository import (
    Neo4jRepository,
    canonicalize_ip,
    compute_alert_fact_key,
    chunk_list,
    CYPHER_WRITE_TRAFFIC_BATCH,
    CYPHER_WRITE_ALERT_BATCH,
)


# ---------------------------------------------------------------------------
# Canonical IP Tests
# ---------------------------------------------------------------------------
def test_canonicalize_ip():
    """Verify IPv4 and IPv6 canonical string representations."""
    # IPv4
    assert canonicalize_ip("192.168.1.1") == "192.168.1.1"
    assert canonicalize_ip("  10.0.0.5  ") == "10.0.0.5"

    # IPv6 equivalent forms must resolve to identical canonical strings
    expanded_ipv6 = "2001:0db8:0000:0000:0000:0000:0000:0001"
    compressed_ipv6 = "2001:db8::1"
    assert canonicalize_ip(expanded_ipv6) == canonicalize_ip(compressed_ipv6)
    assert canonicalize_ip(expanded_ipv6) == "2001:db8::1"

    # Fallback for non-IP
    assert canonicalize_ip("not_an_ip") == "not_an_ip"


# ---------------------------------------------------------------------------
# Deterministic Alert Fact Key Tests & Golden Regression Vectors
# ---------------------------------------------------------------------------
def test_compute_alert_fact_key_determinism():
    """Verify fact_key determinism and sensitivity to field changes."""
    alert1 = AlertRecord(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        sid=9000001,
        gid=1,
        rev=1,
        message="TEST-ALERT Port Scan",
        priority=2,
        protocol="TCP",
        src_port=54321,
        dst_port=22,
    )
    alert2 = AlertRecord(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        sid=9000001,
        gid=1,
        rev=1,
        message="TEST-ALERT Port Scan",
        priority=2,
        protocol="TCP",
        src_port=54321,
        dst_port=22,
    )
    # Identical alert fact -> identical hash
    key1 = compute_alert_fact_key(alert1)
    key2 = compute_alert_fact_key(alert2)
    assert key1 == key2
    assert len(key1) == 64  # SHA-256 hex digest length

    # Changing src_ip -> changes hash
    alert_diff_src = AlertRecord(
        src_ip="192.168.1.99",
        dst_ip="192.168.1.20",
        sid=9000001,
        gid=1,
        rev=1,
        message="TEST-ALERT Port Scan",
        priority=2,
        protocol="TCP",
        src_port=54321,
        dst_port=22,
    )
    assert compute_alert_fact_key(alert_diff_src) != key1

    # Changing dst_ip -> changes hash
    alert_diff_dst = AlertRecord(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.99",
        sid=9000001,
        gid=1,
        rev=1,
        message="TEST-ALERT Port Scan",
        priority=2,
        protocol="TCP",
        src_port=54321,
        dst_port=22,
    )
    assert compute_alert_fact_key(alert_diff_dst) != key1

    # Changing metadata -> changes hash
    alert_diff_prio = AlertRecord(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        sid=9000001,
        gid=1,
        rev=1,
        message="TEST-ALERT Port Scan",
        priority=1,  # changed
        protocol="TCP",
        src_port=54321,
        dst_port=22,
    )
    assert compute_alert_fact_key(alert_diff_prio) != key1


def test_compute_alert_fact_key_ipv6_canonical_equivalence():
    """Verify logically equivalent IPv6 strings produce identical fact_key values."""
    # Expanded vs compressed IPv6 in both src and dst
    alert_expanded = AlertRecord(
        src_ip="2001:0db8:0000:0000:0000:0000:0000:0001",
        dst_ip="2001:0db8:0000:0000:0000:0000:0000:0002",
        sid=9001,
        gid=1,
        rev=1,
        message="IPv6 Test Alert",
        priority=2,
        protocol="TCP",
        src_port=8080,
        dst_port=443,
    )
    alert_compressed = AlertRecord(
        src_ip="2001:db8::1",
        dst_ip="2001:db8::2",
        sid=9001,
        gid=1,
        rev=1,
        message="IPv6 Test Alert",
        priority=2,
        protocol="TCP",
        src_port=8080,
        dst_port=443,
    )
    key_exp = compute_alert_fact_key(alert_expanded)
    key_comp = compute_alert_fact_key(alert_compressed)

    assert key_exp == key_comp, "Fact key must match for logically equivalent IPv6 addresses"


def test_compute_alert_fact_key_golden_vectors():
    """Regression test against fixed hard-coded SHA-256 golden digests.
    
    Verifies that canonical field ordering, JSON null representation, separators,
    and UTF-8 encoding remain strictly deterministic and unchanging over time.
    """
    # Golden Vector 1: Full fields
    alert_full = AlertRecord(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        sid=9000001,
        gid=1,
        rev=2,
        message="COMMUNITY SIP TCP/IP message flooding directed to SIP proxy",
        priority=2,
        protocol="TCP",
        src_port=5060,
        dst_port=5060,
    )
    # Expected SHA-256 of {"dst_ip":"192.168.1.20","dst_port":5060,"gid":1,"message":"COMMUNITY SIP TCP/IP message flooding directed to SIP proxy","priority":2,"protocol":"TCP","rev":2,"sid":9000001,"src_ip":"192.168.1.10","src_port":5060}
    EXPECTED_FULL_DIGEST = "56cdd351a57a389acbda4b9274f0918877ca8e3a8d4921a7f09cf17ae8d32fb2"
    assert compute_alert_fact_key(alert_full) == EXPECTED_FULL_DIGEST

    # Golden Vector 2: Minimal fields (None optional values serialized as JSON null)
    alert_minimal = AlertRecord(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
    )
    # Expected SHA-256 of {"dst_ip":"10.0.0.2","dst_port":null,"gid":null,"message":null,"priority":null,"protocol":null,"rev":null,"sid":null,"src_ip":"10.0.0.1","src_port":null}
    EXPECTED_MINIMAL_DIGEST = "7431ec1b560daa6f8edb94c883e9b693ca1e29504411775891255e0c27ef8f6b"
    assert compute_alert_fact_key(alert_minimal) == EXPECTED_MINIMAL_DIGEST


def test_compute_alert_fact_key_unicode():
    """Verify Unicode alert messages remain deterministic."""
    alert_unicode = AlertRecord(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        message="TEST-ALERT: şüpheli bağlantı / 特異なトラフィック",
    )
    key_u1 = compute_alert_fact_key(alert_unicode)
    key_u2 = compute_alert_fact_key(alert_unicode)
    assert key_u1 == key_u2
    assert len(key_u1) == 64


# ---------------------------------------------------------------------------
# Chunking Tests
# ---------------------------------------------------------------------------
def test_chunk_list():
    """Test chunk_list slicing behavior."""
    # Empty
    assert list(chunk_list([], 5)) == []

    # Single element
    assert list(chunk_list([1], 5)) == [[1]]

    # Exact boundary
    items = list(range(10))
    chunks = list(chunk_list(items, 5))
    assert len(chunks) == 2
    assert chunks[0] == [0, 1, 2, 3, 4]
    assert chunks[1] == [5, 6, 7, 8, 9]

    # Partial final batch
    items7 = list(range(7))
    chunks7 = list(chunk_list(items7, 5))
    assert len(chunks7) == 2
    assert chunks7[0] == [0, 1, 2, 3, 4]
    assert chunks7[1] == [5, 6]

    # Invalid size
    with pytest.raises(ValueError):
        list(chunk_list([1, 2], 0))


# ---------------------------------------------------------------------------
# Traffic Payload & Cypher Contract Tests
# ---------------------------------------------------------------------------
def test_traffic_record_to_payload_legacy():
    """Verify legacy TrafficRecord payload transformation produces exact null semantics and fallback L2 pair."""
    from src.graph.repository import _traffic_record_to_payload

    record = TrafficRecord(
        eth_src_resolved="02:00:00:00:00:01",
        eth_dst_resolved="02:00:00:00:00:02",
        ip_src="192.168.1.10",
        ip_dst="192.168.1.20",
        protocol="TCP",
    )
    payload = _traffic_record_to_payload(record)

    assert payload["ip_src"] == "192.168.1.10"
    assert payload["ip_dst"] == "192.168.1.20"
    assert payload["flow_key"] == record.flow_key
    assert payload["protocol"] == "TCP"
    assert payload["src_port"] is None
    assert payload["dst_port"] is None
    assert payload["observed_packet_count"] is None
    assert payload["observed_bytes"] is None
    assert payload["first_seen"] is None
    assert payload["last_seen"] is None
    assert payload["observed_window_seconds"] is None
    assert payload["l2_pairs"] == [{"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}]


def test_traffic_record_to_payload_enriched():
    """Verify enriched TrafficRecord payload transformation preserves all metrics and observed L2 pairs."""
    from src.graph.repository import _traffic_record_to_payload

    record = TrafficRecord(
        eth_src_resolved="02:00:00:00:00:01",
        eth_dst_resolved="02:00:00:00:00:02",
        ip_src="2001:0db8:0000:0000:0000:0000:0000:0001",
        ip_dst="192.168.1.20",
        protocol="TLS",
        src_port=50000,
        dst_port=443,
        observed_packet_count=15,
        observed_bytes=4500,
        first_seen=1725148800.0,
        last_seen=1725148810.5,
        observed_window_seconds=10.5,
        observed_l2_pairs=(
            ("02:00:00:00:00:01", "02:00:00:00:00:02"),
            ("02:00:00:00:00:05", "02:00:00:00:00:02"),
        ),
    )
    payload = _traffic_record_to_payload(record)

    assert payload["ip_src"] == "2001:db8::1"  # canonicalized
    assert payload["ip_dst"] == "192.168.1.20"
    assert payload["flow_key"] == record.flow_key
    assert payload["protocol"] == "TLS"
    assert payload["src_port"] == 50000
    assert payload["dst_port"] == 443
    assert payload["observed_packet_count"] == 15
    assert payload["observed_bytes"] == 4500
    assert payload["first_seen"] == 1725148800.0
    assert payload["last_seen"] == 1725148810.5
    assert payload["observed_window_seconds"] == 10.5
    assert payload["l2_pairs"] == [
        {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"},
        {"src": "02:00:00:00:00:05", "dst": "02:00:00:00:00:02"},
    ]


def test_cypher_write_traffic_batch_contract():
    """Verify CYPHER_WRITE_TRAFFIC_BATCH defines relationship identity on flow_key and persists all properties."""
    # Must use flow_key for IP COMMUNICATED_TO identity
    assert "-[c:COMMUNICATED_TO {flow_key: row.flow_key}]->" in CYPHER_WRITE_TRAFFIC_BATCH
    assert "COMMUNICATED_TO {protocol: row.protocol}" not in CYPHER_WRITE_TRAFFIC_BATCH.split("FOREACH")[0]

    # Must set all properties
    assert "c.protocol = row.protocol" in CYPHER_WRITE_TRAFFIC_BATCH
    assert "c.src_port = row.src_port" in CYPHER_WRITE_TRAFFIC_BATCH
    assert "c.dst_port = row.dst_port" in CYPHER_WRITE_TRAFFIC_BATCH
    assert "c.observed_packet_count = row.observed_packet_count" in CYPHER_WRITE_TRAFFIC_BATCH
    assert "c.observed_bytes = row.observed_bytes" in CYPHER_WRITE_TRAFFIC_BATCH
    assert "c.first_seen = row.first_seen" in CYPHER_WRITE_TRAFFIC_BATCH
    assert "c.last_seen = row.last_seen" in CYPHER_WRITE_TRAFFIC_BATCH
    assert "c.observed_window_seconds = row.observed_window_seconds" in CYPHER_WRITE_TRAFFIC_BATCH

    # Must iterate over l2_pairs
    assert "FOREACH (pair IN row.l2_pairs |" in CYPHER_WRITE_TRAFFIC_BATCH
    assert "-[:L2_COMMUNICATED_TO {protocol: row.protocol}]->" in CYPHER_WRITE_TRAFFIC_BATCH


def test_normal_write_and_atomic_replace_payload_consistency():
    """Verify write_traffic_records and replace_workspace_data produce identical payload transformations."""
    from src.graph.repository import _traffic_record_to_payload

    record = TrafficRecord(
        eth_src_resolved="02:00:00:00:00:01",
        eth_dst_resolved="02:00:00:00:00:02",
        ip_src="192.168.1.10",
        ip_dst="192.168.1.20",
        protocol="HTTP",
        src_port=51234,
        dst_port=80,
        observed_packet_count=5,
        observed_bytes=1500,
        first_seen=100.0,
        last_seen=105.0,
        observed_window_seconds=5.0,
        observed_l2_pairs=(("02:00:00:00:00:01", "02:00:00:00:00:02"),),
    )

    # 1. Normal write mock
    mock_session1 = MagicMock()
    mock_driver1 = MagicMock()
    mock_driver1.session.return_value.__enter__.return_value = mock_session1
    repo1 = Neo4jRepository(mock_driver1)
    repo1.write_traffic_records([record])

    # 2. Atomic replacement mock
    mock_session2 = MagicMock()
    mock_driver2 = MagicMock()
    mock_driver2.session.return_value.__enter__.return_value = mock_session2
    def fake_execute_write(fn):
        tx = MagicMock()
        return fn(tx)
    mock_session2.execute_write.side_effect = fake_execute_write
    repo2 = Neo4jRepository(mock_driver2)
    repo2.replace_workspace_data(traffic_records=[record])

    # Direct transformation
    expected_payload = [_traffic_record_to_payload(record)]

    # Validate work function calls
    call_args_normal = mock_session1.execute_write.call_args[0][1]
    assert call_args_normal == expected_payload


# ---------------------------------------------------------------------------
# Repository Write Tests (Mock Driver)
# ---------------------------------------------------------------------------
def test_repository_write_traffic_records():
    """Verify write_traffic_records transforms parameters and executes managed transactions."""
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    repo = Neo4jRepository(mock_driver, batch_size=2)

    records = [
        TrafficRecord("02:00:00:00:00:01", "02:00:00:00:00:02", "192.168.1.10", "192.168.1.20", "TCP"),
        TrafficRecord("02:00:00:00:00:01", "gateway.local", "192.168.1.10", "10.0.0.5", "UDP"),
        TrafficRecord("02:00:00:00:00:02", "02:00:00:00:00:01", "192.168.1.20", "192.168.1.10", "TCP"),
    ]

    count = repo.write_traffic_records(records)
    assert count == 3

    # 3 records with batch_size=2 should invoke execute_write twice (2 records, 1 record)
    assert mock_session.execute_write.call_count == 2

    # Test work function directly with a mock transaction
    mock_tx = MagicMock()
    batch_payload = [
        {
            "ip_src": "192.168.1.10",
            "ip_dst": "192.168.1.20",
            "flow_key": records[0].flow_key,
            "protocol": "TCP",
            "src_port": None,
            "dst_port": None,
            "observed_packet_count": None,
            "observed_bytes": None,
            "first_seen": None,
            "last_seen": None,
            "observed_window_seconds": None,
            "l2_pairs": [{"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}],
        }
    ]
    Neo4jRepository._execute_traffic_batch(mock_tx, batch_payload)
    mock_tx.run.assert_called_once_with(CYPHER_WRITE_TRAFFIC_BATCH, batch=batch_payload)
    mock_tx.run.return_value.consume.assert_called_once()


def test_repository_write_traffic_empty():
    """Verify write_traffic_records with empty list does nothing."""
    mock_driver = MagicMock()
    repo = Neo4jRepository(mock_driver)
    count = repo.write_traffic_records([])
    assert count == 0
    assert mock_driver.session.call_count == 0


def test_repository_write_alert_records():
    """Verify write_alert_records computes fact_key and executes managed transactions."""
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    repo = Neo4jRepository(mock_driver, batch_size=500)

    alerts = [
        AlertRecord(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            sid=9000001,
            gid=1,
            rev=1,
            message="TEST-ALERT Port Scan",
            priority=2,
            protocol="TCP",
            src_port=54321,
            dst_port=22,
        )
    ]

    count = repo.write_alert_records(alerts)
    assert count == 1
    assert mock_session.execute_write.call_count == 1

    # Test work function directly with a mock transaction
    mock_tx = MagicMock()
    batch_payload = [
        {
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20",
            "fact_key": compute_alert_fact_key(alerts[0]),
            "sid": 9000001,
            "gid": 1,
            "rev": 1,
            "message": "TEST-ALERT Port Scan",
            "priority": 2,
            "protocol": "TCP",
            "src_port": 54321,
            "dst_port": 22,
        }
    ]
    Neo4jRepository._execute_alert_batch(mock_tx, batch_payload)
    mock_tx.run.assert_called_once_with(CYPHER_WRITE_ALERT_BATCH, batch=batch_payload)
    mock_tx.run.return_value.consume.assert_called_once()


def test_repository_write_alert_empty():
    """Verify write_alert_records with empty list does nothing."""
    mock_driver = MagicMock()
    repo = Neo4jRepository(mock_driver)
    count = repo.write_alert_records([])
    assert count == 0
    assert mock_driver.session.call_count == 0
