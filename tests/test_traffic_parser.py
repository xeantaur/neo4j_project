"""
Unit tests for network traffic parser (TSV).

Validates both legacy 7-column formats and project-defined enriched tshark
TSV export profiles, including flow aggregation, deterministic flow_key,
IPv4/IPv6 coalescing, duplicate tracking, and diagnostics.
"""

import math
import pytest

from src.ingestion.traffic_parser import (
    parse_traffic_file,
    _normalize_mac_or_identifier,
    _is_valid_ip,
    _parse_port,
)
from src.ingestion.models import TrafficRecord, compute_flow_key, canonicalize_ip


# ============================================================================
# 1. Helper & Unit Functions Tests
# ============================================================================

def test_mac_normalization_and_preservation():
    """Test MAC normalization for canonical formats and preservation for resolved names."""
    assert _normalize_mac_or_identifier("02:00:00:AA:BB:CC") == "02:00:00:aa:bb:cc"
    assert _normalize_mac_or_identifier("02-00-00-AA-BB-CC") == "02:00:00:aa:bb:cc"
    assert _normalize_mac_or_identifier("02-00-00-aa-bb-cc") == "02:00:00:aa:bb:cc"
    assert _normalize_mac_or_identifier("gateway.local") == "gateway.local"
    assert _normalize_mac_or_identifier("Broadcast") == "Broadcast"
    assert _normalize_mac_or_identifier("  router-core.net  ") == "router-core.net"


def test_is_valid_ip():
    """Test IPv4 and IPv6 validation."""
    assert _is_valid_ip("192.168.1.1") is True
    assert _is_valid_ip("10.0.0.1") is True
    assert _is_valid_ip("2001:db8::1") is True
    assert _is_valid_ip("999.999.999.999") is False
    assert _is_valid_ip("not_an_ip") is False
    assert _is_valid_ip("") is False
    assert _is_valid_ip(None) is False


def test_parse_port_validation():
    """Test port parsing helper across valid and invalid boundaries."""
    assert _parse_port("80") == 80
    assert _parse_port("443") == 443
    assert _parse_port("1") == 1
    assert _parse_port("65535") == 65535
    assert _parse_port("") is None
    assert _parse_port("   ") is None
    assert _parse_port("-") is None
    assert _parse_port("0") == -1       # out of range (0)
    assert _parse_port("65536") == -1   # out of range (>65535)
    assert _parse_port("-5") == -1      # out of range (<0)
    assert _parse_port("abc") == -2     # malformed non-integer


# ============================================================================
# 2. Legacy / Basic Mode Tests
# ============================================================================

def test_parse_sample_traffic_file():
    """Test parsing the project's synthetic sample traffic file in legacy mode."""
    records, summary = parse_traffic_file("data/samples/sample_traffic.tsv")
    assert len(records) > 0
    assert summary.valid_records == len(records)
    assert summary.total_raw_records == summary.valid_records + summary.skipped_records + summary.duplicate_records
    assert summary.duplicate_records >= 1

    first = records[0]
    assert isinstance(first, TrafficRecord)
    assert first.eth_src_resolved == "02:00:00:00:00:01"
    assert first.ip_src == "192.168.1.10"
    assert first.src_port is None
    assert first.dst_port is None
    assert first.observed_packet_count is None
    assert first.observed_bytes is None
    assert first.first_seen is None
    assert first.last_seen is None
    assert first.observed_window_seconds is None
    assert isinstance(first.flow_key, str)
    assert len(first.flow_key) == 64


def test_parse_traffic_whitespace_and_duplicates(tmp_path):
    """Test whitespace trimming and duplicate removal in legacy mode."""
    tsv_content = (
        "  02:00:00:00:00:01  \t  02:00:00:00:00:02  \t  192.168.1.10  \t  192.168.1.20  \t-\t-\t  tcp  \n"
        "02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\t-\t-\tTCP\n"
    )
    test_file = tmp_path / "traffic_dup.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 1
    assert summary.total_raw_records == 2
    assert summary.duplicate_records == 1
    assert summary.total_raw_records == summary.valid_records + summary.skipped_records + summary.duplicate_records
    assert records[0].protocol == "TCP"
    assert records[0].eth_src_resolved == "02:00:00:00:00:01"


def test_parse_traffic_empty_and_invalid_ips(tmp_path):
    """Test filtering of legacy rows with missing or invalid IP addresses."""
    tsv_content = (
        # Row 0: Valid
        "02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\t-\t-\tTCP\n"
        # Row 1: Empty ip_src
        "02:00:00:00:00:01\t02:00:00:00:00:02\t\t192.168.1.20\t-\t-\tTCP\n"
        # Row 2: Invalid ip_dst
        "02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t300.300.300.300\t-\t-\tTCP\n"
        # Row 3: Empty eth_src
        "\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\t-\t-\tTCP\n"
    )
    test_file = tmp_path / "traffic_invalid.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 1
    assert summary.total_raw_records == 4
    assert summary.skipped_records == 3
    assert "empty_ip" in summary.warning_counts
    assert "invalid_ip_dst" in summary.warning_counts
    assert "empty_mac_or_identifier" in summary.warning_counts


def test_parse_traffic_malformed_columns_too_few_and_too_many(tmp_path):
    """Test explicit counting of legacy rows with too few OR too many columns."""
    tsv_content = (
        # Row 0: Valid (7 columns)
        "02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\t-\t-\tTCP\n"
        # Row 1: Too few columns (only 3 columns)
        "02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\n"
        # Row 2: Too many columns (9 columns)
        "02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\t-\t-\tTCP\textra1\textra2\n"
        # Row 3: Valid (7 columns)
        "02:00:00:00:00:01\t02:00:00:00:00:03\t192.168.1.10\t10.0.0.5\t-\t-\tUDP\n"
    )
    test_file = tmp_path / "traffic_malformed_counts.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 2
    assert summary.total_raw_records == 4
    assert summary.skipped_records == 2
    assert summary.valid_records == 2
    assert summary.duplicate_records == 0
    assert summary.warning_counts["malformed_columns"] == 2


def test_parse_traffic_missing_file():
    """Test that non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        parse_traffic_file("data/samples/non_existent_file_xyz.tsv")


def test_parse_traffic_headered_with_index_0(tmp_path):
    """Regression test: verify headered legacy TSV parses correctly."""
    tsv_content = (
        "eth_src_resolved\teth_dst_resolved\tip_src\tip_dst\tunused1\tunused2\tprotocol\n"
        "02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\t-\t-\tTCP\n"
        "02:00:00:00:00:01\t02:00:00:00:00:03\t192.168.1.10\t192.168.1.30\t-\t-\tUDP\n"
    )
    test_file = tmp_path / "traffic_headered.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 2
    assert summary.total_raw_records == 2
    assert summary.valid_records == 2
    assert summary.skipped_records == 0
    assert summary.duplicate_records == 0


def test_legacy_ipv6_and_mismatched_version(tmp_path):
    """Test IPv6 canonicalization and mismatched IPv4/IPv6 version rejection in legacy mode."""
    tsv_content = (
        # Row 0: Valid IPv6
        "02:00:00:00:00:01\t02:00:00:00:00:02\t2001:0db8:0000:0000:0000:0000:0000:0001\t2001:0db8:0000:0000:0000:0000:0000:0002\t-\t-\tTCP\n"
        # Row 1: Mismatched IPv4 source and IPv6 destination
        "02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t2001:db8::2\t-\t-\tTCP\n"
    )
    test_file = tmp_path / "traffic_legacy_v6.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 1
    assert summary.total_raw_records == 2
    assert summary.skipped_records == 1
    assert "mismatched_ip_version" in summary.warning_counts
    assert records[0].ip_src == "2001:db8::1"
    assert records[0].ip_dst == "2001:db8::2"


# ============================================================================
# 3. Enriched Mode — Profile Header Detection & Validation
# ============================================================================

def test_enriched_complete_header_detection_and_parsing(tmp_path):
    """Test full enriched tshark export profile parsing and flow aggregation."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\t_ws.col.Protocol\ttcp.srcport\ttcp.dstport\n"
        "1725148800.100\t64\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\tTCP\t50000\t443\n"
        "1725148800.200\t128\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\tTCP\t50000\t443\n"
    )
    test_file = tmp_path / "enriched_basic.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 1
    assert summary.total_raw_records == 2
    assert summary.valid_records == 1
    assert summary.skipped_records == 0
    assert summary.duplicate_records == 0

    r = records[0]
    assert r.ip_src == "192.168.1.10"
    assert r.ip_dst == "192.168.1.20"
    assert r.protocol == "TCP"
    assert r.src_port == 50000
    assert r.dst_port == 443
    assert r.observed_packet_count == 2
    assert r.observed_bytes == 192  # 64 + 128
    assert r.first_seen == 1725148800.100
    assert r.last_seen == 1725148800.200
    assert math.isclose(r.observed_window_seconds, 0.100, rel_tol=1e-5)


def test_enriched_partial_header_raises_fatal_error(tmp_path):
    """Test that an incomplete enriched header raises ValueError and does NOT silently fall back to basic mode."""
    # Has frame.len and tcp.dstport (markers) but missing required frame.time_epoch
    tsv_content = (
        "frame.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.dstport\n"
        "64\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\tTCP\t443\n"
    )
    test_file = tmp_path / "enriched_incomplete.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    with pytest.raises(ValueError, match="Incomplete enriched traffic profile: missing required headers: frame.time_epoch"):
        parse_traffic_file(str(test_file))


def test_enriched_missing_frame_len_raises_fatal_error(tmp_path):
    """Test that frame.time_epoch without frame.len is also a fatal error."""
    tsv_content = (
        "frame.time_epoch\teth.src\teth.dst\tip.src\tip.dst\tprotocol\n"
        "1725148800.0\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\tTCP\n"
    )
    test_file = tmp_path / "enriched_missing_len.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    with pytest.raises(ValueError, match="missing required headers: frame.len"):
        parse_traffic_file(str(test_file))


# ============================================================================
# 4. Enriched Mode — IPv4 / IPv6 Coalescing & Canonicalization
# ============================================================================

def test_enriched_ipv4_and_ipv6_coalescing(tmp_path):
    """Test coalescing of IPv4 and IPv6 columns in enriched mode."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tipv6.src\tipv6.dst\tprotocol\n"
        "100.0\t64\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.1\t192.168.1.2\t\t\tTCP\n"
        "101.0\t80\t02:00:00:00:00:01\t02:00:00:00:00:02\t\t\t2001:0db8::1\t2001:0db8::2\tTCP\n"
    )
    test_file = tmp_path / "enriched_coalesce.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 2
    assert summary.valid_records == 2
    assert records[0].ip_src == "192.168.1.1"
    assert records[0].ip_dst == "192.168.1.2"
    assert records[1].ip_src == "2001:db8::1"
    assert records[1].ip_dst == "2001:db8::2"


def test_enriched_ambiguous_simultaneous_ip_skipped(tmp_path):
    """Test that rows with both IPv4 and IPv6 simultaneously populated are warned and skipped."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tipv6.src\tipv6.dst\tprotocol\n"
        "100.0\t64\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.1\t192.168.1.2\t2001:db8::1\t\tTCP\n"
    )
    test_file = tmp_path / "enriched_ambig_ip.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 0
    assert summary.skipped_records == 1
    assert "ambiguous_ip_source" in summary.warning_counts


# ============================================================================
# 5. Enriched Mode — Ports & Protocols
# ============================================================================

def test_enriched_udp_ports_and_non_tcp_udp(tmp_path):
    """Test UDP port extraction and nullable ports for protocols like ICMP."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\n"
        "100.0\t60\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tUDP\t\t\t5353\t53\n"
        "101.0\t40\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tICMP\t\t\t\t\n"
    )
    test_file = tmp_path / "enriched_udp_icmp.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 2
    assert summary.valid_records == 2

    udp_rec = next(r for r in records if r.protocol == "UDP")
    assert udp_rec.src_port == 5353
    assert udp_rec.dst_port == 53

    icmp_rec = next(r for r in records if r.protocol == "ICMP")
    assert icmp_rec.src_port is None
    assert icmp_rec.dst_port is None


def test_enriched_ambiguous_transport_ports_skipped(tmp_path):
    """Test that rows with both TCP and UDP ports populated simultaneously are skipped."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\n"
        "100.0\t60\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t80\t5353\t53\n"
    )
    test_file = tmp_path / "enriched_ambig_ports.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 0
    assert summary.skipped_records == 1
    assert "ambiguous_transport_ports" in summary.warning_counts


def test_enriched_invalid_ports_rejected(tmp_path):
    """Test rejection of port 0, port >65535, negative, and malformed port strings."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\n"
        # Row 1: Port 0
        "100.0\t60\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t0\t80\n"
        # Row 2: Port 70000
        "101.0\t60\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t70000\n"
        # Row 3: Malformed port text
        "102.0\t60\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\tbadport\t80\n"
    )
    test_file = tmp_path / "enriched_invalid_ports.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 0
    assert summary.skipped_records == 3
    assert "invalid_src_port" in summary.warning_counts
    assert "invalid_dst_port" in summary.warning_counts


# ============================================================================
# 6. Enriched Mode — Timestamps & Frame Length Validation
# ============================================================================

def test_enriched_malformed_timestamps_skipped(tmp_path):
    """Test rejection of NaN, Inf, negative, and text timestamps."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\n"
        "NaN\t64\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\n"
        "inf\t64\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\n"
        "-10.5\t64\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\n"
        "not_a_time\t64\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\n"
    )
    test_file = tmp_path / "enriched_bad_times.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 0
    assert summary.skipped_records == 4
    assert summary.warning_counts["invalid_timestamp"] == 4


def test_enriched_malformed_frame_lengths_skipped(tmp_path):
    """Test rejection of zero, negative, float text, and malformed frame lengths."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\n"
        "100.0\t0\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\n"
        "101.0\t-64\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\n"
        "102.0\t64.5\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\n"
        "103.0\tbadlen\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\n"
    )
    test_file = tmp_path / "enriched_bad_len.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 0
    assert summary.skipped_records == 4
    assert summary.warning_counts["invalid_frame_length"] == 4


# ============================================================================
# 7. Duplicate Handling & Aggregation Semantics
# ============================================================================

def test_enriched_repeated_observations_without_frame_number(tmp_path):
    """Test that repeated rows WITHOUT frame.number are preserved as packet observations."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\n"
        "100.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t443\n"
        "100.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t443\n"
        "102.0\t150\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t443\n"
    )
    test_file = tmp_path / "enriched_repeat_no_fn.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 1
    assert summary.total_raw_records == 3
    assert summary.valid_records == 1
    assert summary.duplicate_records == 0

    r = records[0]
    assert r.observed_packet_count == 3
    assert r.observed_bytes == 350
    assert r.first_seen == 100.0
    assert r.last_seen == 102.0
    assert r.observed_window_seconds == 2.0


def test_enriched_frame_number_duplicate_tracking(tmp_path):
    """Test frame.number duplicate detection and conflicting reuse handling."""
    tsv_content = (
        "frame.number\tframe.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\n"
        # Frame 1: Valid initial packet
        "1\t100.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t443\n"
        # Frame 1: Exact duplicate source export row (should be skipped and counted in duplicate_records)
        "1\t100.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t443\n"
        # Frame 2: Valid packet
        "2\t101.0\t200\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t443\n"
        # Frame 2: Conflicting reuse of frame 2 with different data (should warn and skip)
        "2\t101.0\t999\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t443\n"
    )
    test_file = tmp_path / "enriched_fn_dup.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 1
    assert summary.total_raw_records == 4
    assert summary.duplicate_records == 1
    assert summary.skipped_records == 1
    assert "conflicting_frame_number" in summary.warning_counts

    r = records[0]
    assert r.observed_packet_count == 2  # Only Frame 1 and Frame 2
    assert r.observed_bytes == 300       # 100 + 200


def test_enriched_multiple_src_ports_produce_distinct_aggregates(tmp_path):
    """Test that different source ports to the same destination port produce distinct aggregates."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\n"
        "100.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50001\t443\n"
        "101.0\t150\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50002\t443\n"
    )
    test_file = tmp_path / "enriched_multi_srcport.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 2
    assert summary.valid_records == 2

    # Flow keys must be distinct
    assert records[0].flow_key != records[1].flow_key
    assert {r.src_port for r in records} == {50001, 50002}
    assert {r.dst_port for r in records} == {443}


def test_enriched_different_protocols_produce_distinct_aggregates(tmp_path):
    """Test that different protocol labels produce distinct aggregates and flow keys."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\n"
        "100.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50000\t443\n"
        "101.0\t150\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTLS\t50000\t443\n"
    )
    test_file = tmp_path / "enriched_diff_proto.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 2
    assert records[0].flow_key != records[1].flow_key
    assert {r.protocol for r in records} == {"TCP", "TLS"}


# ============================================================================
# 8. Deterministic flow_key Properties
# ============================================================================

def test_flow_key_properties():
    """Test deterministic flow_key generation across IP canonicalization and port changes."""
    # Canonical IP equivalence produces identical flow_key
    key1 = compute_flow_key("2001:0db8:0000:0000:0000:0000:0000:0001", "192.168.1.1", "TCP", 50000, 443)
    key2 = compute_flow_key("2001:db8::1", "192.168.1.1", "tcp", 50000, 443)
    assert key1 == key2

    # Different source ports produce different flow_key
    key3 = compute_flow_key("192.168.1.1", "192.168.1.2", "TCP", 50000, 443)
    key4 = compute_flow_key("192.168.1.1", "192.168.1.2", "TCP", 50001, 443)
    assert key3 != key4

    # None ports produce deterministic key
    key_null = compute_flow_key("192.168.1.1", "192.168.1.2", "ICMP", None, None)
    assert isinstance(key_null, str)
    assert len(key_null) == 64


# ============================================================================
# 9. L2 Aggregation & Unique flow_key Invariant Tests
# ============================================================================

def test_l2_aggregation_edge_case_same_5tuple_different_l2(tmp_path):
    """
    Test edge case where identical IP 5-tuple observations have different L2 addresses.

    Validates that:
    1. In-memory grouping produces EXACTLY ONE TrafficRecord for the canonical 5-tuple.
    2. Exactly ONE flow_key is produced.
    3. Packet counts, byte totals, and time windows aggregate across all L2 pairs.
    4. observed_l2_pairs contains all distinct (eth_src, eth_dst) associations sorted deterministically.
    5. Scalar eth_src_resolved and eth_dst_resolved contain the deterministic primary pair.
    """
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\n"
        # Observation 1: WiFi MAC
        "100.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\tTCP\t50000\t443\n"
        # Observation 2: Ethernet MAC for the same host & flow
        "105.0\t200\t02:00:00:00:00:05\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\tTCP\t50000\t443\n"
    )
    test_file = tmp_path / "enriched_l2_diff.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 1
    assert summary.valid_records == 1

    r = records[0]
    assert r.observed_packet_count == 2
    assert r.observed_bytes == 300
    assert r.first_seen == 100.0
    assert r.last_seen == 105.0
    assert r.observed_window_seconds == 5.0

    # Deterministic representative L2 pair
    assert r.eth_src_resolved == "02:00:00:00:00:01"
    assert r.eth_dst_resolved == "02:00:00:00:00:02"

    # All distinct observed L2 pairs captured in sorted order
    assert r.observed_l2_pairs == (
        ("02:00:00:00:00:01", "02:00:00:00:00:02"),
        ("02:00:00:00:00:05", "02:00:00:00:00:02"),
    )


def test_enriched_unique_flow_keys_invariant(tmp_path):
    """
    Test that every returned TrafficRecord in an enriched parse result has a UNIQUE flow_key.

    Tests multiple aggregates including same IP pair, same dst port, different src ports,
    and different L2 pairs.
    """
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\n"
        # Agg 1: Port 50001 with MAC 1
        "100.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50001\t443\n"
        # Agg 2: Port 50002 with MAC 1
        "101.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50002\t443\n"
        # Agg 1 continuation: Port 50001 with MAC 5 (merges into Agg 1!)
        "102.0\t150\t02:00:00:00:00:05\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50001\t443\n"
        # Agg 3: Port 50003 to port 80
        "103.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t50003\t80\n"
    )
    test_file = tmp_path / "enriched_unique_flowkeys.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 3
    assert summary.valid_records == 3

    # Invariant: Every record has a unique flow_key
    flow_keys = [r.flow_key for r in records]
    assert len(flow_keys) == len(set(flow_keys))

    # Verify Agg 1 merged both observations across L2 pairs
    agg1 = next(r for r in records if r.src_port == 50001)
    assert agg1.observed_packet_count == 2
    assert agg1.observed_bytes == 250
    assert len(agg1.observed_l2_pairs) == 2


# ============================================================================
# 10. Upper-Layer Protocols & Partial Port Pairs Tests
# ============================================================================

def test_enriched_upper_layer_protocols_preserve_transport_ports(tmp_path):
    """
    Test that transport ports are extracted based on transport columns,
    preserving upper-layer protocol/dissector labels (HTTP, TLS, DNS).
    """
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\n"
        # HTTP over TCP
        "100.0\t500\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\tHTTP\t51234\t80\t\t\n"
        # TLS over TCP
        "101.0\t600\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t192.168.1.20\tTLS\t51235\t443\t\t\n"
        # DNS over UDP
        "102.0\t120\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t10.0.0.100\tDNS\t\t\t51236\t53\n"
        # DNS over TCP
        "103.0\t180\t02:00:00:00:00:01\t02:00:00:00:00:02\t192.168.1.10\t10.0.0.100\tDNS\t51237\t53\t\t\n"
    )
    test_file = tmp_path / "enriched_upper_proto.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 4
    assert summary.valid_records == 4

    http_rec = next(r for r in records if r.protocol == "HTTP")
    assert http_rec.src_port == 51234
    assert http_rec.dst_port == 80

    tls_rec = next(r for r in records if r.protocol == "TLS")
    assert tls_rec.src_port == 51235
    assert tls_rec.dst_port == 443

    dns_udp = next(r for r in records if r.protocol == "DNS" and r.src_port == 51236)
    assert dns_udp.dst_port == 53

    dns_tcp = next(r for r in records if r.protocol == "DNS" and r.src_port == 51237)
    assert dns_tcp.dst_port == 53


def test_enriched_partial_port_pairs_allowed(tmp_path):
    """Test that observations with only source port or only destination port are preserved."""
    tsv_content = (
        "frame.time_epoch\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tprotocol\ttcp.srcport\ttcp.dstport\n"
        # Row 1: Source port only
        "100.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t49152\t\n"
        # Row 2: Destination port only
        "101.0\t100\t02:00:00:00:00:01\t02:00:00:00:00:02\t10.0.0.1\t10.0.0.2\tTCP\t\t443\n"
    )
    test_file = tmp_path / "enriched_partial_ports.tsv"
    test_file.write_text(tsv_content, encoding="utf-8")

    records, summary = parse_traffic_file(str(test_file))
    assert len(records) == 2
    assert summary.valid_records == 2

    r1 = next(r for r in records if r.src_port == 49152)
    assert r1.dst_port is None
    assert isinstance(r1.flow_key, str)

    r2 = next(r for r in records if r.dst_port == 443)
    assert r1.flow_key != r2.flow_key


def test_parse_sample_traffic_enriched_file():
    """Test parsing the permanent synthetic sample_traffic_enriched.tsv file."""
    records, summary = parse_traffic_file("data/samples/sample_traffic_enriched.tsv")
    assert summary.skipped_records == 0
    assert summary.duplicate_records == 0
    assert summary.valid_records == len(records)
    assert len(records) == 13

    # Total observed packet count matches raw rows (28)
    total_packets = sum(r.observed_packet_count for r in records)
    assert total_packets == 28
    assert summary.total_raw_records == 28

    # Total observed bytes matches sum of frame.len (19532)
    total_bytes = sum(r.observed_bytes for r in records)
    assert total_bytes == 19532

    # Verify flow keys are unique across returned aggregates
    flow_keys = [r.flow_key for r in records]
    assert len(set(flow_keys)) == len(records)

    # Parallel same-pair/same-protocol aggregates exist with distinct src ports
    tls_parallel = [
        r for r in records
        if r.ip_src == "192.168.1.10" and r.ip_dst == "192.168.1.20" and r.protocol == "TLS"
    ]
    assert len(tls_parallel) == 2
    src_ports = {r.src_port for r in tls_parallel}
    assert src_ports == {50000, 50001}

    # IPv6 aggregate exists
    ipv6_agg = next((r for r in records if r.ip_src == "2001:db8::10"), None)
    assert ipv6_agg is not None
    assert ipv6_agg.ip_dst == "2001:db8::20"

    # Non-TCP/UDP aggregate has null ports
    icmp_agg = next((r for r in records if r.protocol == "ICMP"), None)
    assert icmp_agg is not None
    assert icmp_agg.src_port is None
    assert icmp_agg.dst_port is None
