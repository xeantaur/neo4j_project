"""
Unit tests for network traffic parser (TSV).
"""

import pytest
from src.ingestion.traffic_parser import (
    parse_traffic_file,
    _normalize_mac_or_identifier,
    _is_valid_ip,
)
from src.ingestion.models import TrafficRecord


def test_mac_normalization_and_preservation():
    """Test MAC normalization for canonical formats and preservation for resolved names."""
    # Colon-separated uppercase
    assert _normalize_mac_or_identifier("02:00:00:AA:BB:CC") == "02:00:00:aa:bb:cc"
    # Dash-separated uppercase
    assert _normalize_mac_or_identifier("02-00-00-AA-BB-CC") == "02:00:00:aa:bb:cc"
    # Dash-separated lowercase
    assert _normalize_mac_or_identifier("02-00-00-aa-bb-cc") == "02:00:00:aa:bb:cc"
    # Resolved name preserved intact
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


def test_parse_sample_traffic_file():
    """Test parsing the project's synthetic sample traffic file."""
    records, summary = parse_traffic_file("data/samples/sample_traffic.tsv")
    assert len(records) > 0
    assert summary.valid_records == len(records)
    assert summary.total_raw_records == summary.valid_records + summary.skipped_records + summary.duplicate_records

    # Check that sample duplicate was handled
    assert summary.duplicate_records >= 1

    # Verify normalization on records
    first = records[0]
    assert isinstance(first, TrafficRecord)
    assert first.eth_src_resolved == "02:00:00:00:00:01"
    assert first.ip_src == "192.168.1.10"


def test_parse_traffic_whitespace_and_duplicates(tmp_path):
    """Test whitespace trimming and duplicate removal."""
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
    """Test filtering of rows with missing or invalid IP addresses."""
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
    assert summary.total_raw_records == summary.valid_records + summary.skipped_records + summary.duplicate_records
    assert "empty_ip" in summary.warning_counts
    assert "invalid_ip_dst" in summary.warning_counts
    assert "empty_mac_or_identifier" in summary.warning_counts


def test_parse_traffic_malformed_columns_too_few_and_too_many(tmp_path):
    """Test explicit counting of rows with too few OR too many columns without silent row loss."""
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
    # Internal metric consistency check
    assert summary.total_raw_records == summary.valid_records + summary.skipped_records + summary.duplicate_records
    assert summary.warning_counts["malformed_columns"] == 2


def test_parse_traffic_missing_file():
    """Test that non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        parse_traffic_file("data/samples/non_existent_file_xyz.tsv")
