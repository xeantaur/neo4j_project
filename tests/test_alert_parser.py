"""
Unit tests for IDS alert parser (JSON).
"""

import json
import pytest
from src.ingestion.alert_parser import (
    parse_alert_file,
    _validate_port,
    _validate_positive_int,
    _validate_non_negative_int,
)
from src.ingestion.models import AlertRecord


def test_validate_port():
    """Test port validation bounds."""
    assert _validate_port(80) == 80
    assert _validate_port("443") == 443
    assert _validate_port(1) == 1
    assert _validate_port(65535) == 65535
    assert _validate_port(0) is None
    assert _validate_port(65536) is None
    assert _validate_port(-1) is None
    assert _validate_port("invalid_port") is None
    assert _validate_port(None) is None


def test_validate_positive_and_non_negative_ints():
    """Test priority and sid/gid/rev semantic validation helpers."""
    # Priority requires strictly positive (> 0)
    assert _validate_positive_int(1) == 1
    assert _validate_positive_int("3") == 3
    assert _validate_positive_int(0) is None
    assert _validate_positive_int(-1) is None
    assert _validate_positive_int("invalid") is None

    # sid/gid/rev requires non-negative (>= 0)
    assert _validate_non_negative_int(0) == 0
    assert _validate_non_negative_int(9001) == 9001
    assert _validate_non_negative_int("0") == 0
    assert _validate_non_negative_int(-1) is None
    assert _validate_non_negative_int("-50") is None
    assert _validate_non_negative_int("not_a_number") is None


def test_parse_sample_alerts_file():
    """Test parsing the project's synthetic sample alert JSON file."""
    alerts, summary = parse_alert_file("data/samples/sample_alerts.json")
    assert len(alerts) == 3
    assert summary.valid_records == 3
    assert summary.skipped_records == 0

    first = alerts[0]
    assert isinstance(first, AlertRecord)
    assert first.src_ip == "192.168.1.10"
    assert first.dst_ip == "192.168.1.20"
    assert first.sid == 9000001
    assert first.priority == 2
    assert first.dst_port == 22


def test_alert_integer_coercion_and_optional_none(tmp_path):
    """Test string-to-int coercion and optional fields evaluating to None without guessing defaults."""
    data = [
        {
            # String numeric values
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "sid": "9001",
            "gid": "2",
            "rev": "3",
            "priority": "1",
            "protocol": "tcp",
            "src_port": "54321",
            "dst_port": "80",
            "message": "Test Alert with String Numbers",
        },
        {
            # Minimal alert with required fields only
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.200",
        }
    ]
    test_file = tmp_path / "alerts_coerce.json"
    test_file.write_text(json.dumps(data), encoding="utf-8")

    alerts, summary = parse_alert_file(str(test_file))
    assert len(alerts) == 2
    assert summary.valid_records == 2

    # Verify coercion
    a0 = alerts[0]
    assert a0.sid == 9001
    assert a0.gid == 2
    assert a0.rev == 3
    assert a0.priority == 1
    assert a0.protocol == "TCP"
    assert a0.src_port == 54321
    assert a0.dst_port == 80

    # Verify minimal alert optional fields are None (no invented defaults)
    a1 = alerts[1]
    assert a1.src_ip == "192.168.1.100"
    assert a1.dst_ip == "192.168.1.200"
    assert a1.sid is None
    assert a1.gid is None
    assert a1.rev is None
    assert a1.message is None
    assert a1.priority is None
    assert a1.protocol is None
    assert a1.src_port is None
    assert a1.dst_port is None


def test_alert_invalid_optional_fields_do_not_drop_record(tmp_path):
    """Test that invalid optional fields (port, priority, sid) become None and do NOT drop the record."""
    data = [
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 99999,      # invalid port (> 65535)
            "dst_port": "bad_port",  # invalid port string
            "priority": "invalid",   # invalid priority
            "sid": "not_an_int",     # invalid sid
            "message": "Alert with bad optional fields",
        }
    ]
    test_file = tmp_path / "alerts_invalid_opts.json"
    test_file.write_text(json.dumps(data), encoding="utf-8")

    alerts, summary = parse_alert_file(str(test_file))
    # Record must NOT be dropped
    assert len(alerts) == 1
    assert summary.valid_records == 1
    assert summary.skipped_records == 0

    a = alerts[0]
    assert a.src_ip == "10.0.0.1"
    assert a.dst_ip == "10.0.0.2"
    assert a.src_port is None
    assert a.dst_port is None
    assert a.priority is None
    assert a.sid is None
    assert a.message == "Alert with bad optional fields"
    assert "invalid_src_port" in summary.warning_counts


def test_alert_negative_and_zero_optional_integer_semantics(tmp_path):
    """Test semantic bounds: priority must be > 0, sid/gid/rev must be >= 0."""
    data = [
        {
            # Negative priority and negative sid/gid/rev
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "priority": -1,
            "sid": -100,
            "gid": -5,
            "rev": -1,
            "message": "Negative alert integer fields",
        },
        {
            # Zero priority (invalid) and zero sid/gid/rev (valid)
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.4",
            "priority": 0,
            "sid": 0,
            "gid": 0,
            "rev": 0,
            "message": "Zero alert integer fields",
        }
    ]
    test_file = tmp_path / "alerts_semantics.json"
    test_file.write_text(json.dumps(data), encoding="utf-8")

    alerts, summary = parse_alert_file(str(test_file))
    # Records must NOT be dropped
    assert len(alerts) == 2
    assert summary.valid_records == 2
    assert summary.skipped_records == 0

    a0 = alerts[0]
    assert a0.priority is None  # -1 is invalid for priority
    assert a0.sid is None       # -100 is invalid for sid
    assert a0.gid is None       # -5 is invalid for gid
    assert a0.rev is None       # -1 is invalid for rev

    a1 = alerts[1]
    assert a1.priority is None  # 0 is invalid for priority (> 0 required)
    assert a1.sid == 0          # 0 is valid for sid (>= 0)
    assert a1.gid == 0          # 0 is valid for gid (>= 0)
    assert a1.rev == 0          # 0 is valid for rev (>= 0)

    assert "invalid_priority" in summary.warning_counts
    assert "invalid_sid" in summary.warning_counts


def test_alert_missing_required_ips_skipped(tmp_path):
    """Test that alerts missing required IPs or having invalid IP format are skipped."""
    data = [
        # Missing src_ip
        {"dst_ip": "10.0.0.2", "message": "Missing src_ip"},
        # Invalid dst_ip
        {"src_ip": "10.0.0.1", "dst_ip": "999.999.999.999", "message": "Invalid dst_ip"},
        # Valid alert
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "message": "Valid Alert"},
    ]
    test_file = tmp_path / "alerts_missing_ip.json"
    test_file.write_text(json.dumps(data), encoding="utf-8")

    alerts, summary = parse_alert_file(str(test_file))
    assert len(alerts) == 1
    assert summary.total_raw_records == 3
    assert summary.valid_records == 1
    assert summary.skipped_records == 2
    assert alerts[0].message == "Valid Alert"


def test_alert_malformed_json(tmp_path):
    """Test that malformed JSON raises ValueError."""
    test_file = tmp_path / "malformed.json"
    test_file.write_text("{ this is not valid json }", encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        parse_alert_file(str(test_file))
    assert "Malformed JSON" in str(exc_info.value)


def test_alert_non_array_json(tmp_path):
    """Test that JSON object instead of array raises ValueError."""
    test_file = tmp_path / "obj.json"
    test_file.write_text('{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}', encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        parse_alert_file(str(test_file))
    assert "Expected JSON array" in str(exc_info.value)


def test_alert_missing_file():
    """Test that non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        parse_alert_file("data/samples/non_existent_alerts_xyz.json")
