"""
Parser and normalizer for intrusion detection alerts (JSON format).

Processes IDS/Snort alert data into typed AlertRecord instances with validation
and metrics tracking without inventing synthetic security attributes.
"""

import ipaddress
import json
import logging
import os
from typing import List, Tuple, Dict, Any, Optional

from src.ingestion.models import AlertRecord, IngestionSummary

logger = logging.getLogger(__name__)

MAX_SAMPLE_ERRORS = 10


def _is_valid_ip(ip_str: Any) -> bool:
    """Validate that the given value is a valid IPv4 or IPv6 string."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def _safe_coerce_int(val: Any) -> Optional[int]:
    """Coerce value to integer if possible, otherwise return None."""
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _validate_positive_int(val: Any) -> Optional[int]:
    """Validate that value is a strictly positive integer (> 0)."""
    val_int = _safe_coerce_int(val)
    if val_int is not None and val_int > 0:
        return val_int
    return None


def _validate_non_negative_int(val: Any) -> Optional[int]:
    """Validate that value is a non-negative integer (>= 0)."""
    val_int = _safe_coerce_int(val)
    if val_int is not None and val_int >= 0:
        return val_int
    return None


def _validate_port(val: Any) -> Optional[int]:
    """Validate that port is an integer between 1 and 65535."""
    port_int = _safe_coerce_int(val)
    if port_int is not None and 1 <= port_int <= 65535:
        return port_int
    return None


def parse_alert_file(file_path: str) -> Tuple[List[AlertRecord], IngestionSummary]:
    """Parse, clean, and validate IDS/Snort alert JSON data.

    Expected structure: A JSON array of alert objects.

    Returns:
        tuple of (list of valid AlertRecord objects, IngestionSummary)

    Raises:
        FileNotFoundError: If file does not exist.
        ValueError: If JSON is malformed or top-level element is not a list.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Alert data file not found: {file_path}")

    logger.info("Parsing alert data from: %s", file_path)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in alert file {file_path}: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"Error reading alert file {file_path}: {exc}") from exc

    if not isinstance(raw_data, list):
        raise ValueError(f"Expected JSON array at top level of {file_path}, got {type(raw_data).__name__}")

    total_raw = len(raw_data)
    warning_counts: Dict[str, int] = {}
    sample_errors: List[str] = []

    def record_warning(reason: str, detail: str) -> None:
        warning_counts[reason] = warning_counts.get(reason, 0) + 1
        if len(sample_errors) < MAX_SAMPLE_ERRORS:
            sample_errors.append(f"{reason}: {detail}")
        logger.warning("Alert parse warning [%s]: %s", reason, detail)

    valid_alerts: List[AlertRecord] = []
    skipped_count = 0

    for idx, entry in enumerate(raw_data):
        if not isinstance(entry, dict):
            record_warning("invalid_alert_format", f"Alert at index {idx} is not a JSON object")
            skipped_count += 1
            continue

        src_ip_raw = entry.get("src_ip")
        dst_ip_raw = entry.get("dst_ip")

        # Required fields check
        if not src_ip_raw or not dst_ip_raw:
            record_warning("missing_required_ip", f"Alert at index {idx} missing required src_ip or dst_ip")
            skipped_count += 1
            continue

        src_ip = str(src_ip_raw).strip()
        dst_ip = str(dst_ip_raw).strip()

        if not _is_valid_ip(src_ip):
            record_warning("invalid_src_ip", f"Alert at index {idx} has invalid src_ip '{src_ip}'")
            skipped_count += 1
            continue

        if not _is_valid_ip(dst_ip):
            record_warning("invalid_dst_ip", f"Alert at index {idx} has invalid dst_ip '{dst_ip}'")
            skipped_count += 1
            continue

        # Optional fields parsing with no invented fallback defaults
        # sid (non-negative integer >= 0)
        raw_sid = entry.get("sid")
        sid = None
        if raw_sid is not None and raw_sid != "":
            sid = _validate_non_negative_int(raw_sid)
            if sid is None:
                record_warning("invalid_sid", f"Alert at index {idx} has invalid sid '{raw_sid}'")

        # gid (non-negative integer >= 0)
        raw_gid = entry.get("gid")
        gid = None
        if raw_gid is not None and raw_gid != "":
            gid = _validate_non_negative_int(raw_gid)
            if gid is None:
                record_warning("invalid_gid", f"Alert at index {idx} has invalid gid '{raw_gid}'")

        # rev (non-negative integer >= 0)
        raw_rev = entry.get("rev")
        rev = None
        if raw_rev is not None and raw_rev != "":
            rev = _validate_non_negative_int(raw_rev)
            if rev is None:
                record_warning("invalid_rev", f"Alert at index {idx} has invalid rev '{raw_rev}'")

        # priority (strictly positive integer > 0)
        raw_priority = entry.get("priority")
        priority = None
        if raw_priority is not None and raw_priority != "":
            priority = _validate_positive_int(raw_priority)
            if priority is None:
                record_warning("invalid_priority", f"Alert at index {idx} has invalid priority '{raw_priority}'")

        # message
        raw_msg = entry.get("message")
        message = str(raw_msg).strip() if raw_msg is not None and str(raw_msg).strip() else None

        # protocol
        raw_proto = entry.get("protocol")
        protocol = str(raw_proto).strip().upper() if raw_proto is not None and str(raw_proto).strip() else None

        # src_port (1..65535)
        raw_src_port = entry.get("src_port")
        src_port = None
        if raw_src_port is not None and raw_src_port != "":
            src_port = _validate_port(raw_src_port)
            if src_port is None:
                record_warning("invalid_src_port", f"Alert at index {idx} has invalid src_port '{raw_src_port}'")

        # dst_port (1..65535)
        raw_dst_port = entry.get("dst_port")
        dst_port = None
        if raw_dst_port is not None and raw_dst_port != "":
            dst_port = _validate_port(raw_dst_port)
            if dst_port is None:
                record_warning("invalid_dst_port", f"Alert at index {idx} has invalid dst_port '{raw_dst_port}'")

        valid_alerts.append(
            AlertRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                sid=sid,
                gid=gid,
                rev=rev,
                message=message,
                priority=priority,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
            )
        )

    summary = IngestionSummary(
        total_raw_records=total_raw,
        valid_records=len(valid_alerts),
        skipped_records=skipped_count,
        duplicate_records=0,
        warning_counts=warning_counts,
        sample_errors=tuple(sample_errors),
    )

    logger.info(
        "Alert parsing complete: %d raw -> %d valid (%d skipped).",
        summary.total_raw_records,
        summary.valid_records,
        summary.skipped_records,
    )

    return valid_alerts, summary
