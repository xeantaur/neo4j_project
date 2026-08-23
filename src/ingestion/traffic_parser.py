"""
Parser and normalizer for network traffic export data (tshark/Wireshark TSV).

Processes tabular Layer 2/Layer 3 traffic records with explicit line-by-line validation,
preserving non-MAC resolved identifiers and avoiding silent malformed row loss.
"""

import csv
import ipaddress
import logging
import os
import re
from typing import List, Tuple, Dict

from src.ingestion.models import TrafficRecord, IngestionSummary

logger = logging.getLogger(__name__)

# Canonical MAC pattern (6 pairs of hex digits separated by colon or dash)
_CANONICAL_MAC_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
)

MAX_SAMPLE_ERRORS = 10


def _normalize_mac_or_identifier(val: str) -> str:
    """Normalize canonical MAC to lowercase colon-separated format.
    
    If the string is a non-MAC resolved identifier (e.g. hostname or vendor name),
    preserve it as trimmed string without modification.
    """
    trimmed = val.strip()
    if _CANONICAL_MAC_PATTERN.match(trimmed):
        cleaned = trimmed.replace("-", ":").lower()
        return cleaned
    return trimmed


def _is_valid_ip(ip_str: str) -> bool:
    """Validate that the string is a valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def parse_traffic_file(file_path: str) -> Tuple[List[TrafficRecord], IngestionSummary]:
    """Parse, clean, validate, and deduplicate a network traffic TSV file.
    
    Expected raw layout: 7 tab-separated columns:
    [0: eth_src_resolved, 1: eth_dst_resolved, 2: ip_src, 3: ip_dst, 4: unused, 5: unused, 6: protocol]

    Returns:
        tuple of (list of valid unique TrafficRecord objects, IngestionSummary)
    
    Raises:
        FileNotFoundError: If the input file does not exist.
        ValueError: If file cannot be read.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Traffic file not found: {file_path}")

    logger.info("Parsing traffic data from: %s", file_path)

    warning_counts: Dict[str, int] = {}
    sample_errors: List[str] = []

    def record_warning(reason: str, detail: str) -> None:
        warning_counts[reason] = warning_counts.get(reason, 0) + 1
        if len(sample_errors) < MAX_SAMPLE_ERRORS:
            sample_errors.append(f"{reason}: {detail}")
        logger.warning("Traffic parse warning [%s]: %s", reason, detail)

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f, delimiter="\t")
            raw_rows = [row for row in reader if any(cell.strip() for cell in row)]
    except Exception as exc:
        raise ValueError(f"Error reading traffic file {file_path}: {exc}") from exc

    if not raw_rows:
        return [], IngestionSummary(
            total_raw_records=0,
            valid_records=0,
            skipped_records=0,
            duplicate_records=0,
        )

    # Detect header presence on first row
    first_row = raw_rows[0]
    has_header = any("eth_src" in cell.lower() or "ip_src" in cell.lower() for cell in first_row)

    header_cols = {}
    if has_header:
        header_cols = {col_name.strip().lower(): idx for idx, col_name in enumerate(first_row)}
        data_rows = raw_rows[1:]
        total_raw = len(data_rows)
    else:
        data_rows = raw_rows
        total_raw = len(data_rows)

    valid_records: List[TrafficRecord] = []
    skipped_count = 0

    for idx, row in enumerate(data_rows, start=1 if has_header else 0):
        # Explicit validation of column count to prevent silent row drops
        if has_header:
            if len(row) != len(first_row):
                record_warning("malformed_columns", f"Row {idx} has {len(row)} columns, expected {len(first_row)}")
                skipped_count += 1
                continue
            eth_src_idx = header_cols.get("eth_src_resolved") if "eth_src_resolved" in header_cols else header_cols.get("eth_src")
            eth_dst_idx = header_cols.get("eth_dst_resolved") if "eth_dst_resolved" in header_cols else header_cols.get("eth_dst")
            ip_src_idx = header_cols.get("ip_src")
            ip_dst_idx = header_cols.get("ip_dst")
            proto_idx = header_cols.get("protocol")

            eth_src_raw = row[eth_src_idx] if eth_src_idx is not None and eth_src_idx < len(row) else ""
            eth_dst_raw = row[eth_dst_idx] if eth_dst_idx is not None and eth_dst_idx < len(row) else ""
            ip_src_raw = row[ip_src_idx] if ip_src_idx is not None and ip_src_idx < len(row) else ""
            ip_dst_raw = row[ip_dst_idx] if ip_dst_idx is not None and ip_dst_idx < len(row) else ""
            protocol_raw = row[proto_idx] if proto_idx is not None and proto_idx < len(row) else "UNKNOWN"
        else:
            if len(row) != 7:
                record_warning("malformed_columns", f"Row {idx} has {len(row)} columns, expected exactly 7")
                skipped_count += 1
                continue
            eth_src_raw = row[0]
            eth_dst_raw = row[1]
            ip_src_raw = row[2]
            ip_dst_raw = row[3]
            protocol_raw = row[6]

        eth_src = eth_src_raw.strip()
        eth_dst = eth_dst_raw.strip()
        ip_src = ip_src_raw.strip()
        ip_dst = ip_dst_raw.strip()
        protocol = protocol_raw.strip().upper() if protocol_raw.strip() else "UNKNOWN"

        # Validation: non-empty MAC/identifiers
        if not eth_src or not eth_dst:
            record_warning("empty_mac_or_identifier", f"Row {idx} contains empty eth_src or eth_dst")
            skipped_count += 1
            continue

        # Validation: non-empty and valid IP addresses
        if not ip_src or not ip_dst:
            record_warning("empty_ip", f"Row {idx} contains empty ip_src or ip_dst")
            skipped_count += 1
            continue

        if not _is_valid_ip(ip_src):
            record_warning("invalid_ip_src", f"Row {idx} invalid ip_src '{ip_src}'")
            skipped_count += 1
            continue

        if not _is_valid_ip(ip_dst):
            record_warning("invalid_ip_dst", f"Row {idx} invalid ip_dst '{ip_dst}'")
            skipped_count += 1
            continue

        norm_eth_src = _normalize_mac_or_identifier(eth_src)
        norm_eth_dst = _normalize_mac_or_identifier(eth_dst)

        valid_records.append(
            TrafficRecord(
                eth_src_resolved=norm_eth_src,
                eth_dst_resolved=norm_eth_dst,
                ip_src=ip_src,
                ip_dst=ip_dst,
                protocol=protocol or "UNKNOWN",
            )
        )

    # Deduplicate while preserving order
    unique_records: List[TrafficRecord] = []
    seen = set()
    for rec in valid_records:
        if rec not in seen:
            seen.add(rec)
            unique_records.append(rec)

    duplicate_count = len(valid_records) - len(unique_records)

    summary = IngestionSummary(
        total_raw_records=total_raw,
        valid_records=len(unique_records),
        skipped_records=skipped_count,
        duplicate_records=duplicate_count,
        warning_counts=warning_counts,
        sample_errors=tuple(sample_errors),
    )

    logger.info(
        "Traffic parsing complete: %d raw -> %d unique valid (%d skipped, %d duplicates).",
        summary.total_raw_records,
        summary.valid_records,
        summary.skipped_records,
        summary.duplicate_records,
    )

    return unique_records, summary
