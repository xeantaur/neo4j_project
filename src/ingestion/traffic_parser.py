"""
Parser and normalizer for network traffic export data (tshark/Wireshark TSV).

Processes tabular Layer 2/Layer 3 traffic records using pandas and standard
validation libraries without requiring PySpark or a JVM runtime.
"""

import ipaddress
import logging
import os
import re
from typing import List, Tuple, Dict
import pandas as pd

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
        ValueError: If file is completely empty or cannot be read.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Traffic file not found: {file_path}")

    logger.info("Parsing traffic data from: %s", file_path)

    # Read TSV using pandas with all columns as string to prevent unwanted type coercion
    try:
        # Check first line to detect if header exists
        sample_df = pd.read_csv(file_path, sep="\t", nrows=5, header=None, dtype=str)
        if sample_df.empty:
            return [], IngestionSummary(
                total_raw_records=0,
                valid_records=0,
                skipped_records=0,
                duplicate_records=0,
            )
    except pd.errors.EmptyDataError:
        return [], IngestionSummary(
            total_raw_records=0,
            valid_records=0,
            skipped_records=0,
            duplicate_records=0,
        )
    except Exception as exc:
        raise ValueError(f"Failed to read traffic file {file_path}: {exc}") from exc

    # Check if file has header matching standard column names
    first_row = sample_df.iloc[0].tolist()
    has_header = any("eth_src" in str(col).lower() or "ip_src" in str(col).lower() for col in first_row)

    try:
        if has_header:
            df = pd.read_csv(file_path, sep="\t", header=0, dtype=str, on_bad_lines="skip")
            # Normalize column names
            col_map = {c: c.strip().lower() for c in df.columns}
            df = df.rename(columns=col_map)
        else:
            df = pd.read_csv(file_path, sep="\t", header=None, dtype=str, on_bad_lines="skip")
    except Exception as exc:
        raise ValueError(f"Error parsing tabular data from {file_path}: {exc}") from exc

    total_raw = len(df)
    warning_counts: Dict[str, int] = {}
    sample_errors: List[str] = []

    def record_warning(reason: str, detail: str) -> None:
        warning_counts[reason] = warning_counts.get(reason, 0) + 1
        if len(sample_errors) < MAX_SAMPLE_ERRORS:
            sample_errors.append(f"{reason}: {detail}")
        logger.warning("Traffic parse warning [%s]: %s", reason, detail)

    valid_records: List[TrafficRecord] = []
    skipped_count = 0

    for idx, row in df.iterrows():
        # Handle column extraction based on header presence or column index
        if has_header:
            eth_src_raw = row.get("eth_src_resolved") or row.get("eth_src") or ""
            eth_dst_raw = row.get("eth_dst_resolved") or row.get("eth_dst") or ""
            ip_src_raw = row.get("ip_src") or ""
            ip_dst_raw = row.get("ip_dst") or ""
            protocol_raw = row.get("protocol") or "UNKNOWN"
        else:
            if len(row) < 7:
                record_warning("malformed_columns", f"Row {idx} has only {len(row)} columns, expected at least 7")
                skipped_count += 1
                continue
            eth_src_raw = row.iloc[0]
            eth_dst_raw = row.iloc[1]
            ip_src_raw = row.iloc[2]
            ip_dst_raw = row.iloc[3]
            protocol_raw = row.iloc[6]

        # Convert NaN or non-string to empty string
        eth_src = str(eth_src_raw).strip() if pd.notna(eth_src_raw) else ""
        eth_dst = str(eth_dst_raw).strip() if pd.notna(eth_dst_raw) else ""
        ip_src = str(ip_src_raw).strip() if pd.notna(ip_src_raw) else ""
        ip_dst = str(ip_dst_raw).strip() if pd.notna(ip_dst_raw) else ""
        protocol = str(protocol_raw).strip().upper() if pd.notna(protocol_raw) else "UNKNOWN"

        # Validation: non-empty MAC/identifiers
        if not eth_src or not eth_dst:
            record_warning("empty_mac_or_identifier", f"Row {idx} contains empty eth_src or eth_dst")
            skipped_count += 1
            continue

        # Validation: valid IP addresses
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
