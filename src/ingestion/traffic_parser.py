"""
Parser and normalizer for network traffic export data (tshark/Wireshark TSV).

Processes tabular Layer 2/Layer 3 traffic records with explicit line-by-line validation,
preserving non-MAC resolved identifiers, supporting both legacy 7-column formats
and project-defined enriched tshark TSV export profiles with directional flow aggregation.
"""

import csv
import ipaddress
import logging
import math
import os
import re
from typing import List, Tuple, Dict, Optional, Set, Any

from src.ingestion.models import TrafficRecord, IngestionSummary

logger = logging.getLogger(__name__)

# Canonical MAC pattern (6 pairs of hex digits separated by colon or dash)
_CANONICAL_MAC_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
)

MAX_SAMPLE_ERRORS = 10

# Normalized header aliases for project-defined enriched tshark export profile
ENRICHED_HEADER_ALIASES: Dict[str, str] = {
    # Frame number (optional)
    "frame.number": "frame_number",
    "frame_number": "frame_number",
    # Frame epoch timestamp (required in enriched mode)
    "frame.time_epoch": "frame_time_epoch",
    "frame_time_epoch": "frame_time_epoch",
    # Frame length (required in enriched mode)
    "frame.len": "frame_len",
    "frame_len": "frame_len",
    # Layer 2 Source
    "eth.src": "eth_src",
    "eth_src": "eth_src",
    "eth_src_resolved": "eth_src",
    # Layer 2 Destination
    "eth.dst": "eth_dst",
    "eth_dst": "eth_dst",
    "eth_dst_resolved": "eth_dst",
    # IPv4 Source
    "ip.src": "ip_src",
    "ip_src": "ip_src",
    # IPv4 Destination
    "ip.dst": "ip_dst",
    "ip_dst": "ip_dst",
    # IPv6 Source
    "ipv6.src": "ipv6_src",
    "ipv6_src": "ipv6_src",
    # IPv6 Destination
    "ipv6.dst": "ipv6_dst",
    "ipv6_dst": "ipv6_dst",
    # Protocol
    "_ws.col.protocol": "protocol",
    "protocol": "protocol",
    # TCP Ports
    "tcp.srcport": "tcp_srcport",
    "tcp_srcport": "tcp_srcport",
    "tcp.dstport": "tcp_dstport",
    "tcp_dstport": "tcp_dstport",
    # UDP Ports
    "udp.srcport": "udp_srcport",
    "udp_srcport": "udp_srcport",
    "udp.dstport": "udp_dstport",
    "udp_dstport": "udp_dstport",
}

# Enriched-specific header markers to distinguish from legacy formats
_ENRICHED_SPECIFIC_MARKERS: Set[str] = {
    "frame_time_epoch",
    "frame_len",
    "frame_number",
    "tcp_srcport",
    "tcp_dstport",
    "udp_srcport",
    "udp_dstport",
    "ipv6_src",
    "ipv6_dst",
}


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


def _parse_port(val: str) -> Optional[int]:
    """Parse port string into integer in range 1..65535.

    Returns:
        int: Valid port number (1..65535).
        None: Empty or whitespace string.
        -1: Integer parsed but outside valid range 1..65535.
        -2: Non-integer malformed string.
    """
    trimmed = val.strip()
    if not trimmed or trimmed == "-":
        return None
    try:
        p = int(trimmed)
        if 1 <= p <= 65535:
            return p
        return -1
    except ValueError:
        return -2


def parse_traffic_file(file_path: str) -> Tuple[List[TrafficRecord], IngestionSummary]:
    """Parse, clean, validate, and aggregate a network traffic TSV file.
    
    Supports two operating modes:
    1. Legacy / Basic Mode:
       Headerless 7-column or legacy headered TSV. Performs set deduplication over
       normalized Layer 2 / Layer 3 records. Returns TrafficRecord instances with
       metric fields set to None (indicating metrics unavailable).
    2. Enriched Mode:
       Headered TSV conforming to the project-defined enriched tshark export profile.
       Performs line-by-line validation of timestamps, frame lengths, IP/IPv6 coalescing,
       and transport ports, aggregating raw packet observations into directional
       communication aggregates with observed_packet_count, observed_bytes, first_seen,
       last_seen, and observed_window_seconds.

    Returns:
        tuple of (list of valid unique TrafficRecord objects, IngestionSummary)
    
    Raises:
        FileNotFoundError: If the input file does not exist.
        ValueError: If file cannot be read or contains an incomplete enriched header.
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

    # Detect header presence and mode on first non-empty row
    first_row = raw_rows[0]
    first_row_lower = [cell.strip().lower() for cell in first_row]

    # Map column headers to canonical names
    header_col_map: Dict[str, int] = {}
    for idx, cell in enumerate(first_row_lower):
        if cell in ENRICHED_HEADER_ALIASES:
            canonical_name = ENRICHED_HEADER_ALIASES[cell]
            # First occurrence wins if duplicates exist
            if canonical_name not in header_col_map:
                header_col_map[canonical_name] = idx

    # Check if first row is a recognized header
    is_header = bool(header_col_map) or any(
        "eth_src" in cell or "ip_src" in cell or "protocol" in cell for cell in first_row_lower
    )

    is_enriched_profile = False
    if is_header:
        # Check if any enriched-specific marker is present in the header
        found_canonical_headers = set(header_col_map.keys())
        if found_canonical_headers & _ENRICHED_SPECIFIC_MARKERS:
            is_enriched_profile = True

    if is_enriched_profile:
        # Strict validation of required enriched headers
        missing_required: List[str] = []
        if "frame_time_epoch" not in header_col_map:
            missing_required.append("frame.time_epoch")
        if "frame_len" not in header_col_map:
            missing_required.append("frame.len")
        if "eth_src" not in header_col_map:
            missing_required.append("eth.src")
        if "eth_dst" not in header_col_map:
            missing_required.append("eth.dst")
        if "ip_src" not in header_col_map and "ipv6_src" not in header_col_map:
            missing_required.append("ip.src / ipv6.src")
        if "ip_dst" not in header_col_map and "ipv6_dst" not in header_col_map:
            missing_required.append("ip.dst / ipv6.dst")
        if "protocol" not in header_col_map:
            missing_required.append("protocol / _ws.col.Protocol")

        if missing_required:
            raise ValueError(
                f"Incomplete enriched traffic profile: missing required headers: {', '.join(missing_required)}"
            )

        return _parse_enriched_traffic(
            data_rows=raw_rows[1:],
            header_col_map=header_col_map,
            expected_col_count=len(first_row),
            record_warning=record_warning,
            warning_counts=warning_counts,
            sample_errors=sample_errors,
        )

    # Legacy Mode (Headered or Headerless)
    if is_header:
        data_rows = raw_rows[1:]
        legacy_col_map = header_col_map
        expected_col_count = len(first_row)
        has_header = True
    else:
        data_rows = raw_rows
        legacy_col_map = {}
        expected_col_count = 7
        has_header = False

    return _parse_legacy_traffic(
        data_rows=data_rows,
        has_header=has_header,
        header_col_map=legacy_col_map,
        expected_col_count=expected_col_count,
        record_warning=record_warning,
        warning_counts=warning_counts,
        sample_errors=sample_errors,
    )


def _parse_legacy_traffic(
    data_rows: List[List[str]],
    has_header: bool,
    header_col_map: Dict[str, int],
    expected_col_count: int,
    record_warning: Any,
    warning_counts: Dict[str, int],
    sample_errors: List[str],
) -> Tuple[List[TrafficRecord], IngestionSummary]:
    """Parse legacy / basic traffic TSV data with exact record deduplication."""
    valid_records: List[TrafficRecord] = []
    skipped_count = 0
    total_raw = len(data_rows)

    for idx, row in enumerate(data_rows, start=2 if has_header else 1):
        if len(row) != expected_col_count:
            record_warning("malformed_columns", f"Row {idx} has {len(row)} columns, expected {expected_col_count}")
            skipped_count += 1
            continue

        if has_header:
            eth_src_idx = header_col_map.get("eth_src")
            eth_dst_idx = header_col_map.get("eth_dst")
            ip_src_idx = header_col_map.get("ip_src")
            ip_dst_idx = header_col_map.get("ip_dst")
            proto_idx = header_col_map.get("protocol")

            eth_src_raw = row[eth_src_idx] if eth_src_idx is not None and eth_src_idx < len(row) else ""
            eth_dst_raw = row[eth_dst_idx] if eth_dst_idx is not None and eth_dst_idx < len(row) else ""
            ip_src_raw = row[ip_src_idx] if ip_src_idx is not None and ip_src_idx < len(row) else ""
            ip_dst_raw = row[ip_dst_idx] if ip_dst_idx is not None and ip_dst_idx < len(row) else ""
            protocol_raw = row[proto_idx] if proto_idx is not None and proto_idx < len(row) else "UNKNOWN"
        else:
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

        if not eth_src or not eth_dst:
            record_warning("empty_mac_or_identifier", f"Row {idx} contains empty eth_src or eth_dst")
            skipped_count += 1
            continue

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

        src_ip_obj = ipaddress.ip_address(ip_src)
        dst_ip_obj = ipaddress.ip_address(ip_dst)
        if src_ip_obj.version != dst_ip_obj.version:
            record_warning(
                "mismatched_ip_version",
                f"Row {idx} mismatched IP versions: IPv{src_ip_obj.version} -> IPv{dst_ip_obj.version}",
            )
            skipped_count += 1
            continue

        norm_eth_src = _normalize_mac_or_identifier(eth_src)
        norm_eth_dst = _normalize_mac_or_identifier(eth_dst)
        canonical_src = str(src_ip_obj)
        canonical_dst = str(dst_ip_obj)

        valid_records.append(
            TrafficRecord(
                eth_src_resolved=norm_eth_src,
                eth_dst_resolved=norm_eth_dst,
                ip_src=canonical_src,
                ip_dst=canonical_dst,
                protocol=protocol or "UNKNOWN",
                src_port=None,
                dst_port=None,
                observed_packet_count=None,
                observed_bytes=None,
                first_seen=None,
                last_seen=None,
                observed_window_seconds=None,
            )
        )

    # Legacy deduplication: exact record set deduplication while preserving order
    unique_records: List[TrafficRecord] = []
    seen: Set[TrafficRecord] = set()
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
        "Legacy traffic parsing complete: %d raw -> %d unique valid (%d skipped, %d duplicates).",
        summary.total_raw_records,
        summary.valid_records,
        summary.skipped_records,
        summary.duplicate_records,
    )

    return unique_records, summary


def _parse_enriched_traffic(
    data_rows: List[List[str]],
    header_col_map: Dict[str, int],
    expected_col_count: int,
    record_warning: Any,
    warning_counts: Dict[str, int],
    sample_errors: List[str],
) -> Tuple[List[TrafficRecord], IngestionSummary]:
    """Parse project-defined enriched tshark export profile with flow aggregation."""
    total_raw = len(data_rows)
    skipped_count = 0
    duplicate_count = 0

    # For frame.number duplicate tracking: frame_number -> normalized observation tuple
    seen_frame_numbers: Dict[int, Tuple[Any, ...]] = {}

    # Directional aggregate accumulator
    # Key: (norm_eth_src, norm_eth_dst, canonical_src, canonical_dst, protocol, src_port, dst_port)
    aggregates: Dict[Tuple[str, str, str, str, str, Optional[int], Optional[int]], Dict[str, Any]] = {}

    for idx, row in enumerate(data_rows, start=2):
        if len(row) != expected_col_count:
            record_warning("malformed_columns", f"Row {idx} has {len(row)} columns, expected {expected_col_count}")
            skipped_count += 1
            continue

        # 1. Parse frame.time_epoch (Required float)
        time_idx = header_col_map["frame_time_epoch"]
        time_raw = row[time_idx].strip() if time_idx < len(row) else ""
        if not time_raw:
            record_warning("missing_timestamp", f"Row {idx} missing frame.time_epoch")
            skipped_count += 1
            continue
        try:
            time_val = float(time_raw)
            if math.isnan(time_val) or math.isinf(time_val) or time_val < 0.0:
                record_warning("invalid_timestamp", f"Row {idx} invalid timestamp value '{time_raw}'")
                skipped_count += 1
                continue
        except (ValueError, TypeError):
            record_warning("invalid_timestamp", f"Row {idx} malformed timestamp '{time_raw}'")
            skipped_count += 1
            continue

        # 2. Parse frame.len (Required positive integer)
        len_idx = header_col_map["frame_len"]
        len_raw = row[len_idx].strip() if len_idx < len(row) else ""
        if not len_raw:
            record_warning("missing_frame_length", f"Row {idx} missing frame.len")
            skipped_count += 1
            continue
        try:
            len_val = int(len_raw)
            if len_val <= 0:
                record_warning("invalid_frame_length", f"Row {idx} non-positive frame.len '{len_raw}'")
                skipped_count += 1
                continue
        except (ValueError, TypeError):
            record_warning("invalid_frame_length", f"Row {idx} malformed frame.len '{len_raw}'")
            skipped_count += 1
            continue

        # 3. Parse Layer 2 source / destination (Required)
        eth_src_idx = header_col_map["eth_src"]
        eth_dst_idx = header_col_map["eth_dst"]
        eth_src_raw = row[eth_src_idx].strip() if eth_src_idx < len(row) else ""
        eth_dst_raw = row[eth_dst_idx].strip() if eth_dst_idx < len(row) else ""
        if not eth_src_raw or not eth_dst_raw:
            record_warning("empty_mac_or_identifier", f"Row {idx} contains empty eth.src or eth.dst")
            skipped_count += 1
            continue
        norm_eth_src = _normalize_mac_or_identifier(eth_src_raw)
        norm_eth_dst = _normalize_mac_or_identifier(eth_dst_raw)

        # 4. Parse & coalesce IPv4 / IPv6 endpoints
        ipv4_src_idx = header_col_map.get("ip_src")
        ipv4_dst_idx = header_col_map.get("ip_dst")
        ipv6_src_idx = header_col_map.get("ipv6_src")
        ipv6_dst_idx = header_col_map.get("ipv6_dst")

        ipv4_src = row[ipv4_src_idx].strip() if ipv4_src_idx is not None and ipv4_src_idx < len(row) else ""
        ipv4_dst = row[ipv4_dst_idx].strip() if ipv4_dst_idx is not None and ipv4_dst_idx < len(row) else ""
        ipv6_src = row[ipv6_src_idx].strip() if ipv6_src_idx is not None and ipv6_src_idx < len(row) else ""
        ipv6_dst = row[ipv6_dst_idx].strip() if ipv6_dst_idx is not None and ipv6_dst_idx < len(row) else ""

        # Disallow ambiguous simultaneous IPv4 and IPv6 population
        if ipv4_src and ipv6_src:
            record_warning("ambiguous_ip_source", f"Row {idx} has both IPv4 and IPv6 source populated")
            skipped_count += 1
            continue
        if ipv4_dst and ipv6_dst:
            record_warning("ambiguous_ip_destination", f"Row {idx} has both IPv4 and IPv6 destination populated")
            skipped_count += 1
            continue

        raw_src = ipv4_src or ipv6_src
        raw_dst = ipv4_dst or ipv6_dst

        if not raw_src or not raw_dst:
            record_warning("empty_ip", f"Row {idx} contains empty IP source or destination")
            skipped_count += 1
            continue

        if not _is_valid_ip(raw_src):
            record_warning("invalid_ip_src", f"Row {idx} invalid source IP '{raw_src}'")
            skipped_count += 1
            continue

        if not _is_valid_ip(raw_dst):
            record_warning("invalid_ip_dst", f"Row {idx} invalid destination IP '{raw_dst}'")
            skipped_count += 1
            continue

        # Disallow mismatched IP address versions within a single observation (e.g. IPv4 source with IPv6 destination).
        # This conservative check guards against accidentally combining disjoint addresses from encapsulated/tunneling layers.
        src_ip_obj = ipaddress.ip_address(raw_src)
        dst_ip_obj = ipaddress.ip_address(raw_dst)
        if src_ip_obj.version != dst_ip_obj.version:
            record_warning(
                "mismatched_ip_version",
                f"Row {idx} mismatched IP versions: IPv{src_ip_obj.version} -> IPv{dst_ip_obj.version}",
            )
            skipped_count += 1
            continue

        canonical_src = str(src_ip_obj)
        canonical_dst = str(dst_ip_obj)

        # 5. Protocol normalization
        proto_idx = header_col_map.get("protocol")
        proto_raw = row[proto_idx].strip() if proto_idx is not None and proto_idx < len(row) else ""
        protocol = proto_raw.upper() if proto_raw else "UNKNOWN"

        # 6. Transport Ports extraction (inspect transport columns directly, independent of protocol label)
        tcp_src_idx = header_col_map.get("tcp_srcport")
        tcp_dst_idx = header_col_map.get("tcp_dstport")
        udp_src_idx = header_col_map.get("udp_srcport")
        udp_dst_idx = header_col_map.get("udp_dstport")

        tcp_src_raw = row[tcp_src_idx].strip() if tcp_src_idx is not None and tcp_src_idx < len(row) else ""
        tcp_dst_raw = row[tcp_dst_idx].strip() if tcp_dst_idx is not None and tcp_dst_idx < len(row) else ""
        udp_src_raw = row[udp_src_idx].strip() if udp_src_idx is not None and udp_src_idx < len(row) else ""
        udp_dst_raw = row[udp_dst_idx].strip() if udp_dst_idx is not None and udp_dst_idx < len(row) else ""

        def _has_port_val(v: str) -> bool:
            return bool(v and v != "-")

        has_tcp = _has_port_val(tcp_src_raw) or _has_port_val(tcp_dst_raw)
        has_udp = _has_port_val(udp_src_raw) or _has_port_val(udp_dst_raw)

        if has_tcp and has_udp:
            record_warning("ambiguous_transport_ports", f"Row {idx} has both TCP and UDP ports populated")
            skipped_count += 1
            continue

        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        if has_tcp:
            parsed_sp = _parse_port(tcp_src_raw)
            if parsed_sp is not None and parsed_sp < 0:
                record_warning("invalid_src_port", f"Row {idx} invalid tcp.srcport '{tcp_src_raw}'")
                skipped_count += 1
                continue
            src_port = parsed_sp

            parsed_dp = _parse_port(tcp_dst_raw)
            if parsed_dp is not None and parsed_dp < 0:
                record_warning("invalid_dst_port", f"Row {idx} invalid tcp.dstport '{tcp_dst_raw}'")
                skipped_count += 1
                continue
            dst_port = parsed_dp

        elif has_udp:
            parsed_sp = _parse_port(udp_src_raw)
            if parsed_sp is not None and parsed_sp < 0:
                record_warning("invalid_src_port", f"Row {idx} invalid udp.srcport '{udp_src_raw}'")
                skipped_count += 1
                continue
            src_port = parsed_sp

            parsed_dp = _parse_port(udp_dst_raw)
            if parsed_dp is not None and parsed_dp < 0:
                record_warning("invalid_dst_port", f"Row {idx} invalid udp.dstport '{udp_dst_raw}'")
                skipped_count += 1
                continue
            dst_port = parsed_dp

        # 7. Frame number duplicate detection (if present)
        frame_num_idx = header_col_map.get("frame_number")
        frame_num_raw = row[frame_num_idx].strip() if frame_num_idx is not None and frame_num_idx < len(row) else ""
        frame_num: Optional[int] = None
        if frame_num_raw:
            try:
                frame_num = int(frame_num_raw)
            except ValueError:
                record_warning("invalid_frame_number", f"Row {idx} malformed frame.number '{frame_num_raw}'")
                skipped_count += 1
                continue

        norm_observation = (
            norm_eth_src,
            norm_eth_dst,
            canonical_src,
            canonical_dst,
            protocol,
            src_port,
            dst_port,
            time_val,
            len_val,
        )

        if frame_num is not None:
            if frame_num in seen_frame_numbers:
                if seen_frame_numbers[frame_num] == norm_observation:
                    duplicate_count += 1
                    continue
                else:
                    record_warning(
                        "conflicting_frame_number",
                        f"Row {idx} has conflicting observation for frame.number {frame_num}",
                    )
                    skipped_count += 1
                    continue
            seen_frame_numbers[frame_num] = norm_observation

        # 8. Accumulate observation into directional communication aggregate (grouped by canonical 5-tuple)
        agg_key = (
            canonical_src,
            canonical_dst,
            protocol,
            src_port,
            dst_port,
        )

        if agg_key not in aggregates:
            aggregates[agg_key] = {
                "packet_count": 0,
                "byte_count": 0,
                "first_seen": time_val,
                "last_seen": time_val,
                "l2_pairs": set(),
            }

        entry = aggregates[agg_key]
        entry["packet_count"] += 1
        entry["byte_count"] += len_val
        if time_val < entry["first_seen"]:
            entry["first_seen"] = time_val
        if time_val > entry["last_seen"]:
            entry["last_seen"] = time_val
        entry["l2_pairs"].add((norm_eth_src, norm_eth_dst))

    # 9. Materialize aggregated TrafficRecord instances with deterministic L2 representative and full l2 pairs
    unique_records: List[TrafficRecord] = []
    for (ip_src, ip_dst, proto, s_port, d_port), data in aggregates.items():
        sorted_l2 = tuple(sorted(data["l2_pairs"]))
        primary_eth_src, primary_eth_dst = sorted_l2[0] if sorted_l2 else ("", "")
        window_sec = max(0.0, data["last_seen"] - data["first_seen"])
        record = TrafficRecord(
            eth_src_resolved=primary_eth_src,
            eth_dst_resolved=primary_eth_dst,
            ip_src=ip_src,
            ip_dst=ip_dst,
            protocol=proto,
            src_port=s_port,
            dst_port=d_port,
            observed_packet_count=data["packet_count"],
            observed_bytes=data["byte_count"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            observed_window_seconds=window_sec,
            observed_l2_pairs=sorted_l2,
        )
        unique_records.append(record)

    summary = IngestionSummary(
        total_raw_records=total_raw,
        valid_records=len(unique_records),
        skipped_records=skipped_count,
        duplicate_records=duplicate_count,
        warning_counts=warning_counts,
        sample_errors=tuple(sample_errors),
    )

    logger.info(
        "Enriched traffic parsing complete: %d raw observations -> %d aggregates (%d skipped, %d duplicate rows).",
        summary.total_raw_records,
        summary.valid_records,
        summary.skipped_records,
        summary.duplicate_records,
    )

    return unique_records, summary
