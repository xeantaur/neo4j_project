"""
Normalized domain data models and ingestion summary metrics.

Defines typed, immutable representations for network traffic observations
and security alerts without inventing synthetic attributes.
"""

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple


def canonicalize_ip(ip_str: str) -> str:
    """Return the canonical string representation of an IPv4 or IPv6 address.

    Guarantees equivalent representations (such as expanded vs compressed IPv6)
    map to the exact same string key for graph and flow identity.
    """
    cleaned = ip_str.strip()
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return cleaned


def compute_flow_key(
    ip_src: str,
    ip_dst: str,
    protocol: str,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
) -> str:
    """Generate a deterministic SHA-256 identity key for a directional communication aggregate.

    Canonical identity tuple:
    (canonical src_ip, canonical dst_ip, normalized uppercase protocol, src_port, dst_port)
    with explicit stable null markers for nullable ports.
    """
    canonical_payload = {
        "src_ip": canonicalize_ip(ip_src),
        "dst_ip": canonicalize_ip(ip_dst),
        "protocol": protocol.strip().upper() if protocol else "UNKNOWN",
        "src_port": src_port if src_port is not None else "null",
        "dst_port": dst_port if dst_port is not None else "null",
    }
    serialized = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TrafficRecord:
    """Represents an observed directional network communication aggregate.

    In legacy mode, enriched metric fields default to None (indicating unavailable).
    In enriched mode, metrics reflect observed packet counts, frame bytes, and observation windows.
    The scalar eth_src_resolved / eth_dst_resolved fields contain the primary/deterministic
    representative Layer 2 pairing for backward compatibility, while observed_l2_pairs
    captures all distinct (eth_src, eth_dst) associations observed for this directional aggregate.
    """
    eth_src_resolved: str
    eth_dst_resolved: str
    ip_src: str
    ip_dst: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    observed_packet_count: Optional[int] = None
    observed_bytes: Optional[int] = None
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    observed_window_seconds: Optional[float] = None
    observed_l2_pairs: Tuple[Tuple[str, str], ...] = ()

    @property
    def flow_key(self) -> str:
        """Deterministic SHA-256 identity key for this directional aggregate."""
        return compute_flow_key(
            self.ip_src,
            self.ip_dst,
            self.protocol,
            self.src_port,
            self.dst_port,
        )


@dataclass(frozen=True)
class AlertRecord:
    """Represents an intrusion detection alert (e.g. Snort/Suricata)."""
    src_ip: str
    dst_ip: str
    sid: Optional[int] = None
    gid: Optional[int] = None
    rev: Optional[int] = None
    message: Optional[str] = None
    priority: Optional[int] = None
    protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None


@dataclass(frozen=True)
class IngestionSummary:
    """Metrics and diagnostics for an ingestion parse run.

    Includes bounded error recording to avoid unbounded memory growth.

    NOTE: In enriched mode, valid_records represents the count of directional aggregate
    records produced from the source observations, rather than the raw packet count.
    """
    total_raw_records: int
    valid_records: int
    skipped_records: int
    duplicate_records: int = 0
    warning_counts: Dict[str, int] = field(default_factory=dict)
    sample_errors: Tuple[str, ...] = ()
