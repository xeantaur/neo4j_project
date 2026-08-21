"""
Normalized domain data models and ingestion summary metrics.

Defines typed, immutable representations for network traffic observations
and security alerts without inventing synthetic attributes.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple


@dataclass(frozen=True)
class TrafficRecord:
    """Represents an observed Layer 2 / Layer 3 network flow."""
    eth_src_resolved: str
    eth_dst_resolved: str
    ip_src: str
    ip_dst: str
    protocol: str


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
    """
    total_raw_records: int
    valid_records: int
    skipped_records: int
    duplicate_records: int = 0
    warning_counts: Dict[str, int] = field(default_factory=dict)
    sample_errors: Tuple[str, ...] = ()
