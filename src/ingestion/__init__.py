"""
Ingestion module for network traffic and security alert data.
"""

from src.ingestion.models import TrafficRecord, AlertRecord, IngestionSummary
from src.ingestion.traffic_parser import parse_traffic_file
from src.ingestion.alert_parser import parse_alert_file

__all__ = [
    "TrafficRecord",
    "AlertRecord",
    "IngestionSummary",
    "parse_traffic_file",
    "parse_alert_file",
]
