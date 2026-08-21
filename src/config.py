"""
Configuration module for the Network Traffic Analysis project.

Loads settings from environment variables (with .env file support).
All configuration is centralized here so that no credentials or paths
are hardcoded in application code.
"""

import os
import logging
from dotenv import load_dotenv

# Load .env file if present (does not override existing env vars)
load_dotenv()

logger = logging.getLogger(__name__)


def _require_env(name: str) -> str:
    """Return the value of an environment variable or raise with a clear message."""
    value = os.getenv(name)
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set. "
            f"Copy .env.example to .env and fill in the values."
        )
    return value


# --- Neo4j connection settings ---
NEO4J_URI = _require_env("NEO4J_URI")
NEO4J_USERNAME = _require_env("NEO4J_USERNAME")
NEO4J_PASSWORD = _require_env("NEO4J_PASSWORD")

# --- Data file paths ---
TRAFFIC_CSV_PATH = _require_env("TRAFFIC_CSV_PATH")
ALERTS_JSON_PATH = _require_env("ALERTS_JSON_PATH")

# --- Application constants ---
APP_NAME = "Network Traffic Analysis"
CSV_SEPARATOR = "\t"
CSV_HAS_HEADER = False

# Column names assigned to the raw TSV columns from tshark export.
# The source data has 7 columns; columns at index 4 and 5 are unused.
CSV_COLUMN_NAMES = [
    "eth_src_resolved",
    "eth_dst_resolved",
    "ip_src",
    "ip_dst",
    "_unused_4",
    "_unused_5",
    "protocol",
]
CSV_DROP_COLUMNS = ["_unused_4", "_unused_5"]
