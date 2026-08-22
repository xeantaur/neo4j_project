"""
Configuration module for the Network Traffic Analysis project.

Loads settings from environment variables (with .env file support).
Provides lazy access functions so that importing the module does not eagerly
require environment variables to be set, supporting independent execution of
the API and CLI components.
"""

import os
import logging
from typing import Dict, Optional, List, Any
from dotenv import load_dotenv

# Load .env file if present (does not override existing env vars)
load_dotenv()

logger = logging.getLogger(__name__)

# Application metadata constant
APP_NAME = "Network Traffic Analysis"


def _require_env(name: str) -> str:
    """Return the value of an environment variable or raise EnvironmentError with a clear message."""
    value = os.getenv(name)
    if not value or not value.strip():
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set. "
            f"Copy .env.example to .env and fill in the values."
        )
    return value.strip()


def get_neo4j_config() -> Dict[str, str]:
    """Retrieve and validate required Neo4j database configuration.

    Raises:
        EnvironmentError: If NEO4J_URI, NEO4J_USERNAME, or NEO4J_PASSWORD is not set.
    """
    return {
        "uri": _require_env("NEO4J_URI"),
        "username": _require_env("NEO4J_USERNAME"),
        "password": _require_env("NEO4J_PASSWORD"),
    }


def get_optional_neo4j_config() -> Optional[Dict[str, str]]:
    """Retrieve Neo4j configuration if all required variables are set, otherwise return None.

    Enables API server startup without crashing when Neo4j is temporarily unconfigured.
    """
    uri = os.getenv("NEO4J_URI")
    username = os.getenv("NEO4J_USERNAME")
    password = os.getenv("NEO4J_PASSWORD")

    if uri and username and password and uri.strip() and username.strip() and password.strip():
        return {
            "uri": uri.strip(),
            "username": username.strip(),
            "password": password.strip(),
        }
    return None


def get_ingestion_config() -> Dict[str, str]:
    """Retrieve and validate configuration required strictly for file ingestion.

    Raises:
        EnvironmentError: If TRAFFIC_CSV_PATH or ALERTS_JSON_PATH is not set.
    """
    return {
        "traffic_csv_path": _require_env("TRAFFIC_CSV_PATH"),
        "alerts_json_path": _require_env("ALERTS_JSON_PATH"),
    }


def get_cors_origins() -> List[str]:
    """Retrieve configured allowed CORS origins.

    Returns an empty list by default (CORS disabled unless explicitly configured).
    """
    raw_origins = os.getenv("CORS_ORIGINS", "")
    if not raw_origins or not raw_origins.strip():
        return []
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


def get_data_import_config() -> Dict[str, Any]:
    """Retrieve configuration for browser data import and workspace replacement.

    Defaults to disabled (DATA_IMPORT_ENABLED=false) with a conservative 10 MiB limit.

    Raises:
        EnvironmentError: If DATA_IMPORT_MAX_FILE_SIZE_MB is not a valid positive integer.
    """
    raw_enabled = os.getenv("DATA_IMPORT_ENABLED", "false").strip().lower()
    enabled = raw_enabled in ("true", "1", "yes", "t")

    raw_max_mb = os.getenv("DATA_IMPORT_MAX_FILE_SIZE_MB", "10").strip()
    try:
        max_file_size_mb = int(raw_max_mb)
        if max_file_size_mb <= 0:
            raise ValueError()
    except (ValueError, TypeError):
        raise EnvironmentError(
            f"Invalid DATA_IMPORT_MAX_FILE_SIZE_MB value '{raw_max_mb}'. "
            f"Expected a positive integer (e.g. 10)."
        )

    return {
        "enabled": enabled,
        "max_file_size_mb": max_file_size_mb,
        "max_file_size_bytes": max_file_size_mb * 1024 * 1024,
    }
