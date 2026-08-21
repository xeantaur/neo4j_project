"""
Unit tests for configuration module.
"""

import pytest
from src.config import (
    _require_env,
    get_neo4j_config,
    get_optional_neo4j_config,
    get_ingestion_config,
    get_cors_origins,
)


def test_require_env_success(monkeypatch):
    """Test retrieving existing environment variable."""
    monkeypatch.setenv("TEST_VAR_123", "value_xyz")
    assert _require_env("TEST_VAR_123") == "value_xyz"


def test_require_env_missing_raises(monkeypatch):
    """Test that missing required environment variable raises EnvironmentError."""
    monkeypatch.delenv("NON_EXISTENT_VAR_XYZ", raising=False)
    with pytest.raises(EnvironmentError) as exc_info:
        _require_env("NON_EXISTENT_VAR_XYZ")
    assert "Required environment variable 'NON_EXISTENT_VAR_XYZ' is not set" in str(exc_info.value)


def test_get_neo4j_config_success(monkeypatch):
    """Test get_neo4j_config returns dictionary when all variables are present."""
    monkeypatch.setenv("NEO4J_URI", "bolt://10.0.0.1:7687")
    monkeypatch.setenv("NEO4J_USERNAME", "admin")
    monkeypatch.setenv("NEO4J_PASSWORD", "secret123")

    cfg = get_neo4j_config()
    assert cfg == {
        "uri": "bolt://10.0.0.1:7687",
        "username": "admin",
        "password": "secret123",
    }


def test_get_neo4j_config_missing_raises(monkeypatch):
    """Test get_neo4j_config raises EnvironmentError when a variable is missing."""
    monkeypatch.setenv("NEO4J_URI", "bolt://10.0.0.1:7687")
    monkeypatch.delenv("NEO4J_PASSWORD", raising=False)

    with pytest.raises(EnvironmentError):
        get_neo4j_config()


def test_get_optional_neo4j_config(monkeypatch):
    """Test get_optional_neo4j_config returns dict when complete, None when incomplete."""
    monkeypatch.setenv("NEO4J_URI", "bolt://10.0.0.1:7687")
    monkeypatch.setenv("NEO4J_USERNAME", "admin")
    monkeypatch.setenv("NEO4J_PASSWORD", "secret123")
    assert get_optional_neo4j_config() is not None

    monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
    assert get_optional_neo4j_config() is None


def test_get_ingestion_config_success_and_missing(monkeypatch):
    """Test get_ingestion_config validation."""
    monkeypatch.setenv("TRAFFIC_CSV_PATH", "data/traffic.tsv")
    monkeypatch.setenv("ALERTS_JSON_PATH", "data/alerts.json")
    cfg = get_ingestion_config()
    assert cfg["traffic_csv_path"] == "data/traffic.tsv"
    assert cfg["alerts_json_path"] == "data/alerts.json"

    monkeypatch.delenv("TRAFFIC_CSV_PATH", raising=False)
    with pytest.raises(EnvironmentError):
        get_ingestion_config()


def test_get_cors_origins(monkeypatch):
    """Test parsing CORS origins."""
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    assert get_cors_origins() == []

    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:3000, http://example.com ")
    assert get_cors_origins() == ["http://localhost:3000", "http://example.com"]
