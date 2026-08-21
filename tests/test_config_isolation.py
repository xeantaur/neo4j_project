"""
Unit tests for configuration isolation between API and Ingestion CLI.
"""

import pytest
from fastapi.testclient import TestClient


def test_api_import_and_health_without_ingestion_paths(monkeypatch):
    """Verify that the API can be created and /health succeeds even without ingestion file paths or Neo4j config."""
    monkeypatch.delenv("TRAFFIC_CSV_PATH", raising=False)
    monkeypatch.delenv("ALERTS_JSON_PATH", raising=False)
    monkeypatch.delenv("NEO4J_URI", raising=False)
    monkeypatch.delenv("NEO4J_USERNAME", raising=False)
    monkeypatch.delenv("NEO4J_PASSWORD", raising=False)

    from src.api.app import create_app
    app = create_app()
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_main_cli_fails_gracefully_when_ingestion_config_missing(monkeypatch):
    """Verify that src.main.main() catches missing configuration and exits with code 1."""
    monkeypatch.delenv("TRAFFIC_CSV_PATH", raising=False)
    monkeypatch.delenv("ALERTS_JSON_PATH", raising=False)

    from src.main import main
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
