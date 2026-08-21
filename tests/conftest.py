"""
Pytest configuration and shared test fixtures.
"""

import os
import pytest

# Ensure environment variables are present at import/collection time
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USERNAME", "neo4j_test")
os.environ.setdefault("NEO4J_PASSWORD", "test_password")
os.environ.setdefault("TRAFFIC_CSV_PATH", "data/samples/sample_traffic.tsv")
os.environ.setdefault("ALERTS_JSON_PATH", "data/samples/sample_alerts.json")


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Set default test environment variables for each test execution."""
    monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7687")
    monkeypatch.setenv("NEO4J_USERNAME", "neo4j_test")
    monkeypatch.setenv("NEO4J_PASSWORD", "test_password")
    monkeypatch.setenv("TRAFFIC_CSV_PATH", "data/samples/sample_traffic.tsv")
    monkeypatch.setenv("ALERTS_JSON_PATH", "data/samples/sample_alerts.json")
