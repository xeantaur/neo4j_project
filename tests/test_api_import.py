"""
Unit and API integration tests for Phase 6.5 Data Import endpoints.

Tests stateless validation, feature gating, bounded file size enforcement,
single-process concurrency locking, capability derivation, and atomic workspace replacement.
"""

import io
import json
import os
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.dependencies import get_write_repository
from src.services.import_service import _IMPORT_MUTATION_LOCK


# Sample valid and invalid fixtures for testing
VALID_TRAFFIC_TSV = (
    "eth_src_resolved\teth_dst_resolved\tip_src\tip_dst\tunused1\tunused2\tprotocol\n"
    "00:11:22:33:44:55\t66:77:88:99:aa:bb\t192.168.1.10\t192.168.1.20\t-\t-\tTCP\n"
    "00:11:22:33:44:55\t66:77:88:99:aa:cc\t192.168.1.10\t192.168.1.30\t-\t-\tDNS\n"
).encode("utf-8")

VALID_ALERTS_JSON = json.dumps([
    {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "sid": 2001,
        "message": "ET MALWARE Suspicious Inbound Connection",
        "priority": 1,
        "protocol": "TCP",
    },
    {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.10",
        "sid": 2002,
        "message": "ET SCAN Portscan Detected",
        "priority": 2,
        "protocol": "TCP",
    }
]).encode("utf-8")

PARTIAL_MALFORMED_TRAFFIC_TSV = (
    "eth_src_resolved\teth_dst_resolved\tip_src\tip_dst\tunused1\tunused2\tprotocol\n"
    "00:11:22:33:44:55\t66:77:88:99:aa:bb\t192.168.1.10\t192.168.1.20\t-\t-\tTCP\n"
    "00:11:22:33:44:55\t66:77:88:99:aa:cc\tINVALID_IP\t192.168.1.30\t-\t-\tDNS\n"
).encode("utf-8")

ZERO_VALID_TRAFFIC_TSV = (
    "eth_src_resolved\teth_dst_resolved\tip_src\tip_dst\tunused1\tunused2\tprotocol\n"
    "00:11:22:33:44:55\t66:77:88:99:aa:bb\tINVALID_IP_1\tINVALID_IP_2\t-\t-\tTCP\n"
).encode("utf-8")

MALFORMED_JSON = b"[{invalid_json_here"


@pytest.fixture
def mock_write_repo():
    """Mock Neo4j write repository."""
    mock = MagicMock()
    mock.replace_workspace_data.return_value = (2, 2)
    return mock


@pytest.fixture
def app_with_repo(mock_write_repo):
    """Create FastAPI app overriding write repository dependency."""
    app = create_app()
    app.dependency_overrides[get_write_repository] = lambda: mock_write_repo
    return app


@pytest.fixture
def client(app_with_repo):
    """Test client with mocked repository."""
    return TestClient(app_with_repo, raise_server_exceptions=False)


# ===========================================================================
# 1. Status Endpoint Tests
# ===========================================================================

def test_status_endpoint_when_disabled(client, monkeypatch):
    """GET /api/v1/import/status reports disabled by default."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "false")
    monkeypatch.setenv("DATA_IMPORT_MAX_FILE_SIZE_MB", "10")

    resp = client.get("/api/v1/import/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is False
    assert data["max_file_size_mb"] == 10
    assert data["max_file_size_bytes"] == 10 * 1024 * 1024


def test_status_endpoint_when_enabled(client, monkeypatch):
    """GET /api/v1/import/status reports enabled when configured."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")
    monkeypatch.setenv("DATA_IMPORT_MAX_FILE_SIZE_MB", "25")

    resp = client.get("/api/v1/import/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is True
    assert data["max_file_size_mb"] == 25
    assert data["max_file_size_bytes"] == 25 * 1024 * 1024


# ===========================================================================
# 2. Feature Gate Enforcement
# ===========================================================================

def test_validate_disabled_returns_403(client, monkeypatch):
    """POST /api/v1/import/validate returns 403 when DATA_IMPORT_ENABLED is false."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "false")

    files = {"traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values")}
    resp = client.post("/api/v1/import/validate", files=files)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Data import is disabled by server configuration."


def test_import_disabled_returns_403(client, monkeypatch, mock_write_repo):
    """POST /api/v1/import returns 403 when DATA_IMPORT_ENABLED is false and does not mutate."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "false")

    files = {"traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values")}
    resp = client.post("/api/v1/import", files=files)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Data import is disabled by server configuration."
    mock_write_repo.replace_workspace_data.assert_not_called()


def test_disabled_requests_do_not_invoke_parsers(client, monkeypatch):
    """When disabled, neither traffic nor alert parser is invoked."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "false")

    with patch("src.services.import_service.parse_traffic_file") as mock_tp, \
         patch("src.services.import_service.parse_alert_file") as mock_ap:
        files = {"traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values")}
        resp = client.post("/api/v1/import/validate", files=files)
        assert resp.status_code == 403
        mock_tp.assert_not_called()
        mock_ap.assert_not_called()


# ===========================================================================
# 3. Request Validation (No Files & Oversized Files)
# ===========================================================================

def test_validate_no_files_returns_422(client, monkeypatch):
    """POST /api/v1/import/validate returns 422 if neither file is provided."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")
    resp = client.post("/api/v1/import/validate")
    assert resp.status_code == 422
    assert "At least one file" in resp.json()["detail"]


def test_import_no_files_returns_422(client, monkeypatch):
    """POST /api/v1/import returns 422 if neither file is provided."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")
    resp = client.post("/api/v1/import")
    assert resp.status_code == 422
    assert "At least one file" in resp.json()["detail"]


def test_oversized_traffic_returns_413(client, monkeypatch):
    """POST /api/v1/import/validate returns 413 if uploaded file exceeds size limit."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")
    monkeypatch.setenv("DATA_IMPORT_MAX_FILE_SIZE_MB", "1")

    # Generate 1.5 MiB dummy payload
    oversized_data = b"x" * (1024 * 1024 + 512 * 1024)
    files = {"traffic_file": ("large_traffic.tsv", io.BytesIO(oversized_data), "text/tab-separated-values")}
    resp = client.post("/api/v1/import/validate", files=files)
    assert resp.status_code == 413
    assert "exceeds the maximum allowed size of 1 MiB" in resp.json()["detail"]


# ===========================================================================
# 4. Stateless Validation Scenarios
# ===========================================================================

def test_validate_traffic_only(client, monkeypatch, mock_write_repo):
    """Validate traffic file only succeeds statelessly without Neo4j modification."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    files = {"traffic_file": ("sample_traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values")}
    resp = client.post("/api/v1/import/validate", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["can_import"] is True
    assert data["traffic"]["provided"] is True
    assert data["traffic"]["valid_records"] == 2
    assert data["traffic"]["filename"] == "sample_traffic.tsv"
    assert data["alerts"]["provided"] is False
    # Neo4j repository was NOT called
    mock_write_repo.replace_workspace_data.assert_not_called()


def test_validate_alerts_only(client, monkeypatch, mock_write_repo):
    """Validate alerts file only succeeds statelessly."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    files = {"alerts_file": ("sample_alerts.json", io.BytesIO(VALID_ALERTS_JSON), "application/json")}
    resp = client.post("/api/v1/import/validate", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["can_import"] is True
    assert data["alerts"]["provided"] is True
    assert data["alerts"]["valid_records"] == 2
    assert data["alerts"]["filename"] == "sample_alerts.json"
    assert data["traffic"]["provided"] is False
    mock_write_repo.replace_workspace_data.assert_not_called()


def test_validate_combined_files(client, monkeypatch):
    """Validate combined traffic + alerts datasets."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    files = {
        "traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values"),
        "alerts_file": ("alerts.json", io.BytesIO(VALID_ALERTS_JSON), "application/json"),
    }
    resp = client.post("/api/v1/import/validate", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["can_import"] is True
    assert data["traffic"]["provided"] is True
    assert data["traffic"]["valid_records"] == 2
    assert data["alerts"]["provided"] is True
    assert data["alerts"]["valid_records"] == 2


def test_validate_partial_malformed_rows_valid_with_warnings(client, monkeypatch):
    """Partial malformed rows produce valid_records > 0 and valid=True with warning metrics."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    files = {"traffic_file": ("traffic.tsv", io.BytesIO(PARTIAL_MALFORMED_TRAFFIC_TSV), "text/tab-separated-values")}
    resp = client.post("/api/v1/import/validate", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["can_import"] is True
    assert data["traffic"]["valid_records"] == 1
    assert data["traffic"]["skipped_records"] == 1
    assert "invalid_ip_src" in data["traffic"]["warning_counts"]


def test_validate_zero_usable_records_fails(client, monkeypatch):
    """When a provided file produces 0 valid records, valid is False and can_import is False."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    files = {"traffic_file": ("traffic.tsv", io.BytesIO(ZERO_VALID_TRAFFIC_TSV), "text/tab-separated-values")}
    resp = client.post("/api/v1/import/validate", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["can_import"] is False
    assert data["traffic"]["valid_records"] == 0


def test_validate_malformed_json_fails(client, monkeypatch):
    """Malformed JSON syntax produces valid=False, can_import=False."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    files = {"alerts_file": ("alerts.json", io.BytesIO(MALFORMED_JSON), "application/json")}
    resp = client.post("/api/v1/import/validate", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["can_import"] is False
    assert "fatal_parse_error" in data["alerts"]["warning_counts"]


# ===========================================================================
# 5. Import Execution & Capabilities
# ===========================================================================

def test_import_traffic_only_success(client, monkeypatch, mock_write_repo):
    """Import traffic-only dataset replaces workspace and returns traffic capabilities."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")
    mock_write_repo.replace_workspace_data.return_value = (2, 0)

    files = {"traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values")}
    resp = client.post("/api/v1/import", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["workspace_replaced"] is True
    assert data["traffic_records_persisted"] == 2
    assert data["alert_facts_persisted"] == 0

    caps = data["capabilities"]
    assert caps["network_topology"] is True
    assert caps["ip_investigation"] is True
    assert caps["communication_paths"] is True
    assert caps["alert_facts"] is False
    assert caps["traffic_alert_correlations"] is False

    mock_write_repo.replace_workspace_data.assert_called_once()


def test_import_alerts_only_success(client, monkeypatch, mock_write_repo):
    """Import alerts-only dataset returns alert capabilities with ip_investigation=True."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")
    mock_write_repo.replace_workspace_data.return_value = (0, 2)

    files = {"alerts_file": ("alerts.json", io.BytesIO(VALID_ALERTS_JSON), "application/json")}
    resp = client.post("/api/v1/import", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["traffic_records_persisted"] == 0
    assert data["alert_facts_persisted"] == 2

    caps = data["capabilities"]
    assert caps["network_topology"] is False
    assert caps["ip_investigation"] is True
    assert caps["communication_paths"] is False
    assert caps["alert_facts"] is True
    assert caps["traffic_alert_correlations"] is False


def test_import_combined_success(client, monkeypatch, mock_write_repo):
    """Import combined datasets returns all capabilities enabled."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")
    mock_write_repo.replace_workspace_data.return_value = (2, 2)

    files = {
        "traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values"),
        "alerts_file": ("alerts.json", io.BytesIO(VALID_ALERTS_JSON), "application/json"),
    }
    resp = client.post("/api/v1/import", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True

    caps = data["capabilities"]
    assert caps["network_topology"] is True
    assert caps["ip_investigation"] is True
    assert caps["communication_paths"] is True
    assert caps["alert_facts"] is True
    assert caps["traffic_alert_correlations"] is True


def test_import_fatal_validation_rejects_with_422(client, monkeypatch, mock_write_repo):
    """POST /api/v1/import independently validates and rejects unparseable data with 422."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    files = {"traffic_file": ("traffic.tsv", io.BytesIO(ZERO_VALID_TRAFFIC_TSV), "text/tab-separated-values")}
    resp = client.post("/api/v1/import", files=files)
    assert resp.status_code == 422
    assert "failed validation" in resp.json()["detail"]
    mock_write_repo.replace_workspace_data.assert_not_called()


# ===========================================================================
# 6. Concurrency Guard & Lock Release
# ===========================================================================

def test_concurrent_import_returns_409(client, monkeypatch, mock_write_repo):
    """When import lock is already acquired, subsequent import returns 409 Conflict."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    # Deliberately acquire the lock manually to simulate concurrent import
    _IMPORT_MUTATION_LOCK.acquire(blocking=False)
    try:
        files = {"traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values")}
        resp = client.post("/api/v1/import", files=files)
        assert resp.status_code == 409
        assert "Another data import is already in progress" in resp.json()["detail"]
        mock_write_repo.replace_workspace_data.assert_not_called()
    finally:
        _IMPORT_MUTATION_LOCK.release()


def test_lock_released_after_failure(client, monkeypatch, mock_write_repo):
    """Lock is guaranteed released even when database write raises an exception."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")
    mock_write_repo.replace_workspace_data.side_effect = RuntimeError("Simulated DB write failure")

    files = {"traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values")}
    resp = client.post("/api/v1/import", files=files)
    assert resp.status_code == 500

    # Ensure lock is not left locked
    assert _IMPORT_MUTATION_LOCK.acquire(blocking=False) is True
    _IMPORT_MUTATION_LOCK.release()


# ===========================================================================
# 7. Temp File Cleanup & Public Error Sanitization
# ===========================================================================

def test_temp_files_unlinked_after_validation(client, monkeypatch):
    """Temporary files created during validation are cleanly unlinked."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    created_temp_files = []
    real_spool = src.services.import_service.spool_upload_to_temp

    def tracking_spool(upload_file, max_bytes, max_mb):
        path = real_spool(upload_file, max_bytes, max_mb)
        created_temp_files.append(path)
        return path

    with patch("src.services.import_service.spool_upload_to_temp", side_effect=tracking_spool):
        files = {"traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values")}
        resp = client.post("/api/v1/import/validate", files=files)
        assert resp.status_code == 200

    assert len(created_temp_files) > 0
    for path in created_temp_files:
        assert not os.path.exists(path)


def test_public_errors_do_not_expose_temp_paths(client, monkeypatch):
    """Error responses do not leak temporary filesystem paths."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    files = {"traffic_file": ("traffic.tsv", io.BytesIO(ZERO_VALID_TRAFFIC_TSV), "text/tab-separated-values")}
    resp = client.post("/api/v1/import/validate", files=files)
    assert resp.status_code == 200
    payload_str = json.dumps(resp.json())
    assert "tmp" not in payload_str.lower()
    assert "neo4j_import_" not in payload_str


def test_temp_files_unlinked_when_alert_parsing_fails(client, monkeypatch):
    """Temporary files for both files are unlinked even when alert parsing fails."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")

    created_temp_files = []
    real_spool = src.services.import_service.spool_upload_to_temp

    def tracking_spool(upload_file, max_bytes, max_mb):
        path = real_spool(upload_file, max_bytes, max_mb)
        created_temp_files.append(path)
        return path

    with patch("src.services.import_service.spool_upload_to_temp", side_effect=tracking_spool):
        files = {
            "traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values"),
            "alerts_file": ("alerts.json", io.BytesIO(MALFORMED_JSON), "application/json"),
        }
        resp = client.post("/api/v1/import/validate", files=files)
        assert resp.status_code == 200

    assert len(created_temp_files) == 2
    for path in created_temp_files:
        assert not os.path.exists(path)


def test_temp_files_unlinked_when_second_file_oversized(client, monkeypatch):
    """If first file spools but second exceeds limit, temp files are cleaned up."""
    monkeypatch.setenv("DATA_IMPORT_ENABLED", "true")
    monkeypatch.setenv("DATA_IMPORT_MAX_FILE_SIZE_MB", "1")

    created_temp_files = []
    real_spool = src.services.import_service.spool_upload_to_temp

    def tracking_spool(upload_file, max_bytes, max_mb):
        path = real_spool(upload_file, max_bytes, max_mb)
        created_temp_files.append(path)
        return path

    oversized_alert_data = b"x" * (1024 * 1024 + 256 * 1024)

    with patch("src.services.import_service.spool_upload_to_temp", side_effect=tracking_spool):
        files = {
            "traffic_file": ("traffic.tsv", io.BytesIO(VALID_TRAFFIC_TSV), "text/tab-separated-values"),
            "alerts_file": ("large_alerts.json", io.BytesIO(oversized_alert_data), "application/json"),
        }
        resp = client.post("/api/v1/import/validate", files=files)
        assert resp.status_code == 413

    for path in created_temp_files:
        assert not os.path.exists(path)


import src.services.import_service
