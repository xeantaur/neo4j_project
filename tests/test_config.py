"""
Unit tests for configuration module.
"""

import pytest
from src.config import _require_env


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
