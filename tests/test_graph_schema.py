"""
Unit tests for Neo4j graph schema module.
"""

from unittest.mock import MagicMock
from src.graph.schema import ensure_schema, SCHEMA_STATEMENTS


def test_schema_statements_definitions():
    """Verify expected uniqueness constraints and indexes are defined."""
    statements_text = " ".join(SCHEMA_STATEMENTS)
    assert "CONSTRAINT ip_address_unique" in statements_text
    assert "FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE" in statements_text

    assert "CONSTRAINT layer2_identifier_unique" in statements_text
    assert "FOR (l2:Layer2Identifier) REQUIRE l2.identifier IS UNIQUE" in statements_text

    assert "CONSTRAINT alert_fact_unique" in statements_text
    assert "FOR (fact:AlertFact) REQUIRE fact.fact_key IS UNIQUE" in statements_text

    assert "INDEX alert_fact_priority_index" in statements_text
    assert "INDEX alert_fact_sid_index" in statements_text

    # Verify no legacy labels exist in schema
    assert ":IP " not in statements_text
    assert ":MAC " not in statements_text
    assert "AlertSignature" not in statements_text


def test_ensure_schema_execution():
    """Verify ensure_schema calls session.run and consume() for each DDL statement."""
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_result = MagicMock()
    mock_session.run.return_value = mock_result

    ensure_schema(mock_driver)

    assert mock_session.run.call_count == len(SCHEMA_STATEMENTS)
    assert mock_result.consume.call_count == len(SCHEMA_STATEMENTS)

    executed_statements = [call.args[0] for call in mock_session.run.call_args_list]
    for stmt in SCHEMA_STATEMENTS:
        assert stmt in executed_statements
