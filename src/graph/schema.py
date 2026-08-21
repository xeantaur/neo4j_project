"""
Neo4j Graph Schema and Constraint Management.

Defines idempotent Neo4j 5.x uniqueness constraints and RANGE indexes
for the modernized graph model.
"""

import logging
from typing import List

logger = logging.getLogger(__name__)

# Neo4j 5.x constraint DDL statements (backed by RANGE indexes)
SCHEMA_STATEMENTS: List[str] = [
    # 1. IPAddress uniqueness constraint
    "CREATE CONSTRAINT ip_address_unique IF NOT EXISTS "
    "FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE",

    # 2. Layer2Identifier uniqueness constraint
    "CREATE CONSTRAINT layer2_identifier_unique IF NOT EXISTS "
    "FOR (l2:Layer2Identifier) REQUIRE l2.identifier IS UNIQUE",

    # 3. AlertFact uniqueness constraint on deterministic fact_key
    "CREATE CONSTRAINT alert_fact_unique IF NOT EXISTS "
    "FOR (fact:AlertFact) REQUIRE fact.fact_key IS UNIQUE",

    # 4. AlertFact priority index for severity queries
    "CREATE INDEX alert_fact_priority_index IF NOT EXISTS "
    "FOR (fact:AlertFact) ON (fact.priority)",

    # 5. AlertFact sid index for rule/signature queries
    "CREATE INDEX alert_fact_sid_index IF NOT EXISTS "
    "FOR (fact:AlertFact) ON (fact.sid)",
]


def ensure_schema(driver) -> None:
    """Apply all uniqueness constraints and indexes to the Neo4j database idempotently.
    
    Uses Neo4j 5.x 'IF NOT EXISTS' syntax to ensure safe execution without errors
    on existing databases. Explicitly consumes transaction results for each statement.
    """
    logger.info("Ensuring Neo4j graph schema constraints and indexes...")
    with driver.session() as session:
        for statement in SCHEMA_STATEMENTS:
            logger.debug("Executing schema statement: %s", statement)
            result = session.run(statement)
            result.consume()
    logger.info("Neo4j graph schema constraints and indexes verified.")
