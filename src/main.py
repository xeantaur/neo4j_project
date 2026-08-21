"""
Network Traffic Analysis — Main Application Orchestrator

Processes network traffic data (tshark TSV export) and IDS/Snort alert data
(JSON), then loads the results into a Neo4j graph database using the Phase 3
normalized graph schema (IPAddress, Layer2Identifier, AlertFact).

Originally developed during a cybersecurity internship (September 2024).
Modernized with a pandas-based ingestion pipeline, batched UNWIND persistence,
and idempotent graph schema management.

SECURITY NOTE:
    Historical commits in this repository contain hardcoded credentials.
    Those credentials should be considered compromised and must NOT be
    reused in any environment. All configuration is now loaded from
    environment variables — see .env.example.
"""

import sys
import logging
from neo4j import GraphDatabase

from src.config import (
    NEO4J_URI,
    NEO4J_USERNAME,
    NEO4J_PASSWORD,
    TRAFFIC_CSV_PATH,
    ALERTS_JSON_PATH,
    APP_NAME,
)
from src.ingestion import (
    parse_traffic_file,
    parse_alert_file,
)
from src.graph import (
    ensure_schema,
    Neo4jRepository,
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(APP_NAME)


# ---------------------------------------------------------------------------
# Main entry point (Orchestration only)
# ---------------------------------------------------------------------------
def main():
    """Run the complete pipeline: parse data -> ensure schema -> persist to Neo4j."""
    logger.info("=" * 60)
    logger.info("Starting %s", APP_NAME)
    logger.info("=" * 60)

    driver = None

    try:
        # --- 1. Ingestion: Load & Parse Traffic Data ---
        traffic_records, traffic_summary = parse_traffic_file(TRAFFIC_CSV_PATH)
        logger.info(
            "Traffic Ingestion: %d raw -> %d valid unique (%d skipped, %d duplicates)",
            traffic_summary.total_raw_records,
            traffic_summary.valid_records,
            traffic_summary.skipped_records,
            traffic_summary.duplicate_records,
        )

        # --- 2. Ingestion: Load & Parse Alert Data ---
        alert_records, alert_summary = parse_alert_file(ALERTS_JSON_PATH)
        logger.info(
            "Alert Ingestion: %d raw -> %d valid (%d skipped)",
            alert_summary.total_raw_records,
            alert_summary.valid_records,
            alert_summary.skipped_records,
        )

        # --- 3. Connect to Neo4j (Driver Lifecycle Managed by main) ---
        logger.info("Connecting to Neo4j at %s ...", NEO4J_URI)
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        driver.verify_connectivity()
        logger.info("Neo4j connection established.")

        # --- 4. Apply Schema Constraints & Indexes ---
        ensure_schema(driver)

        # --- 5. Persist to Neo4j via Repository ---
        repo = Neo4jRepository(driver)
        persisted_traffic = repo.write_traffic_records(traffic_records)
        persisted_alerts = repo.write_alert_records(alert_records)

        logger.info("=" * 60)
        logger.info(
            "All data ingested successfully: %d traffic records, %d alert facts persisted.",
            persisted_traffic,
            persisted_alerts,
        )
        logger.info("=" * 60)

    except EnvironmentError as exc:
        logger.error("Configuration error: %s", exc)
        sys.exit(1)
    except FileNotFoundError as exc:
        logger.error("Data file not found: %s", exc)
        sys.exit(1)
    except ValueError as exc:
        logger.error("Data format / parsing error: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error during execution: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        # Resource cleanup
        if driver is not None:
            driver.close()
            logger.info("Neo4j connection closed.")


if __name__ == "__main__":
    main()
