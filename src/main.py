"""
Network Traffic Analysis — Main Application

Processes network traffic data (tshark TSV export) and IDS/Snort alert data
(JSON), then loads the results into a Neo4j graph database for relationship
analysis and visualization.

Originally developed during a cybersecurity internship (September 2024).
Modernized in Phase 2 with a lightweight pandas-based ingestion pipeline,
structured domain models, and comprehensive validation while preserving the
established Neo4j graph schema and relationship semantics.

SECURITY NOTE:
    Historical commits in this repository contain hardcoded credentials.
    Those credentials should be considered compromised and must NOT be
    reused in any environment. All configuration is now loaded from
    environment variables — see .env.example.
"""

import sys
import logging
from typing import List
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
    TrafficRecord,
    AlertRecord,
    parse_traffic_file,
    parse_alert_file,
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
# Neo4j ingestion — Layer 2 (MAC → MAC)
# ---------------------------------------------------------------------------
def load_layer2_data_to_neo4j(driver, data: List[TrafficRecord]) -> None:
    """Create MAC-to-MAC relationships in Neo4j.

    For each traffic record, MERGEs source and destination MAC nodes
    and CREATEs a :DESTINATION relationship carrying the protocol.
    """
    logger.info("Loading Layer 2 (MAC) data into Neo4j (%d records)...", len(data))
    with driver.session() as session:
        for row in data:
            query = """
            MERGE (src:MAC {address: $eth_src_resolved})
            MERGE (dst:MAC {address: $eth_dst_resolved})
            CREATE (src)-[:DESTINATION {protocol: $protocol}]->(dst)
            """
            parameters = {
                "eth_src_resolved": row.eth_src_resolved,
                "eth_dst_resolved": row.eth_dst_resolved,
                "protocol": row.protocol,
            }
            session.run(query, parameters)
    logger.info("Layer 2 data loaded successfully.")


# ---------------------------------------------------------------------------
# Neo4j ingestion — Layer 3 (IP → IP, IP → MAC)
# ---------------------------------------------------------------------------
def load_layer3_data_to_neo4j(driver, data: List[TrafficRecord]) -> None:
    """Create IP-to-IP and IP-to-MAC relationships in Neo4j.

    For each traffic record, MERGEs IP and MAC nodes, then CREATEs
    :ASSOCIATED_WITH (IP→MAC) and :DESTINATION (IP→IP) relationships.
    """
    logger.info("Loading Layer 3 (IP) data into Neo4j (%d records)...", len(data))
    with driver.session() as session:
        for row in data:
            query = """
            MERGE (src_ip:IP {address: $ip_src})
            MERGE (dst_ip:IP {address: $ip_dst})
            MERGE (src_mac:MAC {address: $eth_src_resolved})
            MERGE (dst_mac:MAC {address: $eth_dst_resolved})

            CREATE (src_ip)-[:ASSOCIATED_WITH]->(src_mac)
            CREATE (dst_ip)-[:ASSOCIATED_WITH]->(dst_mac)
            CREATE (src_ip)-[:DESTINATION {protocol: $protocol}]->(dst_ip)
            """
            parameters = {
                "ip_src": row.ip_src,
                "ip_dst": row.ip_dst,
                "eth_src_resolved": row.eth_src_resolved,
                "eth_dst_resolved": row.eth_dst_resolved,
                "protocol": row.protocol,
            }
            session.run(query, parameters)
    logger.info("Layer 3 data loaded successfully.")


# ---------------------------------------------------------------------------
# Neo4j ingestion — Alerts (IP → IP)
# ---------------------------------------------------------------------------
def load_alarm_data_to_neo4j(driver, data: List[AlertRecord]) -> None:
    """Create alert relationships in Neo4j.

    For each alert, MERGEs source and destination IP nodes and CREATEs
    an :ALERT relationship with rule and severity properties.
    """
    logger.info("Loading alert data into Neo4j (%d records)...", len(data))
    with driver.session() as session:
        for entry in data:
            query = """
            MERGE (src_ip:IP {address: $src_ip})
            MERGE (dst_ip:IP {address: $dst_ip})
            CREATE (src_ip)-[:ALERT {sid: $sid, gid: $gid, rev: $rev, message: $message, priority: $priority, protocol: $protocol, src_port: $src_port, dst_port: $dst_port}]->(dst_ip)
            """
            parameters = {
                "src_ip": entry.src_ip,
                "dst_ip": entry.dst_ip,
                "sid": entry.sid,
                "gid": entry.gid,
                "rev": entry.rev,
                "message": entry.message,
                "priority": entry.priority,
                "protocol": entry.protocol,
                "src_port": entry.src_port,
                "dst_port": entry.dst_port,
            }
            session.run(query, parameters)
    logger.info("Alert data loaded successfully.")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main():
    """Run the full ingestion pipeline: parse data → push to Neo4j."""
    logger.info("=" * 60)
    logger.info("Starting %s", APP_NAME)
    logger.info("=" * 60)

    driver = None

    try:
        # --- Connect to Neo4j ---
        logger.info("Connecting to Neo4j at %s ...", NEO4J_URI)
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        driver.verify_connectivity()
        logger.info("Neo4j connection established.")

        # --- Ingestion: Load & Parse Traffic Data ---
        traffic_records, traffic_summary = parse_traffic_file(TRAFFIC_CSV_PATH)
        logger.info(
            "Traffic Ingestion Summary: %d raw records, %d valid unique, %d skipped, %d duplicates",
            traffic_summary.total_raw_records,
            traffic_summary.valid_records,
            traffic_summary.skipped_records,
            traffic_summary.duplicate_records,
        )

        # --- Ingestion: Load & Parse Alert Data ---
        alert_records, alert_summary = parse_alert_file(ALERTS_JSON_PATH)
        logger.info(
            "Alert Ingestion Summary: %d raw records, %d valid, %d skipped",
            alert_summary.total_raw_records,
            alert_summary.valid_records,
            alert_summary.skipped_records,
        )

        # --- Ingest into Neo4j ---
        load_layer2_data_to_neo4j(driver, traffic_records)
        load_layer3_data_to_neo4j(driver, traffic_records)
        load_alarm_data_to_neo4j(driver, alert_records)

        logger.info("=" * 60)
        logger.info("All data ingested successfully.")
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
        logger.error("Unexpected error during ingestion: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        # Always clean up resources, even after errors
        if driver is not None:
            driver.close()
            logger.info("Neo4j connection closed.")


if __name__ == "__main__":
    main()
