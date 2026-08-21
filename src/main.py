"""
Network Traffic Analysis — Main Application

Processes network traffic data (tshark TSV export) and IDS/Snort alert data
(JSON), then loads the results into a Neo4j graph database for relationship
analysis and visualization.

Originally developed during a cybersecurity internship (September 2024).
This version adds configuration management, logging, and resource safety
while preserving the original data processing and graph model.

SECURITY NOTE:
    Historical commits in this repository contain hardcoded credentials.
    Those credentials should be considered compromised and must NOT be
    reused in any environment.  All configuration is now loaded from
    environment variables — see .env.example.
"""

import json
import sys
import logging

from pyspark.sql import SparkSession
from neo4j import GraphDatabase
from pyspark.sql.functions import trim, col

from src.config import (
    NEO4J_URI,
    NEO4J_USERNAME,
    NEO4J_PASSWORD,
    TRAFFIC_CSV_PATH,
    ALERTS_JSON_PATH,
    APP_NAME,
    CSV_SEPARATOR,
    CSV_HAS_HEADER,
    CSV_COLUMN_NAMES,
    CSV_DROP_COLUMNS,
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
# Data loading — Network traffic (PySpark)
# ---------------------------------------------------------------------------
def load_traffic_data(spark: SparkSession, csv_path: str):
    """Read, clean, and deduplicate the tshark TSV traffic export.

    Returns a list of Row objects ready for Neo4j ingestion.
    """
    logger.info("Loading network traffic file: %s", csv_path)

    df = spark.read.csv(csv_path, sep=CSV_SEPARATOR, header=CSV_HAS_HEADER)

    # Assign meaningful column names
    df = df.toDF(*CSV_COLUMN_NAMES)

    # Drop unused columns
    df = df.drop(*CSV_DROP_COLUMNS)

    # Trim whitespace from address and protocol columns
    for column in ["eth_src_resolved", "eth_dst_resolved", "ip_src", "ip_dst"]:
        df = df.withColumn(column, trim(col(column)))

    # Filter out rows with missing essential fields
    df = df.filter(
        (col("ip_src").isNotNull())
        & (col("ip_dst").isNotNull())
        & (col("eth_src_resolved") != "")
        & (col("eth_dst_resolved") != "")
    )

    # Remove duplicate rows
    df = df.dropDuplicates()

    # Collect to driver for Neo4j ingestion
    data_list = df.collect()
    logger.info("Loaded %d unique traffic records.", len(data_list))
    return data_list


# ---------------------------------------------------------------------------
# Data loading — Alerts (JSON)
# ---------------------------------------------------------------------------
def load_alert_data(json_path: str):
    """Read and return IDS/Snort alert data from a JSON file.

    Returns a list of alert dictionaries.
    """
    logger.info("Loading alert data file: %s", json_path)

    with open(json_path, encoding="utf-8") as f:
        json_data = json.load(f)

    logger.info("Loaded %d alert records.", len(json_data))
    return json_data


# ---------------------------------------------------------------------------
# Neo4j ingestion — Layer 2 (MAC → MAC)
# ---------------------------------------------------------------------------
def load_layer2_data_to_neo4j(driver, data):
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
                "eth_src_resolved": row["eth_src_resolved"],
                "eth_dst_resolved": row["eth_dst_resolved"],
                "protocol": row["protocol"],
            }
            session.run(query, parameters)
    logger.info("Layer 2 data loaded successfully.")


# ---------------------------------------------------------------------------
# Neo4j ingestion — Layer 3 (IP → IP, IP → MAC)
# ---------------------------------------------------------------------------
def load_layer3_data_to_neo4j(driver, data):
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
                "ip_src": row["ip_src"],
                "ip_dst": row["ip_dst"],
                "eth_src_resolved": row["eth_src_resolved"],
                "eth_dst_resolved": row["eth_dst_resolved"],
                "protocol": row["protocol"],
            }
            session.run(query, parameters)
    logger.info("Layer 3 data loaded successfully.")


# ---------------------------------------------------------------------------
# Neo4j ingestion — Alerts (IP → IP)
# ---------------------------------------------------------------------------
def load_alarm_data_to_neo4j(driver, data):
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
                "src_ip": entry.get("src_ip"),
                "dst_ip": entry.get("dst_ip"),
                "sid": entry.get("sid"),
                "gid": entry.get("gid"),
                "rev": entry.get("rev"),
                "message": entry.get("message"),
                "priority": entry.get("priority"),
                "protocol": entry.get("protocol"),
                "src_port": entry.get("src_port"),
                "dst_port": entry.get("dst_port"),
            }
            session.run(query, parameters)
    logger.info("Alert data loaded successfully.")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main():
    """Run the full ingestion pipeline: load data → push to Neo4j."""
    logger.info("=" * 60)
    logger.info("Starting %s", APP_NAME)
    logger.info("=" * 60)

    driver = None
    spark = None

    try:
        # --- Connect to Neo4j ---
        logger.info("Connecting to Neo4j at %s ...", NEO4J_URI)
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        driver.verify_connectivity()
        logger.info("Neo4j connection established.")

        # --- Start PySpark session ---
        logger.info("Initializing PySpark session...")
        spark = SparkSession.builder.appName(APP_NAME).getOrCreate()
        logger.info("PySpark session ready.")

        # --- Load traffic data ---
        traffic_data = load_traffic_data(spark, TRAFFIC_CSV_PATH)

        # --- Load alert data ---
        alert_data = load_alert_data(ALERTS_JSON_PATH)

        # --- Ingest into Neo4j ---
        load_layer2_data_to_neo4j(driver, traffic_data)
        load_layer3_data_to_neo4j(driver, traffic_data)
        load_alarm_data_to_neo4j(driver, alert_data)

        logger.info("=" * 60)
        logger.info("All data ingested successfully.")
        logger.info("=" * 60)

    except EnvironmentError as exc:
        logger.error("Configuration error: %s", exc)
        sys.exit(1)
    except FileNotFoundError as exc:
        logger.error("Data file not found: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error during ingestion: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        # Always clean up resources, even after errors
        if driver is not None:
            driver.close()
            logger.info("Neo4j connection closed.")
        if spark is not None:
            spark.stop()
            logger.info("PySpark session stopped.")


if __name__ == "__main__":
    main()
