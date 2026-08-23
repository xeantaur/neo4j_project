"""
Neo4j Graph Persistence Repository.

Implements batched UNWIND write operations using managed transactions
(session.execute_write) for normalized TrafficRecord and AlertRecord models.
"""

import hashlib
import ipaddress
import json
import logging
from typing import List, Dict, Any, Iterator, TypeVar, Optional, Tuple

from src.ingestion.models import TrafficRecord, AlertRecord

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Scoped deletion of all application-owned graph entities
CYPHER_SCOPED_CLEANUP = """
MATCH (n)
WHERE n:IPAddress OR n:Layer2Identifier OR n:AlertFact
DETACH DELETE n
"""

# Cypher statements for batched parameter ingestion
CYPHER_WRITE_TRAFFIC_BATCH = """
UNWIND $batch AS row
MERGE (src_ip:IPAddress {address: row.ip_src})
MERGE (dst_ip:IPAddress {address: row.ip_dst})
MERGE (src_l2:Layer2Identifier {identifier: row.eth_src_resolved})
MERGE (dst_l2:Layer2Identifier {identifier: row.eth_dst_resolved})

MERGE (src_ip)-[:OBSERVED_WITH]->(src_l2)
MERGE (dst_ip)-[:OBSERVED_WITH]->(dst_l2)
MERGE (src_ip)-[:COMMUNICATED_TO {protocol: row.protocol}]->(dst_ip)
MERGE (src_l2)-[:L2_COMMUNICATED_TO {protocol: row.protocol}]->(dst_l2)
"""

CYPHER_WRITE_ALERT_BATCH = """
UNWIND $batch AS row
MERGE (src:IPAddress {address: row.src_ip})
MERGE (dst:IPAddress {address: row.dst_ip})
MERGE (fact:AlertFact {fact_key: row.fact_key})
ON CREATE SET
    fact.sid = row.sid,
    fact.gid = row.gid,
    fact.rev = row.rev,
    fact.message = row.message,
    fact.priority = row.priority,
    fact.protocol = row.protocol,
    fact.src_port = row.src_port,
    fact.dst_port = row.dst_port
MERGE (src)-[:SOURCE_OF]->(fact)
MERGE (fact)-[:TARGETS]->(dst)
"""


def canonicalize_ip(ip_str: str) -> str:
    """Return the canonical string representation of an IPv4 or IPv6 address.
    
    Guarantees equivalent representations (such as expanded vs compressed IPv6)
    map to the exact same string key for graph identity.
    """
    cleaned = ip_str.strip()
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return cleaned


def compute_alert_fact_key(alert: AlertRecord) -> str:
    """Generate a deterministic SHA-256 fact_key for a normalized AlertRecord.
    
    NOTE: fact_key represents a deterministic identity for a unique normalized
    alert fact, NOT an IDS event ID or timestamped instance.
    """
    canonical_payload = {
        "src_ip": canonicalize_ip(alert.src_ip),
        "dst_ip": canonicalize_ip(alert.dst_ip),
        "sid": alert.sid,
        "gid": alert.gid,
        "rev": alert.rev,
        "message": alert.message,
        "priority": alert.priority,
        "protocol": alert.protocol,
        "src_port": alert.src_port,
        "dst_port": alert.dst_port,
    }
    # Deterministic canonical serialization: sort keys, stable delimiters, UTF-8
    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def chunk_list(items: List[T], size: int) -> Iterator[List[T]]:
    """Yield successive chunks of list up to the specified size."""
    if size < 1:
        raise ValueError(f"Batch size must be at least 1, got {size}")
    for i in range(0, len(items), size):
        yield items[i : i + size]


class Neo4jRepository:
    """Repository handling batched graph persistence for traffic and alert data.
    
    Receives an existing Neo4j driver (managed externally by main.py) and executes
    retry-safe managed transactions (session.execute_write).
    """

    def __init__(self, driver, batch_size: int = 500):
        self.driver = driver
        self.batch_size = max(1, batch_size)

    def write_traffic_records(self, records: List[TrafficRecord]) -> int:
        """Persist a list of TrafficRecord instances in batched UNWIND transactions.
        
        Returns the count of records processed.
        """
        if not records:
            logger.info("No traffic records to persist.")
            return 0

        # Transform to parameter dictionaries with canonicalized IPs
        payload = [
            {
                "ip_src": canonicalize_ip(r.ip_src),
                "ip_dst": canonicalize_ip(r.ip_dst),
                "eth_src_resolved": r.eth_src_resolved,
                "eth_dst_resolved": r.eth_dst_resolved,
                "protocol": r.protocol,
            }
            for r in records
        ]

        total_batches = (len(payload) + self.batch_size - 1) // self.batch_size
        logger.info(
            "Persisting %d traffic records in %d batch(es) (batch_size=%d)...",
            len(payload),
            total_batches,
            self.batch_size,
        )

        with self.driver.session() as session:
            for batch_num, batch in enumerate(chunk_list(payload, self.batch_size), start=1):
                session.execute_write(self._execute_traffic_batch, batch)
                logger.debug("Persisted traffic batch %d/%d (%d records)", batch_num, total_batches, len(batch))

        logger.info("Traffic persistence complete: %d records processed.", len(payload))
        return len(payload)

    def write_alert_records(self, records: List[AlertRecord]) -> int:
        """Persist a list of AlertRecord instances as :AlertFact nodes in batched UNWIND transactions.
        
        Returns the count of records processed.
        """
        if not records:
            logger.info("No alert records to persist.")
            return 0

        # Transform to parameter dictionaries with fact_key and canonicalized IPs
        payload = [
            {
                "src_ip": canonicalize_ip(a.src_ip),
                "dst_ip": canonicalize_ip(a.dst_ip),
                "fact_key": compute_alert_fact_key(a),
                "sid": a.sid,
                "gid": a.gid,
                "rev": a.rev,
                "message": a.message,
                "priority": a.priority,
                "protocol": a.protocol,
                "src_port": a.src_port,
                "dst_port": a.dst_port,
            }
            for a in records
        ]

        total_batches = (len(payload) + self.batch_size - 1) // self.batch_size
        logger.info(
            "Persisting %d alert records in %d batch(es) (batch_size=%d)...",
            len(payload),
            total_batches,
            self.batch_size,
        )

        with self.driver.session() as session:
            for batch_num, batch in enumerate(chunk_list(payload, self.batch_size), start=1):
                session.execute_write(self._execute_alert_batch, batch)
                logger.debug("Persisted alert batch %d/%d (%d records)", batch_num, total_batches, len(batch))

        logger.info("Alert persistence complete: %d records processed.", len(payload))
        return len(payload)

    @staticmethod
    def _execute_traffic_batch(tx, batch: List[Dict[str, Any]]) -> None:
        """Managed transaction work function for traffic batch."""
        result = tx.run(CYPHER_WRITE_TRAFFIC_BATCH, batch=batch)
        result.consume()

    @staticmethod
    def _execute_alert_batch(tx, batch: List[Dict[str, Any]]) -> None:
        """Managed transaction work function for alert batch."""
        result = tx.run(CYPHER_WRITE_ALERT_BATCH, batch=batch)
        result.consume()

    def replace_workspace_data(
        self,
        traffic_records: Optional[List[TrafficRecord]] = None,
        alert_records: Optional[List[AlertRecord]] = None,
    ) -> Tuple[int, int]:
        """Atomically replace the current analysis workspace in a single managed write transaction.

        1. Executes scoped deletion of all application-owned graph entities (:IPAddress, :Layer2Identifier, :AlertFact).
        2. Writes all provided traffic records in batched UNWIND calls within the transaction.
        3. Writes all provided alert records in batched UNWIND calls within the transaction.

        If any error occurs during cleanup or write execution, the transaction is automatically
        rolled back by the driver, leaving the previous analysis workspace completely intact.

        Returns:
            Tuple of (traffic_records_persisted_count, alert_facts_persisted_count)
        """
        traffic_payload: List[Dict[str, Any]] = []
        if traffic_records:
            traffic_payload = [
                {
                    "ip_src": canonicalize_ip(r.ip_src),
                    "ip_dst": canonicalize_ip(r.ip_dst),
                    "eth_src_resolved": r.eth_src_resolved,
                    "eth_dst_resolved": r.eth_dst_resolved,
                    "protocol": r.protocol,
                }
                for r in traffic_records
            ]

        alert_payload: List[Dict[str, Any]] = []
        if alert_records:
            alert_payload = [
                {
                    "src_ip": canonicalize_ip(a.src_ip),
                    "dst_ip": canonicalize_ip(a.dst_ip),
                    "fact_key": compute_alert_fact_key(a),
                    "sid": a.sid,
                    "gid": a.gid,
                    "rev": a.rev,
                    "message": a.message,
                    "priority": a.priority,
                    "protocol": a.protocol,
                    "src_port": a.src_port,
                    "dst_port": a.dst_port,
                }
                for a in alert_records
            ]

        logger.info(
            "Executing atomic workspace replacement (%d traffic records, %d alert records)...",
            len(traffic_payload),
            len(alert_payload),
        )

        def _work(tx) -> Tuple[int, int]:
            # Step 1: Scoped graph cleanup
            logger.debug("Executing scoped graph cleanup Cypher...")
            del_result = tx.run(CYPHER_SCOPED_CLEANUP)
            del_result.consume()

            # Step 2: Ingest traffic batches if provided
            if traffic_payload:
                for batch in chunk_list(traffic_payload, self.batch_size):
                    res = tx.run(CYPHER_WRITE_TRAFFIC_BATCH, batch=batch)
                    res.consume()

            # Step 3: Ingest alert batches if provided
            if alert_payload:
                for batch in chunk_list(alert_payload, self.batch_size):
                    res = tx.run(CYPHER_WRITE_ALERT_BATCH, batch=batch)
                    res.consume()

            return len(traffic_payload), len(alert_payload)

        with self.driver.session() as session:
            persisted_traffic, persisted_alerts = session.execute_write(_work)

        logger.info(
            "Atomic workspace replacement completed successfully: %d traffic records, %d alert facts.",
            persisted_traffic,
            persisted_alerts,
        )
        return persisted_traffic, persisted_alerts
