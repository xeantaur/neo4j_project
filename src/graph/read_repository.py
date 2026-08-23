"""
Neo4j Graph Read Repository.

Implements query execution for the Phase 4 FastAPI backend using managed read
transactions (session.execute_read) on a shared Neo4j Driver. All Cypher queries
are parameterized, fully materialized within transaction callbacks, and return
plain Python primitives/dictionaries.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


class Neo4jReadRepository:
    """Read-only repository for querying the network traffic and security alert graph."""

    def __init__(self, driver):
        self.driver = driver

    def check_connectivity(self) -> bool:
        """Verify Neo4j database connectivity.
        
        Returns True if database is reachable, False otherwise.
        """
        if self.driver is None:
            return False
        try:
            self.driver.verify_connectivity()
            return True
        except Exception as exc:
            logger.warning("Neo4j connectivity check failed: %s", exc)
            return False

    def list_ips(self, limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        """List observed IP addresses with pagination."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            count_res = tx.run("MATCH (ip:IPAddress) RETURN count(ip) AS total")
            total = count_res.single()["total"]

            page_res = tx.run(
                "MATCH (ip:IPAddress) "
                "RETURN ip.address AS address "
                "ORDER BY ip.address ASC "
                "SKIP $offset LIMIT $limit",
                offset=offset,
                limit=limit,
            )
            items = [{"address": record["address"]} for record in page_res]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_ip_detail(self, address: str) -> Optional[Dict[str, Any]]:
        """Retrieve local graph context, associated Layer 2 identifiers, flow counts, and volume metrics for an IP."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        cypher = """
        MATCH (ip:IPAddress {address: $address})
        CALL {
            WITH ip
            OPTIONAL MATCH (ip)-[out_c:COMMUNICATED_TO]->(out_peer:IPAddress)
            RETURN count(out_c) AS outbound_aggs,
                   count(DISTINCT out_peer) AS distinct_outbound_peers,
                   count(DISTINCT out_c.dst_port) AS distinct_destination_ports,
                   count(CASE WHEN out_c.observed_packet_count IS NOT NULL
                                   AND out_c.observed_bytes IS NOT NULL
                                   AND out_c.first_seen IS NOT NULL
                                   AND out_c.last_seen IS NOT NULL
                                   AND out_c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS outbound_enriched_aggs,
                   sum(out_c.observed_packet_count) AS raw_pkts_sent,
                   sum(out_c.observed_bytes) AS raw_bytes_sent,
                   min(out_c.first_seen) AS min_out_first,
                   max(out_c.last_seen) AS max_out_last
        }
        CALL {
            WITH ip
            OPTIONAL MATCH (in_peer:IPAddress)-[in_c:COMMUNICATED_TO]->(ip)
            RETURN count(in_c) AS inbound_aggs,
                   count(DISTINCT in_peer) AS distinct_inbound_peers,
                   count(CASE WHEN in_c.observed_packet_count IS NOT NULL
                                   AND in_c.observed_bytes IS NOT NULL
                                   AND in_c.first_seen IS NOT NULL
                                   AND in_c.last_seen IS NOT NULL
                                   AND in_c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS inbound_enriched_aggs,
                   sum(in_c.observed_packet_count) AS raw_pkts_recv,
                   sum(in_c.observed_bytes) AS raw_bytes_recv,
                   min(in_c.first_seen) AS min_in_first,
                   max(in_c.last_seen) AS max_in_last
        }
        RETURN ip.address AS address,
               COLLECT {
                   MATCH (ip)-[:OBSERVED_WITH]->(l2:Layer2Identifier)
                   RETURN l2.identifier ORDER BY l2.identifier ASC
               } AS layer2_identifiers,
               outbound_aggs,
               inbound_aggs,
               distinct_outbound_peers,
               distinct_inbound_peers,
               distinct_destination_ports,
               outbound_enriched_aggs,
               inbound_enriched_aggs,
               CASE WHEN outbound_enriched_aggs > 0 THEN raw_pkts_sent ELSE null END AS observed_packets_sent,
               CASE WHEN inbound_enriched_aggs > 0 THEN raw_pkts_recv ELSE null END AS observed_packets_received,
               CASE WHEN outbound_enriched_aggs > 0 THEN raw_bytes_sent ELSE null END AS observed_bytes_sent,
               CASE WHEN inbound_enriched_aggs > 0 THEN raw_bytes_recv ELSE null END AS observed_bytes_received,
               CASE WHEN outbound_enriched_aggs > 0 OR inbound_enriched_aggs > 0
                    THEN (CASE WHEN min_out_first IS NOT NULL AND min_in_first IS NOT NULL
                               THEN (CASE WHEN min_out_first < min_in_first THEN min_out_first ELSE min_in_first END)
                               ELSE coalesce(min_out_first, min_in_first) END)
                    ELSE null END AS first_observed,
               CASE WHEN outbound_enriched_aggs > 0 OR inbound_enriched_aggs > 0
                    THEN (CASE WHEN max_out_last IS NOT NULL AND max_in_last IS NOT NULL
                               THEN (CASE WHEN max_out_last > max_in_last THEN max_out_last ELSE max_in_last END)
                               ELSE coalesce(max_out_last, max_in_last) END)
                    ELSE null END AS last_observed,
               COUNT { MATCH (ip)-[:SOURCE_OF]->(:AlertFact) } AS alerts_originated,
               COUNT { MATCH (:AlertFact)-[:TARGETS]->(ip) } AS alerts_targeted
        """

        def _work(tx) -> Optional[Dict[str, Any]]:
            res = tx.run(cypher, address=address)
            record = res.single()
            if not record:
                return None

            out_aggs = int(record["outbound_aggs"])
            in_aggs = int(record["inbound_aggs"])
            tot_aggs = out_aggs + in_aggs
            enr_aggs = int(record["outbound_enriched_aggs"]) + int(record["inbound_enriched_aggs"])

            if tot_aggs == 0:
                mode = "none"
            elif enr_aggs == 0:
                mode = "basic"
            elif enr_aggs == tot_aggs:
                mode = "enriched"
            else:
                mode = "mixed"

            return {
                "address": record["address"],
                "layer2_identifiers": [str(x) for x in record["layer2_identifiers"]],
                "outbound_flows": out_aggs,
                "inbound_flows": in_aggs,
                "alerts_originated": int(record["alerts_originated"]),
                "alerts_targeted": int(record["alerts_targeted"]),
                "traffic_metrics_mode": mode,
                "distinct_outbound_peers": int(record["distinct_outbound_peers"]),
                "distinct_inbound_peers": int(record["distinct_inbound_peers"]),
                "distinct_destination_ports": int(record["distinct_destination_ports"]),
                "observed_packets_sent": int(record["observed_packets_sent"]) if record["observed_packets_sent"] is not None else None,
                "observed_packets_received": int(record["observed_packets_received"]) if record["observed_packets_received"] is not None else None,
                "observed_bytes_sent": int(record["observed_bytes_sent"]) if record["observed_bytes_sent"] is not None else None,
                "observed_bytes_received": int(record["observed_bytes_received"]) if record["observed_bytes_received"] is not None else None,
                "first_observed": float(record["first_observed"]) if record["first_observed"] is not None else None,
                "last_observed": float(record["last_observed"]) if record["last_observed"] is not None else None,
            }

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_traffic_analytics_summary(self) -> Dict[str, Any]:
        """Retrieve overall traffic analytics summary and distribution metrics."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Dict[str, Any]:
            # 1. Total & Metric Completeness Aggregates
            summary_cypher = """
            MATCH ()-[c:COMMUNICATED_TO]->()
            WITH count(c) AS total_aggs,
                 count(CASE WHEN c.observed_packet_count IS NOT NULL
                                 AND c.observed_bytes IS NOT NULL
                                 AND c.first_seen IS NOT NULL
                                 AND c.last_seen IS NOT NULL
                                 AND c.observed_window_seconds IS NOT NULL
                            THEN 1 END) AS enriched_aggs,
                 sum(c.observed_packet_count) AS total_pkts,
                 sum(c.observed_bytes) AS total_bytes,
                 min(c.first_seen) AS first_obs,
                 max(c.last_seen) AS last_obs
            RETURN total_aggs, enriched_aggs, total_pkts, total_bytes, first_obs, last_obs
            """
            s_rec = tx.run(summary_cypher).single()
            if not s_rec or s_rec["total_aggs"] == 0:
                return {
                    "traffic_metrics_mode": "none",
                    "total_communication_aggregates": 0,
                    "enriched_communication_aggregates": 0,
                    "basic_communication_aggregates": 0,
                    "total_observed_packets": None,
                    "total_observed_bytes": None,
                    "first_observed": None,
                    "last_observed": None,
                    "protocol_distribution": [],
                    "destination_port_distribution": [],
                    "top_fan_out": [],
                    "top_fan_in": [],
                }

            total_aggs = int(s_rec["total_aggs"])
            enriched_aggs = int(s_rec["enriched_aggs"])
            basic_aggs = total_aggs - enriched_aggs

            if enriched_aggs == 0:
                mode = "basic"
                total_pkts = None
                total_bytes = None
                first_obs = None
                last_obs = None
            elif enriched_aggs == total_aggs:
                mode = "enriched"
                total_pkts = int(s_rec["total_pkts"]) if s_rec["total_pkts"] is not None else None
                total_bytes = int(s_rec["total_bytes"]) if s_rec["total_bytes"] is not None else None
                first_obs = float(s_rec["first_obs"]) if s_rec["first_obs"] is not None else None
                last_obs = float(s_rec["last_obs"]) if s_rec["last_obs"] is not None else None
            else:
                mode = "mixed"
                total_pkts = int(s_rec["total_pkts"]) if s_rec["total_pkts"] is not None else None
                total_bytes = int(s_rec["total_bytes"]) if s_rec["total_bytes"] is not None else None
                first_obs = float(s_rec["first_obs"]) if s_rec["first_obs"] is not None else None
                last_obs = float(s_rec["last_obs"]) if s_rec["last_obs"] is not None else None

            # 2. Protocol Distribution
            proto_cypher = """
            MATCH ()-[c:COMMUNICATED_TO]->()
            RETURN c.protocol AS protocol,
                   count(c) AS agg_count,
                   count(CASE WHEN c.observed_packet_count IS NOT NULL
                                   AND c.observed_bytes IS NOT NULL
                                   AND c.first_seen IS NOT NULL
                                   AND c.last_seen IS NOT NULL
                                   AND c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS enriched_count,
                   sum(c.observed_packet_count) AS pkts,
                   sum(c.observed_bytes) AS bytes
            ORDER BY agg_count DESC, protocol ASC
            """
            proto_res = tx.run(proto_cypher)
            proto_dist = []
            for r in proto_res:
                enr_count = int(r["enriched_count"])
                proto_dist.append({
                    "protocol": r["protocol"],
                    "communication_aggregate_count": int(r["agg_count"]),
                    "observed_packet_count": int(r["pkts"]) if enr_count > 0 and r["pkts"] is not None else None,
                    "observed_bytes": int(r["bytes"]) if enr_count > 0 and r["bytes"] is not None else None,
                })

            # 3. Destination Port Distribution (Top 10 where dst_port IS NOT NULL)
            port_cypher = """
            MATCH ()-[c:COMMUNICATED_TO]->()
            WHERE c.dst_port IS NOT NULL
            RETURN c.dst_port AS dst_port,
                   count(c) AS agg_count,
                   count(CASE WHEN c.observed_packet_count IS NOT NULL
                                   AND c.observed_bytes IS NOT NULL
                                   AND c.first_seen IS NOT NULL
                                   AND c.last_seen IS NOT NULL
                                   AND c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS enriched_count,
                   sum(c.observed_packet_count) AS pkts,
                   sum(c.observed_bytes) AS bytes
            ORDER BY agg_count DESC, dst_port ASC
            LIMIT 10
            """
            port_res = tx.run(port_cypher)
            port_dist = []
            for r in port_res:
                enr_count = int(r["enriched_count"])
                port_dist.append({
                    "dst_port": int(r["dst_port"]),
                    "communication_aggregate_count": int(r["agg_count"]),
                    "observed_packet_count": int(r["pkts"]) if enr_count > 0 and r["pkts"] is not None else None,
                    "observed_bytes": int(r["bytes"]) if enr_count > 0 and r["bytes"] is not None else None,
                })

            # 4. Top Fan-out (Top 10 Source IPs by distinct destination IPs)
            fan_out_cypher = """
            MATCH (src:IPAddress)-[:COMMUNICATED_TO]->(dst:IPAddress)
            RETURN src.address AS address, count(DISTINCT dst) AS distinct_destination_ips
            ORDER BY distinct_destination_ips DESC, address ASC
            LIMIT 10
            """
            fan_out_res = tx.run(fan_out_cypher)
            top_fan_out = [
                {"address": r["address"], "distinct_destination_ips": int(r["distinct_destination_ips"])}
                for r in fan_out_res
            ]

            # 5. Top Fan-in (Top 10 Destination IPs by distinct source IPs)
            fan_in_cypher = """
            MATCH (src:IPAddress)-[:COMMUNICATED_TO]->(dst:IPAddress)
            RETURN dst.address AS address, count(DISTINCT src) AS distinct_source_ips
            ORDER BY distinct_source_ips DESC, address ASC
            LIMIT 10
            """
            fan_in_res = tx.run(fan_in_cypher)
            top_fan_in = [
                {"address": r["address"], "distinct_source_ips": int(r["distinct_source_ips"])}
                for r in fan_in_res
            ]

            return {
                "traffic_metrics_mode": mode,
                "total_communication_aggregates": total_aggs,
                "enriched_communication_aggregates": enriched_aggs,
                "basic_communication_aggregates": basic_aggs,
                "total_observed_packets": total_pkts,
                "total_observed_bytes": total_bytes,
                "first_observed": first_obs,
                "last_observed": last_obs,
                "protocol_distribution": proto_dist,
                "destination_port_distribution": port_dist,
                "top_fan_out": top_fan_out,
                "top_fan_in": top_fan_in,
            }

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_endpoints_analytics(
        self,
        sort_by: str = "fan_out",
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Retrieve paginated, factually ranked endpoint analytics and metrics."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        # Whitelist sorting to guarantee injection safety and deterministic order
        sort_clauses = {
            "fan_out": "distinct_outbound_peers DESC, address ASC",
            "fan_in": "distinct_inbound_peers DESC, address ASC",
            "observed_bytes_sent": "CASE WHEN observed_bytes_sent IS NULL THEN 1 ELSE 0 END, observed_bytes_sent DESC, address ASC",
            "observed_bytes_received": "CASE WHEN observed_bytes_received IS NULL THEN 1 ELSE 0 END, observed_bytes_received DESC, address ASC",
            "observed_packets_sent": "CASE WHEN observed_packets_sent IS NULL THEN 1 ELSE 0 END, observed_packets_sent DESC, address ASC",
            "observed_packets_received": "CASE WHEN observed_packets_received IS NULL THEN 1 ELSE 0 END, observed_packets_received DESC, address ASC",
        }
        order_clause = sort_clauses.get(sort_by, sort_clauses["fan_out"])

        count_cypher = "MATCH (ip:IPAddress) RETURN count(ip) AS total"

        page_cypher = f"""
        MATCH (ip:IPAddress)
        CALL {{
            WITH ip
            OPTIONAL MATCH (ip)-[out_c:COMMUNICATED_TO]->(out_peer:IPAddress)
            RETURN count(out_c) AS outbound_aggs,
                   count(DISTINCT out_peer) AS distinct_outbound_peers,
                   count(DISTINCT out_c.dst_port) AS distinct_destination_ports,
                   count(CASE WHEN out_c.observed_packet_count IS NOT NULL
                                   AND out_c.observed_bytes IS NOT NULL
                                   AND out_c.first_seen IS NOT NULL
                                   AND out_c.last_seen IS NOT NULL
                                   AND out_c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS outbound_enriched_aggs,
                   sum(out_c.observed_packet_count) AS raw_pkts_sent,
                   sum(out_c.observed_bytes) AS raw_bytes_sent,
                   min(out_c.first_seen) AS min_out_first,
                   max(out_c.last_seen) AS max_out_last
        }}
        CALL {{
            WITH ip
            OPTIONAL MATCH (in_peer:IPAddress)-[in_c:COMMUNICATED_TO]->(ip)
            RETURN count(in_c) AS inbound_aggs,
                   count(DISTINCT in_peer) AS distinct_inbound_peers,
                   count(CASE WHEN in_c.observed_packet_count IS NOT NULL
                                   AND in_c.observed_bytes IS NOT NULL
                                   AND in_c.first_seen IS NOT NULL
                                   AND in_c.last_seen IS NOT NULL
                                   AND in_c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS inbound_enriched_aggs,
                   sum(in_c.observed_packet_count) AS raw_pkts_recv,
                   sum(in_c.observed_bytes) AS raw_bytes_recv,
                   min(in_c.first_seen) AS min_in_first,
                   max(in_c.last_seen) AS max_in_last
        }}
        WITH ip,
             outbound_aggs, inbound_aggs,
             distinct_outbound_peers, distinct_inbound_peers, distinct_destination_ports,
             outbound_enriched_aggs, inbound_enriched_aggs,
             CASE WHEN outbound_enriched_aggs > 0 THEN raw_pkts_sent ELSE null END AS observed_packets_sent,
             CASE WHEN inbound_enriched_aggs > 0 THEN raw_pkts_recv ELSE null END AS observed_packets_received,
             CASE WHEN outbound_enriched_aggs > 0 THEN raw_bytes_sent ELSE null END AS observed_bytes_sent,
             CASE WHEN inbound_enriched_aggs > 0 THEN raw_bytes_recv ELSE null END AS observed_bytes_received,
             CASE WHEN outbound_enriched_aggs > 0 OR inbound_enriched_aggs > 0
                  THEN (CASE WHEN min_out_first IS NOT NULL AND min_in_first IS NOT NULL
                             THEN (CASE WHEN min_out_first < min_in_first THEN min_out_first ELSE min_in_first END)
                             ELSE coalesce(min_out_first, min_in_first) END)
                  ELSE null END AS first_observed,
             CASE WHEN outbound_enriched_aggs > 0 OR inbound_enriched_aggs > 0
                  THEN (CASE WHEN max_out_last IS NOT NULL AND max_in_last IS NOT NULL
                             THEN (CASE WHEN max_out_last > max_in_last THEN max_out_last ELSE max_in_last END)
                             ELSE coalesce(max_out_last, max_in_last) END)
                  ELSE null END AS last_observed
        RETURN ip.address AS address,
               outbound_aggs,
               inbound_aggs,
               distinct_outbound_peers,
               distinct_inbound_peers,
               distinct_destination_ports,
               observed_packets_sent,
               observed_packets_received,
               observed_bytes_sent,
               observed_bytes_received,
               first_observed,
               last_observed,
               outbound_enriched_aggs,
               inbound_enriched_aggs
        ORDER BY {order_clause}
        SKIP $offset LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = tx.run(count_cypher).single()["total"]
            page_res = tx.run(page_cypher, offset=offset, limit=limit)
            items = []
            for r in page_res:
                out_aggs = int(r["outbound_aggs"])
                in_aggs = int(r["inbound_aggs"])
                tot_aggs = out_aggs + in_aggs
                enr_aggs = int(r["outbound_enriched_aggs"]) + int(r["inbound_enriched_aggs"])

                if tot_aggs == 0:
                    mode = "none"
                elif enr_aggs == 0:
                    mode = "basic"
                elif enr_aggs == tot_aggs:
                    mode = "enriched"
                else:
                    mode = "mixed"

                items.append({
                    "address": r["address"],
                    "outbound_communication_aggregates": out_aggs,
                    "inbound_communication_aggregates": in_aggs,
                    "distinct_outbound_peers": int(r["distinct_outbound_peers"]),
                    "distinct_inbound_peers": int(r["distinct_inbound_peers"]),
                    "distinct_destination_ports": int(r["distinct_destination_ports"]),
                    "observed_packets_sent": int(r["observed_packets_sent"]) if r["observed_packets_sent"] is not None else None,
                    "observed_packets_received": int(r["observed_packets_received"]) if r["observed_packets_received"] is not None else None,
                    "observed_bytes_sent": int(r["observed_bytes_sent"]) if r["observed_bytes_sent"] is not None else None,
                    "observed_bytes_received": int(r["observed_bytes_received"]) if r["observed_bytes_received"] is not None else None,
                    "first_observed": float(r["first_observed"]) if r["first_observed"] is not None else None,
                    "last_observed": float(r["last_observed"]) if r["last_observed"] is not None else None,
                    "traffic_metrics_mode": mode,
                })
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_ip_peers(
        self,
        address: str,
        direction: str = "all",
        limit: int = 50,
        offset: int = 0,
    ) -> Optional[Tuple[List[Dict[str, Any]], int]]:
        """List communicating peers for an IP address.
        
        Returns None if the specified IP is not found in the graph.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Optional[Tuple[List[Dict[str, Any]], int]]:
            # First check if the IP exists
            ip_check = tx.run("MATCH (ip:IPAddress {address: $address}) RETURN count(ip) AS c", address=address)
            if ip_check.single()["c"] == 0:
                return None

            if direction == "outbound":
                subquery = """
                MATCH (src:IPAddress {address: $address})-[c:COMMUNICATED_TO]->(peer:IPAddress)
                WITH peer.address AS peer_address, 'outbound' AS dir, collect(DISTINCT c.protocol) AS raw_proto
                RETURN peer_address, dir AS direction, raw_proto
                """
            elif direction == "inbound":
                subquery = """
                MATCH (peer:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress {address: $address})
                WITH peer.address AS peer_address, 'inbound' AS dir, collect(DISTINCT c.protocol) AS raw_proto
                RETURN peer_address, dir AS direction, raw_proto
                """
            else:  # "all"
                subquery = """
                MATCH (src:IPAddress {address: $address})-[c:COMMUNICATED_TO]->(peer:IPAddress)
                WITH peer.address AS peer_address, 'outbound' AS dir, collect(DISTINCT c.protocol) AS raw_proto
                RETURN peer_address, dir AS direction, raw_proto
                UNION ALL
                MATCH (peer:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress {address: $address})
                WITH peer.address AS peer_address, 'inbound' AS dir, collect(DISTINCT c.protocol) AS raw_proto
                RETURN peer_address, dir AS direction, raw_proto
                """

            count_cypher = f"CALL {{ {subquery} }} RETURN count(*) AS total"
            total = tx.run(count_cypher, address=address).single()["total"]

            page_cypher = f"""
            CALL {{ {subquery} }}
            RETURN peer_address, direction, raw_proto
            ORDER BY peer_address ASC, direction ASC
            SKIP $offset LIMIT $limit
            """
            page_res = tx.run(page_cypher, address=address, offset=offset, limit=limit)
            items = []
            for r in page_res:
                sorted_protos = sorted(list(set(r["raw_proto"])))
                items.append({
                    "peer_address": r["peer_address"],
                    "direction": r["direction"],
                    "protocols": sorted_protos,
                })
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_ip_layer2(
        self,
        address: str,
        limit: int = 50,
        offset: int = 0,
    ) -> Optional[Tuple[List[Dict[str, Any]], int]]:
        """List Layer 2 identifiers associated with a specific IP address.
        
        Returns None if the specified IP is not found in the graph.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Optional[Tuple[List[Dict[str, Any]], int]]:
            ip_check = tx.run("MATCH (ip:IPAddress {address: $address}) RETURN count(ip) AS c", address=address)
            if ip_check.single()["c"] == 0:
                return None

            count_cypher = """
            MATCH (ip:IPAddress {address: $address})-[:OBSERVED_WITH]->(l2:Layer2Identifier)
            RETURN count(l2) AS total
            """
            total = tx.run(count_cypher, address=address).single()["total"]

            page_cypher = """
            MATCH (ip:IPAddress {address: $address})-[:OBSERVED_WITH]->(l2:Layer2Identifier)
            RETURN l2.identifier AS identifier
            ORDER BY l2.identifier ASC
            SKIP $offset LIMIT $limit
            """
            page_res = tx.run(page_cypher, address=address, offset=offset, limit=limit)
            items = [{"identifier": r["identifier"]} for r in page_res]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_layer2_identifiers(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List all observed Layer 2 identifiers with pagination."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = tx.run("MATCH (l2:Layer2Identifier) RETURN count(l2) AS total").single()["total"]
            page_res = tx.run(
                "MATCH (l2:Layer2Identifier) "
                "RETURN l2.identifier AS identifier "
                "ORDER BY l2.identifier ASC "
                "SKIP $offset LIMIT $limit",
                offset=offset,
                limit=limit,
            )
            items = [{"identifier": r["identifier"]} for r in page_res]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_communications(
        self,
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        sort_by: str = "identity",
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List observed Layer 3 IP-to-IP communications with optional filtering and sorting."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        proto_upper = protocol.strip().upper() if protocol and protocol.strip() else None

        params = {
            "source_ip": source_ip,
            "target_ip": target_ip,
            "protocol": proto_upper,
            "src_port": src_port,
            "dst_port": dst_port,
            "offset": offset,
            "limit": limit,
        }

        where_clause = """
        WHERE ($source_ip IS NULL OR src.address = $source_ip)
          AND ($target_ip IS NULL OR dst.address = $target_ip)
          AND ($protocol IS NULL OR c.protocol = $protocol)
          AND ($src_port IS NULL OR c.src_port = $src_port)
          AND ($dst_port IS NULL OR c.dst_port = $dst_port)
        """

        # Fixed whitelisted sorting clauses
        sort_clauses = {
            "identity": """
            ORDER BY src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.src_port IS NULL THEN 1 ELSE 0 END, c.src_port ASC,
                     CASE WHEN c.dst_port IS NULL THEN 1 ELSE 0 END, c.dst_port ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC
            """,
            "observed_bytes": """
            ORDER BY CASE WHEN c.observed_bytes IS NULL THEN 1 ELSE 0 END, c.observed_bytes DESC,
                     src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC
            """,
            "observed_packets": """
            ORDER BY CASE WHEN c.observed_packet_count IS NULL THEN 1 ELSE 0 END, c.observed_packet_count DESC,
                     src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC
            """,
            "first_seen": """
            ORDER BY CASE WHEN c.first_seen IS NULL THEN 1 ELSE 0 END, c.first_seen ASC,
                     src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC
            """,
        }
        order_clause = sort_clauses.get(sort_by, sort_clauses["identity"])

        count_cypher = f"MATCH (src:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress) {where_clause} RETURN count(c) AS total"
        page_cypher = f"""
        MATCH (src:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress)
        {where_clause}
        RETURN src.address AS source_ip,
               dst.address AS target_ip,
               c.protocol AS protocol,
               c.flow_key AS flow_key,
               c.src_port AS src_port,
               c.dst_port AS dst_port,
               c.observed_packet_count AS observed_packet_count,
               c.observed_bytes AS observed_bytes,
               c.first_seen AS first_seen,
               c.last_seen AS last_seen,
               c.observed_window_seconds AS observed_window_seconds
        {order_clause}
        SKIP $offset LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = tx.run(count_cypher, **params).single()["total"]
            page_res = tx.run(page_cypher, **params)
            items = [
                {
                    "source_ip": r["source_ip"],
                    "target_ip": r["target_ip"],
                    "protocol": r["protocol"],
                    "flow_key": r["flow_key"],
                    "src_port": r["src_port"],
                    "dst_port": r["dst_port"],
                    "observed_packet_count": r["observed_packet_count"],
                    "observed_bytes": r["observed_bytes"],
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                    "observed_window_seconds": r["observed_window_seconds"],
                }
                for r in page_res
            ]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_alert_facts(
        self,
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        priority: Optional[int] = None,
        sid: Optional[int] = None,
        protocol: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List normalized security alert facts with optional filtering."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        proto_upper = protocol.strip().upper() if protocol and protocol.strip() else None

        params = {
            "source_ip": source_ip,
            "target_ip": target_ip,
            "priority": priority,
            "sid": sid,
            "protocol": proto_upper,
            "offset": offset,
            "limit": limit,
        }

        where_clause = """
        WHERE ($source_ip IS NULL OR src.address = $source_ip)
          AND ($target_ip IS NULL OR dst.address = $target_ip)
          AND ($priority IS NULL OR fact.priority = $priority)
          AND ($sid IS NULL OR fact.sid = $sid)
          AND ($protocol IS NULL OR fact.protocol = $protocol)
        """

        count_cypher = f"""
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress)
        {where_clause}
        RETURN count(fact) AS total
        """

        page_cypher = f"""
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress)
        {where_clause}
        RETURN fact.fact_key AS fact_key,
               src.address AS source_ip,
               dst.address AS target_ip,
               fact.sid AS sid,
               fact.gid AS gid,
               fact.rev AS rev,
               fact.message AS message,
               fact.priority AS priority,
               fact.protocol AS protocol,
               fact.src_port AS src_port,
               fact.dst_port AS dst_port
        ORDER BY CASE WHEN fact.priority IS NULL THEN 1 ELSE 0 END, fact.priority ASC,
                 CASE WHEN fact.sid IS NULL THEN 1 ELSE 0 END, fact.sid ASC,
                 fact.fact_key ASC
        SKIP $offset LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = tx.run(count_cypher, **params).single()["total"]
            page_res = tx.run(page_cypher, **params)
            items = [
                {
                    "fact_key": r["fact_key"],
                    "source_ip": r["source_ip"],
                    "target_ip": r["target_ip"],
                    "sid": r["sid"],
                    "gid": r["gid"],
                    "rev": r["rev"],
                    "message": r["message"],
                    "priority": r["priority"],
                    "protocol": r["protocol"],
                    "src_port": r["src_port"],
                    "dst_port": r["dst_port"],
                }
                for r in page_res
            ]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_alert_fact(self, fact_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve single alert fact by its deterministic fact_key."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        cypher = """
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact {fact_key: $fact_key})-[:TARGETS]->(dst:IPAddress)
        RETURN fact.fact_key AS fact_key,
               src.address AS source_ip,
               dst.address AS target_ip,
               fact.sid AS sid,
               fact.gid AS gid,
               fact.rev AS rev,
               fact.message AS message,
               fact.priority AS priority,
               fact.protocol AS protocol,
               fact.src_port AS src_port,
               fact.dst_port AS dst_port
        """

        def _work(tx) -> Optional[Dict[str, Any]]:
            res = tx.run(cypher, fact_key=fact_key)
            record = res.single()
            if not record:
                return None
            return {
                "fact_key": record["fact_key"],
                "source_ip": record["source_ip"],
                "target_ip": record["target_ip"],
                "sid": record["sid"],
                "gid": record["gid"],
                "rev": record["rev"],
                "message": record["message"],
                "priority": record["priority"],
                "protocol": record["protocol"],
                "src_port": record["src_port"],
                "dst_port": record["dst_port"],
            }

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_traffic_alert_correlations(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List correlated traffic communication flows that also generated security alert facts."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        count_cypher = """
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress),
              (src)-[c:COMMUNICATED_TO]->(dst)
        RETURN count(*) AS total
        """

        page_cypher = """
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress),
              (src)-[c:COMMUNICATED_TO]->(dst)
        RETURN src.address AS source_ip,
               dst.address AS target_ip,
               c.protocol AS traffic_protocol,
               c.flow_key AS traffic_flow_key,
               c.src_port AS traffic_src_port,
               c.dst_port AS traffic_dst_port,
               fact.fact_key AS fact_key,
               fact.sid AS sid,
               fact.message AS message,
               fact.priority AS priority,
               fact.protocol AS alert_protocol
        ORDER BY src.address ASC, dst.address ASC, c.protocol ASC,
                 CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC,
                 fact.fact_key ASC
        SKIP $offset LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = tx.run(count_cypher).single()["total"]
            page_res = tx.run(page_cypher, offset=offset, limit=limit)
            items = [
                {
                    "source_ip": r["source_ip"],
                    "target_ip": r["target_ip"],
                    "traffic_protocol": r["traffic_protocol"],
                    "traffic_flow_key": r["traffic_flow_key"],
                    "traffic_src_port": r["traffic_src_port"],
                    "traffic_dst_port": r["traffic_dst_port"],
                    "fact_key": r["fact_key"],
                    "sid": r["sid"],
                    "message": r["message"],
                    "priority": r["priority"],
                    "alert_protocol": r["alert_protocol"],
                }
                for r in page_res
            ]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_neighborhood(
        self,
        address: str,
        depth: int = 1,
        max_nodes: int = 50,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve bounded local graph neighborhood (depth 1 or 2) around an IP address.
        
        Guarantees that returned nodes <= max_nodes, every edge connects returned nodes,
        and center IP is always retained. Parallel same-protocol flows with distinct flow_key
        are preserved. Returns None if center IP does not exist.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        # Select safe fixed Cypher query by validated depth
        if depth == 1:
            cypher = """
            MATCH (center:IPAddress {address: $address})
            OPTIONAL MATCH (center)-[r1:COMMUNICATED_TO]->(out_ip:IPAddress)
            OPTIONAL MATCH (in_ip:IPAddress)-[r2:COMMUNICATED_TO]->(center)
            OPTIONAL MATCH (center)-[r3:OBSERVED_WITH]->(l2:Layer2Identifier)
            RETURN center.address AS center,
                   collect(DISTINCT {id: 'ip:' + out_ip.address, type: 'IPAddress', value: out_ip.address}) AS out_ips,
                   collect(DISTINCT {id: 'ip:' + in_ip.address, type: 'IPAddress', value: in_ip.address}) AS in_ips,
                   collect(DISTINCT {id: 'l2:' + l2.identifier, type: 'Layer2Identifier', value: l2.identifier}) AS l2_nodes,
                   collect(DISTINCT {
                       source: 'ip:' + center.address,
                       target: 'ip:' + out_ip.address,
                       type: 'COMMUNICATED_TO',
                       protocol: r1.protocol,
                       flow_key: r1.flow_key,
                       src_port: r1.src_port,
                       dst_port: r1.dst_port,
                       observed_packet_count: r1.observed_packet_count,
                       observed_bytes: r1.observed_bytes,
                       first_seen: r1.first_seen,
                       last_seen: r1.last_seen,
                       observed_window_seconds: r1.observed_window_seconds
                   }) AS out_edges,
                   collect(DISTINCT {
                       source: 'ip:' + in_ip.address,
                       target: 'ip:' + center.address,
                       type: 'COMMUNICATED_TO',
                       protocol: r2.protocol,
                       flow_key: r2.flow_key,
                       src_port: r2.src_port,
                       dst_port: r2.dst_port,
                       observed_packet_count: r2.observed_packet_count,
                       observed_bytes: r2.observed_bytes,
                       first_seen: r2.first_seen,
                       last_seen: r2.last_seen,
                       observed_window_seconds: r2.observed_window_seconds
                   }) AS in_edges,
                   collect(DISTINCT {
                       source: 'ip:' + center.address,
                       target: 'l2:' + l2.identifier,
                       type: 'OBSERVED_WITH',
                       protocol: null,
                       flow_key: null,
                       src_port: null,
                       dst_port: null,
                       observed_packet_count: null,
                       observed_bytes: null,
                       first_seen: null,
                       last_seen: null,
                       observed_window_seconds: null
                   }) AS l2_edges
            """
        else:  # depth == 2
            cypher = """
            MATCH (center:IPAddress {address: $address})
            OPTIONAL MATCH p = (center)-[r:COMMUNICATED_TO|OBSERVED_WITH*1..2]-(target)
            WITH center, collect(DISTINCT p) AS paths
            RETURN center.address AS center, paths
            """

        def _work(tx) -> Optional[Dict[str, Any]]:
            # Verify center node exists
            center_check = tx.run("MATCH (ip:IPAddress {address: $address}) RETURN count(ip) AS c", address=address)
            if center_check.single()["c"] == 0:
                return None

            center_id = f"ip:{address}"
            nodes_map = {center_id: {"id": center_id, "type": "IPAddress", "value": address}}
            candidate_edges = []

            if depth == 1:
                rec = tx.run(cypher, address=address).single()
                for group in [rec["out_ips"], rec["in_ips"], rec["l2_nodes"]]:
                    for n in group:
                        if n.get("value") is not None:
                            nodes_map[n["id"]] = n

                for egroup in [rec["out_edges"], rec["in_edges"], rec["l2_edges"]]:
                    for e in egroup:
                        if e.get("source") and e.get("target") and "None" not in e["source"] and "None" not in e["target"]:
                            candidate_edges.append(e)
            else:
                rec = tx.run(cypher, address=address).single()
                paths = rec["paths"]
                for p in paths:
                    if p is not None:
                        for n in p.nodes:
                            if "IPAddress" in n.labels:
                                nid = f"ip:{n['address']}"
                                nodes_map[nid] = {"id": nid, "type": "IPAddress", "value": n["address"]}
                            elif "Layer2Identifier" in n.labels:
                                nid = f"l2:{n['identifier']}"
                                nodes_map[nid] = {"id": nid, "type": "Layer2Identifier", "value": n["identifier"]}
                        for rel in p.relationships:
                            src_node = rel.start_node
                            dst_node = rel.end_node
                            src_id = f"ip:{src_node['address']}" if "IPAddress" in src_node.labels else f"l2:{src_node['identifier']}"
                            dst_id = f"ip:{dst_node['address']}" if "IPAddress" in dst_node.labels else f"l2:{dst_node['identifier']}"
                            candidate_edges.append({
                                "source": src_id,
                                "target": dst_id,
                                "type": rel.type,
                                "protocol": rel.get("protocol"),
                                "flow_key": rel.get("flow_key"),
                                "src_port": rel.get("src_port"),
                                "dst_port": rel.get("dst_port"),
                                "observed_packet_count": rel.get("observed_packet_count"),
                                "observed_bytes": rel.get("observed_bytes"),
                                "first_seen": rel.get("first_seen"),
                                "last_seen": rel.get("last_seen"),
                                "observed_window_seconds": rel.get("observed_window_seconds"),
                            })

            # Deterministic node trimming (always retaining center node)
            sorted_other_nodes = sorted(
                [n for nid, n in nodes_map.items() if nid != center_id],
                key=lambda x: (x["type"], x["value"]),
            )
            retained_nodes = [nodes_map[center_id]] + sorted_other_nodes[: max_nodes - 1]
            retained_node_ids = {n["id"] for n in retained_nodes}

            # Filter edges to only those where both endpoints are in retained nodes
            valid_edges = []
            seen_edge_keys = set()
            for e in candidate_edges:
                if e["source"] in retained_node_ids and e["target"] in retained_node_ids:
                    # Parallel flow identity: use flow_key if present, fallback to protocol
                    if e.get("flow_key"):
                        edge_key = (e["source"], e["target"], e["type"], e["flow_key"])
                    else:
                        edge_key = (e["source"], e["target"], e["type"], e.get("protocol"))

                    if edge_key not in seen_edge_keys:
                        seen_edge_keys.add(edge_key)
                        valid_edges.append(e)

            # Sort edges deterministically
            valid_edges.sort(
                key=lambda x: (
                    x["source"],
                    x["target"],
                    x["type"],
                    str(x.get("protocol")),
                    str(x.get("flow_key")),
                )
            )

            return {
                "center": address,
                "depth": depth,
                "nodes": retained_nodes,
                "edges": valid_edges,
            }

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_shortest_path(
        self,
        source: str,
        target: str,
        max_hops: int = 5,
    ) -> Dict[str, Any]:
        """Find the shortest directional communication path between two IP addresses.
        
        Returns dict with path details or error flag ('source_not_found', 'target_not_found', 'no_path').
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Dict[str, Any]:
            src_c = tx.run("MATCH (n:IPAddress {address: $source}) RETURN count(n) AS c", source=source).single()["c"]
            if src_c == 0:
                return {"error": "source_not_found"}

            dst_c = tx.run("MATCH (n:IPAddress {address: $target}) RETURN count(n) AS c", target=target).single()["c"]
            if dst_c == 0:
                return {"error": "target_not_found"}

            if source == target:
                return {
                    "source": source,
                    "target": target,
                    "hops": [source],
                    "protocols": [],
                    "length": 0,
                }

            cypher = """
            MATCH (src:IPAddress {address: $source}), (dst:IPAddress {address: $target})
            MATCH p = shortestPath((src)-[:COMMUNICATED_TO*1..10]->(dst))
            WHERE length(p) <= $max_hops
            RETURN [n IN nodes(p) | n.address] AS hops,
                   [r IN relationships(p) | r.protocol] AS protocols,
                   length(p) AS length
            """
            res = tx.run(cypher, source=source, target=target, max_hops=max_hops)
            record = res.single()
            if not record:
                return {"error": "no_path"}

            return {
                "source": source,
                "target": target,
                "hops": [str(h) for h in record["hops"]],
                "protocols": [str(p) for p in record["protocols"]],
                "length": int(record["length"]),
            }

        with self.driver.session() as session:
            return session.execute_read(_work)
