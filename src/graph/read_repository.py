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
        """Retrieve local graph context and flow counts for a specific IP address."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        cypher = """
        MATCH (ip:IPAddress {address: $address})
        RETURN ip.address AS address,
               COLLECT {
                   MATCH (ip)-[:OBSERVED_WITH]->(l2:Layer2Identifier)
                   RETURN l2.identifier ORDER BY l2.identifier ASC
               } AS layer2_identifiers,
               COUNT { MATCH (ip)-[:COMMUNICATED_TO]->(:IPAddress) } AS outbound_flows,
               COUNT { MATCH (:IPAddress)-[:COMMUNICATED_TO]->(ip) } AS inbound_flows,
               COUNT { MATCH (ip)-[:SOURCE_OF]->(:AlertFact) } AS alerts_originated,
               COUNT { MATCH (:AlertFact)-[:TARGETS]->(ip) } AS alerts_targeted
        """

        def _work(tx) -> Optional[Dict[str, Any]]:
            res = tx.run(cypher, address=address)
            record = res.single()
            if not record:
                return None
            return {
                "address": record["address"],
                "layer2_identifiers": [str(x) for x in record["layer2_identifiers"]],
                "outbound_flows": int(record["outbound_flows"]),
                "inbound_flows": int(record["inbound_flows"]),
                "alerts_originated": int(record["alerts_originated"]),
                "alerts_targeted": int(record["alerts_targeted"]),
            }

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
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List observed Layer 3 IP-to-IP communications with optional filtering."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        proto_upper = protocol.strip().upper() if protocol and protocol.strip() else None

        params = {
            "source_ip": source_ip,
            "target_ip": target_ip,
            "protocol": proto_upper,
            "offset": offset,
            "limit": limit,
        }

        where_clause = """
        WHERE ($source_ip IS NULL OR src.address = $source_ip)
          AND ($target_ip IS NULL OR dst.address = $target_ip)
          AND ($protocol IS NULL OR c.protocol = $protocol)
        """

        count_cypher = f"MATCH (src:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress) {where_clause} RETURN count(c) AS total"
        page_cypher = f"""
        MATCH (src:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress)
        {where_clause}
        RETURN src.address AS source_ip, dst.address AS target_ip, c.protocol AS protocol
        ORDER BY src.address ASC, dst.address ASC, c.protocol ASC
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
        RETURN count(fact) AS total
        """

        page_cypher = """
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress),
              (src)-[c:COMMUNICATED_TO]->(dst)
        RETURN src.address AS source_ip,
               dst.address AS target_ip,
               c.protocol AS traffic_protocol,
               fact.fact_key AS fact_key,
               fact.sid AS sid,
               fact.message AS message,
               fact.priority AS priority,
               fact.protocol AS alert_protocol
        ORDER BY src.address ASC, dst.address ASC, c.protocol ASC, fact.fact_key ASC
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
        and center IP is always retained. Returns None if center IP does not exist.
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
                   collect(DISTINCT {source: 'ip:' + center.address, target: 'ip:' + out_ip.address, type: 'COMMUNICATED_TO', protocol: r1.protocol}) AS out_edges,
                   collect(DISTINCT {source: 'ip:' + in_ip.address, target: 'ip:' + center.address, type: 'COMMUNICATED_TO', protocol: r2.protocol}) AS in_edges,
                   collect(DISTINCT {source: 'ip:' + center.address, target: 'l2:' + l2.identifier, type: 'OBSERVED_WITH', protocol: null}) AS l2_edges
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
                            proto = rel.get("protocol")
                            candidate_edges.append({
                                "source": src_id,
                                "target": dst_id,
                                "type": rel.type,
                                "protocol": proto,
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
                    edge_key = (e["source"], e["target"], e["type"], e.get("protocol"))
                    if edge_key not in seen_edge_keys:
                        seen_edge_keys.add(edge_key)
                        valid_edges.append(e)

            # Sort edges deterministically
            valid_edges.sort(key=lambda x: (x["source"], x["target"], x["type"], str(x.get("protocol"))))

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
