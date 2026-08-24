[← Back to README](../README.md)

# Traffic Ingestion, Aggregation & Graph Data Model

This document details the network traffic input formats, deterministic aggregation semantics, Neo4j graph property schema, metric availability modes, and analysis boundaries implemented in the system.

---

## Traffic Input Formats

The parser (`src/ingestion/traffic_parser.py`) supports two distinct TSV formats:

### 1. Basic / Legacy Format (7-Column TSV)
A backward-compatible 7-column tab-separated format (headerless or with header):
```tsv
eth.src    eth.dst    ip.src    ip.dst    -    -    protocol
```
- Ingests Layer 2 MAC addresses, IPv4/IPv6 endpoints, and dissector protocol labels.
- Detailed volume metrics (`observed_packet_count`, `observed_bytes`, `observed_window_seconds`, transport ports) default to `None` (`traffic_metrics_mode = "basic"`).

### 2. Enriched Format (Project-Defined Enriched tshark TSV Profile)
A headered TSV export generated from packet analysis tools (such as Wireshark / tshark):
```tsv
frame.number    frame.time_epoch    frame.len    eth.src    eth.dst    ip.src    ip.dst    ipv6.src    ipv6.dst    _ws.col.Protocol    tcp.srcport    tcp.dstport    udp.srcport    udp.dstport
```

#### Enriched Field Semantics:
- **`frame.number`** *(optional / recommended)*: Packet index used for duplicate observation tracking.
- **`frame.time_epoch`** *(required in enriched mode)*: Floating-point observation epoch timestamp used to compute `first_seen`, `last_seen`, and `observed_window_seconds`.
- **`frame.len`** *(required in enriched mode)*: Reported wire frame length in bytes, summed into `observed_bytes`.
- **`eth.src` / `eth.dst`**: Layer 2 Ethernet hardware MAC addresses or resolved identifiers.
- **`ip.src` / `ip.dst`**: IPv4 endpoints (coalesced with IPv6; ambiguous rows containing both are skipped).
- **`ipv6.src` / `ipv6.dst`**: IPv6 endpoints (canonicalized to RFC 5952 lowercase compressed format).
- **`_ws.col.Protocol`** *(or `protocol`)*: Dissector protocol label (e.g. `TLS`, `HTTP`, `DNS`, `TCP`, `ICMP`).
- **`tcp.srcport` / `tcp.dstport` / `udp.srcport` / `udp.dstport`**: Transport-layer port numbers extracted independently of upper-layer dissector protocol labels.

---

## Aggregation Model

Packet observations sharing the same directional 5-tuple are deterministically aggregated into a single `TrafficRecord`:

- **Canonical Identity Tuple:** `(canonical src_ip, canonical dst_ip, normalized protocol, src_port, dst_port)`
- **`flow_key`:** Deterministic SHA-256 digest of the canonical identity tuple:
  ```python
  raw_key = f"{src_ip}|{dst_ip}|{protocol}|{src_port or ''}|{dst_port or ''}"
  flow_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
  ```
- **Volume Metrics:** Sum of packet observations (`observed_packet_count`) and sum of wire frame bytes (`observed_bytes`).
- **Time Bounds:** Earliest observation (`first_seen`), latest observation (`last_seen`), and window duration (`observed_window_seconds = last_seen - first_seen`).
- **Layer 2 Associations:** Distinct `(eth_src, eth_dst)` pairs observed across packet records with the same 5-tuple are collected into `observed_l2_pairs` and written as `:OBSERVED_WITH` and `:L2_COMMUNICATED_TO` relationships.
- **Parallel Relationships:** Distinct source ports to the same destination IP and port produce separate, parallel `COMMUNICATED_TO` relationships in Neo4j.

---

## Neo4j Graph Model

### Graph Schema

```
                  (:Layer2Identifier)
                 {identifier: str (UQ)}
                           ▲
                           │ [:OBSERVED_WITH]
                           │
     (src:IPAddress) ──────────────[:COMMUNICATED_TO]─────────────▶ (dst:IPAddress)
    {address: str (UQ)}   {flow_key: str,                         {address: str (UQ)}
           │               protocol: str,                                  ▲
           │               src_port: int | None,                           │
           │               dst_port: int | None,                           │
           │               observed_packet_count: int | None,              │
           │               observed_bytes: int | None,                     │
           │               first_seen: float | None,                       │
           │               last_seen: float | None,                        │
           │               observed_window_seconds: float | None}          │
           │                                                               │
           │ [:SOURCE_OF]                                                  │
           ▼                                                               │
      (:AlertFact) ──────────────────────────────────[:TARGETS]────────────┘
     {fact_key: str (UQ),
      sid: int | None,
      gid: int | None,
      rev: int | None,
      message: str | None,
      priority: int | None,
      protocol: str | None,
      src_port: int | None,
      dst_port: int | None}
```

```
Layer 2 Frame Topology:
(:Layer2Identifier) ──[:L2_COMMUNICATED_TO {protocol: str}]──▶ (:Layer2Identifier)
```

### Node Entities
- **`:IPAddress`**: Observed IPv4 or canonicalized IPv6 endpoint. Unique constraint on `address`.
- **`:Layer2Identifier`**: Observed Layer 2 hardware MAC address or resolved identifier. Unique constraint on `identifier`.
- **`:AlertFact`**: Unique normalized alert fact binding source, target, and security rule metadata. Unique constraint on `fact_key`.

### Relationship Entities
- **`(:IPAddress)-[:COMMUNICATED_TO]->(:IPAddress)`**: Directional Layer 3 communication aggregate. Contains `flow_key`, `protocol`, transport ports, and volume metrics when ingested from enriched data.
- **`(:Layer2Identifier)-[:L2_COMMUNICATED_TO {protocol}]->(:Layer2Identifier)`**: Directional Layer 2 frame communication topology.
- **`(:IPAddress)-[:OBSERVED_WITH]->(:Layer2Identifier)`**: Observed Layer 2 / Layer 3 association in captured traffic.
- **`(:IPAddress)-[:SOURCE_OF]->(:AlertFact)`**: Connects the initiator/source IP to the alert fact.
- **`(:AlertFact)-[:TARGETS]->(:IPAddress)`**: Connects the alert fact to the destination/target IP.

---

## Metric Availability Modes

The API and web dashboard categorize traffic metric availability into four explicit modes:

| Mode | Description | Volume Properties Behavior |
|---|---|---|
| **`none`** | No communication aggregates exist in the active workspace. | Metrics unavailable. |
| **`basic`** | Traffic exists, but detailed measurements are absent (legacy TSV). | Packets, frame bytes, timestamps, and ports are `None`. |
| **`enriched`** | All communication aggregates have complete Phase 7 measurements. | Full volume, port, and timestamp metrics are available. |
| **`mixed`** | Both basic and enriched aggregates coexist in the graph. | Global totals and timestamp spans reflect only the enriched subset. |

---

## Semantic & Analysis Boundaries

To ensure analytical integrity and prevent misinterpretation of graph data:

1. **Directional Communication Aggregate (`COMMUNICATED_TO`):** Represents an observed directional aggregation identified by `(src_ip, dst_ip, protocol, src_port, dst_port)`. It is **not** a reconstructed TCP session or connection state machine.
2. **Observed Frame Bytes (`observed_bytes`):** Sum of reported `frame.len` values across aggregated observations. It reflects total wire frame/protocol bytes including headers, **not** application payload bytes.
3. **Observation Window (`observed_window_seconds`):** Difference between `last_seen` and `first_seen` observation timestamps. It is **not** an active session duration.
4. **Correlation vs Causation:** Traffic/alert correlation represents endpoint co-occurrence in captured data and does **not** prove causality.
5. **Source / Target Semantics:** Directional endpoints reflect communication orientation and do **not** infer attacker or victim roles.
6. **Port Context:** Transport ports reflect observed packet headers and do **not** verify the active service or daemon running on the host.
7. **Cardinality Rankings:** Fan-out and fan-in metrics reflect factual peer counts and volume distributions; they do **not** generate automated scan verdicts, maliciousness scores, or C2/beaconing inferences.
