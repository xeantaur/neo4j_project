[← Back to README](../README.md)

# REST API Reference

The **Network Traffic & Security Alert Analysis** backend is built with FastAPI and Pydantic v2. It provides a read-oriented API for relationship exploration and analytics, alongside explicitly gated endpoints for browser-based data import.

---

## Interactive Documentation

When the API server is running (`uvicorn src.api.app:app --port 8000`), interactive API documentation is available at:
- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **ReDoc:** `http://127.0.0.1:8000/redoc`

---

## Endpoint Reference Table

| Group | Method | Endpoint | Description | Parameters |
|---|---|---|---|---|
| **System** | `GET` | `/health` | Application liveness check (0 database calls) | None |
| **System** | `GET` | `/ready` | Database connectivity readiness check | None |
| **Import** | `GET` | `/api/v1/import/status` | Check if browser import is enabled and view upload size limit | None |
| **Import** | `POST` | `/api/v1/import/validate` | Statelessly validate uploaded traffic TSV / alerts JSON without database mutation | `traffic_file`, `alerts_file` [`multipart/form-data`] |
| **Import** | `POST` | `/api/v1/import` | Atomically replace the single active workspace with validated uploaded data | `traffic_file`, `alerts_file` [`multipart/form-data`] |
| **Analytics** | `GET` | `/api/v1/network/analytics/summary` | Global traffic metrics, metric mode, protocol & destination port distributions, top fan-out / fan-in | None |
| **Analytics** | `GET` | `/api/v1/network/analytics/endpoints` | Paginated endpoint ranking by distinct peers, packet volume, or byte volume | `sort_by`, `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/ips` | Paginated list of observed IP addresses | `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/ips/{address}` | IP context, L2 associations, peer counts, and enriched packet/byte volumes | `address` (path) |
| **Network** | `GET` | `/api/v1/network/ips/{address}/peers` | Communicating peers and observed protocols | `address`, `direction`, `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/ips/{address}/layer2` | Paginated Layer 2 associations for an IP | `address`, `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/layer2` | Paginated list of Layer 2 identifiers | `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/communications` | Filterable and sortable Layer 3 communication aggregates | `source_ip`, `target_ip`, `protocol`, `src_port`, `dst_port`, `sort_by`, `limit`, `offset` |
| **Alerts** | `GET` | `/api/v1/alerts` | Filterable normalized security alert facts | `source_ip`, `target_ip`, `priority`, `sid`, `protocol`, `limit`, `offset` |
| **Alerts** | `GET` | `/api/v1/alerts/{fact_key}` | Retrieve single alert fact by SHA-256 key | `fact_key` (path) |
| **Correlations** | `GET` | `/api/v1/correlations/traffic-alerts` | Communicating IP pairs with matching alerts (with flow keys and transport ports) | `limit`, `offset` |
| **Graph** | `GET` | `/api/v1/graph/neighborhood/{address}` | Bounded subgraph around an IP (preserves parallel edges with distinct `flow_key`) | `address`, `depth`, `max_nodes` |
| **Graph** | `GET` | `/api/v1/graph/path` | Shortest Layer 3 path between two IPs | `source`, `target`, `max_hops` |

---

## Detailed Endpoint Notes

### 1. `GET /api/v1/network/analytics/summary`
Returns global workspace metrics including:
- `traffic_metrics_mode`: `"none" | "basic" | "enriched" | "mixed"`
- `total_communication_aggregates`, `enriched_communication_aggregates`, `basic_communication_aggregates`
- `total_observed_packets`, `total_observed_bytes`
- `first_observed`, `last_observed`
- `protocol_distribution`, `destination_port_distribution`
- `top_fan_out` (highest outbound peer count), `top_fan_in` (highest inbound peer count)

### 2. `GET /api/v1/network/analytics/endpoints`
Supports sorting endpoint rankings by `sort_by`:
- `fan_out` (default): outbound peer count
- `fan_in`: inbound peer count
- `observed_bytes_sent`, `observed_bytes_received`
- `observed_packets_sent`, `observed_packets_received`

### 3. `GET /api/v1/network/communications`
Allows multi-attribute filtering by `source_ip`, `target_ip`, `protocol`, `src_port`, and `dst_port`. Supports sorting via `sort_by` (`"identity"` [default], `"observed_bytes"`, `"observed_packets"`, `"first_seen"`).

### 4. `GET /api/v1/graph/neighborhood/{address}`
Extracts a bounded subgraph (up to depth 2) around an IP. Relationships preserve composite element IDs (`${flow_key}`) to allow Cytoscape.js to render distinct parallel edges between the same node pair.
