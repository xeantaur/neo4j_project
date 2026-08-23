# Network Traffic & Security Alert Analysis with Neo4j

[![CI](https://github.com/s3rt4c/neo4j_project/actions/workflows/ci.yml/badge.svg)](https://github.com/s3rt4c/neo4j_project/actions/workflows/ci.yml)

Graph-based network traffic and security alert analysis using Neo4j, FastAPI, and React with Cytoscape.js.

> **Origin:** This project was originally developed during a cybersecurity internship (September 2024). It is being modernized from an internship prototype into a portfolio-quality cybersecurity analysis tool. The modernized system uses a typed, modular ingestion pipeline supporting both basic topology and enriched packet-observation aggregation, a normalized fact-based graph model, batched `UNWIND` persistence with Neo4j 5.x constraints, a read-oriented FastAPI REST backend with traffic analytics endpoints and explicitly gated browser data-import mutation endpoints, and an interactive React + Cytoscape.js web dashboard with parallel flow visualization and communication edge inspection.

## What It Does

This application ingests network traffic and security alert data, persists them into a Neo4j graph database for relationship and volume analysis, and provides a typed REST API and interactive web dashboard.

Users can analyze data across three supported operational modes:

1. **Network traffic only** (basic legacy TSV or project-defined enriched tshark export) — Layer 2 identifiers, IP addresses, observed communication protocols, transport ports, observed packet counts, frame bytes, observation windows, and network path exploration.
2. **IDS/Snort alerts only** (JSON array) — unique normalized security alert facts with signature IDs, priority levels, protocol/port metadata, and source-target IP investigation.
3. **Network traffic + IDS alerts together** — unified topology, traffic volume analytics, and alert fact analysis plus cross-domain traffic/alert correlation where matching endpoint evidence exists.

At least one source file is required for browser data import.

The resulting graph models:
- **Layer 3 Communication Aggregates** — directional IP-to-IP communication aggregates with observed protocol labels, transport ports, packet counts, frame bytes, and observation windows
- **Layer 2 Communication** — directional interface-to-interface frame topology
- **Layer 2 / Layer 3 Resolution** — observed associations between IP addresses and Layer 2 identifiers
- **Security Alert Facts** — unique normalized alert facts preserving source-target pairings and rule metadata

> **Analysis & Semantic Boundaries:**
> - **Directional Communication Aggregate (`COMMUNICATED_TO`):** Represents an observed directional aggregation identified by `(src_ip, dst_ip, protocol, src_port, dst_port)`. It is **not** a reconstructed TCP session or connection state machine.
> - **Observed Frame Bytes (`observed_bytes`):** Sum of reported `frame.len` values across aggregated observations. It reflects total wire frame/protocol bytes including headers, **not** application payload bytes.
> - **Observation Window (`observed_window_seconds`):** Difference between `last_seen` and `first_seen` observation timestamps. It is **not** an active session duration.
> - **Correlation vs Causation:** Traffic/alert correlation represents endpoint co-occurrence in captured data and does **not** prove causality.
> - **Source / Target Semantics:** Directional endpoints reflect communication orientation and do **not** infer attacker or victim roles.
> - **Factual Analytics:** The system reports factual cardinality and volume distributions. It does **not** generate automatic scan verdicts, maliciousness scores, or beaconing/C2 inferences.

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.10+ | Main backend language (CI verified on Python 3.10 and 3.14; local live integration verified on Python 3.11.9) |
| FastAPI | Typed REST API framework (v1.2.0) |
| Uvicorn | ASGI application server |
| Pydantic v2 | Strict request validation, canonicalization, and response serialization |
| pandas | Tabular network traffic parsing, cleaning, and deduplication |
| Neo4j 5.x | Graph database with uniqueness constraints and RANGE indexes |
| neo4j (Python driver) | Database connectivity with managed retry-safe transactions (`session.execute_read` / `session.execute_write`) |
| python-dotenv | Environment-based configuration with lazy loading |
| pytest | Automated backend test suite (unit tests, API test client, and opt-in live Neo4j integration tests) |
| React 19 | Frontend user interface framework |
| TypeScript 6 | Type-safe frontend client and component modeling |
| Vite 8 | Frontend build toolchain and development server with API proxying |
| Cytoscape.js 3+ | Interactive graph visualization engine with parallel edge support |
| Vitest | Frontend component and unit test suite |

## Architecture

```
[ Ingestion Entry Points ]
A. CLI Ingestion (python -m src.main)
   Network traffic (TSV)             IDS alerts (JSON)
             │                              │
             ▼                              ▼
   src/ingestion/traffic_parser.py   src/ingestion/alert_parser.py
             │                              │
             ▼                              ▼
     list[TrafficRecord]            list[AlertRecord]
             │                              │
             └──────────────┬───────────────┘
                            │
                            ▼
                src/graph/repository.py
     - Batched UNWIND write persistence (session.execute_write)

B. Browser Data Import (React UI -> POST /api/v1/import/validate -> POST /api/v1/import)
   Browser Upload (TSV / JSON) ──▶ src/services/import_service.py (Stateless validation & staging)
                                               │
                                               ▼
                                 src/graph/repository.py
     - Atomic single active workspace replacement & rollback (replace_workspace_data)
                            │
                            ▼
                   Neo4j Graph Database
       ┌─────────────────────────────────────────┐
       │  (:IPAddress)  (:Layer2Identifier)      │
       │  (:AlertFact)                           │
       │  [:COMMUNICATED_TO]                     │
       │  [:L2_COMMUNICATED_TO]                  │
       │  [:OBSERVED_WITH]                       │
       │  [:SOURCE_OF]  [:TARGETS]               │
       └─────────────────────────────────────────┘
                            ▲
                            │ session.execute_read
                            │
                src/graph/read_repository.py
                            ▲
                            │ dependency injection
                            │
[ FastAPI Backend API — Server: uvicorn src.api.app:app ]
src/api/routes/
  ├── health.py        (GET /health, GET /ready)
  ├── import_data.py   (GET /api/v1/import/status, POST /validate, POST /import)
  ├── network.py       (GET /api/v1/network/*, including /analytics/summary and /analytics/endpoints)
  ├── alerts.py        (GET /api/v1/alerts/*)
  ├── correlations.py  (GET /api/v1/correlations/*)
  └── graph.py         (GET /api/v1/graph/*)
                            ▲
                            │ REST / JSON (Vite Dev Proxy)
                            │
[ Web Dashboard & Visualization — frontend/ (React 19 + Cytoscape.js) ]
frontend/src/
  ├── pages/
  │   ├── OverviewPage.tsx         (Global metrics, mode banners, distribution grids, endpoint rankings)
  │   ├── NetworkExplorerPage.tsx  (Cytoscape graph canvas, parallel edge rendering, edge & IP inspectors)
  │   ├── AlertExplorerPage.tsx    (Normalized alert facts table & detail modal)
  │   ├── CorrelationsPage.tsx     (Traffic & alert co-occurrence table with flow keys and ports)
  │   ├── PathFinderPage.tsx       (Directional L3 communication hop chain visualizer)
  │   └── ImportDataPage.tsx       (Browser data import, dual-file validation & workspace replacement)
  └── components/
      ├── graph/
      │   ├── CytoscapeCanvas.tsx  (Interactive canvas lifecycle, parallel edge layout & selection)
      │   └── cytoscapeStyle.ts    (Dark cybersecurity theme stylesheet)
      └── network/
          ├── CommunicationEdgePanel.tsx (Edge inspector drawer for directional aggregate metrics)
          └── IPDetailPanel.tsx          (IP context drawer with topology and volume metrics)
```

## Traffic Ingestion & Aggregation Model

The system supports two distinct network traffic formats via `src/ingestion/traffic_parser.py`:

### 1. Basic / Legacy Format (7-Column TSV)
The backward-compatible headerless or headered 7-column format:
```
eth.src    eth.dst    ip.src    ip.dst    -    -    protocol
```
- Preserves compatibility with existing v1.0/v1.1 datasets.
- Persists topology and observed protocol labels.
- Detailed volume metrics (packets, frame bytes, timestamps, transport ports) default to `None` (`traffic_metrics_mode = "basic"`).

### 2. Enriched Format (Project-Defined Enriched tshark TSV Profile)
A headered TSV format exported from packet analysis tools (such as Wireshark / tshark):
```
frame.number    frame.time_epoch    frame.len    eth.src    eth.dst    ip.src    ip.dst    ipv6.src    ipv6.dst    _ws.col.Protocol    tcp.srcport    tcp.dstport    udp.srcport    udp.dstport
```

#### Field Semantics:
- **`frame.number`** *(optional / recommended)*: Packet index within the export used for duplicate tracking and deduplication.
- **`frame.time_epoch`** *(required in enriched mode)*: Float observation epoch timestamp used to compute `first_seen`, `last_seen`, and `observed_window_seconds`.
- **`frame.len`** *(required in enriched mode)*: Reported wire frame length in bytes, summed into `observed_bytes`.
- **`eth.src` / `eth.dst`**: Layer 2 Ethernet hardware MAC addresses or resolved identifiers.
- **`ip.src` / `ip.dst`**: IPv4 endpoints (coalesced with IPv6 endpoints; ambiguous rows containing both are skipped).
- **`ipv6.src` / `ipv6.dst`**: IPv6 endpoints (canonicalized to RFC 5952 standard representation).
- **`_ws.col.Protocol`** *(or `protocol`)*: Dissector protocol label (e.g. `TLS`, `HTTP`, `DNS`, `TCP`, `ICMP`).
- **`tcp.srcport` / `tcp.dstport` / `udp.srcport` / `udp.dstport`**: Transport-layer port context extracted independently of upper-layer dissector protocol labels.

#### Aggregation Semantics (`flow_key`):
Packet observations sharing the same 5-tuple are deterministically aggregated into a single `TrafficRecord`:
- **Identity:** `(canonical src_ip, canonical dst_ip, normalized protocol, src_port, dst_port)`
- **`flow_key`:** Deterministic SHA-256 digest of the canonical identity tuple.
- **Volume Metrics:** Summed packet count (`observed_packet_count`) and summed frame bytes (`observed_bytes`).
- **Time Bounds:** Earliest observation (`first_seen`), latest observation (`last_seen`), and window duration (`observed_window_seconds`).
- **Layer 2 Associations:** Distinct `(eth_src, eth_dst)` pairs observed for this directional aggregate are preserved in `observed_l2_pairs` and written as `:OBSERVED_WITH` associations.
- **Parallel Relationships:** Distinct source ports to the same destination IP and port produce separate, parallel `COMMUNICATED_TO` relationships in Neo4j.

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

- **`:IPAddress`**: Observed IPv4 or canonicalized IPv6 endpoint. Unique on `address`.
- **`:Layer2Identifier`**: Observed Layer 2 hardware MAC address or resolved local identifier (e.g. `gateway.local`, `Broadcast`). Unique on `identifier`.
- **`:AlertFact`**: Unique normalized alert fact binding source, target, and security rule metadata. Unique on `fact_key`.

### Relationship Entities

- **`(:IPAddress)-[:COMMUNICATED_TO]->(:IPAddress)`**: Directional Layer 3 communication aggregate. Contains `flow_key`, `protocol`, ports, and volume metrics when ingested from enriched data. Basic/legacy relationships retain `protocol` while detailed volume properties remain `None`.
- **`(:Layer2Identifier)-[:L2_COMMUNICATED_TO {protocol}]->(:Layer2Identifier)`**: Directional Layer 2 frame communication topology.
- **`(:IPAddress)-[:OBSERVED_WITH]->(:Layer2Identifier)`**: Observed Layer 2 / Layer 3 association in captured traffic.
- **`(:IPAddress)-[:SOURCE_OF]->(:AlertFact)`**: Connects the initiator/source IP to the alert fact.
- **`(:AlertFact)-[:TARGETS]->(:IPAddress)`**: Connects the alert fact to the destination/target IP.

### Metric Availability Modes

The API and UI categorize metric availability into four explicit modes:
- **`none`**: No communication aggregates exist in the active workspace.
- **`basic`**: Traffic exists, but detailed measurements (packets, frame bytes, timestamps, ports) are unavailable.
- **`enriched`**: All communication aggregates have complete Phase 7 measurements.
- **`mixed`**: Both basic and enriched aggregates coexist. Global volume and timestamp totals reflect the enriched subset only.

## REST API (FastAPI)

The API is read-oriented for analysis queries, with explicitly gated browser data-import endpoints for validation and atomic workspace replacement (`DATA_IMPORT_ENABLED=true`, disabled by default).

### Interactive API Documentation

When the API server is running, interactive OpenAPI documentation is available at:
- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **ReDoc:** `http://127.0.0.1:8000/redoc`

### API Endpoints Reference

| Method | Endpoint | Description | Parameters |
|---|---|---|---|
| `GET` | `/health` | Application liveness (0 database calls) | None |
| `GET` | `/ready` | Database readiness check | None |
| `GET` | `/api/v1/import/status` | Browser data import enablement and configured file-size limit | None |
| `POST` | `/api/v1/import/validate` | Statelessly validate uploaded traffic and/or alert data without modifying Neo4j | `traffic_file`, `alerts_file` [`multipart/form-data`] |
| `POST` | `/api/v1/import` | Atomically replace the single active analysis workspace with validated uploaded data | `traffic_file`, `alerts_file` [`multipart/form-data`] |
| `GET` | `/api/v1/network/analytics/summary` | Global traffic metrics, metric mode, protocol & destination port distributions, top fan-out / fan-in | None |
| `GET` | `/api/v1/network/analytics/endpoints` | Paginated endpoint ranking by distinct peers, packet volume, byte volume, or observation timestamps | `sort_by`, `direction`, `limit`, `offset` |
| `GET` | `/api/v1/network/ips` | Paginated list of observed IP addresses | `limit`, `offset` |
| `GET` | `/api/v1/network/ips/{address}` | IP context, L2 associations, peer counts, and enriched packet/byte volumes | `address` (path) |
| `GET` | `/api/v1/network/ips/{address}/peers` | Communicating peers and observed protocols | `address`, `direction`, `limit`, `offset` |
| `GET` | `/api/v1/network/ips/{address}/layer2` | Paginated Layer 2 associations for an IP | `address`, `limit`, `offset` |
| `GET` | `/api/v1/network/layer2` | Paginated list of Layer 2 identifiers | `limit`, `offset` |
| `GET` | `/api/v1/network/communications` | Filterable and sortable Layer 3 communication aggregates | `source_ip`, `target_ip`, `protocol`, `src_port`, `dst_port`, `sort_by`, `direction`, `limit`, `offset` |
| `GET` | `/api/v1/alerts` | Filterable normalized security alert facts | `source_ip`, `target_ip`, `priority`, `sid`, `protocol`, `limit`, `offset` |
| `GET` | `/api/v1/alerts/{fact_key}` | Retrieve single alert fact by SHA-256 key | `fact_key` (path) |
| `GET` | `/api/v1/correlations/traffic-alerts` | Communicating IP pairs with matching alerts (with flow keys and transport ports) | `limit`, `offset` |
| `GET` | `/api/v1/graph/neighborhood/{address}` | Bounded subgraph around an IP (preserves parallel edges with distinct `flow_key`) | `address`, `depth`, `max_nodes` |
| `GET` | `/api/v1/graph/path` | Shortest Layer 3 path between two IPs | `source`, `target`, `max_hops` |

## Web Dashboard (React + Cytoscape.js)

The frontend provides a six-view cybersecurity dashboard:

1. **Overview Dashboard:** Global entity totals, traffic metric mode badge, measured volume cards (packets, frame bytes, observation window), protocol and destination port distribution grids, top fan-out / fan-in rankings, and sortable endpoint volume tables.
2. **Network Explorer:** Interactive Cytoscape.js canvas supporting hierarchical, force-directed, and concentric layouts. Preserves parallel communication edges between the same IP pair using composite `flow_key` element IDs. Includes an **Edge Inspector Drawer** (`CommunicationEdgePanel`) showing transport ports, packets, frame bytes, timestamps, and window duration, alongside the **IP Detail Drawer**.
3. **Alert Explorer:** Searchable, filterable table of normalized alert facts with exact numeric priorities, rule IDs, and detailed JSON inspection modal.
4. **Correlations:** Cross-domain correlation table pairing observed communication flows with security alert facts matching source and destination IP addresses, including transport ports and distinct flow keys.
5. **Path Finder:** Directional Layer 3 shortest path visualizer displaying intermediate hop chains and observed communication protocols.
6. **Import Data:** Browser-based data upload interface for validating custom traffic and alert files, inspecting diagnostics, acknowledging atomic workspace replacement, and loading new datasets into Neo4j.

## Synthetic Sample Datasets

All sample data included in the repository is 100% synthetic RFC 1918 / RFC 3849 test data:

- **`data/samples/sample_traffic.tsv`**: Basic 7-column synthetic traffic export demonstrating backward-compatible topology ingestion.
- **`data/samples/sample_traffic_enriched.tsv`**: Enriched synthetic tshark export (28 raw observation rows producing 13 communication aggregates, 19,532 total frame bytes, IPv4/IPv6, parallel TLS flows, DNS, HTTP, SSH, and ICMP).
- **`data/samples/sample_alerts.json`**: Synthetic IDS/Snort alert fact array with signature IDs, priorities, and matching endpoint pairings.

## Setup & Running

### 1. Clone and Install Dependencies

#### Backend (Python)
```bash
git clone <repository-url>
cd neo4j_project
pip install -r requirements.txt
```

#### Frontend (Node.js)
```bash
cd frontend
npm install
cd ..
```

### 2. Configure Environment

Copy and configure `.env`:
```bash
cp .env.example .env
```

Edit `.env` settings:
```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_actual_password
TRAFFIC_CSV_PATH=data/samples/sample_traffic_enriched.tsv
ALERTS_JSON_PATH=data/samples/sample_alerts.json

# Browser data import & workspace replacement (Phase 6.5)
# Set to true to allow trusted/local browser uploads. Keep false for public read-only deployments.
DATA_IMPORT_ENABLED=false
# Maximum upload file size in megabytes (per file, positive integer)
DATA_IMPORT_MAX_FILE_SIZE_MB=10

# Optional: comma-separated origins (CORS disabled if unset)
# CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

### 3. Ingestion Workflows

#### A. CLI Ingestion (Terminal)
Ingests files specified in `.env` directly into Neo4j:
```bash
python -m src.main
```

#### B. Browser Data Import (Interactive Dashboard)
1. Start Neo4j and launch FastAPI with `DATA_IMPORT_ENABLED=true`.
2. Launch the frontend dashboard (`npm run dev`).
3. Navigate to **Import Data**, select traffic TSV (basic or enriched) and/or alerts JSON.
4. Click **Validate Files**, review diagnostics, acknowledge workspace replacement, and click **Import & Analyze**.

### 4. Start the Application

#### Start Backend API
```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload
```

#### Start Frontend Web Dashboard
```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser.

### 5. Run Automated Tests

#### Backend Test Suite
```bash
pytest
```

#### Frontend Test Suite
```bash
cd frontend
npm test -- --run
```

#### Frontend Production Build & Lint
```bash
cd frontend
npm run build
npm run lint
npm audit --omit=dev
```

#### Opt-In Live Neo4j Integration Testing
```bash
# 1. Start disposable Neo4j test instance
docker compose up -d neo4j-test

# 2. Run live integration suite (PowerShell example)
$env:RUN_NEO4J_INTEGRATION="1"
$env:NEO4J_TEST_URI="bolt://localhost:17687"
$env:NEO4J_TEST_USERNAME="neo4j"
$env:NEO4J_TEST_PASSWORD="phase6-test-password"
python -m pytest -m integration -v

# 3. Stop disposable test instance
docker compose down
```

## Migration & Rebuild Policy

- **Graph Identity Changes (v1.1 vs v1.2):** In v1.1, `COMMUNICATED_TO` relationships were keyed solely on `(src_ip, dst_ip, protocol)`. In v1.2, relationships are keyed on `flow_key` `(src_ip, dst_ip, protocol, src_port, dst_port)`, supporting parallel communication edges.
- **Re-Ingestion Recommendation:** Re-import source data or rebuild the graph from source datasets when updating from v1.1 to v1.2. The browser workspace replacement workflow naturally rebuilds the active workspace atomically.
- **No Destructive Startup Migration:** The application does not perform destructive automatic schema migrations at startup.

## Security Notice

- **Historical Credentials:** Commits from the original prototype contained hardcoded credentials. Those historical credentials must be considered **compromised** and must never be reused in any environment. Active application configuration is loaded exclusively from environment variables via `.env`.
- **Browser Data Import Security:** `DATA_IMPORT_ENABLED` defaults to `false`. The import endpoints do not implement user authentication or authorization. Browser mutation should only be enabled in trusted/local environments. Configured CORS origins govern cross-origin browser policies and do not provide access control.

## Project Structure

```
neo4j_project/
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions CI workflow (unit, frontend, integration)
├── data/
│   └── samples/
│       ├── sample_traffic.tsv     # Basic synthetic RFC 1918 traffic data
│       ├── sample_traffic_enriched.tsv # Enriched synthetic tshark profile data
│       └── sample_alerts.json     # Synthetic IDS alert data
├── frontend/                      # React 19 + TypeScript + Cytoscape.js Dashboard
│   ├── src/
│   │   ├── api/                   # Typed API client modules (network, alerts, graph, importData)
│   │   ├── components/            # Graph canvas, IPDetailPanel, CommunicationEdgePanel, common UI
│   │   ├── pages/                 # Overview, Network, Alert, Correlation, Path, ImportData pages
│   │   ├── utils/                 # Pure metric & timestamp formatting utilities (formatters.ts)
│   │   └── styles/                # CSS variables & dark cybersecurity theme
│   ├── package.json               # Node >=20.19.0 engine declaration
│   └── vite.config.ts             # Vite build & proxy configuration
├── src/
│   ├── config.py                  # Centralized configuration with lazy access
│   ├── main.py                    # Application CLI orchestrator
│   ├── api/                       # FastAPI REST Backend (v1.2.0)
│   │   ├── app.py                 # FastAPI application factory & error handlers
│   │   ├── dependencies.py        # Lifespan management & dependency injection
│   │   ├── models.py              # Pydantic v2 response schemas
│   │   └── routes/                # health, network, alerts, correlations, graph, import_data
│   ├── services/                  # Business logic services (stateless import validation & staging)
│   │   └── import_service.py
│   ├── graph/                     # Graph persistence & query repositories
│   │   ├── schema.py              # Constraints and RANGE indexes
│   │   ├── repository.py          # Write persistence (batched UNWIND & atomic workspace replacement)
│   │   └── read_repository.py     # Read queries (analytics, endpoints, communications, graph)
│   └── ingestion/                 # Dual-mode parsers & domain models
│       ├── models.py              # Normalized domain dataclasses & flow_key computation
│       ├── traffic_parser.py      # Dual-mode (basic & enriched) traffic parser
│       └── alert_parser.py        # JSON alert parser
├── tests/
│   ├── conftest.py                # Shared pytest fixtures
│   ├── test_alert_parser.py       # Alert parser test suite
│   ├── test_api_*.py              # API endpoint unit test suites
│   ├── test_api_live_neo4j.py     # FastAPI live integration tests against real Neo4j
│   ├── test_graph_*.py            # Graph repository & schema unit tests
│   ├── test_neo4j_atomic_replace.py # Atomic replacement & rollback integration tests
│   ├── test_neo4j_integration.py  # Live schema, ingestion & read integration tests
│   ├── test_repository_atomic.py  # Atomic repository replacement tests
│   └── test_traffic_parser.py     # Traffic parser dual-mode & sample regression test suite
├── .env.example                   # Environment template (safe to commit)
├── .gitignore
├── compose.yaml                   # Disposable Neo4j 5 container for local integration testing
├── pytest.ini
├── requirements.txt               # Python 3.10+ dependencies
└── README.md
```

## Roadmap

### Current Features

- ✅ Environment-based configuration with lazy loading (`.env` + `python-dotenv`)
- ✅ Dual-mode traffic ingestion: basic 7-column TSV and project-defined enriched tshark export profile
- ✅ Deterministic SHA-256 `flow_key` directional aggregate identity
- ✅ Packet, frame-byte, and observation window aggregation with Layer 2 association preservation
- ✅ Typed JSON ingestion of IDS/Snort alert data
- ✅ Normalized domain dataclasses (`TrafficRecord`, `AlertRecord`, `IngestionSummary`)
- ✅ Fact-based Neo4j graph model (`:IPAddress`, `:Layer2Identifier`, `:AlertFact`)
- ✅ Directional relationships with parallel edge support (`:COMMUNICATED_TO`, `:L2_COMMUNICATED_TO`, `:OBSERVED_WITH`, `:SOURCE_OF`, `:TARGETS`)
- ✅ Deterministic `fact_key` hashing (SHA-256) for unique normalized alert facts
- ✅ Uniqueness constraints and RANGE indexes (Neo4j 5.x)
- ✅ Parameterized `UNWIND` batched writes with managed transactions (`session.execute_write`)
- ✅ Read-oriented FastAPI backend API (v1.2.0) with Pydantic v2 schemas and OpenAPI documentation
- ✅ Dedicated endpoints for traffic analytics summaries, endpoint volume rankings, filtered communications, IPs, peers, Layer 2 associations, alert facts, correlations, neighborhood, and shortest path
- ✅ Gated browser data-import endpoints (`GET /status`, `POST /validate`, `POST /import`) with atomic workspace replacement and rollback protection
- ✅ Interactive React 19 + TypeScript web dashboard with dark cybersecurity theme
- ✅ Cytoscape.js graph neighborhood canvas with parallel edge rendering and edge tap selection
- ✅ Communication edge inspector drawer (`CommunicationEdgePanel`) and enriched IP detail drawer (`IPDetailPanel`)
- ✅ Alert fact inspector, flow-aware correlation table, and shortest path chain visualizer
- ✅ Browser Data Import UI with dual-format traffic support, client-side size limits, live validation diagnostics, replace acknowledgement, and capability breakdowns
- ✅ Automated backend test suite (`pytest`) with default mock regression and opt-in live Neo4j integration
- ✅ Automated frontend test suite (`vitest`) with full component, formatter, and routing coverage
- ✅ Disposable Neo4j 5 Docker Compose test environment (`compose.yaml`)
- ✅ GitHub Actions multi-job CI workflow (`.github/workflows/ci.yml`)
- ✅ Synthetic basic and enriched sample datasets included

### Phases

| Phase | Objective | Testing scope | Status |
|---|---|---|---|
| ~~0~~ | ~~Preserve original internship version~~ (`v0-internship` tag) | — | ✅ Complete |
| ~~1~~ | ~~Project foundation~~ (configuration, structure, logging) | — | ✅ Complete |
| ~~2~~ | ~~Refactor ingestion pipeline~~ (pandas migration, models, tests) | Ingestion/parser unit tests | ✅ Complete |
| ~~3~~ | ~~Redesign Neo4j graph model & persistence~~ (schema, batching, facts) | Graph schema, repository, integration tests | ✅ Complete |
| ~~4~~ | ~~Add backend API~~ (FastAPI REST API) | API route & ReadRepository unit tests | ✅ Complete |
| ~~5~~ | ~~Add web dashboard~~ (React 19 + TypeScript + Cytoscape.js) | Vitest frontend test suite & build verification | ✅ Complete |
| ~~6~~ | ~~Integration validation, CI, regression coverage & hardening~~ | Live Neo4j integration, FastAPI live test, CI workflows | ✅ Complete |
| ~~6.5~~ | ~~Browser data import & single active workspace replacement~~ | Stateless validation, atomic replacement, rollback, UI tests | ✅ Complete |
| 7 | Traffic model enrichment & security analytics | Dual-mode parser, persistence, analytics API & dashboard | 🚀 Implemented (v1.2.0 RC) |

## License

This project is part of a cybersecurity internship portfolio. License TBD.
