# Network Traffic & Security Alert Analysis with Neo4j

[![CI](https://github.com/s3rt4c/neo4j_project/actions/workflows/ci.yml/badge.svg)](https://github.com/s3rt4c/neo4j_project/actions/workflows/ci.yml)

Graph-based network traffic and security alert analysis using Neo4j, FastAPI, and React with Cytoscape.js.

> **Origin:** This project was originally developed during a cybersecurity internship (September 2024). It is being modernized from an internship prototype into a portfolio-quality cybersecurity analysis tool. The original prototype used PySpark and unindexed row-by-row `CREATE` relationships; the modernized system uses a lightweight pandas ingestion pipeline, a normalized fact-based graph model, batched `UNWIND` persistence with Neo4j 5.x constraints, a read-oriented FastAPI REST backend with explicitly gated browser data-import mutation endpoints, and an interactive React + Cytoscape.js web dashboard.

## What It Does

This application processes cybersecurity data, loads them into a Neo4j graph database for relationship analysis, and provides a typed REST API and interactive web dashboard.

Users can analyze data across three supported operational modes:

1. **Network traffic only** (tshark/Wireshark TSV export) — Layer 2 identifiers, IP addresses, observed communication protocols, and network path exploration.
2. **IDS/Snort alerts only** (JSON array) — unique normalized security alert facts with rule IDs, priority levels, protocol/port metadata, and source-target IP investigation.
3. **Network traffic + IDS alerts together** — unified topology and alert fact analysis plus cross-domain traffic/alert correlation where matching endpoint evidence exists.

At least one source file is required for browser data import.

The resulting graph models:
- **Layer 3 communication** — directional IP-to-IP flows with observed protocol properties
- **Layer 2 communication** — directional interface-to-interface frame flows
- **Layer 2 / Layer 3 resolution** — observed associations between IP addresses and Layer 2 identifiers
- **Security alert facts** — unique normalized alert facts preserving source-target pairings and rule metadata

> **Analysis Semantics:**
> Traffic/alert correlation represents endpoint co-occurrence in captured data and does not imply causation. Directional source/target endpoints reflect communication orientation and do not infer attacker or victim roles.

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.10+ | Main backend language (CI verified on Python 3.10 and 3.14; local live integration verified on Python 3.11.9) |
| FastAPI | Typed REST API framework |
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
| Cytoscape.js 3+ | Interactive graph visualization engine (hierarchical, force-directed, concentric layouts) |
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
  ├── network.py       (GET /api/v1/network/*)
  ├── alerts.py        (GET /api/v1/alerts/*)
  ├── correlations.py  (GET /api/v1/correlations/*)
  └── graph.py         (GET /api/v1/graph/*)
                            ▲
                            │ REST / JSON (Vite Dev Proxy)
                            │
[ Web Dashboard & Visualization — frontend/ (React 19 + Cytoscape.js) ]
frontend/src/
  ├── pages/
  │   ├── OverviewPage.tsx         (Entity totals, health indicators)
  │   ├── NetworkExplorerPage.tsx  (Cytoscape graph canvas, depth toggle, IP inspector)
  │   ├── AlertExplorerPage.tsx    (Normalized alert facts table & detail modal)
  │   ├── CorrelationsPage.tsx     (Traffic & alert co-occurrence table)
  │   ├── PathFinderPage.tsx       (Directional L3 communication hop chain visualizer)
  │   └── ImportDataPage.tsx       (Browser data import, dual-file validation & workspace replacement)
  └── components/graph/
      ├── CytoscapeCanvas.tsx      (Interactive canvas lifecycle & event bindings)
      └── cytoscapeStyle.ts        (Dark cybersecurity theme stylesheet)
```

## Neo4j Graph Model

### Graph Schema

```
              (:Layer2Identifier)
             {identifier: str (UQ)}
                       ▲
                       │ [:OBSERVED_WITH]
                       │
 (src:IPAddress) ──────────────[:COMMUNICATED_TO {protocol: str}]─────────────▶ (dst:IPAddress)
{address: str (UQ)}                                                            {address: str (UQ)}
       │                                                                               ▲
       │ [:SOURCE_OF]                                                                  │
       ▼                                                                               │
  (:AlertFact) ──────────────────────────────────[:TARGETS]────────────────────────────┘
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

- **`:IPAddress`**: Observed IPv4 or IPv6 endpoint. Unique on `address`.
- **`:Layer2Identifier`**: Observed Layer 2 hardware MAC address or resolved local identifier (e.g. `gateway.local`, `Broadcast`). Unique on `identifier`.
- **`:AlertFact`**: Unique normalized alert fact binding source, target, and security rule metadata. Unique on `fact_key`.

### Relationship Entities

- **`(:IPAddress)-[:COMMUNICATED_TO {protocol}]->(:IPAddress)`**: Directional Layer 3 communication.
- **`(:Layer2Identifier)-[:L2_COMMUNICATED_TO {protocol}]->(:Layer2Identifier)`**: Directional Layer 2 frame communication.
- **`(:IPAddress)-[:OBSERVED_WITH]->(:Layer2Identifier)`**: Observed Layer 2 / Layer 3 association in captured traffic.
- **`(:IPAddress)-[:SOURCE_OF]->(:AlertFact)`**: Connects the initiator/source IP to the alert fact.
- **`(:AlertFact)-[:TARGETS]->(:IPAddress)`**: Connects the alert fact to the destination/target IP.

### Alert Fact Identity Semantics (`fact_key`)

The `fact_key` on `:AlertFact` is a deterministic SHA-256 hash calculated over the canonical normalized tuple:
`(src_ip, dst_ip, sid, gid, rev, message, priority, protocol, src_port, dst_port)`.

> **Data Limitation Note:**
> The input datasets lack timestamps, packet IDs, flow IDs, and IDS event IDs. Therefore, `fact_key` represents a **unique normalized alert fact**, NOT a discrete event instance. Two identical real-world alerts with the same attributes collapse into a single `:AlertFact` node upon re-ingestion.

## REST API (FastAPI)

The API is read-oriented for analysis queries, with explicitly gated browser data-import endpoints for validation and atomic workspace replacement. Browser data-import mutation endpoints require `DATA_IMPORT_ENABLED=true` (disabled by default).

### Interactive API Documentation

When the API server is running, interactive OpenAPI documentation is available at:
- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **ReDoc:** `http://127.0.0.1:8000/redoc`

### API Endpoints Reference

| Method | Endpoint | Description | Query / Path / Body Parameters |
|---|---|---|---|
| `GET` | `/health` | Application liveness (0 database calls) | None |
| `GET` | `/ready` | Database readiness check | None |
| `GET` | `/api/v1/import/status` | Browser data import enablement and configured file-size limit | None |
| `POST` | `/api/v1/import/validate` | Statelessly validate uploaded traffic and/or alert data without modifying Neo4j | `traffic_file` (optional), `alerts_file` (optional) [`multipart/form-data`] |
| `POST` | `/api/v1/import` | Atomically replace the single active analysis workspace with validated uploaded data | `traffic_file` (optional), `alerts_file` (optional) [`multipart/form-data`] |
| `GET` | `/api/v1/network/ips` | Paginated list of observed IP addresses | `limit` (1..200), `offset` |
| `GET` | `/api/v1/network/ips/{address}` | IP context, L2 associations & flow counts | `address` (path) |
| `GET` | `/api/v1/network/ips/{address}/peers` | Communicating peers and observed protocols | `address` (path), `direction` (`outbound`, `inbound`, `all`), `limit`, `offset` |
| `GET` | `/api/v1/network/ips/{address}/layer2` | Paginated Layer 2 associations for an IP | `address` (path), `limit`, `offset` |
| `GET` | `/api/v1/network/layer2` | Paginated list of Layer 2 identifiers | `limit`, `offset` |
| `GET` | `/api/v1/network/communications` | Filterable Layer 3 IP-to-IP flows | `source_ip`, `target_ip`, `protocol`, `limit`, `offset` |
| `GET` | `/api/v1/alerts` | Filterable normalized security alert facts | `source_ip`, `target_ip`, `priority`, `sid`, `protocol`, `limit`, `offset` |
| `GET` | `/api/v1/alerts/{fact_key}` | Retrieve single alert fact by SHA-256 key | `fact_key` (64-char hex path) |
| `GET` | `/api/v1/correlations/traffic-alerts` | Communicating IP pairs with matching alerts | `limit`, `offset` |
| `GET` | `/api/v1/graph/neighborhood/{address}` | Bounded subgraph around an IP | `address` (path), `depth` (1..2), `max_nodes` (1..100) |
| `GET` | `/api/v1/graph/path` | Shortest Layer 3 path between two IPs | `source`, `target`, `max_hops` (1..10) |

### Pagination Envelope

All collection endpoints return a standardized pagination envelope:

```json
{
  "items": [ ... ],
  "total": 42,
  "limit": 50,
  "offset": 0
}
```

## Setup & Running

### 1. Clone and install dependencies

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

### 2. Configure environment

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your actual configuration:

```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_actual_password
TRAFFIC_CSV_PATH=data/samples/sample_traffic.tsv
ALERTS_JSON_PATH=data/samples/sample_alerts.json

# Browser data import & workspace replacement (Phase 6.5)
# Set to true to allow trusted/local browser uploads. Keep false for public read-only deployments.
DATA_IMPORT_ENABLED=false
# Maximum upload file size in megabytes (per file, positive integer)
DATA_IMPORT_MAX_FILE_SIZE_MB=10

# Optional: comma-separated origins (CORS disabled if unset)
# CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

> **Deployment Guidance:**
> `DATA_IMPORT_ENABLED=false` is the secure default. Browser data import should be enabled only for trusted/local deployments because this project does not implement user authentication or authorization on import mutation endpoints.

### 3. Ingestion Workflows

This system supports two independent data ingestion workflows:

#### A. CLI Ingestion (Terminal)
Ingest files configured in `.env` (`TRAFFIC_CSV_PATH`, `ALERTS_JSON_PATH`). CLI ingestion operates directly against Neo4j and does **not** depend on `DATA_IMPORT_ENABLED`:

```bash
python -m src.main
```

#### B. Browser Data Import (Interactive Dashboard)
Load and analyze custom cybersecurity data directly from the React dashboard:

**Prerequisites:**
- Neo4j database running and reachable
- FastAPI backend running with `DATA_IMPORT_ENABLED=true` in `.env`
- Frontend dashboard running (`http://localhost:5173`)

**Workflow:**
1. Open the dashboard and navigate to the **Import Data** tab.
2. Select your data file(s):
   - **Network Traffic:** tshark-compatible TSV export
   - **Security Alerts:** IDS/Snort-compatible JSON array format
   - *Supported combinations:* traffic only, alerts only, or traffic + alerts together (at least one file required).
3. Click **Validate Files** to run stateless server-side validation.
4. Review structured validation diagnostics (record counts, column checks, duplicate filters).
5. Read and acknowledge the single active workspace replacement warning.
6. Click **Import & Analyze** to execute atomic graph persistence.
7. Use the rendered navigation actions (**Open Overview**, **Explore Network**) to explore your dataset.

**Single Active Workspace & Atomic Replacement:**
- The browser import workflow manages a **single active analysis workspace**. A successful import atomically replaces previous application-owned data (`:IPAddress`, `:Layer2Identifier`, `:AlertFact`).
  - *Traffic only:* Previous alert data is replaced; topology and path exploration are enabled.
  - *Alerts only:* Previous traffic data is replaced; alert facts and IP investigations are enabled.
  - *Traffic + alerts:* Both datasets form the new active analysis workspace, enabling correlation analysis.
- **Safety & Rollback:** All provided files are fully validated and parsed before any database writes occur. Ingestion executes inside a single managed Neo4j write transaction (`session.execute_write`). If any batch fails or database error occurs, the entire transaction rolls back automatically, leaving the previous analysis workspace intact.
- **File Handling:** Uploads stream into temporary files for parsing and are unlinked immediately after validation or ingestion. Uploaded datasets are not permanently retained on disk. Default per-file upload limit is **10 MiB** (configurable via `DATA_IMPORT_MAX_FILE_SIZE_MB`).

### 4. Start the FastAPI Backend Server

```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Start the Frontend Web Dashboard

In a separate terminal:

```bash
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser.

### 6. Run Automated Tests

#### Backend Test Suite
Execute Python unit and API tests (100% in-memory with mocked drivers and zero network calls):

```bash
pytest
```

#### Frontend Test Suite
Execute Vitest component, API client, and page tests:

```bash
cd frontend
npm run test:run
```

#### Frontend Production Build
Verify TypeScript compilation and static bundle generation:

```bash
cd frontend
npm run build
```

#### Opt-In Live Neo4j Integration Testing

Live Neo4j integration tests are **strictly opt-in** and require an explicitly configured, disposable Neo4j 5.x test instance. Standard test runs (`pytest`) will safely skip live integration testing.

A disposable Neo4j test database can be launched locally using Docker Compose:

```bash
# 1. Start disposable Neo4j 5 test instance (ports 17687/17474)
docker compose up -d neo4j-test

# 2. Run live integration tests (PowerShell example)
$env:RUN_NEO4J_INTEGRATION="1"
$env:NEO4J_TEST_URI="bolt://localhost:17687"
$env:NEO4J_TEST_USERNAME="neo4j"
$env:NEO4J_TEST_PASSWORD="phase6-test-password"
python -m pytest -m integration -v

# 3. Clean up disposable container
docker compose down
```

> **Important Notes:**
> - Integration tests require explicit `RUN_NEO4J_INTEGRATION=1`, `NEO4J_TEST_URI`, `NEO4J_TEST_USERNAME`, and `NEO4J_TEST_PASSWORD` environment variables.
> - Live integration tests **never** fall back to normal application Neo4j credentials (`NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`).
> - The live integration suite must always target a dedicated/disposable test database instance.
> - In GitHub Actions CI, live integration tests run against an ephemeral Neo4j 5 service container with job-local credentials.

## Continuous Integration

Automated testing is configured via GitHub Actions (`.github/workflows/ci.yml`) on pull requests and pushes to `main`:
- **`backend-unit`**: Unit and API tests across Python 3.10 and 3.14 with `pip check` and bytecode compilation.
- **`frontend`**: React/TypeScript Vitest suite, production build (`tsc -b && vite build`), Oxlint linter, and runtime vulnerability audit (`npm audit --omit=dev`) on Node 24.
- **`neo4j-integration`**: Live schema, file ingestion, atomic workspace replacement, rollback protection, read repository, and FastAPI endpoint integration tests executed against an ephemeral `neo4j:5.26.29-community` service container.

## Migration Policy

The modern Phase 3+ graph schema is designed to be **rebuilt directly from normalized source datasets** rather than migrated in-place from the legacy prototype schema (`:IP`, `:MAC`, `:DESTINATION`, `:ASSOCIATED_WITH`, `:ALERT`).

The application does not perform automatic destructive migration cleanup during startup or schema migration. The browser data-import feature is a separate, explicit operation: when enabled and confirmed by the user, it atomically replaces the application-owned single active analysis workspace.

## Security Notice

- **Historical Credentials:** Commits from the original internship prototype contained hardcoded credentials. Those historical credentials must be considered **compromised** and must never be reused in any environment. Active application configuration is loaded exclusively from environment variables via `.env` (excluded from version control).
- **Browser Data Import Security:** `DATA_IMPORT_ENABLED` defaults to `false`. The import endpoints do not implement user authentication or authorization. Browser mutation should only be enabled in trusted/local environments. Public unauthenticated deployments must keep browser data import disabled. Configured CORS origins govern cross-origin browser policies and do not provide authentication or access control.

## Project Structure

```
neo4j_project/
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions CI workflow (unit, frontend, integration)
├── data/
│   └── samples/
│       ├── sample_traffic.tsv     # Synthetic RFC 1918 traffic data
│       └── sample_alerts.json      # Synthetic IDS alert data
├── frontend/                      # Phase 5 & 6.5 React 19 + TypeScript + Cytoscape.js Dashboard
│   ├── src/
│   │   ├── api/                   # Typed API client modules (network, alerts, graph, importData)
│   │   ├── components/            # Reusable UI, graph canvas & detail panels
│   │   ├── pages/                 # Overview, Network, Alert, Correlation, Path, ImportData pages
│   │   └── styles/                # CSS variables & dark cybersecurity theme
│   ├── package.json               # Node >=20.19.0 engine declaration
│   └── vite.config.ts             # Vite build & proxy configuration
├── src/
│   ├── config.py                  # Centralized configuration with lazy access
│   ├── main.py                    # Application CLI orchestrator
│   ├── api/                       # Phase 4 & 6.5 FastAPI REST Backend
│   │   ├── app.py                 # FastAPI application factory & error handlers
│   │   ├── dependencies.py        # Lifespan management & dependency injection
│   │   ├── models.py              # Pydantic v2 response schemas
│   │   └── routes/                # health, network, alerts, correlations, graph, import_data
│   ├── services/                  # Business logic services (stateless import validation & staging)
│   │   └── import_service.py
│   ├── graph/                     # Graph persistence & query repositories
│   │   ├── schema.py              # Constraints and RANGE indexes
│   │   ├── repository.py          # Write persistence (batched UNWIND & atomic workspace replacement)
│   │   └── read_repository.py     # Read queries (session.execute_read)
│   └── ingestion/                 # Ingestion parsers & domain models
│       ├── traffic_parser.py      # pandas-based TSV traffic parser
│       └── alert_parser.py        # JSON alert parser
├── tests/
│   ├── conftest.py                # Shared pytest fixtures
│   ├── test_alert_parser.py       # Alert parser test suite
│   ├── test_api_*.py              # API endpoint unit test suites (including test_api_import.py)
│   ├── test_api_live_neo4j.py     # FastAPI live integration tests against real Neo4j
│   ├── test_graph_*.py            # Graph repository & schema unit tests
│   ├── test_neo4j_atomic_replace.py # Atomic replacement & rollback integration tests
│   ├── test_neo4j_integration.py  # Live schema, ingestion & read integration tests
│   ├── test_repository_atomic.py  # Atomic repository replacement tests
│   └── test_traffic_parser.py     # Traffic parser test suite
├── .env.example                   # Environment template (safe to commit)
├── .gitignore
├── compose.yaml                   # Disposable Neo4j 5 container for local integration testing
├── pytest.ini
├── requirements.txt               # Python 3.10+ dependencies
└── README.md
```

## Roadmap

This project is being modernized through the following planned phases:

### Current Features

- ✅ Environment-based configuration with lazy loading (`.env` + `python-dotenv`)
- ✅ Modular pandas-based ingestion of tshark TSV network traffic data
- ✅ Typed JSON ingestion of IDS/Snort alert data
- ✅ Normalized domain dataclasses (`TrafficRecord`, `AlertRecord`)
- ✅ Fact-based Neo4j graph model (`:IPAddress`, `:Layer2Identifier`, `:AlertFact`)
- ✅ Directional relationships (`:COMMUNICATED_TO`, `:L2_COMMUNICATED_TO`, `:OBSERVED_WITH`, `:SOURCE_OF`, `:TARGETS`)
- ✅ Deterministic `fact_key` hashing (SHA-256) for unique normalized alert facts
- ✅ Uniqueness constraints and RANGE indexes (Neo4j 5.x)
- ✅ Parameterized `UNWIND` batched writes with managed transactions (`session.execute_write`)
- ✅ Read-oriented FastAPI backend API with Pydantic v2 schemas and OpenAPI documentation
- ✅ Dedicated endpoints for IPs, peers, Layer 2 associations, alert facts, correlations, neighborhood, and shortest path
- ✅ Gated browser data-import endpoints (`GET /status`, `POST /validate`, `POST /import`) with atomic workspace replacement and rollback protection
- ✅ Interactive React 19 + TypeScript web dashboard with dark cybersecurity theme
- ✅ Cytoscape.js graph neighborhood canvas with hierarchical, force-directed, and concentric layouts
- ✅ IP inspection drawer, Layer 2 inspection, alert fact inspector, correlation table, and shortest path chain visualizer
- ✅ Browser Data Import UI with dual-file selection, client-side size limits, live validation diagnostics, replace acknowledgement, and capability breakdowns
- ✅ Automated backend test suite with 111 passing unit/API tests (`pytest`)
- ✅ Automated frontend test suite with 37 passing unit/component tests (`vitest`)
- ✅ Live Neo4j integration test suite with schema, file ingestion, atomic replacement rollback, read repository, and live FastAPI validation
- ✅ Disposable Neo4j 5 Docker Compose test environment (`compose.yaml`)
- ✅ GitHub Actions multi-job CI workflow (`.github/workflows/ci.yml`)
- ✅ Synthetic sample datasets included
- ✅ Structured Python logging and deterministic resource cleanup

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
| 7 | Advanced security analytics | Analytics-specific tests | 🔲 Planned |

## License

This project is part of a cybersecurity internship portfolio. License TBD.
