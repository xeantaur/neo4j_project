# Network Traffic & Security Alert Analysis with Neo4j

Graph-based network traffic and security alert analysis using Neo4j, FastAPI, and React with Cytoscape.js.

> **Origin:** This project was originally developed during a cybersecurity internship (September 2024). It is being modernized from an internship prototype into a portfolio-quality cybersecurity analysis tool. The original prototype used PySpark and unindexed row-by-row `CREATE` relationships; the modernized system uses a lightweight pandas ingestion pipeline, a normalized fact-based graph model, batched `UNWIND` persistence with Neo4j 5.x constraints, a read-only FastAPI REST backend, and an interactive React + Cytoscape.js web dashboard.

## What It Does

This application processes two types of cybersecurity data, loads them into a Neo4j graph database for relationship analysis, and provides a typed REST API and web dashboard:

1. **Network traffic data** (tshark/Wireshark TSV export) — Layer 2 identifiers, IP addresses, and observed protocols
2. **IDS/Snort alert data** (JSON array) — security alerts with rule IDs, severity ratings, and connection details

The resulting graph models:
- **Layer 3 communication** — directional IP-to-IP flows with observed protocol properties
- **Layer 2 communication** — directional interface-to-interface frame flows
- **Layer 2 / Layer 3 resolution** — observed associations between IP addresses and Layer 2 identifiers
- **Security alert facts** — unique normalized alert facts preserving source-target pairings and rule metadata

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.10+ | Main backend language (Actively verified on Python 3.11.9) |
| FastAPI | Typed REST API framework |
| Uvicorn | ASGI application server |
| Pydantic v2 | Strict request validation, canonicalization, and response serialization |
| pandas | Tabular network traffic parsing, cleaning, and deduplication |
| Neo4j 5.x | Graph database with uniqueness constraints and RANGE indexes |
| neo4j (Python driver) | Database connectivity with managed retry-safe transactions (`session.execute_read` / `session.execute_write`) |
| python-dotenv | Environment-based configuration with lazy loading |
| pytest | Automated backend test suite (unit tests, API test client, and opt-in live Neo4j integration tests) |
| React 19 | Frontend user interface framework |
| TypeScript 5+ | Type-safe frontend client and component modeling |
| Vite 8 | Frontend build toolchain and development server with API proxying |
| Cytoscape.js 3+ | Interactive graph visualization engine (hierarchical, force-directed, concentric layouts) |
| Vitest | Frontend component and unit test suite |

## Architecture

```
[ Ingestion Pipeline — CLI: python -m src.main ]
Network traffic (TSV)             IDS alerts (JSON)
          │                              │
          ▼                              ▼
src/ingestion/traffic_parser.py   src/ingestion/alert_parser.py
  - TSV extraction & cleaning       - JSON array parsing
  - MAC normalization               - Type coercion & validation
  - IP validation & deduplication   - Missing fields -> None
          │                              │
          ▼                              ▼
  list[TrafficRecord]            list[AlertRecord]
          │                              │
          └──────────────┬───────────────┘
                         │
                         ▼
             src/graph/repository.py
  - Parameterized UNWIND batching (session.execute_write)
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
  │   └── PathFinderPage.tsx       (Directional L3 communication hop chain visualizer)
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

Phase 4 introduces a read-only REST API exposing graph topology, security alert facts, cross-domain correlations, and graph traversal.

### Interactive API Documentation

When the API server is running, interactive OpenAPI documentation is available at:
- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **ReDoc:** `http://127.0.0.1:8000/redoc`

### API Endpoints Reference

| Method | Endpoint | Description | Query / Path Parameters |
|---|---|---|---|
| `GET` | `/health` | Application liveness (0 database calls) | None |
| `GET` | `/ready` | Database readiness check | None |
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
# Optional: comma-separated origins (CORS disabled if unset)
# CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

### 3. Run Ingestion CLI

```bash
python -m src.main
```

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
Execute Vitest component and client tests:

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
- **`neo4j-integration`**: Live schema, file ingestion, read repository, and FastAPI endpoint integration tests executed against an ephemeral `neo4j:5.26.29-community` service container.

## Migration Policy

The modern Phase 3+ graph schema is designed to be **rebuilt directly from normalized source datasets** rather than migrated in-place from the legacy prototype schema (`:IP`, `:MAC`, `:DESTINATION`, `:ASSOCIATED_WITH`, `:ALERT`). No destructive database cleanup is performed automatically.

## Security Notice

Historical commits from the original internship prototype contained hardcoded credentials. Those historical credentials must be considered **compromised** and must never be reused in any environment. Active application configuration is loaded exclusively from environment variables via `.env` (excluded from version control).

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
├── frontend/                      # Phase 5 React 19 + TypeScript + Cytoscape.js Dashboard
│   ├── src/
│   │   ├── api/                   # Typed API client modules & interfaces
│   │   ├── components/            # Reusable UI, graph canvas & detail panels
│   │   ├── pages/                 # Overview, Network, Alert, Correlation, Path pages
│   │   └── styles/                # CSS variables & dark cybersecurity theme
│   ├── package.json               # Node >=20.19.0 engine declaration
│   └── vite.config.ts             # Vite build & proxy configuration
├── src/
│   ├── config.py                  # Centralized configuration with lazy access
│   ├── main.py                    # Application CLI orchestrator
│   ├── api/                       # Phase 4 FastAPI REST Backend
│   │   ├── app.py                 # FastAPI application factory & error handlers
│   │   ├── dependencies.py        # Lifespan management & dependency injection
│   │   ├── models.py              # Pydantic v2 response schemas
│   │   └── routes/                # health, network, alerts, correlations, graph
│   ├── graph/                     # Graph persistence & query repositories
│   │   ├── schema.py              # Constraints and RANGE indexes
│   │   ├── repository.py          # Write persistence (batched UNWIND)
│   │   └── read_repository.py     # Read queries (session.execute_read)
│   └── ingestion/                 # Ingestion parsers & domain models
│       ├── traffic_parser.py      # pandas-based TSV traffic parser
│       └── alert_parser.py        # JSON alert parser
├── tests/
│   ├── conftest.py                # Shared pytest fixtures
│   ├── test_alert_parser.py       # Alert parser test suite
│   ├── test_api_*.py              # API endpoint unit test suites
│   ├── test_api_live_neo4j.py     # FastAPI live integration tests against real Neo4j
│   ├── test_graph_*.py            # Graph repository & schema unit tests
│   ├── test_neo4j_integration.py  # Live schema, ingestion & read integration tests
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
- ✅ Read-only FastAPI backend API with Pydantic v2 schemas and OpenAPI documentation
- ✅ Dedicated endpoints for IPs, peers, Layer 2 associations, alert facts, correlations, neighborhood, and shortest path
- ✅ Interactive React 19 + TypeScript web dashboard with dark cybersecurity theme
- ✅ Cytoscape.js graph neighborhood canvas with hierarchical, force-directed, and concentric layouts
- ✅ IP inspection drawer, Layer 2 inspection, alert fact inspector, correlation table, and shortest path chain visualizer
- ✅ Automated backend test suite with 82 passing unit/API tests (`pytest`)
- ✅ Automated frontend test suite with 19 passing unit/component tests (`vitest`)
- ✅ Live Neo4j integration test suite with schema, file ingestion, read repository, and live FastAPI validation
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
| ~~4~~ | ~~Add backend API~~ (FastAPI read-only REST API) | API route & ReadRepository unit tests | ✅ Complete |
| ~~5~~ | ~~Add web dashboard~~ (React 19 + TypeScript + Cytoscape.js) | Vitest frontend test suite & build verification | ✅ Complete |
| 6 | Integration validation, CI, regression coverage & hardening | Live Neo4j integration, FastAPI live test, CI workflows | 🔄 In Progress |
| 7 | Advanced security analytics | Analytics-specific tests | 🔲 Planned |

## License

This project is part of a cybersecurity internship portfolio. License TBD.
