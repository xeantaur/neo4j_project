# Network Traffic & Security Alert Analysis with Neo4j

Graph-based network traffic and security alert analysis using Neo4j and FastAPI.

> **Origin:** This project was originally developed during a cybersecurity internship (September 2024). It is being modernized from an internship prototype into a portfolio-quality cybersecurity analysis tool. The original prototype used PySpark and unindexed row-by-row `CREATE` relationships; the modernized system uses a lightweight pandas ingestion pipeline, a normalized fact-based graph model, batched `UNWIND` persistence with Neo4j 5.x constraints, and a read-only FastAPI REST backend.

## What It Does

This application processes two types of cybersecurity data, loads them into a Neo4j graph database for relationship analysis, and provides a typed REST API:

1. **Network traffic data** (tshark/Wireshark TSV export) — Layer 2 identifiers, IP addresses, and observed protocols
2. **IDS/Snort alert data** (JSON array) — security alerts with rule IDs, severity ratings, and connection details

The resulting graph models:
- **Layer 3 communication** — directional IP-to-IP flows with observed protocol properties
- **Layer 2 communication** — directional interface-to-interface frame flows
- **Layer 2 / Layer 3 resolution** — observed associations between IP addresses and Layer 2 identifiers
- **Security alert facts** — discrete, normalized alert facts preserving source-target pairings and rule metadata

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.9+ | Main language (Actively verified on Python 3.11.9) |
| FastAPI | Modern, typed, asynchronous/multithreaded REST API framework |
| Uvicorn | High-performance ASGI server |
| Pydantic v2 | Strict request validation, canonicalization, and response serialization |
| pandas | Tabular network traffic parsing, cleaning, and deduplication |
| Neo4j 5.x | Graph database with uniqueness constraints and RANGE indexes |
| neo4j (Python driver) | Database connectivity with managed retry-safe transactions (`session.execute_read` / `session.execute_write`) |
| python-dotenv | Environment-based configuration with lazy loading |
| pytest | Automated test suite (unit tests, API test client, and opt-in live Neo4j integration tests) |

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

```bash
git clone <repository-url>
cd neo4j_project
pip install -r requirements.txt
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
# CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

### 3. Run Ingestion CLI

```bash
python -m src.main
```

### 4. Start the FastAPI Backend Server

```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Run Automated Tests

Execute the test suite (all unit and API tests run 100% in-memory with mocked drivers and zero network calls):

```bash
pytest
```

#### Opt-In Live Neo4j Integration Testing

Live Neo4j integration tests are **strictly opt-in** and require a dedicated, disposable Neo4j test instance. Standard test runs will safely skip live integration testing.

To run against a disposable test instance (PowerShell example):

```powershell
$env:RUN_NEO4J_INTEGRATION="1"
$env:NEO4J_TEST_URI="bolt://localhost:17687"
$env:NEO4J_TEST_USERNAME="neo4j"
$env:NEO4J_TEST_PASSWORD="<your-test-password>"
python -m pytest tests/test_neo4j_integration.py -v
```

> **Note:** The live integration suite has **not** yet been executed in the current development environment as no disposable Neo4j instance was available.

## Project Structure

```
neo4j_project/
├── data/
│   └── samples/
│       ├── sample_traffic.tsv     # Synthetic RFC 1918 traffic data
│       └── sample_alerts.json      # Synthetic IDS alert data
├── src/
│   ├── __init__.py
│   ├── config.py                  # Centralized configuration with lazy access
│   ├── main.py                    # Application CLI orchestrator
│   ├── api/                       # Phase 4 FastAPI REST Backend
│   │   ├── __init__.py
│   │   ├── app.py                 # FastAPI application factory & error handlers
│   │   ├── dependencies.py        # Lifespan management & dependency injection
│   │   ├── models.py              # Pydantic v2 response schemas
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── health.py          # GET /health, GET /ready
│   │       ├── network.py         # GET /api/v1/network/*
│   │       ├── alerts.py          # GET /api/v1/alerts/*
│   │       ├── correlations.py    # GET /api/v1/correlations/*
│   │       └── graph.py           # GET /api/v1/graph/*
│   ├── graph/                     # Graph persistence & query repositories
│   │   ├── __init__.py            # Graph exports
│   │   ├── schema.py              # Constraints and RANGE indexes
│   │   ├── repository.py          # Write persistence (batched UNWIND)
│   │   └── read_repository.py     # Read queries (session.execute_read)
│   └── ingestion/                 # Ingestion parsers & domain models
│       ├── __init__.py
│       ├── models.py              # TrafficRecord, AlertRecord, IngestionSummary
│       ├── traffic_parser.py      # pandas-based TSV traffic parser
│       └── alert_parser.py        # JSON alert parser
├── tests/
│   ├── __init__.py
│   ├── conftest.py                # Shared pytest fixtures
│   ├── test_alert_parser.py       # Alert parser test suite
│   ├── test_api_alerts.py         # Alert API endpoints test suite
│   ├── test_api_correlations.py   # Correlation API endpoints test suite
│   ├── test_api_errors.py         # Error handling & CORS test suite
│   ├── test_api_graph.py          # Graph traversal API test suite
│   ├── test_api_health.py         # Health & readiness API test suite
│   ├── test_api_network.py        # Network & IP API test suite
│   ├── test_config.py             # Config validation tests
│   ├── test_config_isolation.py   # Config isolation between API and CLI
│   ├── test_graph_read_repository.py # Read repository unit tests
│   ├── test_graph_repository.py   # Write repository & fact_key tests
│   ├── test_graph_schema.py       # Neo4j schema constraint tests
│   ├── test_main_ingestion.py     # Main orchestrator unit tests
│   ├── test_neo4j_integration.py  # Opt-in live Neo4j integration tests
│   └── test_traffic_parser.py     # Traffic parser test suite
├── .env.example                   # Environment template (safe to commit)
├── .gitignore
├── pytest.ini
├── requirements.txt
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
- ✅ Automated test suite with 82 passing unit/API tests (`pytest`)
- ✅ Synthetic sample datasets included
- ✅ Structured Python logging and deterministic resource cleanup

### Planned Features

- 🔲 Web dashboard with graph visualization (Phase 5)
- 🔲 Docker Compose deployment (Phase 5)
- 🔲 Coverage improvements and regression hardening (Phase 6)
- 🔲 Advanced security analytics (timeline, scoring, detection) (Phase 7)

### Phases

| Phase | Objective | Testing scope | Status |
|---|---|---|---|
| ~~0~~ | ~~Preserve original internship version~~ (`v0-internship` tag) | — | ✅ Complete |
| ~~1~~ | ~~Project foundation~~ (configuration, structure, logging) | — | ✅ Complete |
| ~~2~~ | ~~Refactor ingestion pipeline~~ (pandas migration, models, tests) | Ingestion/parser unit tests | ✅ Complete |
| ~~3~~ | ~~Redesign Neo4j graph model & persistence~~ (schema, batching, facts) | Graph schema, repository, integration tests | ✅ Complete |
| ~~4~~ | ~~Add backend API~~ (FastAPI read-only REST API) | API route & ReadRepository unit tests | ✅ Complete |
| 5 | Add web dashboard | Basic frontend/API integration verification | 🔲 Planned |
| 6 | Final quality pass | Coverage improvements, regression tests, documentation | 🔲 Planned |
| 7 | Advanced security analytics | Analytics-specific tests | 🔲 Planned |

## License

This project is part of a cybersecurity internship portfolio. License TBD.
