[← Back to README](../README.md)

# Application Architecture & System Design

This document details the internal architecture, component interactions, data flows, and codebase layout for the **Network Traffic & Security Alert Analysis** platform.

---

## High-Level System Architecture

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

---

## Component Breakdown

### 1. Ingestion Pipeline (`src/ingestion/`)
- **`traffic_parser.py`**: Dual-mode parser supporting basic 7-column TSVs and enriched 14-column tshark TSVs. Performs IP canonicalization (RFC 5952), port validation, packet count and wire frame byte aggregation, timestamp interval tracking, and deterministic SHA-256 `flow_key` calculation.
- **`alert_parser.py`**: Parses Snort/IDS JSON alert arrays, validates required source and destination IP endpoints, normalizes and validates optional numeric rule metadata (signature IDs, generator IDs, revisions, numeric priorities), normalizes protocols, and creates immutable `AlertRecord` instances with bounded diagnostic telemetry. (Canonical IP transformation and deterministic SHA-256 `fact_key` computation are performed by the persistence layer in `src/graph/repository.py`).
- **`models.py`**: Immutable domain dataclasses (`TrafficRecord`, `AlertRecord`, `IngestionSummary`, `L2Pair`).

### 2. Graph Persistence Layer (`src/graph/`)
- **`schema.py`**: Declares and ensures Neo4j 5.x uniqueness constraints (`IPAddress.address`, `Layer2Identifier.identifier`, `AlertFact.fact_key`) and RANGE indexes (`AlertFact.priority`, `AlertFact.sid`).
- **`repository.py`**: Executes batched Cypher writes using parameterized `UNWIND` blocks inside managed write transactions (`session.execute_write`). Contains `replace_workspace_data` for atomic workspace clearing and re-ingestion with rollback protection.

### 3. Read Query Layer (`src/graph/read_repository.py`)
- Executes optimized Cypher read queries using managed read transactions (`session.execute_read`).
- Provides aggregated analytics summaries, paginated endpoint volume rankings, filtered communication queries, bounded graph neighborhood traversals, and directional shortest-path computations.

### 4. REST API Backend (`src/api/`)
- Built with **FastAPI** and **Pydantic v2**.
- Structured into modular routers: `health.py`, `import_data.py`, `network.py`, `alerts.py`, `correlations.py`, and `graph.py`.
- Employs lifespan events for database connectivity lifecycle and FastAPI dependency injection for repository access.

### 5. Web Frontend (`frontend/`)
- Single-page application built with **React 19**, **TypeScript 6.x**, and **Vite 8**.
- **Graph Engine:** Cytoscape.js with custom dark cybersecurity styling, bezier curve multi-edge routing for parallel flows, and node/edge interaction handlers.
- **Slide Drawers:** Contextual inspectors (`CommunicationEdgePanel`, `IPDetailPanel`, `Layer2DetailPanel`) for deep entity analysis without navigating away from the canvas.

---

## Codebase Directory Layout

```
neo4j_project/
├── .github/
│   └── workflows/
│       └── ci.yml                 # Multi-job CI workflow (unit, frontend, live Neo4j)
├── data/
│   └── samples/
│       ├── sample_traffic.tsv     # Basic synthetic RFC 1918 traffic export
│       ├── sample_traffic_enriched.tsv # Enriched synthetic tshark profile export
│       └── sample_alerts.json     # Synthetic IDS alert array
├── docs/
│   ├── ARCHITECTURE.md            # System architecture & component design (this file)
│   ├── TRAFFIC_MODEL.md           # Traffic formats, flow aggregation & graph schema
│   ├── API.md                     # REST API endpoints & query behavior
│   ├── IMPORT_SECURITY.md         # Browser import model & security boundaries
│   ├── MIGRATION.md               # v1.1 -> v1.2 graph migration guidance
│   └── images/                    # UI visuals and dashboard screenshots
├── frontend/                      # React 19 + TypeScript + Cytoscape.js SPA
│   ├── src/
│   │   ├── api/                   # Typed API client modules
│   │   ├── components/            # Graph canvas, inspectors, UI widgets
│   │   ├── pages/                 # Overview, Network, Alerts, Correlations, Path, Import
│   │   ├── utils/                 # Formatting & pure utility functions
│   │   └── styles/                # CSS variables & dark cybersecurity theme
│   ├── package.json
│   └── vite.config.ts
├── src/
│   ├── config.py                  # Environment-based configuration with lazy loading
│   ├── main.py                    # Application CLI entry point
│   ├── api/                       # FastAPI REST API backend (v1.2.0)
│   ├── services/                  # Business logic services (import validation & staging)
│   ├── graph/                     # Graph persistence, schema & read repositories
│   └── ingestion/                 # Dual-mode parsers & domain dataclasses
├── tests/
│   ├── conftest.py                # Pytest fixtures and mock factories
│   ├── test_alert_parser.py       # Alert parsing tests
│   ├── test_api_*.py              # API endpoint unit tests
│   ├── test_api_live_neo4j.py     # Live API integration tests
│   ├── test_graph_*.py            # Graph schema and repository unit tests
│   ├── test_neo4j_atomic_replace.py # Atomic replacement & rollback integration tests
│   ├── test_neo4j_integration.py  # Live Neo4j schema & query tests
│   └── test_traffic_parser.py     # Traffic parser dual-mode unit tests
├── compose.yaml                   # Disposable Neo4j 5 test container
├── pytest.ini
├── requirements.txt               # Python dependencies
└── README.md
```
