# Network Traffic & Security Alert Analysis with Neo4j

Graph-based network traffic and security alert analysis using Neo4j.

> **Origin:** This project was originally developed during a cybersecurity internship (September 2024). It is being modernized from an internship prototype into a portfolio-quality cybersecurity analysis tool. The original prototype used PySpark and unindexed row-by-row `CREATE` relationships; the modernized system uses a lightweight pandas ingestion pipeline, a normalized fact-based graph model, and batched `UNWIND` persistence with Neo4j 5.x constraints.

## What It Does

This application processes two types of cybersecurity data and loads them into a Neo4j graph database for relationship analysis:

1. **Network traffic data** (tshark/Wireshark TSV export) — Layer 2 identifiers, IP addresses, and transport protocols
2. **IDS/Snort alert data** (JSON array) — security alerts with rule IDs, severity ratings, and connection details

The resulting graph models:
- **Layer 3 communication** — directional IP-to-IP flows with transport protocol properties
- **Layer 2 communication** — directional interface-to-interface frame flows
- **Layer 2 / Layer 3 resolution** — observed associations between IP addresses and Layer 2 identifiers
- **Security alert facts** — discrete, normalized alert facts preserving source-target pairings and rule metadata

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.9+ | Main language (Verified on Python 3.11.9) |
| pandas | Tabular network traffic parsing, cleaning, and deduplication |
| Neo4j 5.x | Graph database with uniqueness constraints and RANGE indexes |
| neo4j (Python driver) | Database connectivity with managed retry-safe transactions (`session.execute_write`) |
| python-dotenv | Environment-based configuration |
| pytest | Automated test suite (unit tests and opt-in live Neo4j integration tests) |

## Architecture

```
Network traffic (TSV)             IDS alerts (JSON)
          │                              │
          ▼                              ▼
src/ingestion/traffic_parser.py   src/ingestion/alert_parser.py
  - TSV extraction & cleaning       - JSON array parsing
  - MAC normalization               - Type coercion & semantic validation
  - IP validation & deduplication   - Missing fields -> None
          │                              │
          ▼                              ▼
  list[TrafficRecord]            list[AlertRecord]
          │                              │
          └──────────────┬───────────────┘
                         │
                         ▼
                    src/main.py
                         │
                         ▼
             src/graph/repository.py
  - IP canonicalization (IPv4/IPv6)
  - Deterministic fact_key generation (SHA-256)
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
- **`(:IPAddress)-[:OBSERVED_WITH]->(:Layer2Identifier)`**: Observed Layer 2 / Layer 3 association in captured traffic (does not assert permanent hardware ownership).
- **`(:IPAddress)-[:SOURCE_OF]->(:AlertFact)`**: Connects the initiator/source IP to the alert fact.
- **`(:AlertFact)-[:TARGETS]->(:IPAddress)`**: Connects the alert fact to the destination/target IP.

### Alert Fact Identity Semantics (`fact_key`)

The `fact_key` on `:AlertFact` is a deterministic SHA-256 hash calculated over the canonical normalized tuple:
`(src_ip, dst_ip, sid, gid, rev, message, priority, protocol, src_port, dst_port)`.

> **Data Limitation Note:**
> The input datasets lack timestamps, packet IDs, flow IDs, and IDS event IDs. Therefore, `fact_key` represents a **unique normalized alert fact**, NOT a discrete event instance. Two identical real-world alerts with the same attributes collapse into a single `:AlertFact` node upon re-ingestion.

## Uniqueness Constraints & Indexes (Neo4j 5.x)

Applied automatically via `src/graph/schema.py`:

```cypher
// Uniqueness constraints (backed by Neo4j 5.x RANGE indexes)
CREATE CONSTRAINT ip_address_unique IF NOT EXISTS
FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE;

CREATE CONSTRAINT layer2_identifier_unique IF NOT EXISTS
FOR (l2:Layer2Identifier) REQUIRE l2.identifier IS UNIQUE;

CREATE CONSTRAINT alert_fact_unique IF NOT EXISTS
FOR (fact:AlertFact) REQUIRE fact.fact_key IS UNIQUE;

// Property indexes for fast filtering
CREATE INDEX alert_fact_priority_index IF NOT EXISTS
FOR (fact:AlertFact) ON (fact.priority);

CREATE INDEX alert_fact_sid_index IF NOT EXISTS
FOR (fact:AlertFact) ON (fact.sid);
```

## Example Cypher Queries

### 1. Network Topology (Communicating IP Pairs)
```cypher
MATCH (src:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress)
RETURN src.address AS source, dst.address AS destination, c.protocol AS protocol
ORDER BY source, destination;
```

### 2. High-Severity Security Alerts with Source and Target
```cypher
MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress)
WHERE fact.priority <= 2
RETURN src.address AS attacker, dst.address AS victim, fact.message AS alert_name,
       fact.priority AS severity, fact.src_port AS src_port, fact.dst_port AS dst_port
ORDER BY fact.priority ASC;
```

### 3. Threat Correlation (Endpoints with Traffic AND Security Alerts)
```cypher
MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress)
MATCH (src)-[c:COMMUNICATED_TO]->(dst)
RETURN src.address AS source, dst.address AS target, fact.message AS alert, c.protocol AS traffic_protocol;
```

### 4. Layer 2 to Layer 3 Resolution Mapping
```cypher
MATCH (ip:IPAddress)-[:OBSERVED_WITH]->(l2:Layer2Identifier)
RETURN ip.address AS ip_address, l2.identifier AS layer2_identifier;
```

## Prerequisites

- **Python 3.9+** (Target compatibility: Python 3.9–3.12; actively verified on Python 3.11.9)
- **No Java or JVM runtime required** for ingestion
- **Neo4j 5.x** — [Download Neo4j Desktop](https://neo4j.com/download/) or run via Docker:

```bash
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_password_here \
  neo4j:5
```

## Setup

### 1. Clone and install dependencies

```bash
git clone <repository-url>
cd neo4j_project
pip install -r requirements.txt
```

### 2. Configure environment

Copy the example environment file and fill in your values:

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
```

> **⚠️ Security:** Never commit the `.env` file. It is excluded by `.gitignore`.

### 3. Run Automated Tests

Execute the full unit test suite:

```bash
pytest
```

To run opt-in live Neo4j integration tests (requires reachable running Neo4j instance):

```bash
pytest -m integration
```

### 4. Run Ingestion Application

```bash
python -m src.main
```

## Migration Policy

The modernized Phase 3 graph schema is designed to be **rebuilt directly from source datasets** rather than migrated in-place from the legacy `:IP` / `:MAC` / `:DESTINATION` model. No destructive database cleanup is performed automatically.

## Security Notice

Historical commits in this repository contain hardcoded credentials from the original internship prototype. Those credentials should be considered **compromised** and must not be reused in any environment. All configuration is now loaded from environment variables.

## Project Structure

```
neo4j_project/
├── data/
│   └── samples/
│       ├── sample_traffic.tsv     # Synthetic RFC 1918 traffic data
│       └── sample_alerts.json      # Synthetic IDS alert data
├── src/
│   ├── __init__.py
│   ├── config.py                  # Centralized configuration
│   ├── main.py                    # Application CLI orchestrator
│   ├── ingestion/                 # Ingestion pipeline
│   │   ├── __init__.py            # Ingestion exports
│   │   ├── models.py              # TrafficRecord, AlertRecord, IngestionSummary
│   │   ├── traffic_parser.py      # pandas-based TSV traffic parser
│   │   └── alert_parser.py        # JSON alert parser
│   └── graph/                     # Graph persistence & schema
│       ├── __init__.py            # Graph exports
│       ├── schema.py              # Constraints and RANGE indexes
│       └── repository.py          # Neo4jRepository with batched UNWIND writes
├── tests/
│   ├── __init__.py
│   ├── conftest.py                # Shared pytest fixtures
│   ├── test_config.py             # Config validation tests
│   ├── test_traffic_parser.py     # Traffic parser test suite
│   ├── test_alert_parser.py       # Alert parser test suite
│   ├── test_graph_schema.py       # Neo4j schema constraint tests
│   ├── test_graph_repository.py   # Repository & fact_key tests
│   ├── test_main_ingestion.py     # Main orchestrator unit tests
│   └── test_neo4j_integration.py  # Opt-in live Neo4j integration tests
├── .env.example                   # Environment template (safe to commit)
├── .gitignore
├── pytest.ini
├── requirements.txt
└── README.md
```

> **Note:** The original internship script (`project.py`) was removed from the active branch but is preserved in Git history. To view it: `git show v0-internship:project.py`

## Roadmap

This project is being modernized through the following planned phases:

### Current Features

- ✅ Environment-based configuration (`.env` + `python-dotenv`)
- ✅ Modular pandas-based ingestion of tshark TSV network traffic data
- ✅ Typed JSON ingestion of IDS/Snort alert data
- ✅ Normalized domain dataclasses (`TrafficRecord`, `AlertRecord`)
- ✅ Fact-based Neo4j graph model (`:IPAddress`, `:Layer2Identifier`, `:AlertFact`)
- ✅ Directional relationships (`:COMMUNICATED_TO`, `:L2_COMMUNICATED_TO`, `:OBSERVED_WITH`, `:SOURCE_OF`, `:TARGETS`)
- ✅ Deterministic `fact_key` hashing (SHA-256) for alert facts
- ✅ Uniqueness constraints and RANGE indexes (Neo4j 5.x)
- ✅ Parameterized `UNWIND` batched writes with managed transactions (`session.execute_write`)
- ✅ Automated unit test suite with 100% pass rate (`pytest`)
- ✅ Synthetic sample datasets included
- ✅ Structured Python logging and deterministic resource cleanup

### Planned Features

- 🔲 REST API (FastAPI)
- 🔲 Web dashboard with graph visualization
- 🔲 Docker Compose deployment
- 🔲 Advanced security analytics (timeline, scoring, detection)

### Phases

| Phase | Objective | Testing scope | Status |
|---|---|---|---|
| ~~0~~ | ~~Preserve original internship version~~ (`v0-internship` tag) | — | ✅ Complete |
| ~~1~~ | ~~Project foundation~~ (configuration, structure, logging) | — | ✅ Complete |
| ~~2~~ | ~~Refactor ingestion pipeline~~ (pandas migration, models, tests) | Ingestion/parser unit tests | ✅ Complete |
| ~~3~~ | ~~Redesign Neo4j graph model & persistence~~ (schema, batching, facts) | Graph schema, repository, integration tests | ✅ Complete |
| 4 | Add backend API (FastAPI) | API endpoint tests | 🔲 Planned |
| 5 | Add web dashboard | Basic frontend/API integration verification | 🔲 Planned |
| 6 | Final quality pass | Coverage improvements, regression tests, documentation | 🔲 Planned |
| 7 | Advanced security analytics | Analytics-specific tests | 🔲 Planned |

## License

This project is part of a cybersecurity internship portfolio. License TBD.
