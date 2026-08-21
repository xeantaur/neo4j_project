# Network Traffic Analysis with Neo4j

Graph-based network traffic and security alert analysis using Neo4j.

> **Origin:** This project was originally developed during a cybersecurity internship (September 2024). It is being modernized from an internship prototype into a portfolio-quality cybersecurity analysis tool. The original prototype used PySpark; the modernized pipeline uses a lightweight, typed Python/pandas ingestion architecture.

## What It Does

This application processes two types of cybersecurity data and loads them into a Neo4j graph database for relationship analysis:

1. **Network traffic data** (tshark/Wireshark TSV export) — MAC addresses, IP addresses, and protocols
2. **IDS/Snort alert data** (JSON array) — security alerts with rule IDs, severity, and connection details

The resulting graph models:
- **Layer 2 relationships** — which MAC addresses communicated with each other
- **Layer 3 relationships** — which IP addresses communicated, and how IPs map to MACs
- **Security alerts** — which IP connections triggered IDS alerts, with rule details and priority

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.9+ | Main language |
| pandas | Tabular network traffic data parsing, cleaning, and deduplication |
| Neo4j 5.x | Graph database for storing and querying network relationships |
| neo4j (Python driver) | Database connectivity |
| python-dotenv | Environment-based configuration |
| pytest | Automated unit and integration testing suite |

## Architecture

```
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
                    src/main.py
                         │
                         ▼
               Neo4j Graph Database
    ┌─────────────────────────────────────────┐
    │  (:MAC)  (:IP)                          │
    │  [:DESTINATION]  [:ASSOCIATED_WITH]     │
    │  [:ALERT]                               │
    └─────────────────────────────────────────┘
```

## Prerequisites

- **Python 3.9+** (Target compatibility: Python 3.9–3.12; actively verified on Python 3.11.9)
- **No Java or JVM runtime required** for the modernized ingestion pipeline
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

Execute the test suite across ingestion parsers, data models, and configuration:

```bash
pytest
```

### 4. Run Ingestion Application

```bash
python -m src.main
```

## Neo4j Graph Model

The current graph contains:

**Nodes:**
- `(:MAC {address})` — Network interface (resolved MAC address)
- `(:IP {address})` — IP address

**Relationships:**
- `(:MAC)-[:DESTINATION {protocol}]->(:MAC)` — Layer 2 communication
- `(:IP)-[:DESTINATION {protocol}]->(:IP)` — Layer 3 communication
- `(:IP)-[:ASSOCIATED_WITH]->(:MAC)` — IP-to-MAC mapping
- `(:IP)-[:ALERT {sid, gid, rev, message, priority, protocol, src_port, dst_port}]->(:IP)` — IDS security alert

## Security Notice

Historical commits in this repository contain hardcoded credentials from the original internship prototype. Those credentials should be considered **compromised** and must not be reused in any environment. All configuration is now loaded from environment variables.

## Project Structure

```
neo4j_project/
├── data/
│   └── samples/
│       ├── sample_traffic.tsv  # Synthetic RFC 1918 traffic data
│       └── sample_alerts.json   # Synthetic IDS alert data
├── src/
│   ├── __init__.py
│   ├── config.py               # Centralized configuration
│   ├── main.py                 # Application orchestrator
│   └── ingestion/
│       ├── __init__.py         # Ingestion exports
│       ├── models.py           # TrafficRecord, AlertRecord, IngestionSummary
│       ├── traffic_parser.py   # pandas-based TSV traffic parser
│       └── alert_parser.py     # JSON alert parser
├── tests/
│   ├── __init__.py
│   ├── conftest.py             # Shared pytest fixtures
│   ├── test_config.py          # Config validation tests
│   ├── test_traffic_parser.py  # Traffic parser test suite
│   ├── test_alert_parser.py    # Alert parser test suite
│   └── test_main_ingestion.py  # Neo4j loader compatibility smoke test
├── .env.example                # Environment template (safe to commit)
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
- ✅ Normalized, immutable domain dataclasses (`TrafficRecord`, `AlertRecord`)
- ✅ Validation with diagnostics metrics (`IngestionSummary`)
- ✅ Automated test suite with 100% pass rate (`pytest`)
- ✅ Synthetic sample datasets included
- ✅ Structured Python logging
- ✅ Proper resource management (Neo4j driver cleanup)

### Planned Features

- 🔲 Redesigned Neo4j graph model (nodes for Alerts, relationship batching, MERGE idempotency)
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
| 3 | Redesign Neo4j graph model | Neo4j repository + graph integration tests | 🔲 Planned |
| 4 | Add backend API (FastAPI) | API endpoint tests | 🔲 Planned |
| 5 | Add web dashboard | Basic frontend/API integration verification | 🔲 Planned |
| 6 | Final quality pass | Coverage improvements, regression tests, documentation | 🔲 Planned |
| 7 | Advanced security analytics | Analytics-specific tests | 🔲 Planned |

## License

This project is part of a cybersecurity internship portfolio. License TBD.
