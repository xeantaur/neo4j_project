# Network Traffic Analysis with Neo4j

Graph-based network traffic and security alert analysis using Neo4j.

> **Origin:** This project was originally developed during a cybersecurity internship (September 2024). It is currently being modernized from an internship prototype into a portfolio-quality cybersecurity analysis tool.

## What It Does

This application processes two types of cybersecurity data and loads them into a Neo4j graph database for relationship analysis:

1. **Network traffic data** (tshark/Wireshark TSV export) — MAC addresses, IP addresses, and protocols
2. **IDS/Snort alert data** (JSON) — security alerts with rule IDs, severity, and connection details

The resulting graph models:
- **Layer 2 relationships** — which MAC addresses communicated with each other
- **Layer 3 relationships** — which IP addresses communicated, and how IPs map to MACs
- **Security alerts** — which IP connections triggered IDS alerts, with rule details and priority

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.9–3.11 | Main language (constrained by PySpark 3.5) |
| PySpark | Network traffic data parsing and transformation |
| Neo4j 5.x | Graph database for storing and querying network relationships |
| neo4j (Python driver) | Database connectivity |
| python-dotenv | Environment-based configuration |

## Current Architecture

```
Network traffic (TSV)  +  IDS alerts (JSON)
            │                      │
            ▼                      │
    PySpark ingestion              │
    - read TSV                     │
    - clean / deduplicate          │
    - collect to driver            │
            │                      │
            ▼                      ▼
         Neo4j Graph Database
    ┌─────────────────────────────────────┐
    │  (:MAC)  (:IP)                     │
    │  [:DESTINATION]  [:ASSOCIATED_WITH]│
    │  [:ALERT]                          │
    └─────────────────────────────────────┘
```

## Prerequisites

- **Python 3.9–3.11** (PySpark 3.5 does not officially support 3.12+)
- **Java 8 or 11** (required by PySpark)
- **Neo4j 5.x** — [Download Neo4j Desktop](https://neo4j.com/download/) or use Docker:

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
TRAFFIC_CSV_PATH=path/to/your/traffic_data.csv
ALERTS_JSON_PATH=path/to/your/alerts.json
```

> **⚠️ Security:** Never commit the `.env` file. It is excluded by `.gitignore`.

### 3. Prepare data files

**Network traffic file** — Tab-separated (TSV) with 7 columns exported from tshark/Wireshark:

```
src_mac    dst_mac    src_ip    dst_ip    (unused)    (unused)    protocol
```

**Alert file** — JSON array of alert objects:

```json
[
  {
    "src_ip": "192.168.1.10",
    "dst_ip": "10.0.0.1",
    "sid": "2001",
    "gid": "1",
    "rev": "3",
    "message": "ET SCAN Potential SSH Scan",
    "priority": "2",
    "protocol": "TCP",
    "src_port": "54321",
    "dst_port": "22"
  }
]
```

### 4. Run

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
├── src/
│   ├── __init__.py
│   ├── config.py       # Configuration from environment variables
│   └── main.py         # Application entry point
├── .env.example        # Environment template (safe to commit)
├── .gitignore
├── requirements.txt
└── README.md
```

> **Note:** The original internship script (`project.py`) was removed from the active branch but is preserved in Git history. To view it: `git show v0-internship:project.py`

## Roadmap

This project is being modernized through the following planned phases.
Testing evolves with each phase rather than being deferred to the end.

### Current Features

- ✅ Environment-based configuration (`.env` + `python-dotenv`)
- ✅ PySpark ingestion of tshark TSV network traffic data
- ✅ JSON ingestion of IDS/Snort alert data
- ✅ Neo4j graph ingestion (MAC, IP, and alert relationships)
- ✅ Structured Python logging
- ✅ Proper resource management (Neo4j driver, SparkSession)

### Planned Features

- 🔲 Ingestion refactor (pandas migration decision)
- 🔲 Redesigned Neo4j graph model
- 🔲 REST API (FastAPI)
- 🔲 Web dashboard with graph visualization
- 🔲 Docker Compose deployment
- 🔲 Advanced security analytics (timeline, scoring, detection)

### Phases

| Phase | Objective | Testing scope |
|---|---|---|
| ~~0~~ | ~~Preserve original internship version~~ (`v0-internship` tag) | — |
| ~~1~~ | ~~Project foundation~~ (configuration, structure, logging) | — |
| 2 | Refactor ingestion pipeline | Ingestion/parser unit tests |
| 3 | Redesign Neo4j graph model | Neo4j repository + graph integration tests |
| 4 | Add backend API (FastAPI) | API endpoint tests |
| 5 | Add web dashboard | Basic frontend/API integration verification |
| 6 | Final quality pass | Coverage improvements, regression tests, documentation |
| 7 | Advanced security analytics | Analytics-specific tests |

## License

This project is part of a cybersecurity internship portfolio. License TBD.
