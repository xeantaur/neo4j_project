[← Back to README](../README.md)

# Browser Data Import & Security Model

This document outlines the browser data import workflow, architecture, security boundaries, and operational safeguards implemented in the application.

---

## Operational Model

The browser data import workflow enables users to upload custom network traffic TSVs and Snort/IDS alert JSON files directly through the web UI to populate the active Neo4j analysis workspace.

### Key Operational Characteristics:
- **Single Active Workspace:** The application operates on a single active analysis workspace. Importing a new dataset atomically replaces the current graph data.
- **Disabled by Default:** Browser mutation endpoints are disabled by default (`DATA_IMPORT_ENABLED=false`). They must be explicitly enabled via environment configuration.
- **Stateless Validation Pre-Flight:** Uploads can be pre-validated (`POST /api/v1/import/validate`) to inspect diagnostics, format detection, and parse statistics before executing database mutations.
- **Atomic Replacement & Rollback:** Graph data replacement (`POST /api/v1/import`) runs inside managed transactions (`session.execute_write`). If ingestion fails at any stage, the transaction rolls back, preserving previous graph state.
- **Concurrency Locking:** An in-process `threading.Lock` ensures that only one import request can execute at a time per FastAPI worker process (returning `409 Conflict` on concurrent attempts).
- **Immediate File Cleanup:** Uploaded temporary files on disk are unlinked in `finally` blocks immediately after validation or ingestion.

---

## Security Boundaries & Considerations

### 1. Trusted / Local Environment Use Only
The browser data import endpoints do **not** implement user authentication, access control lists, or session management. Browser data import is designed strictly for local development, demo environments, or trusted internal network deployments.

### 2. CORS Policy is Not Authentication
Configured `CORS_ORIGINS` in `.env` govern browser cross-origin resource sharing policies. CORS restrictions do **not** authenticate users, prevent direct API calls from scripts, or act as an access control boundary.

### 3. Upload File Size Limits
File uploads are restricted by `DATA_IMPORT_MAX_FILE_SIZE_MB` (default: 10 MiB per file). Requests exceeding this limit are rejected immediately with HTTP `413 Payload Too Large`.

### 4. Dedicated Neo4j Instance Recommendation
Because workspace replacement executes destructive clearing of application-owned nodes (`:IPAddress`, `:Layer2Identifier`, `:AlertFact`), it is strongly recommended to run the platform against a dedicated Neo4j database or disposable Docker container (`compose.yaml`).

### 5. Historical Credentials Warning
> **Warning:** Commits from the original prototype contained hardcoded credentials. Those historical credentials must be considered **compromised** and must never be reused in any environment. Active application configuration is loaded exclusively from environment variables via `.env`.
