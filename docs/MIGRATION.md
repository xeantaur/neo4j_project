[← Back to README](../README.md)

# Migration & Rebuild Guide (v1.1 → v1.2)

This document provides guidance on graph schema identity evolution between version 1.1 and version 1.2 of the platform.

---

## Graph Identity Evolution

In **v1.1.0**, Layer 3 communication relationships in Neo4j were keyed solely by 3-tuple identity:
```
(src_ip, dst_ip, protocol)
```

In **v1.2.0**, the enriched traffic model introduced deterministic 5-tuple `flow_key` hashing:
```
(src_ip, dst_ip, protocol, src_port, dst_port)
```

This evolution enables the graph database and Cytoscape.js canvas to distinguish and visualize parallel communication flows (such as concurrent TLS sessions or distinct transport services between the same host pair).

---

## Migration Policy & Recommendations

1. **Re-Ingestion from Source:**
   Because relationship identity criteria changed from 3-tuple to 5-tuple, re-ingesting source datasets is the recommended migration path.
2. **Atomic Browser Workspace Replacement:**
   Using the **Import Data** dashboard tab naturally clears the prior workspace and reconstructs the graph with v1.2 schema and `flow_key` properties atomically.
3. **No Automatic Startup Migrations:**
   The application does **not** execute destructive automatic schema migrations on startup.
4. **Direct Ingestion Warning:**
   Running CLI ingestion (`python -m src.main`) into an existing v1.1 database without clearing prior data will leave legacy relationships alongside new ones, resulting in a `mixed` metric availability mode.
5. **Dedicated Database Recommended:**
   Running the application with a dedicated Neo4j instance or disposable container (`compose.yaml`) ensures a clean, isolated workspace.
