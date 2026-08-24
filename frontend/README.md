# Security Investigation Dashboard (Frontend)

React 19 + TypeScript 6.x + Cytoscape.js web application for investigating network traffic topology, enriched communication aggregates, Layer 2 associations, normalized security alert facts, and communication paths powered by the read-oriented FastAPI backend with explicitly gated browser data-import mutation endpoints.

## Getting Started

### 1. Install Dependencies

```bash
npm install
```

### 2. Development Server

```bash
npm run dev
```

By default, Vite runs at `http://localhost:5173`.

### 3. API Proxy & Base URL Configuration

- **Development Proxy:** The Vite dev server automatically proxies `/api`, `/health`, and `/ready` requests to the local FastAPI backend running at `http://127.0.0.1:8000`.
- **API Base URL Override:** The environment variable `VITE_API_BASE_URL` can optionally be set to override the target API root. When unset, requests default to same-origin / proxy paths.

## Available Scripts

- `npm run dev`: Starts the Vite development server with Hot Module Replacement (HMR).
- `npm run build`: Type-checks with TypeScript compiler (`tsc -b`) and produces a static production bundle in `dist/`.
- `npm run test`: Runs the Vitest test suite in interactive watch mode.
- `npm run test:run`: Runs the Vitest test suite once with `@testing-library/react` and `jsdom`.
- `npm run lint`: Runs `oxlint` for fast static code analysis.

## Architecture

- **`src/api/`**: Typed native-fetch API client matching FastAPI Pydantic response models with explicit nullability.
- **`src/components/graph/`**: Cytoscape.js canvas integration with hierarchical, force-directed, and concentric layout algorithms.
- **`src/components/layout/`**: Header with live backend health/readiness pills and contextual slide drawers.
- **`src/pages/`**: Single-page application views:
  - `OverviewPage`: Global volume metrics, metric completeness mode, and endpoint rankings.
  - `NetworkExplorerPage`: Center-rooted neighborhood graph, parallel flow rendering, and inspection drawers.
  - `AlertExplorerPage`: Normalized security alert facts table and detail modal.
  - `CorrelationsPage`: Traffic/alert co-occurrence analysis with flow keys and ports.
  - `PathFinderPage`: Observed directional communication hop chain visualizer.
  - `ImportDataPage`: Browser data import, dual-file validation, and workspace replacement.
