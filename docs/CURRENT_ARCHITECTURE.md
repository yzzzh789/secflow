# Current Architecture

This file is the current source of truth for repository boundaries.

For a shorter directory-level index, see `docs/source-map.md`.

It describes what is mainline, what is legacy, what is runtime data, and which interfaces are frozen during the current cleanup phase.

## 1. Mainline Product

The current mainline product is the Go service under `cmd/secflow/` plus static pages plus Python analysis modules.

Primary entrypoint:

- `go run ./cmd/secflow`

Compatibility entrypoint retained during cleanup:

- `go run .`

Default address:

- `http://localhost:9090`

### Go mainline

- `cmd/secflow/main.go`
  - main Go entrypoint
- `main.go`
  - compatibility shim for the previous root startup command
- `internal/app/`
  - current composition root, route registration, handlers, runtime control, storage, and website security service

### Frontend mainline

- `static/`
  - current user-facing pages

Mainline user paths currently include:

- `static/index.html`
- `static/analyzer.html`
- `static/report.html`
- `static/lan_monitor.html`
- `static/nic_traffic.html`
- `static/traffic_monitor.html`
- `static/website_security.html`
- `static/settings.html`

Note:

- `static/nic_traffic.html` and `static/traffic_monitor.html` both still exist.
- They currently overlap and both talk to the same NIC runtime APIs.
- During this phase, keep both paths stable.
- `static/nic_traffic.html` is the recommended mainline entry for NIC monitoring.
- `static/traffic_monitor.html` is kept as a compatibility entry and should not receive new product-first navigation links.

### Python mainline

- `packet_analyzer/improved_packet_analyzer.py`
  - threat capture and packet analysis
- `scripts/traffic_analyzer.py`
  - behavior analysis
- `scripts/lan_behavior_monitor.py`
  - LAN behavior monitoring
- `scripts/nic_runtime.py`
  - mainline NIC monitor runtime entrypoint used by the Go service
- `traffic_monitor/nic_monitor_server_enhanced.py`
  - compatibility implementation module for the NIC runtime during cleanup
- `nic_monitor/`
  - shared NIC collection, state, storage, and utilities

## 2. Mixed Legacy Area

`traffic_monitor/` is now a reduced compatibility boundary.

It is not the main product root, and it is not safe to delete wholesale yet because root call-sites still point into it.

Current status inside `traffic_monitor/`:

- compatibility dependency:
  - `nic_monitor_server_enhanced.py`
  - `list_nics.py`

Current mainline shim:

- `scripts/nic_runtime.py`
  - imports and runs `traffic_monitor/nic_monitor_server_enhanced.py`
  - keeps the old path executable while moving Go defaults to a mainline script path

Existing files inside this boundary:

  - `nic_monitor_server_enhanced.py`
  - `list_nics.py`
- boundary docs:
  - `README_LEGACY_BOUNDARY.md`
  - `FILE_STATUS.md`
  - `MIGRATION_PLAN.md`

Archived legacy material:

- `legacy/traffic_monitor/`
  - older Go standalone sources
  - older Python variants
  - historical HTML entry files
  - legacy module files and recovery copies

Operational rule:

- do not move `traffic_monitor/nic_monitor_server_enhanced.py` during the current cleanup phase
- do not move `traffic_monitor/list_nics.py` until its root call-site is redirected

## 3. Runtime Data

Treat these as runtime artifacts, not as architecture anchors:

- `data/*.sqlite`
- `data/*.sqlite-shm`
- `data/*.sqlite-wal`
- `data/website_security_state.json`
- `__pycache__/`
- `*.exe`
- `.gocache/`
- local browser profiles
- local caches, dumps, and temp files

`data/` is part of runtime state, not part of the source layout.

## 4. Storage Boundaries

The current product does not use one single storage backend.

Current storage split:

- root service data:
  - SQLite
- NIC history:
  - separate SQLite database
- website security state:
  - JSON file

This split remains in place during the current phase.

## 5. Frozen Interfaces For This Phase

Do not change these in the current cleanup phase:

- existing HTTP paths
- existing WebSocket paths
- Python CLI flags used by the Go service
- stdout and stdin protocol for `traffic_monitor/nic_monitor_server_enhanced.py`
- current SQLite table shapes
- current JSON state file shape for website security
- static page paths under `static/`

## 6. Near-Term Cleanup Direction

The intended low-risk order is:

1. clarify boundaries
2. centralize paths and config
3. separate store concerns
4. separate runtime concerns
5. group handlers by feature
6. extract shared Python logic
7. shrink the mixed legacy area
8. only then move to `cmd/` and `internal/`
