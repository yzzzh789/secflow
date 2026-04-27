# Source Map

This file is the quick repository map for the current cleanup phase.

Use it together with `docs/CURRENT_ARCHITECTURE.md` when deciding whether a file is mainline code, compatibility code, legacy material, or runtime output.

## Mainline Source

These paths are the current product baseline and should receive product-first changes:

- `cmd/secflow/`
- `internal/app/`
- `static/`
- `packet_analyzer/improved_packet_analyzer.py`
- `scripts/traffic_analyzer.py`
- `scripts/lan_behavior_monitor.py`
- `python/secflow_common/`
- `nic_monitor/`

## Compatibility Boundary

These paths are still active but are retained mainly for compatibility or transition reasons:

- `main.go`
- `static/traffic_monitor.html`
- `static/traffic_monitor.js`
- `traffic_monitor/nic_monitor_server_enhanced.py`
- `traffic_monitor/list_nics.py`

Operational rule:

- keep paths stable until call-sites and runtime contracts are centralized
- prefer moving shared helpers or adapters before moving these files

## Legacy Area

These paths are not the main product and should be treated as archived or migration-only material:

- `legacy/`
- `legacy/traffic_monitor/`
- `traffic_monitor/README_LEGACY_BOUNDARY.md`
- `traffic_monitor/FILE_STATUS.md`
- `traffic_monitor/MIGRATION_PLAN.md`

## Runtime Artifacts

These are generated, local, or deployment outputs and should not be treated as source layout anchors:

- `data/`
- `.runtime/`
- `__pycache__/`
- `*.pyc`
- `*.sqlite`
- `*.sqlite-shm`
- `*.sqlite-wal`
- `*.exe`

## Practical Rules

- Add new backend logic under `internal/app/` unless it is shared Python logic.
- Add shared Python parsing, formatting, or classification logic under `python/secflow_common/`.
- Do not add new product features under `legacy/`.
- Do not expand `traffic_monitor/` with fresh product-first logic; only keep compatibility runtime pieces there until migration is complete.
