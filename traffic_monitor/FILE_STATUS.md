# traffic_monitor File Status

Updated: 2026-04-26

This file is the working inventory for the reduced `traffic_monitor/` boundary.
Statuses are assigned from current call-sites, not from filename age alone.

## Active: current mainline dependency

- `nic_monitor_server_enhanced.py`
  - Called by root service via `NICMonitorScript` in `main.go`.
  - Must keep current stdin/stdout command protocol stable until an adapter replaces it.
- `list_nics.py`
  - Called by root service handlers for NIC enumeration fallback.
  - Must keep current CLI behavior stable until the handler path is redirected.

## Active boundary docs

- `README_LEGACY_BOUNDARY.md`
  - Boundary contract for the mixed legacy area.

- `FILE_STATUS.md`
  - Current source-of-truth inventory.

- `MIGRATION_PLAN.md`
  - Current execution plan.

## Archived to `legacy/traffic_monitor/`

- `go.mod`
- `go.sum`
- `traffic_monitor_server_multi.go`
- `multi_nic_monitor.html`
- `simple_traffic_monitor.py`
- `find_active_nic.py`
- `check_system.py`
- `nic_monitor_server.py`
- `traffic_monitor_server.go.bak`

Operational meaning:

- They are no longer part of the active root runtime path.
- They remain in-repo only as archived legacy source under an explicit archive root.

## Runtime artifacts: never treat as source

- `.gocache_traffic/`
- `__chrome_profile/`
- `__edge_profile/`
- `__pycache__/`

These stay ignored and should be deleted opportunistically, not migrated.

## Immediate migration implications

1. Do not move `nic_monitor_server_enhanced.py` yet.
2. Do not move `list_nics.py` yet.
3. Any future standalone packaging must source from `legacy/traffic_monitor/`, not from this boundary directory.
4. The next cleanup target is removing root call-site knowledge of `traffic_monitor/` through an adapter.
