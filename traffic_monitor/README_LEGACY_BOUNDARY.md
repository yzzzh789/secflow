# traffic_monitor Legacy Boundary

This directory is now a reduced compatibility boundary. Do not delete it directly.

## Active dependency in current mainline

- `nic_monitor_server_enhanced.py`
  - Still called by root service (`main.go`) as the NIC monitoring script.
- `list_nics.py`
  - Still called by root service handlers for NIC discovery fallback.

## Legacy material moved out of this directory

- Archived legacy standalone files now live under `legacy/traffic_monitor/`.
- This includes old Go/Python server variants and historical HTML entry files.
- Runtime artifacts may still appear locally under this directory if generated during development.

## Current rules

1. Keep backward compatibility for `nic_monitor_server_enhanced.py`.
2. Keep backward compatibility for `list_nics.py` until its root call-site is replaced.
3. Do not move file paths referenced by root service during this phase.
4. Runtime artifacts must remain ignored by `.gitignore`.
5. Any cleanup should be additive first (docs, markers, adapters), then destructive.
6. `start_monitor.bat` is a legacy launcher only and is not the mainline startup path.

## Status entry points

- `FILE_STATUS.md`
  - Canonical `active` / `compat` / `deprecated` inventory for this directory.
- `MIGRATION_PLAN.md`
  - Executable phase plan for shrinking this mixed legacy boundary safely.

## Suggested next migration steps

1. Create a small adapter layer for NIC monitor invocation in root service.
2. Move `list_nics.py` behind the same adapter or into a non-legacy active runtime path.
3. Remove stale binaries/caches only after CI and runtime path checks pass.
4. Delete or archive the remaining compatibility boundary only after active call-sites are gone.
