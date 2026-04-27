# GitHub Upload Checklist

Use this checklist before publishing or packaging the repository. The goal is to publish source code and documentation, not local runtime state.

## Source Files To Keep

- `cmd/secflow/`
- root `main.go` compatibility shim
- `internal/app/`
- `static/`
- `packet_analyzer/`
- `python/secflow_common/`
- `scripts/`
- `nic_monitor/`
- `traffic_monitor/`
  - keep during this phase because compatibility entrypoints still exist
- `docs/`
- `go.mod`
- `go.sum`
- `requirements-nic-monitor.txt`
- `.gitignore`
- `.env.example`

## Runtime Artifacts To Exclude

- `.runtime/`
- `.gocache/`
- `.gotmp/`
- `data/*.sqlite`
- `data/*.sqlite-shm`
- `data/*.sqlite-wal`
- `data/website_security_state.json`
- any `__pycache__/`
- any `*.pyc`
- any `*.exe`
- `traffic_monitor/__chrome_profile/`
- `traffic_monitor/__edge_profile/`
- `traffic_monitor/.gocache_traffic/`
- `*.dmp`
- `*.pma`

## Required Check

Run this from the repository root before publishing:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\release_check.ps1
```

The check fails if local runtime artifacts are still present in the working tree. Clean or exclude those files before upload.

## Current Boundary Notes

- `scripts/nic_runtime.py` is the mainline NIC runtime entrypoint used by the Go service.
- `traffic_monitor/nic_monitor_server_enhanced.py` remains executable as a compatibility implementation module.
- Do not delete `traffic_monitor/` wholesale until all call-sites and rollback paths are verified.
