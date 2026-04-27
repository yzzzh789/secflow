# traffic_monitor Migration Plan

Updated: 2026-04-26

Goal: reduce `traffic_monitor/` from a mixed legacy area into explicit, auditable boundaries without breaking:

- root NIC monitor runtime in `main.go`
- any current file paths relied on by operators

Note:

- The old root-side standalone export endpoint for `traffic_monitor/` was removed on 2026-04-13.
- Historical deployment files under `traffic_monitor/` have been removed from the repository.
- Any remaining standalone packaging work should be treated as legacy-only, not current product surface.

## Phase 0: freeze and document

Status: completed

Actions:

1. Keep `main.go -> traffic_monitor/nic_monitor_server_enhanced.py` unchanged.
2. Maintain runtime artifact ignores in `.gitignore`.
3. Maintain `README_LEGACY_BOUNDARY.md`, `FILE_STATUS.md`, and this plan.

Exit criteria:

- Everyone can identify which files are active, compat, deprecated.

## Phase 1: archive non-mainline legacy files

Status: completed

Actions completed:

1. Moved non-mainline legacy Go/Python/HTML files from `traffic_monitor/` to `legacy/traffic_monitor/`.
2. Kept `traffic_monitor/nic_monitor_server_enhanced.py` unchanged.
3. Kept `traffic_monitor/list_nics.py` unchanged because it still has an active root call-site.
4. Updated boundary inventory docs to reflect the reduced active surface.

Exit criteria:

- `traffic_monitor/` now contains only active compatibility files plus boundary docs.
- Archived standalone legacy source no longer sits next to active runtime files.

Rollback:

- Move archived files back to `traffic_monitor/` if an undocumented dependency appears.

## Phase 2: add an adapter boundary for root NIC monitor calls

Status: next

Actions:

1. Introduce a root-side adapter layer for NIC monitor invocation.
   - Suggested target: a dedicated Go file such as `nic_monitor_runtime.go`.
   - Responsibility: own script path resolution, process startup contract, and protocol framing.
2. Replace direct script-path knowledge in business handlers with adapter calls.
3. Add a small protocol smoke test against `nic_monitor_server_enhanced.py`.

Exit criteria:

- Root service no longer spreads `traffic_monitor/` path knowledge across unrelated code.
- One adapter owns the compatibility contract.

Rollback:

- Repoint adapter to the current script path and keep the existing protocol.

## Phase 3: decide standalone bundle ownership

Status: planned

Actions:

1. If standalone distribution is still needed, define an explicit supported source root.
2. Use `legacy/traffic_monitor/` only as archive input, not as an implicit active package root.
3. If standalone export is ever restored, wire it from the new source root instead of `traffic_monitor/`.
4. Validate the exported zip contents against the intended standalone bundle contract.

Exit criteria:

- Any future standalone export no longer depends on the mixed legacy directory as its source root.

Rollback:

- Reintroduce a dedicated export handler only if standalone distribution becomes a supported feature again.

## Phase 4: archive compat files

Status: planned

Actions:

1. Diff `nic_monitor_server.py` against `nic_monitor_server_enhanced.py` and record the remaining behavior delta.
2. If no live workflow still needs it, keep `nic_monitor_server.py` archived under `legacy/traffic_monitor/`.
3. Keep a short archival note with the reason and removal date.

Exit criteria:

- Compat files are either archived with rationale or promoted back to active with a documented reason.

Rollback:

- Move archived files back to their original path if a missed dependency appears.

## Phase 5: delete deprecated files

Status: planned

Actions:

1. Remove `legacy/traffic_monitor/traffic_monitor_server.go.bak` after a manual recovery audit.
2. Remove `traffic_monitor.exe` after confirming release workflows build binaries instead of storing them in-tree.
3. Clean local runtime artifacts opportunistically.

Exit criteria:

- Deprecated files are gone from source control.
- No in-tree generated binary remains in `traffic_monitor/`.

Rollback:

- Recover deleted files from version control history if an undocumented workflow appears.

## Phase 6: close the mixed legacy boundary

Status: planned

Actions:

1. Re-run file inventory.
2. Reclassify any remaining files as either active product source or archive-only.
3. Rename or relocate `traffic_monitor/` only after both active paths have moved away.

Exit criteria:

- `traffic_monitor/` is no longer a mixed-purpose directory.

## First executable task queue

These are the next concrete tasks that can be implemented immediately:

1. Add the root NIC monitor adapter and route all root-side process control through it.
2. Move `list_nics.py` behind the same adapter or out of `traffic_monitor/`.
3. Record protocol differences between `legacy/traffic_monitor/nic_monitor_server.py` and `traffic_monitor/nic_monitor_server_enhanced.py`.
4. Remove archived recovery-only files after adapter and workflow audit pass.
