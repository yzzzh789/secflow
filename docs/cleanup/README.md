# Cleanup Docs

This directory contains low-risk cleanup documentation for the current repository.

The purpose of this phase is repository clarification, not feature rewrites.

Current scope:

- clarify which directories are mainline
- separate runtime artifacts from source code in documentation and ignore rules
- record naming debt and duplication debt
- define frozen interfaces that should not change during cleanup

Recommended reading order:

1. `../CURRENT_ARCHITECTURE.md`
2. `DIRECTORY_ROLES.md`
3. `RUNTIME_ARTIFACTS.md`
4. `NAMING_AND_DUPLICATION_DEBT.md`
5. `FROZEN_BOUNDARIES.md`
6. `GITHUB_UPLOAD_CHECKLIST.md`

Working rules for this phase:

- additive changes first
- no business behavior changes
- no path migrations until call-sites are centralized
- no new dependencies
