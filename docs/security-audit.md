# Security Audit Log

## Fri Jul 10, 2026 — SARIF export + code scanning integration

- **Scope:** `src/workflow_warden/__init__.py`, `src/workflow_warden/__main__.py`, `src/workflow_warden/cli.py`, `src/workflow_warden/scanner.py`, `src/workflow_warden/sarif.py`, `tests/test_cli.py`, `tests/test_scanner.py`, `tests/test_sarif.py`, `README.md`, `docs/SKILL_REGISTRY.md`, `.github/workflows/ci.yml`, `.github/workflows/security.yml`
- **Manual changed-area review:** no credentials, tokens, `.env` files, private keys, generated artifacts, or unsafe logging were introduced.
- **Native secret scanning:** not available for this repository because GitHub Advanced Security is not enabled, so changed content was reviewed manually instead of with repository-native secret scanning.
- **Dependency posture:** runtime dependency count remains zero; validation continues to use stdlib `unittest` only.
- **Workflow review:** CI and security workflows keep explicit `contents: read`; SARIF upload is narrowly scoped to `security-events: write` and uses GitHub-owned actions only.
- **Verified findings in changed area:** critical 0, high 0, medium 0.
- **Remediation shipped:** added SARIF serialization with stable fingerprints, CLI support for SARIF file output, regression tests, and a security workflow that uploads Workflow Warden findings into GitHub code scanning.
- **Residual risk:** the scanner still uses heuristic text analysis, so YAML edge cases and deeper reusable-workflow chains remain a medium-priority follow-up rather than a resolved capability.
