# Skill Registry

Prioritized by security first, then adoption impact.

## Ready

1. **SKILL-001 — SARIF export**
   - Add GitHub code scanning compatible output so findings can surface natively in pull requests.
   - Acceptance: `--format sarif` emits valid SARIF 2.1.0 and a fixture test validates core schema fields.

2. **SKILL-002 — Allowlist and suppression support**
   - Let teams suppress known acceptable findings by rule ID, file path, or inline annotation.
   - Acceptance: scanner loads a suppression file, excludes matching findings, and records suppressed counts.

3. **SKILL-003 — Policy packs**
   - Add opinionated profiles (`strict`, `balanced`, `legacy`) that map severities and enabled rules.
   - Acceptance: CLI supports `--policy`, and tests verify rule enablement and fail thresholds.

## Later

4. **SKILL-004 — Reusable workflow analysis**
5. **SKILL-005 — Autofix suggestions for permissions hardening**
6. **SKILL-006 — Markdown report generation for pull request comments**
