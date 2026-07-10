# Allowlist and Suppression Contract

This document defines the proposed contract for `SKILL-002`: allowlist and suppression support for Workflow Warden findings.

The goal is to reduce adoption friction without hiding real risk. Suppressions must be explicit, reviewable, and time-bounded.

## Design goals

- Keep suppressions **local, auditable, and deterministic**.
- Require a human-readable justification for every suppression.
- Make expiry easy so temporary exceptions do not become permanent blind spots.
- Prefer exact matching over broad patterns in the first implementation.
- Keep the format compatible with SARIF workflow follow-up and future PR annotations.

## Proposed file location

Workflow Warden should look for a repository-local JSON document at one of these locations:

1. `.workflow-warden-allowlist.json`
2. `config/workflow-warden-allowlist.json`

If both exist, the root file should win so local overrides remain explicit.

## Proposed JSON shape

```json
{
  "version": 1,
  "suppressions": [
    {
      "rule_id": "untrusted-pull-request-target",
      "path": ".github/workflows/release.yml",
      "justification": "Workflow runs with read-only permissions and never checks out fork code.",
      "expires_on": "2026-12-31"
    }
  ]
}
```

## Field contract

### Root object

- `version` — required integer. Start with `1`.
- `suppressions` — required array of suppression entries.

### Suppression entry

- `rule_id` — required string. Must match the emitted Workflow Warden rule identifier exactly.
- `path` — required string. Repository-relative workflow file path.
- `justification` — required string with reviewer-facing rationale.
- `expires_on` — optional `YYYY-MM-DD` string. Recommended for any non-permanent exception.

## Matching semantics for the first implementation

The first implementation should keep matching intentionally narrow:

- Exact `rule_id` match.
- Exact `path` match.
- No globbing.
- No regex.
- No blanket suppressions for whole rule families.

This keeps behavior predictable and easier to audit.

## Safety rules

Suppressions should be rejected when:

- `justification` is empty.
- `rule_id` is missing.
- `path` is missing.
- `expires_on` is malformed.
- Duplicate `rule_id` + `path` entries exist.

The CLI should surface malformed allowlists as a configuration error instead of silently ignoring them.

## Review guidance

- Review suppressions in code review like application code.
- Prefer short expiry windows for riskier workflows.
- Remove suppressions as soon as the underlying workflow is hardened.
- Treat suppressions for `pull_request_target`, `write-all`, unpinned third-party actions, and `self-hosted` runners as high-scrutiny entries.

## Suggested CLI behavior for the upcoming implementation

- Load the allowlist before rendering terminal or SARIF output.
- Mark suppressed findings separately from active findings.
- Expose a switch to show suppressed findings for audit mode.
- Emit a warning for expired suppressions.
- Preserve unsuppressed findings exit-code behavior.

## Why this matters

SARIF support made Workflow Warden easier to wire into CI and code scanning. The next adoption blocker is false-positive management. A narrow, well-documented suppression contract helps teams adopt the scanner without normalizing invisible risk.
