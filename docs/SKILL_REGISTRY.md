# Skill Registry

| ID | Title | Priority | Status | Notes |
| --- | --- | --- | --- | --- |
| SKILL-001 | SARIF export + GitHub code scanning integration | High | Done | Added `--format sarif`, `--sarif-output`, SARIF rule metadata, regression tests, and a least-privilege upload workflow. |
| SKILL-002 | Allowlist and suppressions | High | Ready | Add per-rule and per-path suppressions so teams can adopt the scanner without muting real risk. |
| SKILL-003 | Reusable workflow and composite action coverage | Medium | Ready | Expand detection beyond flat workflow files into `workflow_call` chains and local composite actions. |
| SKILL-004 | Remediation guidance and optional autofix hints | Medium | Backlog | Add prescriptive fix snippets for common findings while keeping dry-run defaults. |

**Next recommended move:** SKILL-002. It reduces adoption friction without weakening the current high-signal rule set.
