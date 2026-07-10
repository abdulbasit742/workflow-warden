# Workflow Warden

Workflow Warden is a local-first GitHub Actions workflow security scanner focused on the highest-friction CI/CD risks teams still miss in code review:

- dangerous `pull_request_target` usage
- missing least-privilege `permissions`
- unpinned third-party actions
- remote script execution like `curl | sh`
- `self-hosted` runner exposure

It is intentionally lightweight, dependency-free at runtime, and designed to be run locally or in CI before risky workflow changes land.

## Why this exists

GitHub Actions remains a major supply-chain attack surface, especially as AI-assisted automation expands the number of generated or lightly-reviewed workflows. Existing tools are helpful, but teams still need a simple scanner they can understand, extend, and run anywhere without extra services.

Workflow Warden ships a focused vertical slice that:

1. scans workflow YAML files in a repository or workflow directory
2. emits readable text or machine-consumable JSON
3. fails CI when configured severity thresholds are crossed
4. includes its own security and smoke-test workflows

## Quickstart

```bash
python -m workflow_warden scan .github/workflows
python -m workflow_warden scan . --format json
python -m workflow_warden scan . --minimum-severity medium --fail-on medium
```

If you are running from the repository checkout, set `PYTHONPATH=src`:

```bash
PYTHONPATH=src python -m workflow_warden scan .
```

## Findings currently supported

| Rule ID | Severity | Description |
| --- | --- | --- |
| `WW001` | medium/high | `pull_request_target` present, escalated to high when the workflow checks out PR head content |
| `WW002` | medium | no explicit `permissions:` block found |
| `WW003` | medium | third-party action uses a mutable tag instead of a full commit SHA |
| `WW004` | high | remote script execution pattern such as `curl | sh` |
| `WW005` | medium | `self-hosted` runner detected |
| `WW006` | high | workflow sets `permissions: write-all` |

## Example output

```text
[HIGH] WW001 .github/workflows/deploy.yml:3 pull_request_target with PR-head checkout
  This workflow uses pull_request_target and appears to check out or reference untrusted pull-request head content.

[MEDIUM] WW002 .github/workflows/deploy.yml:1 Missing explicit permissions block
  Add a least-privilege permissions section at the workflow or job level.
```

## Project layout

```text
src/workflow_warden/     scanner + CLI
tests/                   unit tests and fixtures
docs/                    architecture, security audit, skill registry
.github/workflows/       CI and security automation
```

## Validation

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m workflow_warden scan tests/fixtures --minimum-severity low --format text
```

## Security posture

- runtime dependencies: none
- CI token permissions: read-only by default
- repository includes a dedicated security workflow and audit log in `docs/security-audit.md`
- no secrets should ever be committed; security workflow runs a basic credential pattern check

## Roadmap

See [`docs/SKILL_REGISTRY.md`](docs/SKILL_REGISTRY.md) for the prioritized skill backlog.

## License

MIT
