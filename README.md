## Workflow Warden

Workflow Warden is a local-first GitHub Actions security scanner for teams that want fast feedback before risky workflow changes land. It looks for high-signal CI/CD hazards and now exports SARIF so findings can flow into GitHub code scanning.

### What it catches

- `pull_request_target` usage on untrusted pull request paths
- Missing explicit `permissions` blocks
- `permissions: write-all`
- `self-hosted` runner exposure in workflow jobs
- `curl | sh` / `wget | sh` execution patterns
- Third-party actions pinned to mutable tags instead of full commit SHAs

### Why this slice matters

The strongest next improvement for Workflow Warden was turning its terminal output into a format GitHub can ingest directly. SARIF output makes the scanner easier to adopt in pull requests, branch protection, and recurring audit workflows without adding runtime dependencies.

### Quickstart

```bash
python -m pip install -e .
python -m workflow_warden .
```

Generate SARIF for local review or GitHub upload:

```bash
python -m workflow_warden . --format sarif --sarif-output workflow-warden.sarif
```

Emit JSON for custom automation:

```bash
python -m workflow_warden . --format json
```

### Example GitHub Actions integration

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - uses: actions/setup-python@v6
    with:
      python-version: "3.11"
  - run: |
      python -m pip install --upgrade pip
      pip install -e .
  - run: python -m workflow_warden . --format sarif --sarif-output workflow-warden.sarif
  - uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: workflow-warden.sarif
```

### Development

```bash
python -m unittest discover -s tests -p "test_*.py"
```

### Repository standards

- Zero runtime dependencies
- Least-privilege CI workflows
- Security audit log in `docs/security-audit.md`
- Skill registry in `docs/SKILL_REGISTRY.md`

### Roadmap

1. Add allowlist and suppression controls for known-safe exceptions.
2. Expand structural parsing for reusable workflows and composite actions.
3. Add remediation guidance and optional autofix hints for common findings.
