# Contributing

Thanks for improving Workflow Warden.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
export PYTHONPATH=src
python -m unittest discover -s tests -v
python -m workflow_warden scan tests/fixtures --minimum-severity low
```

## Development rules

- keep runtime dependencies at zero unless a change is clearly worth the supply-chain cost
- add or update tests for every rule change
- prefer deterministic scanners over network-dependent checks
- preserve least-privilege GitHub Actions permissions
- document security-relevant decisions in `docs/security-audit.md`

## Pull requests

Please include:

- problem statement
- validation evidence
- security impact
- follow-up risks or limitations
