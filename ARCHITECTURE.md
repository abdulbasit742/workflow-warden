# Architecture

Workflow Warden is intentionally small and local-first.

## Design goals

- zero runtime dependencies
- deterministic offline scanning
- human-readable findings with line numbers and evidence
- CI-friendly exit behavior
- extensible rule engine without framework lock-in

## Components

### `scanner.py`

Core rule engine that:

1. discovers workflow files
2. loads text safely
3. applies regex- and heuristic-based rules
4. returns normalized `Finding` objects

### `cli.py`

Thin argparse wrapper that:

- accepts scan targets
- filters by minimum severity
- emits text or JSON
- exits non-zero only when configured via `--fail-on`

### `tests/`

Fixture-driven unit tests cover:

- insecure workflow detection
- clean workflow behavior
- CLI output and exit codes

## Security trade-offs

This first slice deliberately avoids YAML execution or external parsers to reduce supply-chain footprint. That means parsing is heuristic rather than fully semantic. The roadmap includes SARIF export, suppressions, and richer structural analysis once the baseline UX is proven.
