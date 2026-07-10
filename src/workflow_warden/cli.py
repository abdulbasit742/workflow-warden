from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from .sarif import findings_to_sarif
from .scanner import Finding, scan_repository, serialize_findings, summarize_findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workflow-warden",
        description="Scan GitHub Actions workflows for risky patterns.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository root to scan (defaults to current directory).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--sarif-output",
        help="Optional path to also write SARIF output.",
    )
    return parser


def _render_text(findings: list[Finding], root: Path) -> str:
    if not findings:
        return f"No findings detected in {root}."

    counts = summarize_findings(findings)
    lines = [
        f"Detected {len(findings)} workflow risk(s) in {root}.",
        (
            "Severity counts: "
            f"high={counts['high']}, medium={counts['medium']}, low={counts['low']}"
        ),
    ]
    for finding in findings:
        location = f"{finding.path}:{finding.line}"
        lines.append(
            f"- [{finding.severity.upper()}] {finding.rule_id} {location} — {finding.message}"
        )
    return "\n".join(lines)


def _write_sarif_output(path: str, findings: list[Finding]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(findings_to_sarif(findings), indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(args.path)

    try:
        findings = scan_repository(root)
    except FileNotFoundError:
        print(f"Repository path does not exist: {root}", file=sys.stderr)
        return 2

    if args.sarif_output:
        _write_sarif_output(args.sarif_output, findings)

    if args.format == "json":
        print(json.dumps(serialize_findings(findings), indent=2))
    elif args.format == "sarif":
        print(json.dumps(findings_to_sarif(findings), indent=2))
    else:
        print(_render_text(findings, root))

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
