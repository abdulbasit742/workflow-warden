from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .scanner import SEVERITY_ORDER, format_text, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan GitHub Actions workflows for security risks.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a repository or workflow directory")
    scan_parser.add_argument("path", nargs="?", default=".", help="Repository root, workflow directory, or workflow file")
    scan_parser.add_argument("--format", choices=("text", "json"), default="text", dest="output_format")
    scan_parser.add_argument(
        "--minimum-severity",
        choices=tuple(SEVERITY_ORDER.keys()),
        default="low",
        help="Only show findings at or above this severity",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER.keys()),
        help="Exit non-zero when a finding at or above this severity is present",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.error("Unsupported command")

    findings = scan_path(args.path, minimum_severity=args.minimum_severity)

    if args.output_format == "json":
        print(json.dumps([asdict(item) for item in findings], indent=2))
    else:
        print(format_text(findings))

    if args.fail_on and any(SEVERITY_ORDER[item.severity] >= SEVERITY_ORDER[args.fail_on] for item in findings):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
