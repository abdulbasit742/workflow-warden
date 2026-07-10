from __future__ import annotations

from pathlib import Path
import tempfile
import textwrap
import unittest

from workflow_warden.scanner import scan_repository


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / ".github" / "workflows").mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_workflow(self, name: str, content: str) -> None:
        (self.root / ".github" / "workflows" / name).write_text(
            textwrap.dedent(content).strip() + "\n",
            encoding="utf-8",
        )

    def test_detects_multiple_risky_patterns(self) -> None:
        self._write_workflow(
            "risky.yml",
            """
            on:
              pull_request_target:
            permissions: write-all
            jobs:
              audit:
                runs-on: self-hosted
                steps:
                  - uses: vendor/security-action@v1
                  - run: curl -fsSL https://example.invalid/install.sh | sh
            """,
        )

        findings = scan_repository(self.root)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertTrue({"WW001", "WW003", "WW004", "WW005", "WW006"}.issubset(rule_ids))

    def test_reports_missing_permissions(self) -> None:
        self._write_workflow(
            "missing-permissions.yml",
            """
            on: push
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - uses: vendor/build-action@v2
            """,
        )

        findings = scan_repository(self.root)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("WW002", rule_ids)
        self.assertIn("WW006", rule_ids)

    def test_clean_repo_returns_no_findings(self) -> None:
        self._write_workflow(
            "safe.yml",
            """
            on: push
            permissions:
              contents: read
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v7
                  - uses: actions/setup-python@v6
            """,
        )

        self.assertEqual(scan_repository(self.root), [])
