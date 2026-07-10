from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


class CLITests(unittest.TestCase):
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

    def test_sarif_output_file_is_written(self) -> None:
        self._write_workflow(
            "risky.yml",
            """
            on:
              pull_request_target:
            permissions: write-all
            jobs:
              audit:
                runs-on: ubuntu-latest
                steps:
                  - uses: vendor/security-action@v1
            """,
        )
        sarif_output = self.root / "artifacts" / "workflow-warden.sarif"

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "workflow_warden",
                str(self.root),
                "--format",
                "sarif",
                "--sarif-output",
                str(sarif_output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertTrue(sarif_output.exists())
        stdout = json.loads(completed.stdout)
        written = json.loads(sarif_output.read_text(encoding="utf-8"))
        self.assertEqual(stdout["version"], "2.1.0")
        self.assertEqual(written["runs"][0]["results"][0]["ruleId"], "WW001")

    def test_clean_repo_returns_zero(self) -> None:
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

        completed = subprocess.run(
            [sys.executable, "-m", "workflow_warden", str(self.root)],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertIn("No findings detected", completed.stdout)
