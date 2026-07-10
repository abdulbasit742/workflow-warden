from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from workflow_warden.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


class CliTests(unittest.TestCase):
    def test_json_output_is_machine_readable(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            exit_code = main(["scan", str(FIXTURES / "insecure.yml"), "--format", "json"])
        self.assertEqual(0, exit_code)
        payload = json.loads(buffer.getvalue())
        self.assertTrue(any(item["rule_id"] == "WW004" for item in payload))

    def test_fail_on_threshold_returns_non_zero(self) -> None:
        exit_code = main(["scan", str(FIXTURES / "insecure.yml"), "--fail-on", "medium"])
        self.assertEqual(1, exit_code)

    def test_clean_scan_returns_zero(self) -> None:
        exit_code = main(["scan", str(FIXTURES / "secure.yml"), "--fail-on", "medium"])
        self.assertEqual(0, exit_code)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
