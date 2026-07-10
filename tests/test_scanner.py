from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from workflow_warden.scanner import format_text, scan_path


FIXTURES = Path(__file__).parent / "fixtures"


class ScannerTests(unittest.TestCase):
    def test_insecure_fixture_reports_multiple_findings(self) -> None:
        findings = scan_path(FIXTURES / "insecure.yml")
        rule_ids = {item.rule_id for item in findings}
        self.assertTrue({"WW001", "WW002", "WW003", "WW004", "WW005"}.issubset(rule_ids))
        self.assertIn("pull_request_target", format_text(findings))

    def test_secure_fixture_is_clean(self) -> None:
        findings = scan_path(FIXTURES / "secure.yml")
        self.assertEqual([], findings)

    def test_repository_root_discovers_workflows_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text((FIXTURES / "secure.yml").read_text(encoding="utf-8"), encoding="utf-8")
            findings = scan_path(root)
            self.assertEqual([], findings)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
