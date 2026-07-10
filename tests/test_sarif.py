from __future__ import annotations

import json
import unittest

from workflow_warden.scanner import Finding
from workflow_warden.sarif import findings_to_sarif


class SarifTests(unittest.TestCase):
    def test_serializes_findings_into_sarif(self) -> None:
        findings = [
            Finding(
                rule_id="WW003",
                title="Avoid write-all workflow permissions",
                message="`permissions: write-all` grants unnecessary write access across scopes and increases blast radius.",
                severity="high",
                path=".github/workflows/release.yml",
                line=4,
                snippet="permissions: write-all",
            )
        ]

        sarif = findings_to_sarif(findings)
        encoded = json.dumps(sarif)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertIn("Workflow Warden", encoded)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "WW003")
        self.assertEqual(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            ".github/workflows/release.yml",
        )
