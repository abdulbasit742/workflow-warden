from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Iterable

from . import __version__
from .scanner import Finding, RULES, sort_findings

LEVEL_BY_SEVERITY = {"high": "error", "medium": "warning", "low": "note"}


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _fingerprint(finding: Finding) -> str:
    payload = f"{finding.rule_id}|{finding.path}|{finding.line}|{finding.message}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rule_descriptors() -> list[dict[str, object]]:
    descriptors: list[dict[str, object]] = []
    for rule_id, metadata in sorted(RULES.items()):
        descriptors.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": str(metadata["title"])},
                "fullDescription": {"text": str(metadata["message"])},
                "help": {"text": str(metadata["help"])},
                "helpUri": str(metadata["help_uri"]),
                "defaultConfiguration": {
                    "level": LEVEL_BY_SEVERITY[str(metadata["severity"])]
                },
                "properties": {
                    "tags": list(metadata["tags"]),
                    "precision": "high",
                    "security-severity": str(metadata["security_severity"]),
                },
            }
        )
    return descriptors


def findings_to_sarif(findings: Iterable[Finding]) -> dict[str, object]:
    ordered_findings = sort_findings(findings)
    descriptors = _rule_descriptors()
    rule_index = {
        descriptor["id"]: position for position, descriptor in enumerate(descriptors)
    }

    results: list[dict[str, object]] = []
    for finding in ordered_findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": LEVEL_BY_SEVERITY[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {
                                "startLine": max(finding.line, 1),
                                "snippet": {"text": finding.snippet},
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": _fingerprint(finding)
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Workflow Warden",
                        "version": __version__,
                        "informationUri": "https://github.com/abdulbasit742/workflow-warden",
                        "rules": descriptors,
                    }
                },
                "automationDetails": {"id": "workflow-warden/default"},
                "columnKind": "utf16CodeUnits",
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": _utc_now(),
                    }
                ],
                "results": results,
            }
        ],
    }
