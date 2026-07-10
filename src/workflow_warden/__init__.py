"""Workflow Warden flags risky GitHub Actions patterns and exports SARIF."""

__version__ = "0.2.0"

from .sarif import findings_to_sarif
from .scanner import Finding, RULES, scan_repository, summarize_findings

__all__ = [
    "Finding",
    "RULES",
    "findings_to_sarif",
    "scan_repository",
    "summarize_findings",
    "__version__",
]
