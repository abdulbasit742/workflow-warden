from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterable

SUPPORTED_EXTENSIONS = {".yml", ".yaml"}
TRUSTED_ACTION_OWNERS = {"actions", "github", "dependabot"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

RULES: dict[str, dict[str, object]] = {
    "WW001": {
        "title": "Avoid pull_request_target on untrusted code",
        "severity": "high",
        "message": "`pull_request_target` can expose write-capable tokens or secrets to attacker-controlled pull request content.",
        "help": "Prefer `pull_request` for untrusted contributions, or isolate privileged steps behind strict conditional guards.",
        "help_uri": "https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#pull_request_target",
        "security_severity": "8.8",
        "tags": ["github-actions", "tokens", "pull_request_target"],
    },
    "WW002": {
        "title": "Declare explicit workflow permissions",
        "severity": "medium",
        "message": "Workflow files should declare explicit `permissions` to avoid broad default token access.",
        "help": "Add a top-level or job-level `permissions` block and keep scopes at the minimum needed for the job.",
        "help_uri": "https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs",
        "security_severity": "4.8",
        "tags": ["github-actions", "least-privilege", "permissions"],
    },
    "WW003": {
        "title": "Avoid write-all workflow permissions",
        "severity": "high",
        "message": "`permissions: write-all` grants unnecessary write access across scopes and increases blast radius.",
        "help": "Replace `write-all` with the smallest set of read or write scopes the workflow actually needs.",
        "help_uri": "https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs",
        "security_severity": "8.0",
        "tags": ["github-actions", "least-privilege", "permissions"],
    },
    "WW004": {
        "title": "Review self-hosted runner trust boundaries",
        "severity": "medium",
        "message": "`self-hosted` runners can expose long-lived credentials or network access if untrusted code reaches them.",
        "help": "Reserve self-hosted runners for tightly controlled jobs and isolate them from untrusted pull request execution.",
        "help_uri": "https://docs.github.com/actions/hosting-your-own-runners/about-self-hosted-runners",
        "security_severity": "5.9",
        "tags": ["github-actions", "runners", "network-boundary"],
    },
    "WW005": {
        "title": "Avoid piping network downloads directly into shells",
        "severity": "high",
        "message": "`curl | sh` or `wget | sh` hides integrity checks and increases remote code execution risk in CI.",
        "help": "Download artifacts separately, verify integrity, and execute pinned scripts from trusted, reviewed sources.",
        "help_uri": "https://docs.github.com/actions/security-guides/security-hardening-for-github-actions",
        "security_severity": "8.1",
        "tags": ["github-actions", "supply-chain", "shell"],
    },
    "WW006": {
        "title": "Pin third-party actions to full commit SHAs",
        "severity": "medium",
        "message": "Third-party actions referenced by tags can change underneath you and create supply-chain risk.",
        "help": "Pin third-party actions to immutable full-length commit SHAs, then update them deliberately.",
        "help_uri": "https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        "security_severity": "5.0",
        "tags": ["github-actions", "supply-chain", "actions"],
    },
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    message: str
    severity: str
    path: str
    line: int
    snippet: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
        }


def iter_workflow_files(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return []
    return sorted(
        path
        for path in workflow_dir.iterdir()
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS
    )


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _build_finding(
    rule_id: str,
    root: Path,
    path: Path,
    line: int,
    snippet: str,
    *,
    extra_message: str = "",
) -> Finding:
    rule = RULES[rule_id]
    message = str(rule["message"])
    if extra_message:
        message = f"{message} {extra_message}".strip()
    return Finding(
        rule_id=rule_id,
        title=str(rule["title"]),
        message=message,
        severity=str(rule["severity"]),
        path=_relative_path(path, root),
        line=max(line, 1),
        snippet=snippet.strip(),
    )


def _extract_action_reference(line: str) -> str | None:
    match = re.search(r"uses:\s*([^\s#]+)", line)
    if not match:
        return None
    return match.group(1).strip()


def _is_unpinned_third_party_action(action_ref: str) -> bool:
    if action_ref.startswith("./") or action_ref.startswith("docker://"):
        return False
    if "@" not in action_ref:
        return False
    action_slug, ref = action_ref.split("@", 1)
    parts = action_slug.split("/")
    if len(parts) < 2:
        return False
    owner = parts[0].lower()
    if owner in TRUSTED_ACTION_OWNERS:
        return False
    return re.fullmatch(r"[a-fA-F0-9]{40}", ref) is None


def scan_workflow_file(path: Path, root: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    findings: list[Finding] = []

    if not any(re.match(r"^\s*permissions\s*:", line) for line in lines):
        findings.append(
            _build_finding(
                "WW002",
                root,
                path,
                1,
                lines[0] if lines else "",
            )
        )

    for line_number, line in enumerate(lines, start=1):
        snippet = line.strip()
        if "pull_request_target" in snippet:
            findings.append(_build_finding("WW001", root, path, line_number, snippet))
        if re.search(r"^\s*permissions\s*:\s*write-all\b", line):
            findings.append(_build_finding("WW003", root, path, line_number, snippet))
        if "self-hosted" in snippet:
            findings.append(_build_finding("WW004", root, path, line_number, snippet))
        if ("curl" in snippet or "wget" in snippet) and re.search(
            r"\|\s*(?:sh|bash|zsh)\b", snippet
        ):
            findings.append(_build_finding("WW005", root, path, line_number, snippet))
        action_ref = _extract_action_reference(line)
        if action_ref and _is_unpinned_third_party_action(action_ref):
            findings.append(
                _build_finding(
                    "WW006",
                    root,
                    path,
                    line_number,
                    snippet,
                    extra_message=f"Found `{action_ref}`.",
                )
            )

    return findings


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 99),
            finding.path,
            finding.line,
            finding.rule_id,
        ),
    )


def serialize_findings(findings: Iterable[Finding]) -> list[dict[str, object]]:
    return [finding.to_dict() for finding in sort_findings(findings)]


def summarize_findings(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def scan_repository(root: str | Path) -> list[Finding]:
    repository_root = Path(root)
    if not repository_root.exists():
        raise FileNotFoundError(str(repository_root))

    findings: list[Finding] = []
    for workflow_file in iter_workflow_files(repository_root):
        findings.extend(scan_workflow_file(workflow_file, repository_root))
    return sort_findings(findings)
