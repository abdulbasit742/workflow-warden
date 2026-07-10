from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
RUNS_ON_RE = re.compile(r"^\s*runs-on:\s*(.+)")
REMOTE_EXEC_RE = re.compile(r"(curl|wget)[^\n|>]*\|\s*(sh|bash)\b|bash\s*<\(\s*curl", re.IGNORECASE)
PULL_REQUEST_TARGET_RE = re.compile(r"^\s*-?\s*pull_request_target\s*:?")
PERMISSIONS_RE = re.compile(r"^\s*permissions\s*:\s*(.*)$")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    title: str
    message: str
    evidence: str


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minimum]


def discover_workflow_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix in WORKFLOW_SUFFIXES else []

    workflow_dir = target / ".github" / "workflows"
    search_root = workflow_dir if workflow_dir.exists() else target
    return sorted(path for path in search_root.rglob("*") if path.suffix in WORKFLOW_SUFFIXES and path.is_file())


def _line_number(lines: list[str], needle: str) -> int:
    for index, line in enumerate(lines, start=1):
        if needle in line:
            return index
    return 1


def scan_file(path: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    findings: list[Finding] = []

    permissions_matches = [(idx + 1, match.group(1).strip()) for idx, line in enumerate(lines) if (match := PERMISSIONS_RE.match(line))]
    if not permissions_matches:
        findings.append(
            Finding(
                rule_id="WW002",
                severity="medium",
                path=str(path),
                line=1,
                title="Missing explicit permissions block",
                message="Add a least-privilege permissions section at the workflow or job level.",
                evidence="No 'permissions:' stanza found.",
            )
        )
    else:
        for line_number, value in permissions_matches:
            if value == "write-all":
                findings.append(
                    Finding(
                        rule_id="WW006",
                        severity="high",
                        path=str(path),
                        line=line_number,
                        title="Workflow grants write-all permissions",
                        message="Replace write-all with the smallest explicit permission set required by the job.",
                        evidence=f"permissions: {value}",
                    )
                )

    uses_checkout = any("actions/checkout@" in line for line in lines)
    head_reference_line = next(
        (
            idx + 1
            for idx, line in enumerate(lines)
            if "github.event.pull_request.head" in line or "github.head_ref" in line
        ),
        None,
    )
    for idx, line in enumerate(lines, start=1):
        uses_match = USES_RE.match(line)
        if uses_match:
            action_ref = uses_match.group(1)
            if action_ref.startswith(("./", "docker://")) or "@" not in action_ref:
                continue
            owner_repo, ref = action_ref.rsplit("@", 1)
            if owner_repo.startswith(("actions/", "github/")):
                continue
            if not HEX40_RE.fullmatch(ref):
                findings.append(
                    Finding(
                        rule_id="WW003",
                        severity="medium",
                        path=str(path),
                        line=idx,
                        title="Third-party action is not pinned to a commit SHA",
                        message="Pin external actions to a full 40-character commit SHA to reduce supply-chain drift.",
                        evidence=action_ref,
                    )
                )

        runs_on_match = RUNS_ON_RE.match(line)
        if runs_on_match and "self-hosted" in runs_on_match.group(1):
            findings.append(
                Finding(
                    rule_id="WW005",
                    severity="medium",
                    path=str(path),
                    line=idx,
                    title="Self-hosted runner detected",
                    message="Review network reachability, credential scope, and repository trust before using self-hosted runners.",
                    evidence=line.strip(),
                )
            )

        if REMOTE_EXEC_RE.search(line):
            findings.append(
                Finding(
                    rule_id="WW004",
                    severity="high",
                    path=str(path),
                    line=idx,
                    title="Remote script execution pattern detected",
                    message="Avoid executing fetched remote content directly; download, verify, and review before running.",
                    evidence=line.strip(),
                )
            )

    pr_target_line = next((idx + 1 for idx, line in enumerate(lines) if PULL_REQUEST_TARGET_RE.match(line)), None)
    if pr_target_line:
        dangerous_checkout = uses_checkout and head_reference_line is not None
        findings.append(
            Finding(
                rule_id="WW001",
                severity="high" if dangerous_checkout else "medium",
                path=str(path),
                line=pr_target_line,
                title="pull_request_target with PR-head checkout" if dangerous_checkout else "pull_request_target requires careful review",
                message=(
                    "This workflow uses pull_request_target and appears to check out or reference untrusted pull-request head content."
                    if dangerous_checkout
                    else "Avoid pull_request_target unless elevated repository permissions are strictly required."
                ),
                evidence=lines[pr_target_line - 1].strip(),
            )
        )

    return findings


def scan_path(target: str | Path, minimum_severity: str = "low") -> list[Finding]:
    base = Path(target)
    findings: list[Finding] = []
    for workflow_file in discover_workflow_files(base):
        for finding in scan_file(workflow_file):
            if severity_at_least(finding.severity, minimum_severity):
                findings.append(finding)
    return findings


def format_text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."

    blocks = []
    for finding in findings:
        blocks.append(
            f"[{finding.severity.upper()}] {finding.rule_id} {finding.path}:{finding.line} {finding.title}\n"
            f"  {finding.message}\n"
            f"  evidence: {finding.evidence}"
        )
    return "\n\n".join(blocks)
