"""Detect suspicious file patterns in pull requests.

Scans the list of changed files in a PR for patterns that indicate
potential security risks: malware injection vectors (.claude/),
untrusted agent skill modifications, IDE config injection (.vscode/),
and CI/CD workflow tampering (.github/workflows/).

Usage:
    python pattern-check.py --pr-number N --author LOGIN --branch REF --output FILE
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


TRUSTED_BOT = "ansibuddy"
TRUSTED_SKILL_BRANCH = "chore/sync-agent-skills"


def _get_changed_files() -> list[str]:
    """Get list of changed files from git diff against the merge base."""
    result = subprocess.run(
        ["git", "diff", "--name-only", "origin/main...HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1"],
            capture_output=True,
            text=True,
            check=False,
        )
    return [f for f in result.stdout.strip().split("\n") if f]


def _classify_files(
    files: list[str],
) -> dict[str, list[str]]:
    """Classify changed files into security-relevant categories."""
    categories: dict[str, list[str]] = {
        "claude": [],
        "skills": [],
        "vscode": [],
        "workflows": [],
    }
    for f in files:
        if f.startswith(".claude/"):
            categories["claude"].append(f)
        elif f.startswith(".agents/skills/"):
            categories["skills"].append(f)
        elif f.startswith(".vscode/"):
            categories["vscode"].append(f)
        elif f.startswith(".github/workflows/"):
            categories["workflows"].append(f)
    return categories


def _check_claude(files: list[str]) -> dict[str, object] | None:
    """Check for .claude/ directory (known malware vector)."""
    if not files:
        return None
    return {
        "severity": "CRITICAL",
        "category": "claude_directory",
        "title": ".claude/ directory detected",
        "description": (
            "This PR adds or modifies files in .claude/. "
            "This is a known malware injection vector (Miasma campaign). "
            "Files containing 'command: node .claude/setup.mjs' are confirmed malware."
        ),
        "files": files,
    }


def _check_skills(
    files: list[str], author: str, branch: str
) -> dict[str, object] | None:
    """Check for untrusted .agents/skills/ modifications."""
    if not files:
        return None
    is_trusted = author == TRUSTED_BOT and branch == TRUSTED_SKILL_BRANCH
    if is_trusted:
        return {
            "severity": "PASS",
            "category": "skill_sync",
            "title": "Skill sync from trusted source",
            "description": (
                f"Author: {author} (trusted bot), "
                f"Branch: {branch} (matches sync pattern)"
            ),
            "files": files,
        }
    return {
        "severity": "HIGH",
        "category": "untrusted_skills",
        "title": "Untrusted .agents/skills/ modification",
        "description": (
            "This PR modifies agent skills but does NOT match the trusted sync pattern. "
            f"Author: {author} (expected: {TRUSTED_BOT}), "
            f"Branch: {branch} (expected: {TRUSTED_SKILL_BRANCH}). "
            "Skill changes from untrusted sources require manual security review."
        ),
        "files": files,
    }


def _check_vscode(files: list[str]) -> dict[str, object] | None:
    """Check for .vscode/ directory modifications."""
    if not files:
        return None
    return {
        "severity": "HIGH",
        "category": "vscode_config",
        "title": ".vscode/ directory modified",
        "description": (
            "This PR modifies IDE configuration files. "
            "Malicious extensions or tasks in .vscode/ can execute arbitrary code."
        ),
        "files": files,
    }


def _check_workflows(
    files: list[str], author: str, branch: str
) -> dict[str, object] | None:
    """Check for .github/workflows/ modifications from untrusted sources."""
    if not files:
        return None
    if author == TRUSTED_BOT or branch.startswith(("chore/", "fix/")):
        return None
    return {
        "severity": "MEDIUM",
        "category": "workflow_modified",
        "title": "CI/CD workflow modified",
        "description": (
            "This PR modifies GitHub Actions workflows. "
            "Unauthorized pipeline changes can exfiltrate secrets "
            "or inject malware into builds."
        ),
        "files": files,
    }


def main() -> int:
    """Run pattern checks and output structured JSON."""
    parser = argparse.ArgumentParser(description="PR file pattern security checker")
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--author", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument(
        "--output", default="-", help="Output JSON file, or '-' for stdout"
    )
    args = parser.parse_args()

    files = _get_changed_files()
    categories = _classify_files(files)

    findings = [
        check
        for check in [
            _check_claude(categories["claude"]),
            _check_skills(categories["skills"], args.author, args.branch),
            _check_vscode(categories["vscode"]),
            _check_workflows(categories["workflows"], args.author, args.branch),
        ]
        if check is not None
    ]

    severities = [f["severity"] for f in findings if f["severity"] != "PASS"]
    if "CRITICAL" in severities:
        overall = "CRITICAL"
    elif "HIGH" in severities:
        overall = "HIGH"
    elif "MEDIUM" in severities:
        overall = "MEDIUM"
    else:
        overall = "PASS"

    result = {
        "status": overall,
        "findings": findings,
        "total_files_scanned": len(files),
    }

    output = json.dumps(result, indent=2)
    if args.output == "-":
        sys.stdout.write(output + "\n")
    else:
        Path(args.output).write_text(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
