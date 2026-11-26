#!/usr/bin/env python3
"""Build a release body from GitHub's generated notes and shipped references."""

from __future__ import annotations

import json
import re
import subprocess
import sys


def gh(*args: str) -> dict:
    result = subprocess.run(
        ["gh", "api", *args], check=True, capture_output=True, text=True
    )
    return json.loads(result.stdout)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate-release-notes.py OWNER/REPO TAG")

    repository, tag = sys.argv[1:]
    generated = gh(
        "--method",
        "POST",
        f"repos/{repository}/releases/generate-notes",
        "-f",
        f"tag_name={tag}",
        "-f",
        f"target_commitish={tag}",
    )
    generated_body = generated["body"].strip()

    # GitHub includes the previous tag in its generated comparison link.
    comparison = re.search(
        rf"https://github\.com/{re.escape(repository)}/compare/([^\s]+?)\.\.\.{re.escape(tag)}",
        generated_body,
    )
    references: set[int] = set()
    if comparison:
        previous = comparison.group(1)
        compared = gh(f"repos/{repository}/compare/{previous}...{tag}")
        for commit in compared.get("commits", []):
            message = commit.get("commit", {}).get("message", "").splitlines()[0]
            references.update(int(number) for number in re.findall(r"(?<![\w])#(\d+)", message))

    for number in re.findall(
        rf"https://github\.com/{re.escape(repository)}/(?:issues|pull)/(\d+)",
        generated_body,
    ):
        references.add(int(number))

    # Pull request descriptions often carry the actual issue references
    # (for example, "Closes #153"), so follow those references as well.
    inspected: dict[int, dict] = {}
    pending = sorted(references)
    while pending:
        number = pending.pop(0)
        if number in inspected:
            continue
        item = gh(f"repos/{repository}/issues/{number}")
        inspected[number] = item
        if item.get("pull_request"):
            for referenced in re.findall(r"(?<![\w])#(\d+)", item.get("body") or ""):
                ref_number = int(referenced)
                if ref_number not in inspected and ref_number not in references:
                    references.add(ref_number)
                    pending.append(ref_number)

    shipped = []
    for number in sorted(references):
        item = inspected[number]
        kind = "pull" if item.get("pull_request") else "issues"
        title = item.get("title", f"#{number}")
        shipped.append(f"- [{title}](https://github.com/{repository}/{kind}/{number})")

    body = [generated_body, "", "## Shipped tickets and pull requests"]
    if shipped:
        body.extend(shipped)
    else:
        body.append("- No issue or pull request references were present in the release commits.")
    body.extend(
        [
            "",
            "## Downloads",
            "- Linux (x86_64): `git-veil-linux-x86_64`",
            "- macOS (x86_64): `git-veil-macos-x86_64`",
            "- macOS (Apple Silicon): `git-veil-macos-aarch64`",
            "- Windows (x86_64): `git-veil-windows-x86_64.exe`, `git-veil-windows-x86_64.msi`, and `git-veil-windows-x86_64-portable.zip`",
            "- Man pages: `git-veil-man-pages.tar.gz`",
            "",
            "SHA-256 checksums are provided for every asset (`*.sha256`).",
            "",
            "## Installation",
            "```bash",
            "chmod +x git-veil-*",
            "sudo mv git-veil-linux-x86_64 /usr/local/bin/git-veil",
            "```",
            "",
            "## Documentation",
            "Tutorials and guides live in [docs/](https://github.com/prompt-cult/git-veil/tree/main/docs):",
            "solo workflows, two-collaborator setup, joining and departing",
            "repos, and migrations from git-crypt / git-secret.",
            "",
        ]
    )
    sys.stdout.write("\n".join(body))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
