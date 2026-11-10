"""Check that a pull request body ends with its ``Refs: FREES-<n>`` footer (FREES-204).

The repository squash merges with the pull request body as the commit message, so the
commit on ``main`` ends with whatever ends the body. AGENTS.md asks every commit to end
with a ``Refs: FREES-<n>`` footer, so the last non-empty line of the body must be that
footer, and the paragraph that holds it must contain only trailer lines, so that Git
reads it as a trailer of the body. Attribution lines such as ``Co-Authored-By:`` may
share that paragraph; a line such as "Generated with ..." goes in a paragraph before it.

When the head branch is named ``<type>/FREES-<n>-<slug>``, the footer must list that key.
Dependabot writes its own body, cannot add a footer and has no Jira key; a pull request
opened by ``dependabot[bot]`` is accepted without the footer and reported as exempt. That
gap is tracked on FREES-81.

The tool reads only its arguments and the body file and needs no package outside the
standard library, so CI runs it without installing the development environment.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Sequence

ISSUE_KEY: Final[str] = r"FREES-[1-9][0-9]*"
FOOTER: Final[re.Pattern[str]] = re.compile(rf"^Refs: {ISSUE_KEY}(?:, {ISSUE_KEY})*$")
TRAILER: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z][A-Za-z0-9-]*: \S")
BRANCH_KEY: Final[re.Pattern[str]] = re.compile(rf"^[a-z]+/({ISSUE_KEY})-[a-z0-9]")
EXEMPT_AUTHORS: Final[frozenset[str]] = frozenset({"dependabot[bot]"})
FOOTER_HINT: Final[str] = (
    "end the body with a line 'Refs: FREES-<n>' in a paragraph of trailer lines only; "
    "attribution lines come before it"
)


def footer_findings(body: str, head_ref: str = "") -> list[str]:
    """Return what is wrong with the footer of ``body``; an empty list means it is valid.

    Lines are compared without trailing white space, and empty lines at the end of the
    body are ignored, because GitHub keeps the line endings and final newlines that the
    editor sent.
    """
    lines = [line.rstrip() for line in body.splitlines()]
    while lines and not lines[-1]:
        lines.pop()
    if not lines:
        return [f"the pull request body is empty: {FOOTER_HINT}"]
    last = lines[-1]
    if not FOOTER.match(last):
        return [f"the last line of the body is {last!r}, not a Refs footer: {FOOTER_HINT}"]
    findings: list[str] = []
    paragraph_start = len(lines) - 1
    while paragraph_start > 0 and lines[paragraph_start - 1]:
        paragraph_start -= 1
    findings.extend(
        f"the footer paragraph holds a line that is not a trailer, {line!r}: {FOOTER_HINT}"
        for line in lines[paragraph_start:-1]
        if not TRAILER.match(line)
    )
    branch = BRANCH_KEY.match(head_ref)
    if branch is not None and branch.group(1) not in last.removeprefix("Refs: ").split(", "):
        findings.append(
            f"the footer {last!r} does not list {branch.group(1)}, "
            f"the key of the branch {head_ref!r}"
        )
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--body-file", type=Path, required=True, help="File that holds the pull request body."
    )
    parser.add_argument("--author", default="", help="Login of the pull request author.")
    parser.add_argument("--head-ref", default="", help="Name of the pull request's head branch.")
    arguments = parser.parse_args(argv)
    if arguments.author in EXEMPT_AUTHORS:
        print(f"exempt: {arguments.author} writes its own body and has no Jira key (FREES-81)")
        return 0
    findings = footer_findings(arguments.body_file.read_text(encoding="utf-8"), arguments.head_ref)
    for finding in findings:
        print(f"error: {finding}", file=sys.stderr)
    if findings:
        return 1
    print("the pull request body ends with its Refs footer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
