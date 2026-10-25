"""Check that relative links in Markdown files point at existing paths."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final
from urllib.parse import unquote

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

INLINE_LINK: Final[re.Pattern[str]] = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
INLINE_CODE: Final[re.Pattern[str]] = re.compile(r"`[^`]*`")
EXTERNAL_TARGET: Final[re.Pattern[str]] = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|#|//)")
FENCE_MARKERS: Final[frozenset[str]] = frozenset({"```", "~~~"})
MARKDOWN_SUFFIXES: Final[frozenset[str]] = frozenset({".md", ".markdown"})


@dataclass(frozen=True, order=True, slots=True)
class BrokenLink:
    """A relative link whose target does not exist."""

    path: Path
    line: int
    target: str

    def __str__(self) -> str:
        """Render the broken link as ``path:line: message``."""
        return f"{self.path}:{self.line}: broken relative link '{self.target}'"


def extract_links(text: str) -> list[tuple[int, str]]:
    """Return ``(line, target)`` pairs for inline links outside code."""
    links: list[tuple[int, str]] = []
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        marker = line.lstrip()[:3]
        if fence is None and marker in FENCE_MARKERS:
            fence = marker
        elif fence is not None and marker == fence:
            fence = None
        elif fence is None:
            stripped = INLINE_CODE.sub("", line)
            links.extend((number, match) for match in INLINE_LINK.findall(stripped))
    return links


def target_exists(base: Path, target: str) -> bool:
    """Return whether ``target`` resolves to an existing path relative to ``base``."""
    relative = unquote(target.split("#", 1)[0].split("?", 1)[0])
    if not relative:
        return True
    if relative.startswith("/"):
        return False
    try:
        return (base / relative).exists()
    except (OSError, ValueError):
        return False


def check_file(path: Path) -> list[BrokenLink]:
    """Return the broken relative links in the Markdown file ``path``."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [BrokenLink(path, 1, "<unreadable file>")]
    return [
        BrokenLink(path, number, target)
        for number, target in extract_links(text)
        if EXTERNAL_TARGET.match(target) is None and not target_exists(path.parent, target)
    ]


def check_paths(paths: Iterable[Path]) -> list[BrokenLink]:
    """Check every Markdown file in ``paths`` and return sorted findings."""
    return sorted(
        broken
        for path in paths
        if path.suffix.lower() in MARKDOWN_SUFFIXES
        for broken in check_file(path)
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="Markdown files to check.")
    arguments = parser.parse_args(argv)
    broken = check_paths(arguments.paths)
    for finding in broken:
        print(finding, file=sys.stderr)
    if broken:
        print(f"{len(broken)} broken relative link(s)", file=sys.stderr)
        return 1
    print(f"relative links valid in {len(arguments.paths)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
