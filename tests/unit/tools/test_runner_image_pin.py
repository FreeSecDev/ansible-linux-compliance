"""The collection consumes the CI runner image by digest only (FREES-36).

Every reference to ``ghcr.io/freesecdev/linux-compliance-runner`` in a workflow, Makefile,
script or configuration file must be pinned as ``@sha256:<64 hex>``. A tag, a bare name or a digest
combined with a tag fails. Markdown is exempt because the documentation names the package.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

ROOT: Final[Path] = Path(__file__).resolve().parents[3]
IMAGE: Final[str] = "ghcr.io/freesecdev/linux-compliance-runner"
REFERENCE: Final[re.Pattern[str]] = re.compile(
    re.escape(IMAGE) + r"(?P<rest>[^\s\"'`,)\]}]*)", re.IGNORECASE
)
DIGEST_ONLY: Final[re.Pattern[str]] = re.compile(r"@sha256:[0-9a-f]{64}")
EXEMPT_SUFFIXES: Final[frozenset[str]] = frozenset({".md"})
THIS_FILE: Final[str] = "tests/unit/tools/test_runner_image_pin.py"
TOP_LEVEL_FILES: Final[tuple[str, ...]] = ("Makefile", "galaxy.yml", ".pre-commit-config.yaml")
SCANNED_DIRECTORIES: Final[tuple[str, ...]] = (
    ".github",
    "extensions",
    "infra",
    "playbooks",
    "plugins",
    "roles",
    "tests",
    "tools",
)
SKIPPED_PARTS: Final[frozenset[str]] = frozenset({".terraform", "__pycache__", "node_modules"})


def unpinned_references(text: str) -> list[str]:
    """Return every runner image reference in ``text`` that is not a bare digest pin."""
    return [
        match.group(0)
        for match in REFERENCE.finditer(text)
        if DIGEST_ONLY.fullmatch(match.group("rest")) is None
    ]


def scanned_files() -> list[Path]:
    paths: list[Path] = [ROOT / name for name in TOP_LEVEL_FILES if (ROOT / name).is_file()]
    for directory in SCANNED_DIRECTORIES:
        paths.extend(path for path in sorted((ROOT / directory).rglob("*")) if path.is_file())
    return [
        path
        for path in paths
        if path.suffix not in EXEMPT_SUFFIXES
        and path.relative_to(ROOT).as_posix() != THIS_FILE
        and not set(path.relative_to(ROOT).parts) & SKIPPED_PARTS
    ]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"image: {IMAGE}@sha256:{'a' * 64}\n", []),
        (f"container: '{IMAGE}@sha256:{'b' * 64}'", []),
        (f"image: {IMAGE}:latest", [f"{IMAGE}:latest"]),
        (f"image: {IMAGE}", [IMAGE]),
        (f"image: {IMAGE}:v1@sha256:{'c' * 64}", [f"{IMAGE}:v1@sha256:{'c' * 64}"]),
        (f"image: {IMAGE}@sha256:{'d' * 63}", [f"{IMAGE}@sha256:{'d' * 63}"]),
        (f"image: {IMAGE.upper()}:1", [f"{IMAGE.upper()}:1"]),
        ("image: ghcr.io/freesecdev/linux-compliance-report:1", []),
    ],
)
def test_unpinned_references_are_detected(text: str, expected: list[str]) -> None:
    assert unpinned_references(text) == expected


def test_repository_files_reference_the_runner_image_by_digest_only() -> None:
    offenders: list[str] = []
    for path in scanned_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        offenders.extend(
            f"{path.relative_to(ROOT)}: {reference}" for reference in unpinned_references(text)
        )
    assert offenders == []
