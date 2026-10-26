"""The collection consumes the CI runner image by digest only (FREES-36).

Every reference to ``ghcr.io/freesecdev/linux-compliance-runner`` in a tracked file other than
Markdown must be pinned as ``@sha256:<64 hex>``. A tag, a bare name or a digest combined with a
tag fails. The private, unsigned ECR staging image (``linux-compliance-runner-staging`` or any
``*.dkr.ecr.*`` registry) must not be referenced at all outside the AWS stack that defines it and
its pinning test and snapshot. The check reads literal text, so a name assembled from variables
or split strings is not seen; review catches those.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Final

import pytest

ROOT: Final[Path] = Path(__file__).resolve().parents[3]
IMAGE: Final[str] = "ghcr.io/freesecdev/linux-compliance-runner"
REFERENCE: Final[re.Pattern[str]] = re.compile(
    re.escape(IMAGE) + r"(?![\w-])(?P<rest>[^\s\"'`,)\]}]*)", re.IGNORECASE
)
DIGEST_ONLY: Final[re.Pattern[str]] = re.compile(r"@sha256:[0-9a-f]{64}")
STAGING: Final[re.Pattern[str]] = re.compile(
    r"linux-compliance-runner-staging|[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com",
    re.IGNORECASE,
)
EXEMPT_SUFFIXES: Final[frozenset[str]] = frozenset({".md"})
STAGING_ALLOWED_PREFIXES: Final[tuple[str, ...]] = (
    "infra/",
    "tests/unit/infra/",
    "tests/fixtures/infra/",
)
THIS_FILE: Final[str] = "tests/unit/tools/test_runner_image_pin.py"
GIT_TIMEOUT_SECONDS: Final[int] = 30


def unpinned_references(text: str) -> list[str]:
    """Return every GHCR runner image reference in ``text`` that is not a bare digest pin."""
    return [
        match.group(0)
        for match in REFERENCE.finditer(text)
        if DIGEST_ONLY.fullmatch(match.group("rest")) is None
    ]


def staging_references(text: str) -> list[str]:
    """Return every reference to the private ECR staging image in ``text``."""
    return [match.group(0) for match in STAGING.finditer(text)]


def tracked_files() -> list[str]:
    git = shutil.which("git")
    if git is None:
        message = "git is required to list the tracked files"
        raise RuntimeError(message)
    completed = subprocess.run(
        [git, "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
    )
    return sorted(
        name
        for name in completed.stdout.split("\0")
        if name and name != THIS_FILE and Path(name).suffix not in EXEMPT_SUFFIXES
    )


def offenders() -> list[str]:
    found: list[str] = []
    for name in tracked_files():
        try:
            text = (ROOT / name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        found.extend(f"{name}: {reference}" for reference in unpinned_references(text))
        if not name.startswith(STAGING_ALLOWED_PREFIXES):
            found.extend(f"{name}: {reference}" for reference in staging_references(text))
    return found


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
        (f"image: {IMAGE}-staging:1", []),
    ],
)
def test_unpinned_references_are_detected(text: str, expected: list[str]) -> None:
    assert unpinned_references(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            (
                "image: 910736812072.dkr.ecr.eu-west-1.amazonaws.com/"
                f"linux-compliance-runner-staging@sha256:{'a' * 64}"
            ),
            [
                "910736812072.dkr.ecr.eu-west-1.amazonaws.com",
                "linux-compliance-runner-staging",
            ],
        ),
        ("pull linux-compliance-runner-staging", ["linux-compliance-runner-staging"]),
        (
            "image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/x",
            ["123456789012.dkr.ecr.us-east-1.amazonaws.com"],
        ),
        (f"image: {IMAGE}@sha256:{'a' * 64}", []),
    ],
)
def test_staging_references_are_detected(text: str, expected: list[str]) -> None:
    assert staging_references(text) == expected


def test_tracked_files_consume_only_the_published_digest() -> None:
    assert offenders() == []
