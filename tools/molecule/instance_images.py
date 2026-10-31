r"""Plan the Docker instance images of the Molecule scenarios (FREES-182, ADR 0009).

CI builds each instance image once per workflow run, and every Molecule leg loads that image
instead of building its own. Both sides must agree on the image tag that
``extensions/molecule/shared/create.yml`` computes: the first 12 hex digits of the base digest,
a hyphen, and the first 12 hex digits of a SHA-256 over
``<reference>:<tag>@<digest>``, a literal backslash and ``n`` (two characters, because Jinja
reads ``'\n'`` inside the folded YAML scalar as written), and the Dockerfile with its trailing
whitespace removed, as ``lookup('ansible.builtin.file')`` returns it. ``create.yml`` checks the
tag that this plan recorded against its own, so a drift fails the leg instead of using another
image.

The plan lists one line per image that the given platform files use (a scenario's
``molecule.yml`` or a self-test vars file with ``molecule_yml.platforms``), or every image of
``shared/vars/versions.yml`` when none is given: ``<image> <tag> <base reference> <Dockerfile>``.
``--output github`` prints ``<image>=<tag>`` lines for ``$GITHUB_OUTPUT`` instead. Nothing here
runs Docker; ``tools/molecule/instance-images.sh`` builds, saves, loads and verifies.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml

if TYPE_CHECKING:
    from collections.abc import Sequence

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SHARED: Final[Path] = REPO_ROOT / "extensions" / "molecule" / "shared"
DEFAULT_VERSIONS: Final[Path] = SHARED / "vars" / "versions.yml"
DEFAULT_IMAGES: Final[Path] = SHARED / "images"
TAG_DIGITS: Final[int] = 12
SEPARATOR: Final[str] = "\\n"
IMAGE_KEY: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]{0,30}")
REFERENCE: Final[re.Pattern[str]] = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
)
TAG: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
DIGEST: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}")
DOCKERFILE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9-]*\.Dockerfile")


class PlanError(ValueError):
    """A pinned image or a platform file is not acceptable."""


@dataclass(frozen=True)
class Image:
    """One pinned instance image: its key, base reference, tag, digest and Dockerfile name."""

    key: str
    reference: str
    tag: str
    digest: str
    dockerfile: str

    @property
    def base(self) -> str:
        """The digest-pinned base reference that the Dockerfile takes as ``BASE_IMAGE``."""
        return f"{self.reference}:{self.tag}@{self.digest}"


def image_tag(image: Image, dockerfile_text: str) -> str:
    """Return the tag that ``create.yml`` computes for ``image`` built from ``dockerfile_text``."""
    inputs = f"{image.base}{SEPARATOR}{dockerfile_text.rstrip()}"
    digest = hashlib.sha256(inputs.encode("utf-8")).hexdigest()
    return f"{image.digest.removeprefix('sha256:')[:TAG_DIGITS]}-{digest[:TAG_DIGITS]}"


def _mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        message = f"{where} is not a mapping"
        raise PlanError(message)
    return cast("dict[str, object]", value)


def _field(entry: dict[str, object], name: str, pattern: re.Pattern[str], where: str) -> str:
    value = entry.get(name)
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        message = f"{where}: {name} is missing or malformed"
        raise PlanError(message)
    return value


def load_images(versions: Path) -> dict[str, Image]:
    """Read and check every pinned image of ``versions``."""
    document = _mapping(yaml.safe_load(versions.read_text(encoding="utf-8")), str(versions))
    entries = _mapping(document.get("molecule_images"), f"{versions}: molecule_images")
    images: dict[str, Image] = {}
    for key, value in sorted(entries.items()):
        where = f"{versions}: {key}"
        if IMAGE_KEY.fullmatch(key) is None:
            message = f"{where}: the image key is malformed"
            raise PlanError(message)
        entry = _mapping(value, where)
        images[key] = Image(
            key=key,
            reference=_field(entry, "reference", REFERENCE, where),
            tag=_field(entry, "tag", TAG, where),
            digest=_field(entry, "digest", DIGEST, where),
            dockerfile=_field(entry, "dockerfile", DOCKERFILE, where),
        )
    if not images:
        message = f"{versions} pins no image"
        raise PlanError(message)
    return images


def platform_images(path: Path) -> list[str]:
    """Return the image keys of the platforms in a ``molecule.yml`` or a self-test vars file."""
    document = _mapping(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))
    if "molecule_yml" in document:
        document = _mapping(document["molecule_yml"], f"{path}: molecule_yml")
    platforms = document.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        message = f"{path} lists no platforms"
        raise PlanError(message)
    keys: list[str] = []
    for platform in cast("list[object]", platforms):
        image = _mapping(platform, f"{path}: a platform").get("image")
        if not isinstance(image, str):
            message = f"{path}: a platform names no image"
            raise PlanError(message)
        keys.append(image)
    return keys


def plan(
    versions: Path, images_dir: Path, platform_files: Sequence[Path]
) -> list[tuple[Image, str]]:
    """Return each needed image with its tag, sorted by key."""
    images = load_images(versions)
    keys = (
        sorted({key for path in platform_files for key in platform_images(path)})
        if platform_files
        else sorted(images)
    )
    planned: list[tuple[Image, str]] = []
    for key in keys:
        if key not in images:
            message = f"no image {key!r} is pinned in {versions}"
            raise PlanError(message)
        image = images[key]
        dockerfile = images_dir / image.dockerfile
        planned.append((image, image_tag(image, dockerfile.read_text(encoding="utf-8"))))
    return planned


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--versions", type=Path, default=DEFAULT_VERSIONS)
    parser.add_argument("--images-dir", type=Path, default=DEFAULT_IMAGES)
    parser.add_argument("--platforms", type=Path, action="append", default=[])
    parser.add_argument("--output", choices=("plan", "github"), default="plan")
    arguments = parser.parse_args(argv)
    images_dir = cast("Path", arguments.images_dir)
    try:
        planned = plan(
            cast("Path", arguments.versions), images_dir, cast("list[Path]", arguments.platforms)
        )
    except (OSError, yaml.YAMLError, PlanError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for image, tag in planned:
        if arguments.output == "github":
            print(f"{image.key}={tag}")
        else:
            print(image.key, tag, image.base, (images_dir / image.dockerfile).resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
