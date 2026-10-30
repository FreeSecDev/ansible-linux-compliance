"""Print the CI matrix of the Molecule toggle lifecycle legs (FREES-53).

The toggle lifecycle of every native topic (``extensions/molecule/shared/lifecycle.yml``) runs in
scenarios of their own, ``docker-<platform>-lifecycle``, so that the standard scenarios stay short.
Run in one job, the lifecycle of every topic grew with every native topic (52 minutes per
platform with three topics). CI therefore runs one leg per platform, native topic and toggle
mode: each leg sets ``MOLECULE_LIFECYCLE_TOPIC`` and ``MOLECULE_LIFECYCLE_MODE``, and the harness
runs only the cycles of that topic and mode, from every declared pre-state.

The legs are derived from the catalogue with ``generate_toggles.native_families``, the predicate
of the remediation dispatch and of ``make lint-lifecycle``, and from the Molecule platforms of
``extensions/molecule/shared/vars/versions.yml``. A new native topic therefore gets its legs
without any change to the workflow, and no topic can be left out: the matrix holds every native
topic in both modes on every platform. A platform without its lifecycle scenario is an error.
The output is one line of JSON, ``{"include": [...]}``, for ``fromJSON`` in the workflow.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from tools.roles import check_lifecycle_topics, generate_toggles

if TYPE_CHECKING:
    from collections.abc import Sequence

GenerationError = generate_toggles.GenerationError
MOLECULE: Final[Path] = Path("extensions/molecule")
SCENARIO_PREFIX: Final[str] = "docker-"
SCENARIO_SUFFIX: Final[str] = "-lifecycle"
MODES: Final[tuple[str, ...]] = ("topic", "rule")


def scenario_of(platform: str) -> str:
    """Return the lifecycle scenario of a platform, ``docker-<platform>-lifecycle``."""
    return SCENARIO_PREFIX + platform.replace("_", "-") + SCENARIO_SUFFIX


def legs(root: Path) -> list[dict[str, str]]:
    """Return one leg per platform, native topic and toggle mode, in platform and registry order."""
    catalogue = generate_toggles.load_catalogue(root / generate_toggles.CATALOGUE)
    topics = generate_toggles.native_families(catalogue)
    if not topics:
        message = (
            f"{generate_toggles.CATALOGUE} has no native topic, so there is no lifecycle to run"
        )
        raise GenerationError(message)
    found: list[dict[str, str]] = []
    for platform in sorted(check_lifecycle_topics.platforms(root)):
        scenario = scenario_of(platform)
        if not (root / MOLECULE / scenario / "molecule.yml").is_file():
            message = f"the platform {platform} has no lifecycle scenario {MOLECULE / scenario}"
            raise GenerationError(message)
        found.extend(
            {"platform": platform, "scenario": scenario, "topic": topic, "mode": mode}
            for topic in topics
            for mode in MODES
        )
    return found


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path())
    arguments = parser.parse_args(argv)
    try:
        found = legs(cast("Path", arguments.root))
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"include": found}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
