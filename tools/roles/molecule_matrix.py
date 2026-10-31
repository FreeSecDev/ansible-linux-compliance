"""Print the CI matrix of the Molecule toggle lifecycle legs (FREES-53, FREES-61).

The toggle lifecycle of every native topic (``extensions/molecule/shared/lifecycle.yml``) runs in
scenarios of their own, ``<driver>-<platform>-lifecycle``, so that the standard scenarios stay
short. Run in one job, the lifecycle of every topic grew with every native topic (52 minutes per
platform with three topics). CI therefore runs one leg per platform, native topic and toggle
mode: each leg sets ``MOLECULE_LIFECYCLE_TOPIC`` and ``MOLECULE_LIFECYCLE_MODE``, and the harness
runs only the cycles of that topic and mode, from every declared pre-state of the leg's driver.

The legs are derived from the catalogue with ``generate_toggles.native_families``, the predicate
of the remediation dispatch and of ``make lint-lifecycle``, from the Molecule platforms of
``extensions/molecule/shared/vars/versions.yml`` and from the drivers of each cycle that
``check_lifecycle_topics.cycle_platforms`` reports: a cycle runs with the drivers its pre-state
``requires``, else with those its topic ``requires``, else in Docker only. A new native topic
therefore gets its legs without any change to the workflow, and no cycle can be left out: the
matrix of a driver holds every topic with a cycle of that driver, in both modes, on every
platform that the topic runs. A platform without its lifecycle scenario is an error.

``--driver docker`` (the default) prints the legs of ``docker-<platform>-lifecycle``: the two
toggle modes of every topic, and one leg per regression group that a topic declares, with the
mode ``regressions-<group>`` (FREES-175), so that regressions do not lengthen the cycle legs.
``--driver libvirt`` prints, for KVM runners, a fixed base leg per platform (``libvirt-<platform>``:
the real scan, remediation, idempotence and cleanup of the reference rule), the lifecycle legs of
the cycles that require libvirt, one leg per regression group that requires libvirt (FREES-107),
and the ``libvirt-selftest`` leg. The output is one line of
JSON, ``{"include": [...]}``, for ``fromJSON`` in the workflow.
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
REGRESSION_MODE_PREFIX: Final[str] = "regressions-"
DRIVERS: Final[tuple[str, ...]] = ("docker", "libvirt")
LIBVIRT_SELFTEST: Final[str] = "libvirt-selftest"
LIBVIRT_SELFTEST_PLATFORM: Final[str] = "ubuntu"


def scenario_of(platform: str, driver: str = "docker", suffix: str = SCENARIO_SUFFIX) -> str:
    """Return the scenario of a platform, ``<driver>-<platform><suffix>``."""
    return f"{driver}-" + platform.replace("_", "-") + suffix


def _require(root: Path, scenario: str, platform: str, kind: str) -> None:
    if not (root / MOLECULE / scenario / "molecule.yml").is_file():
        message = f"the platform {platform} has no {kind} scenario {MOLECULE / scenario}"
        raise GenerationError(message)


def legs(root: Path, driver: str = "docker") -> list[dict[str, str]]:
    """Return the legs of ``driver``: one per platform, topic with a cycle there and mode."""
    if driver not in DRIVERS:
        message = f"unknown driver {driver!r}; use one of {', '.join(DRIVERS)}"
        raise GenerationError(message)
    catalogue = generate_toggles.load_catalogue(root / generate_toggles.CATALOGUE)
    topics = generate_toggles.native_families(catalogue)
    if not topics:
        message = (
            f"{generate_toggles.CATALOGUE} has no native topic, so there is no lifecycle to run"
        )
        raise GenerationError(message)
    cycles = check_lifecycle_topics.cycle_platforms(root)
    regressions = check_lifecycle_topics.regression_platforms(root, driver)
    known = sorted(check_lifecycle_topics.platforms(root))
    found: list[dict[str, str]] = []
    for platform in known:
        scenario = scenario_of(platform, driver)
        _require(root, scenario, platform, "lifecycle")
        if driver == "libvirt":
            base = scenario_of(platform, driver, "")
            _require(root, base, platform, "libvirt base")
            found.append({"platform": platform, "scenario": base, "topic": "", "mode": ""})
        for topic in topics:
            if platform not in cycles[topic].get(driver, frozenset()):
                continue
            found.extend(
                {"platform": platform, "scenario": scenario, "topic": topic, "mode": mode}
                for mode in MODES
            )
            found.extend(
                {
                    "platform": platform,
                    "scenario": scenario,
                    "topic": topic,
                    "mode": REGRESSION_MODE_PREFIX + name,
                }
                for name, chosen in regressions.get(topic, {}).items()
                if platform in chosen
            )
    if driver == "libvirt":
        if LIBVIRT_SELFTEST_PLATFORM not in known:
            message = f"the self-test platform {LIBVIRT_SELFTEST_PLATFORM} is not a platform"
            raise GenerationError(message)
        found.append(
            {
                "platform": LIBVIRT_SELFTEST_PLATFORM,
                "scenario": LIBVIRT_SELFTEST,
                "topic": "",
                "mode": "",
            }
        )
    return found


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path())
    parser.add_argument("--driver", default="docker")
    arguments = parser.parse_args(argv)
    try:
        found = legs(cast("Path", arguments.root), cast("str", arguments.driver))
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"include": found}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
