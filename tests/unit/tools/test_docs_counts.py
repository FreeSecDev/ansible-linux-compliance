"""Counts and lists in the documentation that the code determines (FREES-206).

The CI legs of ``docs/molecule.md`` come from ``tools/roles/molecule_matrix.py``, the disruptive
native topics and the family table of ``docs/remediation.md`` from the family registry, and the
rule counts of ``docs/remediation.md`` and ``roles/remediate/README.md`` from the catalogue
``roles/remediate/vars/rules.yml``. Each of them went stale after merges that added topics, so
these tests derive every number from the code and compare it with the text. A failure names the
text to write. ``docs/collection-design.md`` refers to the ansible-core pin of ``pyproject.toml``
instead of naming a version; a version that it names again must be the pin.
"""

from __future__ import annotations

import functools
import re
import tomllib
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)
from tools.roles import check_lifecycle_topics, generate_toggles
from tools.roles import molecule_matrix as matrix

if TYPE_CHECKING:
    from collections.abc import Iterable

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
MOLECULE_DOC: Final[Path] = REPOSITORY_ROOT / "docs" / "molecule.md"
REMEDIATION_DOC: Final[Path] = REPOSITORY_ROOT / "docs" / "remediation.md"
COLLECTION_DESIGN: Final[Path] = REPOSITORY_ROOT / "docs" / "collection-design.md"
ROLE_README: Final[Path] = REPOSITORY_ROOT / "roles" / "remediate" / "README.md"
PYPROJECT: Final[Path] = REPOSITORY_ROOT / "pyproject.toml"
PLATFORM_NAMES: Final[dict[str, str]] = {"ubuntu": "Ubuntu", "rhel_compatible": "Rocky Linux"}
ALL_PLATFORMS: Final[str] = "both"
NONE: Final[str] = "none"
LEG_TABLE_HEADER: Final[str] = (
    "| Topic | Docker cycles | Docker regression groups"
    " | libvirt cycles | libvirt regression groups |"
)
FAMILY_TABLE_HEADER: Final[str] = "| Disruptive | Families |"
REFERENCE_FAMILY: Final[str] = "file_permissions"
BACKTICKED: Final[re.Pattern[str]] = re.compile(r"`([^`]+)`")
ANSIBLE_CORE_VERSION: Final[re.Pattern[str]] = re.compile(r"ansible-core\s+(\d+\.\d+\.\d+)")

Leg = dict[str, str]


def flat(path: Path) -> str:
    """Return the text of ``path`` with every run of whitespace as one space."""
    return " ".join(path.read_text(encoding="utf-8").split())


def search(pattern: str, text: str, where: Path) -> re.Match[str]:
    found = re.search(pattern, text)
    assert found is not None, f"{where.relative_to(REPOSITORY_ROOT)} no longer says {pattern!r}"
    return found


def table(path: Path, header: str) -> list[str]:
    """Return the rows of the Markdown table under ``header`` in ``path``."""
    lines = path.read_text(encoding="utf-8").splitlines()
    assert header in lines, f"{path.relative_to(REPOSITORY_ROOT)} has no table {header!r}"
    rows: list[str] = []
    for line in lines[lines.index(header) + 2 :]:
        if not line.startswith("|"):
            break
        rows.append(line)
    return rows


@functools.cache
def catalogue() -> toggles.Catalogue:
    return generate_toggles.load_catalogue(REPOSITORY_ROOT / generate_toggles.CATALOGUE)


@functools.cache
def legs(driver: str) -> tuple[Leg, ...]:
    return tuple(matrix.legs(REPOSITORY_ROOT, driver))


def is_cycle(leg: Leg) -> bool:
    return leg["mode"] in matrix.MODES


def group_of(leg: Leg) -> str | None:
    mode = leg["mode"]
    return (
        mode.removeprefix(matrix.REGRESSION_MODE_PREFIX)
        if mode.startswith(matrix.REGRESSION_MODE_PREFIX)
        else None
    )


def native_counts() -> Counter[str]:
    return Counter(str(rule["family"]) for rule in catalogue().rules if toggles.is_native(rule))


def platforms_text(platforms: Iterable[str]) -> str:
    chosen = set(platforms)
    if not chosen:
        return NONE
    if chosen == set(PLATFORM_NAMES):
        return ALL_PLATFORMS
    return ", ".join(PLATFORM_NAMES[platform] for platform in sorted(chosen))


def groups_text(found: Iterable[Leg], cycles: set[str]) -> str:
    """Return the regression groups of a topic, each with its platforms where they differ."""
    groups: dict[str, set[str]] = {}
    for leg in found:
        group = group_of(leg)
        if group is not None:
            groups.setdefault(group, set()).add(leg["platform"])
    return (
        ", ".join(
            f"`{group}`" + ("" if platforms == cycles else f" ({platforms_text(platforms)})")
            for group, platforms in sorted(groups.items())
        )
        or NONE
    )


def leg_row(topic: str) -> str:
    """Return the row of ``topic`` in the table of regression groups of ``docs/molecule.md``."""
    cells = [f"`{topic}`"]
    for driver in matrix.DRIVERS:
        found = [leg for leg in legs(driver) if leg["topic"] == topic]
        cycles = {leg["platform"] for leg in found if is_cycle(leg)}
        cells += [platforms_text(cycles), groups_text(found, cycles)]
    return "| " + " | ".join(cells) + " |"


def test_the_platform_names_of_the_documentation_are_the_molecule_platforms() -> None:
    assert set(PLATFORM_NAMES) == set(check_lifecycle_topics.platforms(REPOSITORY_ROOT))


def test_the_molecule_page_states_the_leg_counts_of_the_matrix() -> None:
    text = flat(MOLECULE_DOC)
    docker = legs("docker")
    found = search(
        r"The full Docker matrix has (\d+) cycle legs and (\d+) regression legs\.",
        text,
        MOLECULE_DOC,
    )
    expected = (
        sum(is_cycle(leg) for leg in docker),
        sum(group_of(leg) is not None for leg in docker),
    )
    assert (int(found[1]), int(found[2])) == expected
    assert len(docker) == sum(expected)
    libvirt = legs("libvirt")
    found = search(
        r"The full libvirt matrix has (\d+) cycle legs, (\d+) regression legs and (\d+) legs "
        r"without a topic \(([^)]*)\)",
        text,
        MOLECULE_DOC,
    )
    without_topic = sorted(leg["scenario"] for leg in libvirt if not leg["topic"])
    assert (int(found[1]), int(found[2]), int(found[3])) == (
        sum(is_cycle(leg) for leg in libvirt),
        sum(group_of(leg) is not None for leg in libvirt),
        len(without_topic),
    )
    assert sorted(BACKTICKED.findall(found[4])) == without_topic


def test_the_molecule_page_lists_the_regression_groups_of_the_matrix() -> None:
    expected = [leg_row(topic) for topic in generate_toggles.native_families(catalogue())]
    assert table(MOLECULE_DOC, LEG_TABLE_HEADER) == expected, "\n" + "\n".join(expected)


def test_the_molecule_page_names_every_disruptive_native_topic() -> None:
    found = search(
        r"### Disruptive topics (.*?) are the disruptive families with native rules",
        flat(MOLECULE_DOC),
        MOLECULE_DOC,
    )
    assert BACKTICKED.findall(found[1]) == [
        family
        for family in generate_toggles.native_families(catalogue())
        if generate_toggles.is_disruptive(catalogue(), family)
    ]


def test_the_remediation_page_states_the_counts_of_the_catalogue() -> None:
    text = flat(REMEDIATION_DOC)
    counts = native_counts()
    found = search(
        r"the safety model and (\d+) native families are implemented", text, REMEDIATION_DOC
    )
    assert int(found[1]) == len(counts) == len(generate_toggles.native_families(catalogue()))
    found = search(r"(\d+) rules in (\d+) families", text, REMEDIATION_DOC)
    assert (int(found[1]), int(found[2])) == (len(catalogue().rules), len(catalogue().families))
    found = search(r"lists all (\d+) families", text, REMEDIATION_DOC)
    assert int(found[1]) == len(catalogue().families)
    found = search(
        r"(\d+) rules have a native remediation: (.*?) \(\[native families\]", text, REMEDIATION_DOC
    )
    assert int(found[1]) == sum(counts.values())
    stated = {
        family: int(count) for count, family in re.findall(r"(\d+) (?:rules )?of `(\w+)`", found[2])
    }
    assert (
        f"the reference rule `xccdf_org.ssgproject.content_rule_{REFERENCE_FAMILY}_crontab`"
        in found[2]
    )
    assert counts[REFERENCE_FAMILY] == 1
    assert stated == {
        family: count for family, count in counts.items() if family != REFERENCE_FAMILY
    }


def test_the_family_table_of_the_remediation_page_follows_the_registry() -> None:
    loaded = catalogue()
    top: list[str] = []
    for family in loaded.families:
        name = loaded.umbrellas.get(family, family)
        if name not in top:
            top.append(name)
    found = search(
        r"The table names the (\d+) top-level topics", flat(REMEDIATION_DOC), REMEDIATION_DOC
    )
    assert int(found[1]) == len(top)
    expected = [
        f"| {'yes' if flag else 'no'} | "
        + ", ".join(
            f"`{name}`" for name in top if generate_toggles.is_disruptive(loaded, name) == flag
        )
        + " |"
        for flag in (False, True)
    ]
    assert table(REMEDIATION_DOC, FAMILY_TABLE_HEADER) == expected


def test_the_role_readme_states_the_counts_of_the_catalogue() -> None:
    text = flat(ROLE_README)
    found = search(r"(\d+) rules have a native remediation", text, ROLE_README)
    assert int(found[1]) == sum(native_counts().values())
    found = search(r"(\d+) rules in (\d+) families", text, ROLE_README)
    assert (int(found[1]), int(found[2])) == (len(catalogue().rules), len(catalogue().families))


def test_the_collection_design_names_no_ansible_core_version_but_the_pin() -> None:
    project = cast("dict[str, object]", tomllib.loads(PYPROJECT.read_text(encoding="utf-8")))
    groups = cast("dict[str, list[str]]", project["dependency-groups"])
    pins = [
        entry.removeprefix("ansible-core==")
        for entry in groups["dev"]
        if entry.startswith("ansible-core==")
    ]
    assert len(pins) == 1
    text = flat(COLLECTION_DESIGN)
    assert "[`pyproject.toml`](../pyproject.toml)" in text
    assert set(ANSIBLE_CORE_VERSION.findall(text)) <= set(pins)
