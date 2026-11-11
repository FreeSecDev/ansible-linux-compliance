"""List the Molecule legs that a branch must pass on a Docker host before it merges.

A pull request into ``integration`` runs only the fast tier on GitHub, without the Molecule jobs,
and the full matrix runs once a day in the merge queue of the promotion into ``main``
(ADR 0034). Before such a pull request merges, its author and its independent reviewer run the
Molecule legs that its change can affect on a Docker host, and the verdict lists them with their
results. This tool says which legs those are and how to run each one.

It does not classify paths itself. The plan comes from the base revision's planner, the same one
that the ``molecule-plan`` job runs (``tools/molecule/plan-lifecycle.sh`` and
``tools/roles/affected_topics.py``): every changed path is confined to native topics or plans the
full matrix, and an unknown path plans the full matrix. The tool checks the plan as the
``molecule-plan`` step does and plans the full matrix when the plan is missing, is not JSON or is
not a subset of the full matrices that keeps every leg without a topic (fail safe).

* **Lifecycle legs.** Every Docker leg of the plan, as ``molecule-lifecycle`` runs it. Of a
  ``full`` plan only the legs of the topics that the plan names are required; the others are
  optional, because one host runs about ten legs an hour and the daily full run covers them.
* **Standard scenarios.** The scenarios of the ``molecule-docker`` job of ``ci.yml``, read from
  the workflow, whenever the plan is full or keeps at least one lifecycle leg. A change that
  plans no lifecycle leg (documentation, unit tests, the lint tools) runs none.
* **libvirt legs.** Listed, but left to the daily full run: they need KVM and the libvirt host
  packages of the hosted runner (``docs/molecule-libvirt.md``).

The output is a Markdown table for the review verdict (one row per leg, with the ``make`` command
and a result column that the reviewer fills in), the worker commands one per line, or JSON.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple, cast

import yaml

from tools import yaml_loader

if TYPE_CHECKING:
    from collections.abc import Sequence

LEG_KEYS: Final[tuple[str, ...]] = ("platform", "scenario", "topic", "mode")
NAME: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9_-]*")
SCOPE_FULL: Final[str] = "full"
SCOPE_AFFECTED: Final[str] = "affected"
WORKER: Final[str] = "worker"
OPTIONAL: Final[str] = "worker, optional"
DAILY: Final[str] = "daily full run"
WHERE: Final[tuple[str, ...]] = (WORKER, OPTIONAL, DAILY)
DOCKER_SELFTEST: Final[str] = "docker-selftest"
LIBVIRT_SELFTEST: Final[str] = "libvirt-selftest"
LIBVIRT_SELFTEST_TARGET: Final[str] = "test-molecule-libvirt-selftest"
STANDARD_JOB: Final[str] = "molecule-docker"
NOT_RUN: Final[str] = "not run"
DEFERRED: Final[str] = "deferred"
FORMATS: Final[tuple[str, ...]] = ("markdown", "commands", "json")

Leg = dict[str, str]


class LegsError(Exception):
    """An input without which not even the full matrix can be listed."""


class Plan(NamedTuple):
    """The scope, topics and reasons of a plan, and the Docker and libvirt legs it keeps."""

    scope: str
    topics: tuple[str, ...]
    reasons: tuple[str, ...]
    docker: tuple[Leg, ...]
    libvirt: tuple[Leg, ...]


class Run(NamedTuple):
    """One leg: its CI job name, where it runs before the merge and its ``make`` arguments."""

    job: str
    where: str
    make: tuple[str, ...]


def _field(data: object, key: str) -> object:
    if not isinstance(data, dict):
        return None
    return cast("dict[object, object]", data).get(key)


def matrix_legs(data: object, where: str) -> list[Leg]:
    """Return the legs of a matrix printed by ``make molecule-matrix``.

    Raises:
        LegsError: When ``data`` is not such a matrix or a value is not a plain name.
    """
    include = _field(data, "include")
    if not isinstance(include, list):
        message = f"{where} is not a matrix with an include list"
        raise LegsError(message)
    legs: list[Leg] = []
    for entry in cast("list[object]", include):
        if not isinstance(entry, dict) or set(cast("dict[object, object]", entry)) != set(LEG_KEYS):
            message = f"{where}: every leg must have exactly the keys {', '.join(LEG_KEYS)}"
            raise LegsError(message)
        leg = cast("dict[str, object]", entry)
        if not all(isinstance(value, str) for value in leg.values()):
            message = f"{where}: every value of a leg must be a string"
            raise LegsError(message)
        found = {key: str(leg[key]) for key in LEG_KEYS}
        required = (found["platform"], found["scenario"])
        optional = (found["topic"], found["mode"])
        if not all(NAME.fullmatch(value) for value in required) or not all(
            value == "" or NAME.fullmatch(value) for value in optional
        ):
            message = f"{where}: a leg holds a value that is not a plain name: {found}"
            raise LegsError(message)
        legs.append(found)
    return legs


def standard_scenarios(workflow: object) -> list[str]:
    """Return the scenarios of the ``molecule-docker`` matrix of ``ci.yml``.

    Raises:
        LegsError: When the workflow has no such job or its scenarios are not plain names.
    """
    scenarios: object = workflow
    for key in ("jobs", STANDARD_JOB, "strategy", "matrix", "scenario"):
        scenarios = _field(scenarios, key)
    if (
        not isinstance(scenarios, list)
        or not scenarios
        or not all(
            isinstance(item, str) and NAME.fullmatch(item)
            for item in cast("list[object]", scenarios)
        )
    ):
        message = f"ci.yml has no {STANDARD_JOB} job with a list of scenario names"
        raise LegsError(message)
    return [str(item) for item in cast("list[object]", scenarios)]


def full_plan(docker: Sequence[Leg], libvirt: Sequence[Leg], reason: str) -> Plan:
    """Return the plan of the full matrices, for ``reason``."""
    return Plan(SCOPE_FULL, (), (reason,), tuple(docker), tuple(libvirt))


def _strings(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    items = cast("list[object]", value)
    if not all(isinstance(item, str) for item in items):
        return None
    return tuple(str(item) for item in items)


def _keeps(kept: Sequence[Leg], full: Sequence[Leg]) -> bool:
    return all(leg in full for leg in kept) and all(
        leg in kept for leg in full if leg["topic"] == ""
    )


def _validated(text: str, docker: Sequence[Leg], libvirt: Sequence[Leg]) -> Plan:
    if not text.strip():
        message = "the base revision's planner gave no plan"
        raise LegsError(message)
    try:
        data = cast("object", json.loads(text))
    except ValueError as error:
        message = "the plan is not JSON"
        raise LegsError(message) from error
    found = cast("dict[str, object]", data) if isinstance(data, dict) else {}
    scope = found.get("scope")
    topics = _strings(found.get("topics"))
    reasons = _strings(found.get("reasons"))
    if scope not in (SCOPE_FULL, SCOPE_AFFECTED) or topics is None or reasons is None:
        message = "the plan is not a JSON object with a scope, topics and reasons"
        raise LegsError(message)
    kept_docker = matrix_legs(found.get("docker"), "the plan's Docker matrix")
    kept_libvirt = matrix_legs(found.get("libvirt"), "the plan's libvirt matrix")
    if not _keeps(kept_docker, docker) or not _keeps(kept_libvirt, libvirt):
        message = (
            "the plan is not a subset of the full matrices that keeps every leg without a topic"
        )
        raise LegsError(message)
    if scope == SCOPE_FULL and (kept_docker != list(docker) or kept_libvirt != list(libvirt)):
        message = "the plan is full but does not hold the full matrices"
        raise LegsError(message)
    return Plan(str(scope), topics, reasons, tuple(kept_docker), tuple(kept_libvirt))


def checked_plan(text: str, docker: Sequence[Leg], libvirt: Sequence[Leg]) -> Plan:
    """Return the plan that ``text`` holds, or the full plan when it cannot be used."""
    try:
        return _validated(text, docker, libvirt)
    except LegsError as error:
        return full_plan(docker, libvirt, str(error))


def _standard_run(scenario: str) -> Run:
    if scenario == DOCKER_SELFTEST:
        return Run(f"{STANDARD_JOB} ({scenario})", WORKER, ("test-molecule-docker-selftest",))
    return Run(
        f"{STANDARD_JOB} ({scenario})",
        WORKER,
        (
            "test-molecule-docker",
            f"MOLECULE_DOCKER_SCENARIOS={scenario}",
            "MOLECULE_DOCKER_SELFTEST=false",
        ),
    )


def _lifecycle_run(leg: Leg, where: str) -> Run:
    return Run(
        f"molecule-lifecycle ({leg['platform']}, {leg['topic']}, {leg['mode']})",
        where,
        (
            "test-molecule-docker",
            f"MOLECULE_DOCKER_SCENARIOS={leg['scenario']}",
            "MOLECULE_DOCKER_SELFTEST=false",
            f"MOLECULE_LIFECYCLE_TOPIC={leg['topic']}",
            f"MOLECULE_LIFECYCLE_MODE={leg['mode']}",
        ),
    )


def _libvirt_run(leg: Leg) -> Run:
    platforms = f"MOLECULE_LIBVIRT_PLATFORMS={leg['platform']}"
    if leg["scenario"] == LIBVIRT_SELFTEST:
        job = f"molecule-libvirt ({leg['scenario']})"
        return Run(job, DAILY, (LIBVIRT_SELFTEST_TARGET, platforms))
    make = (
        "test-molecule-libvirt",
        f"MOLECULE_LIBVIRT_SCENARIOS={leg['scenario']}",
        platforms,
        "MOLECULE_LIBVIRT_SELFTEST=false",
    )
    if not leg["topic"]:
        return Run(f"molecule-libvirt ({leg['scenario']})", DAILY, make)
    return Run(
        f"molecule-libvirt ({leg['scenario']}, {leg['topic']}, {leg['mode']})",
        DAILY,
        (
            *make,
            f"MOLECULE_LIFECYCLE_TOPIC={leg['topic']}",
            f"MOLECULE_LIFECYCLE_MODE={leg['mode']}",
        ),
    )


def runs(plan: Plan, scenarios: Sequence[str]) -> list[Run]:
    """Return every leg of ``plan``, in the order: required, optional, daily full run.

    Every worker leg of an ``affected`` plan is required. Of a ``full`` plan, the standard
    scenarios and the legs of the topics that the plan names are required, and the other
    lifecycle legs are optional: the daily full run covers them, and the reviewer may ask for
    them (ADR 0034).
    """
    required: list[Run] = []
    optional: list[Run] = []
    if plan.scope == SCOPE_FULL or plan.docker:
        required.extend(_standard_run(scenario) for scenario in scenarios)
    for leg in plan.docker:
        if plan.scope == SCOPE_AFFECTED or leg["topic"] in plan.topics:
            required.append(_lifecycle_run(leg, WORKER))
        else:
            optional.append(_lifecycle_run(leg, OPTIONAL))
    daily = [_libvirt_run(leg) for leg in plan.libvirt]
    return [*required, *optional, *daily]


def command(run: Run, prefix: str) -> str:
    """Return the shell command of ``run``, after ``prefix`` when one is given."""
    line = shlex.join(("make", *run.make))
    return f"{prefix.strip()} {line}" if prefix.strip() else line


def render_markdown(plan: Plan, found: Sequence[Run], prefix: str) -> str:
    """Return the table of the legs for the review verdict, with the plan's reasons."""
    counts = {where: sum(run.where == where for run in found) for where in WHERE}
    topics = ", ".join(f"`{topic}`" for topic in plan.topics) or "none"
    lines = [
        f"Scope: `{plan.scope}`; topics: {topics}.",
        (
            f"Required on the worker: {counts[WORKER]}. Optional on the worker: "
            f"{counts[OPTIONAL]}. Left to the daily full run: {counts[DAILY]}."
        ),
        "",
        "| CI leg | Where | Command | Result |",
        "|---|---|---|---|",
    ]
    lines.extend(
        f"| `{run.job}` | {run.where} | `{command(run, prefix)}` | "
        f"{DEFERRED if run.where == DAILY else NOT_RUN} |"
        for run in found
    )
    lines.extend(["", "Planner reasons:", ""])
    lines.extend(f"- {reason}" for reason in plan.reasons or ("no path changed",))
    return "\n".join(lines)


def render_commands(found: Sequence[Run], prefix: str) -> str:
    """Return the commands of the required worker legs, one per line."""
    return "\n".join(command(run, prefix) for run in found if run.where == WORKER)


def render_json(plan: Plan, found: Sequence[Run], prefix: str) -> str:
    """Return the plan and its legs as one line of JSON."""
    document = {
        "scope": plan.scope,
        "topics": list(plan.topics),
        "reasons": list(plan.reasons),
        "legs": [
            {"job": run.job, "where": run.where, "command": command(run, prefix)} for run in found
        ],
    }
    return json.dumps(document, separators=(",", ":"))


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        message = f"{path} cannot be read: {error}"
        raise LegsError(message) from error


def _read_json(path: Path, where: str) -> object:
    try:
        return cast("object", json.loads(_read(path)))
    except ValueError as error:
        message = f"{where} ({path}) is not JSON: {error}"
        raise LegsError(message) from error


def read_workflow(path: Path) -> object:
    """Return the parsed workflow at ``path``.

    Raises:
        LegsError: When the file cannot be read or is not YAML.
    """
    try:
        return yaml_loader.safe_load(_read(path))
    except yaml.YAMLError as error:
        message = f"{path} is not YAML: {error}"
        raise LegsError(message) from error


def _plan_text(path: Path) -> str:
    try:
        return _read(path)
    except LegsError:
        return ""


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--plan", type=Path, required=True, help="Plan of the base's planner.")
    parser.add_argument("--docker", type=Path, required=True, help="Full Docker matrix.")
    parser.add_argument("--libvirt", type=Path, required=True, help="Full libvirt matrix.")
    parser.add_argument("--workflow", type=Path, required=True, help="The ci.yml workflow.")
    parser.add_argument("--format", choices=FORMATS, default="markdown")
    parser.add_argument("--prefix", default="", help="Put before each make command.")
    arguments = parser.parse_args(argv)
    try:
        docker = matrix_legs(
            _read_json(cast("Path", arguments.docker), "the Docker matrix"), "the Docker matrix"
        )
        libvirt = matrix_legs(
            _read_json(cast("Path", arguments.libvirt), "the libvirt matrix"),
            "the libvirt matrix",
        )
        scenarios = standard_scenarios(read_workflow(cast("Path", arguments.workflow)))
    except LegsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    plan = checked_plan(_plan_text(cast("Path", arguments.plan)), docker, libvirt)
    found = runs(plan, scenarios)
    prefix = cast("str", arguments.prefix)
    renderers = {
        "markdown": lambda: render_markdown(plan, found, prefix),
        "commands": lambda: render_commands(found, prefix),
        "json": lambda: render_json(plan, found, prefix),
    }
    print(renderers[cast("str", arguments.format)]())
    return 0


if __name__ == "__main__":
    sys.exit(main())
