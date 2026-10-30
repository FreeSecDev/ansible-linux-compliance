"""Print the slowest Ansible tasks of a Molecule run from its GitHub Actions job log (FREES-180).

GitHub Actions stamps every line of a job log with the time the runner received it, and Ansible's
default callback prints a banner when each task starts. The time of a task is therefore the time
from its ``TASK [...]`` or ``RUNNING HANDLER [...]`` banner to the next banner of any kind (a task,
handler, play, play recap or Molecule action). This needs no callback plugin in the run: the
repository rules refuse ``callbacks_enabled`` and its environment variable, because a callback
is code that Ansible loads (ADR 0004).

The input is the log of one job as the web interface or
``gh api repos/<owner>/<repo>/actions/jobs/<id>/logs`` downloads it (``<timestamp> <text>`` per
line); the tab-separated job and step prefix of ``gh run view --log`` is accepted too. Each task
is attributed to the Molecule action that runs it (``create``, ``prepare``, ``side_effect``,
``destroy``, ...). The output is Markdown: the time of each action, the slowest single tasks and
the tasks whose repeated runs take the most time in total.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

LINE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[^\t]*\t){0,2}(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z (.*)$"
)
ESCAPE: Final[re.Pattern[str]] = re.compile(r"\x1b\[[0-9;]*m")
TASK: Final[re.Pattern[str]] = re.compile(r"^(?:TASK|RUNNING HANDLER) \[(.*)\] \**$")
OTHER_BANNER: Final[re.Pattern[str]] = re.compile(r"^(?:PLAY \[.*\] \**|PLAY RECAP \**)$")
ACTION: Final[re.Pattern[str]] = re.compile(r"\[[^\]]* > ([a-z_]+)\] (?:Executing|Completed)")
NO_ACTION: Final[str] = "-"


class TimingError(ValueError):
    """The log holds no timestamped Ansible task."""


@dataclass(frozen=True)
class Task:
    """One run of one task: its Molecule action, its name and its duration in seconds."""

    action: str
    name: str
    seconds: float


def _timestamp(base: str, fraction: str | None) -> float:
    moment = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    return moment.timestamp() + (float(f"0.{fraction}") if fraction else 0.0)


def tasks(lines: Iterable[str]) -> list[Task]:
    """Return every task run of the log with its duration, in log order."""
    found: list[Task] = []
    action = NO_ACTION
    current: tuple[str, str, float] | None = None
    for raw in lines:
        match = LINE.match(raw.rstrip("\r\n"))
        if match is None:
            continue
        when = _timestamp(match.group(1), match.group(2))
        text = ESCAPE.sub("", match.group(3)).strip()
        task = TASK.match(text)
        marker = ACTION.search(text)
        if task is None and marker is None and OTHER_BANNER.match(text) is None:
            continue
        if current is not None:
            found.append(Task(current[0], current[1], max(0.0, when - current[2])))
            current = None
        if marker is not None:
            action = marker.group(1)
        if task is not None:
            current = (action, task.group(1), when)
    if not found:
        message = "the log holds no timestamped Ansible task followed by another banner"
        raise TimingError(message)
    return found


def action_totals(found: Iterable[Task]) -> dict[str, float]:
    """Return the summed task time of each Molecule action, in order of first appearance."""
    totals: dict[str, float] = {}
    for task in found:
        totals[task.action] = totals.get(task.action, 0.0) + task.seconds
    return totals


def repeated(found: Iterable[Task]) -> list[tuple[str, str, int, float]]:
    """Return ``(action, name, runs, total seconds)`` per task name, the largest total first."""
    totals: dict[tuple[str, str], tuple[int, float]] = {}
    for task in found:
        runs, seconds = totals.get((task.action, task.name), (0, 0.0))
        totals[task.action, task.name] = (runs + 1, seconds + task.seconds)
    rows = [(action, name, runs, seconds) for (action, name), (runs, seconds) in totals.items()]
    return sorted(rows, key=lambda row: (-row[3], row[0], row[1]))


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def report(found: Sequence[Task], top: int) -> str:
    """Return the Markdown report of the ``top`` slowest tasks."""
    total = sum(task.seconds for task in found)
    lines = ["| Action | Minutes |", "|---|---|"]
    lines += [
        f"| {action} | {seconds / 60:.1f} |" for action, seconds in action_totals(found).items()
    ]
    lines += [f"| all tasks | {total / 60:.1f} |", ""]
    lines += [f"Top {top} single task runs:", ""]
    lines += ["| # | Seconds | Action | Task |", "|---|---|---|---|"]
    slowest = sorted(found, key=lambda task: -task.seconds)[:top]
    lines += [
        f"| {rank} | {task.seconds:.1f} | {task.action} | {_cell(task.name)} |"
        for rank, task in enumerate(slowest, 1)
    ]
    lines += ["", f"Top {top} tasks by total time over their runs:", ""]
    lines += ["| # | Seconds | Runs | Action | Task |", "|---|---|---|---|---|"]
    lines += [
        f"| {rank} | {seconds:.1f} | {runs} | {action} | {_cell(name)} |"
        for rank, (action, name, runs, seconds) in enumerate(repeated(found)[:top], 1)
    ]
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--top", type=int, default=15)
    arguments = parser.parse_args(argv)
    top = cast("int", arguments.top)
    if top < 1:
        print("error: --top must be at least 1", file=sys.stderr)
        return 2
    try:
        text = cast("Path", arguments.log).read_text(encoding="utf-8", errors="replace")
        found = tasks(text.splitlines())
    except (OSError, TimingError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(report(found, top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
