"""Per-task timings of a Molecule run from its GitHub Actions job log (FREES-180)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.molecule import task_timings

if TYPE_CHECKING:
    from pathlib import Path

LOG = """\
2026-10-30T11:35:00.0000000Z ##[group]Run make test-molecule-libvirt
2026-10-30T11:35:03.2794945Z INFO     [libvirt-ubuntu-lifecycle > create] Executing
2026-10-30T11:35:04.0000000Z PLAY [Create disposable libvirt virtual machines] ****
2026-10-30T11:35:04.5000000Z TASK [Refuse a scenario name | that cannot form names] ****
2026-10-30T11:35:04.5100000Z ok: [localhost]
2026-10-30T11:35:06.0000000Z TASK [Wait until every instance answers on SSH] ****
2026-10-30T11:35:22.0000000Z PLAY RECAP *****
2026-10-30T11:35:22.1000000Z INFO     [libvirt-ubuntu-lifecycle > create] Completed: Successful
2026-10-30T11:35:23.0000000Z INFO     [libvirt-ubuntu-lifecycle > side_effect] Executing
2026-10-30T11:35:24.0000000Z \x1b[0;32mTASK [Snapshot | Find every entry] ****\x1b[0m
2026-10-30T11:36:00.0000000Z TASK [Snapshot | Record every entry] ****
2026-10-30T11:36:10Z TASK [Snapshot | Find every entry] ****
2026-10-30T11:36:40.0000000Z RUNNING HANDLER [Restart nothing] ****
2026-10-30T11:36:41.0000000Z PLAY RECAP *****
not a log line
"""


def test_tasks_are_timed_to_the_next_banner_and_attributed_to_their_action() -> None:
    found = task_timings.tasks(LOG.splitlines())
    assert [(task.action, task.name, round(task.seconds, 2)) for task in found] == [
        ("create", "Refuse a scenario name | that cannot form names", 1.5),
        ("create", "Wait until every instance answers on SSH", 16.0),
        ("side_effect", "Snapshot | Find every entry", 36.0),
        ("side_effect", "Snapshot | Record every entry", 10.0),
        ("side_effect", "Snapshot | Find every entry", 30.0),
        ("side_effect", "Restart nothing", 1.0),
    ]


def test_the_prefix_of_gh_run_view_is_accepted() -> None:
    lines = [f"job\tstep\t{line}" for line in LOG.splitlines()]
    assert len(task_timings.tasks(lines)) == 6


def test_a_log_without_tasks_is_refused() -> None:
    with pytest.raises(task_timings.TimingError):
        task_timings.tasks(["2026-10-30T11:35:00Z PLAY RECAP ****", "plain text"])


def test_the_report_lists_actions_single_runs_and_repeated_tasks() -> None:
    found = task_timings.tasks(LOG.splitlines())
    text = task_timings.report(found, 2)
    assert "| create | 0.3 |" in text
    assert "| side_effect | 1.3 |" in text
    assert "| 1 | 36.0 | side_effect | Snapshot \\| Find every entry |" in text
    assert "| 2 | 30.0 | side_effect | Snapshot \\| Find every entry |" in text
    assert "| 1 | 66.0 | 2 | side_effect | Snapshot \\| Find every entry |" in text
    assert "| 2 | 16.0 | 1 | create | Wait until every instance answers on SSH |" in text
    assert "| 3 |" not in text


def test_main_prints_the_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "job.log"
    log.write_text(LOG, encoding="utf-8")
    assert task_timings.main([str(log), "--top", "1"]) == 0
    assert "Top 1 single task runs:" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--top", "0"], "--top must be at least 1"),
        ([], "no timestamped Ansible task"),
        (["--missing"], "No such file"),
    ],
)
def test_main_refuses_bad_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], arguments: list[str], message: str
) -> None:
    log = tmp_path / "job.log"
    log.write_text("2026-10-30T11:35:00Z nothing\n", encoding="utf-8")
    path = str(tmp_path / "absent.log") if "--missing" in arguments else str(log)
    options = [argument for argument in arguments if argument != "--missing"]
    assert task_timings.main([path, *options]) == 2
    assert message in capsys.readouterr().err
