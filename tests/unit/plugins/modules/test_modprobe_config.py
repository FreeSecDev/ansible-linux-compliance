"""Tests of modprobe_config against output captured from the real kmod of both pinned images.

``tests/fixtures/kmod/showconfig/<image>/<scenario>/`` holds what ``modprobe -c -d /dev`` printed
in a throwaway, network-less container of each pinned Molecule image (kmod 31 on Ubuntu 24.04,
kmod 28 on Rocky Linux 9) with every modprobe directory emptied and two files written::

    /etc/modprobe.d/00-site.conf      blacklist cramfs / install cram* /sbin/modprobe ...
    /usr/lib/modprobe.d/vendor.conf   blacklist hfs / blacklist nouveau / install hfs  /bin/false

``/proc/cmdline`` was bind-mounted from the file ``cmdline`` of each scenario: ``plain`` without a
modprobe entry, ``blacklist`` with ``modprobe.blacklist=nouveau,foo pty.legacy_count=0``. For each,
``null.out`` is ``-C /dev/null``, ``site.out`` and ``vendor.out`` are ``-C`` with that file, and
``default.out`` is the whole configuration. kmod parses the command line after the files, so its
blacklist entries are the last ones of every run.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from ansible.module_utils.testing import patch_module_args

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    process,
)
from ansible_collections.freesecdev.linux_compliance.plugins.modules import modprobe_config

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

MODULE_FILE = Path(__file__).resolve().parents[4] / "plugins" / "modules" / "modprobe_config.py"
CAPTURES = Path(__file__).resolve().parents[3] / "fixtures" / "kmod" / "showconfig"
END = b"\n# End of configuration files. Dumping indexes now:\n\n"
SITE = "/etc/modprobe.d/00-site.conf"
VENDOR = "/usr/lib/modprobe.d/vendor.conf"
CAPTURED = sorted(
    f"{image.name}/{scenario.name}"
    for image in CAPTURES.iterdir()
    for scenario in image.iterdir()
    if scenario.is_dir()
)
HARDEST = "ubuntu-kmod31/blacklist"
RUNS: dict[tuple[str, ...], str] = {
    (): "default.out",
    ("-C", "/dev/null"): "null.out",
    ("-C", SITE): "site.out",
    ("-C", VENDOR): "vendor.out",
}


def captured(capture: str) -> dict[tuple[str, ...], bytes]:
    """Return what the real modprobe printed for each argument list of ``capture``."""
    return {extra: (CAPTURES / capture / name).read_bytes() for extra, name in RUNS.items()}


OUTPUTS: dict[tuple[str, ...], bytes] = captured(HARDEST)


def result(
    stdout: bytes = b"",
    returncode: int = 0,
    stderr: bytes = b"",
    *,
    timed_out: bool = False,
    truncated: bool = False,
) -> process.CommandResult:
    return process.CommandResult(
        argv=("/usr/sbin/modprobe",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=truncated,
        stderr_truncated=False,
        duration_seconds=0.01,
        timed_out=timed_out,
    )


def from_outputs(extra: tuple[str, ...]) -> process.CommandResult:
    return result(OUTPUTS[extra])


def fails(_extra: tuple[str, ...]) -> process.CommandResult:
    return result(b"", 1, b"modprobe: FATAL: \x1b[31mbroken\n")


def times_out(_extra: tuple[str, ...]) -> process.CommandResult:
    return result(b"", timed_out=True)


def overflows(_extra: tuple[str, ...]) -> process.CommandResult:
    return result(b"x", truncated=True)


def puts_the_command_line_first(extra: tuple[str, ...]) -> process.CommandResult:
    first = b"blacklist nouveau\nblacklist foo\nblacklist cramfs\nblacklist hfs\n"
    first += b"blacklist nouveau\n"
    return result(OUTPUTS[extra] if extra else first + END)


def loses_it_for_one_file(extra: tuple[str, ...]) -> process.CommandResult:
    return result(b"blacklist cramfs\n" + END if extra == ("-C", SITE) else OUTPUTS[extra])


class Captured:
    """Answers every run with what the real modprobe printed for one capture."""

    def __init__(self, capture: str) -> None:
        self.outputs = captured(capture)

    def __call__(self, extra: tuple[str, ...]) -> process.CommandResult:
        return result(self.outputs[extra])


class FakeRun:
    """Checks each specification against the shipped policy and answers per argument list."""

    def __init__(
        self, answer: Callable[[tuple[str, ...]], process.CommandResult] | None = None
    ) -> None:
        self.answer = answer or from_outputs
        self.specs: list[process.CommandSpec] = []

    def __call__(self, spec: process.CommandSpec) -> process.CommandResult:
        assert process.check_policy(spec).name == "modprobe"
        assert spec.args[:3] == process.MODPROBE_SHOW_CONFIG
        self.specs.append(spec)
        return self.answer(spec.args[3:])


def found(name: str) -> str:
    assert name == "modprobe"
    return "/usr/sbin/modprobe"


def install(monkeypatch: pytest.MonkeyPatch, fake: FakeRun) -> FakeRun:
    monkeypatch.setattr(process, "resolve_executable", found)
    monkeypatch.setattr(process, "run", fake)
    return fake


def run(
    capsys: pytest.CaptureFixture[str], arguments: Mapping[str, object]
) -> tuple[int, dict[str, object]]:
    capsys.readouterr()
    with patch_module_args(dict(arguments)), pytest.raises(SystemExit) as raised:
        modprobe_config.main()
    output = capsys.readouterr().out
    return int(cast("int", raised.value.code)), cast("dict[str, object]", json.loads(output))


def test_the_captures_are_the_two_pinned_kmods_with_and_without_a_command_line_blacklist() -> None:
    assert CAPTURED == [
        "rocky-kmod28/blacklist",
        "rocky-kmod28/plain",
        "ubuntu-kmod31/blacklist",
        "ubuntu-kmod31/plain",
    ]
    assert (CAPTURES / "rocky-kmod28" / "kmod-version").read_text() == "kmod version 28\n"
    assert (CAPTURES / "ubuntu-kmod31" / "kmod-version").read_text() == "kmod version 31\n"
    for capture in CAPTURED:
        command_line = (CAPTURES / capture / "cmdline").read_text()
        blacklisted = "modprobe.blacklist=nouveau,foo" in command_line
        assert blacklisted is capture.endswith("/blacklist")


@pytest.mark.parametrize("capture", [c for c in CAPTURED if c.endswith("/blacklist")])
def test_kmod_puts_the_blacklist_of_the_command_line_after_every_file(capture: str) -> None:
    outputs = captured(capture)
    command_line = modprobe_config.directives(outputs[("-C", "/dev/null")].decode())
    assert command_line == {"install": [], "blacklist": ["nouveau", "foo"]}
    for extra in RUNS:
        blacklist = modprobe_config.directives(outputs[extra].decode())["blacklist"]
        assert blacklist[-2:] == ["nouveau", "foo"]
    assert modprobe_config.directives(outputs[()].decode())["blacklist"] == [
        "cramfs",
        "hfs",
        "nouveau",
        "nouveau",
        "foo",
    ]


def test_the_policy_allows_only_the_two_read_only_forms() -> None:
    for arguments in (("-c", "-d", "/dev"), ("-c", "-d", "/dev", "-C", SITE)):
        assert process.check_policy(process.CommandSpec("modprobe", arguments, 1)).name == (
            "modprobe"
        )
    refused: tuple[tuple[str, ...], ...] = (
        (),
        ("cramfs",),
        ("-r", "cramfs"),
        ("-n", "-v", "cramfs"),
        ("-c",),
        ("-c", "-d", "/srv"),
        ("-c", "-d", "/dev", "-C", "relative.conf"),
        ("-c", "-d", "/dev", "-C", SITE, "cramfs"),
        ("-c", "-d", "/dev", "--config", SITE),
        ("--showconfig", "-d", "/dev"),
    )
    for refusal in refused:
        with pytest.raises(process.ProcessPolicyError):
            process.check_policy(process.CommandSpec("modprobe", refusal, 1))


@pytest.mark.parametrize("capture", CAPTURED)
def test_each_file_has_its_own_directives_without_the_command_line(
    monkeypatch: pytest.MonkeyPatch, capture: str
) -> None:
    fake = install(monkeypatch, FakeRun(Captured(capture)))
    outcome = modprobe_config.read([SITE, VENDOR])
    assert outcome["available"] is True
    assert outcome["consistent"] is True
    assert outcome["message"] == ""
    assert outcome["files"] == [
        {
            "path": SITE,
            "install": [{"module": "cram*", "command": "/sbin/modprobe --ignore-install cramfs"}],
            "blacklist": ["cramfs"],
        },
        {
            "path": VENDOR,
            "install": [{"module": "hfs", "command": "/bin/false"}],
            "blacklist": ["hfs", "nouveau"],
        },
    ]
    assert cast("dict[str, list[object]]", outcome["merged"])["blacklist"] == [
        "cramfs",
        "hfs",
        "nouveau",
    ]
    assert [spec.args[3:] for spec in fake.specs] == [
        ("-C", "/dev/null"),
        (),
        ("-C", SITE),
        ("-C", VENDOR),
    ]
    assert {spec.timeout_seconds for spec in fake.specs} == {modprobe_config.TIMEOUT_SECONDS}


@pytest.mark.parametrize("capture", CAPTURED)
def test_files_in_another_order_or_a_missing_file_are_not_consistent(
    monkeypatch: pytest.MonkeyPatch, capture: str
) -> None:
    install(monkeypatch, FakeRun(Captured(capture)))
    for files in ([VENDOR, SITE], [SITE], []):
        outcome = modprobe_config.read(files)
        assert outcome["consistent"] is False
        assert "differ from the configuration that modprobe reads" in str(outcome["message"])


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (fails, "exited with 1: modprobe"),
        (times_out, "did not finish within 30 s"),
        (overflows, "printed more than"),
        (puts_the_command_line_first, "the kernel command line are not at the end"),
        (loses_it_for_one_file, "do not end with the command line"),
    ],
)
def test_a_failed_or_odd_run_is_not_consistent(
    monkeypatch: pytest.MonkeyPatch,
    answer: Callable[[tuple[str, ...]], process.CommandResult],
    message: str,
) -> None:
    install(monkeypatch, FakeRun(answer))
    outcome = modprobe_config.read([SITE, VENDOR])
    assert outcome["available"] is True
    assert outcome["consistent"] is False
    assert message in str(outcome["message"])


def test_a_link_that_leaves_the_modprobe_directories_is_never_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = os.path.realpath

    def resolved(path: str) -> str:
        return "/etc/shadow" if path == VENDOR else real(path)

    fake = install(monkeypatch, FakeRun())
    monkeypatch.setattr(os.path, "realpath", resolved)
    outcome = modprobe_config.read([SITE, VENDOR])
    assert outcome["available"] is True
    assert outcome["consistent"] is False
    assert f"{VENDOR} is not a configuration file of a modprobe directory" in str(
        outcome["message"]
    )
    assert ("-C", VENDOR) not in [spec.args[3:] for spec in fake.specs]


def test_a_missing_modprobe_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str) -> str:
        message = f"executable not found in the trusted directories: {name!r}"
        raise process.ProcessExecutionError(message)

    fake = install(monkeypatch, FakeRun())
    monkeypatch.setattr(process, "resolve_executable", missing)
    outcome = modprobe_config.read([SITE])
    assert outcome["available"] is False
    assert outcome["consistent"] is False
    assert outcome["files"] == []
    assert fake.specs == []


@pytest.mark.parametrize(
    "files",
    [
        "x",
        ["/etc/modprobe.d"] * 300,
        [1],
        ["/srv/x.conf"],
        ["/etc/modprobe.d/../shadow.conf"],
        ["/etc/modprobe.d/sub/x.conf"],
        ["/etc/modprobe.d/.hidden.conf"],
        ["/etc/modprobe.d/x.txt"],
        ["/etc/modprobe.d/x\n.conf"],
        ["etc/modprobe.d/x.conf"],
    ],
)
def test_a_file_outside_the_modprobe_directories_is_refused(files: object) -> None:
    with pytest.raises(modprobe_config.FileError):
        modprobe_config.checked_files(files)


def test_the_directives_stop_at_the_end_of_the_configuration() -> None:
    assert modprobe_config.directives(
        "blacklist a\ninstall b  c d\ninstall broken\nblacklist\n"
        "# End of configuration files. Dumping indexes now:\nblacklist z\n"
    ) == {"install": [{"module": "b", "command": "c d"}], "blacklist": ["a"]}


def test_an_unsafe_modprobe_fails_the_module(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def unsafe(name: str) -> str:
        message = f"executable is writable by group or others: {name!r}"
        raise process.ProcessPolicyError(message)

    fake = install(monkeypatch, FakeRun())
    monkeypatch.setattr(process, "resolve_executable", unsafe)
    code, outcome = run(capsys, {"files": [SITE]})
    assert code == 1
    assert "could not be run safely" in str(outcome["msg"])
    assert fake.specs == []


def test_the_directives_without_an_end_marker_are_all_read() -> None:
    assert modprobe_config.directives("blacklist a\ninstall b c") == {
        "install": [{"module": "b", "command": "c"}],
        "blacklist": ["a"],
    }


def test_a_modprobe_that_cannot_start_fails_the_module(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def cannot_start(extra: tuple[str, ...]) -> process.CommandResult:
        message = f"cannot start 'modprobe': Permission denied {extra}"
        raise process.ProcessExecutionError(message)

    install(monkeypatch, FakeRun(cannot_start))
    code, outcome = run(capsys, {"files": [SITE]})
    assert code == 1
    assert "cannot start" in str(outcome["msg"])


def test_the_module_reports_without_change_also_in_check_mode(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, FakeRun())
    code, outcome = run(capsys, {"files": [SITE, VENDOR], "_ansible_check_mode": True})
    assert code == 0
    assert outcome["changed"] is False
    assert outcome["consistent"] is True


def test_the_module_refuses_a_file_before_running_modprobe(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = install(monkeypatch, FakeRun())
    code, outcome = run(capsys, {"files": ["/etc/shadow"]})
    assert code == 1
    assert "not a configuration file" in str(outcome["msg"])
    assert fake.specs == []


def test_the_module_runs_as_a_script(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, FakeRun(lambda _extra: result(OUTPUTS[("-C", "/dev/null")])))
    spec = importlib.util.spec_from_file_location("__main__", MODULE_FILE)
    assert spec is not None
    assert spec.loader is not None
    capsys.readouterr()
    with patch_module_args({}), pytest.raises(SystemExit) as raised:
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
    assert raised.value.code == 0
