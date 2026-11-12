"""The tracer of the sysctl reader verdicts (FREES-208): every write to a watched file, in order.

The tests trace real child processes with ptrace(2), as the generator does in the Molecule images:
each child stops itself before it executes Python, as the oracle starts a reader, so they need
Linux on x86_64 and a shell.
"""

from __future__ import annotations

import base64
import os
import platform
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools.molecule import sysctl_trace

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or platform.machine() != sysctl_trace.MACHINE,
    reason="ptrace(2) system calls and registers of Linux on x86_64",
)
SHELL = shutil.which("sh") or "/bin/sh"
STOPPED = 'kill -STOP "$$"; exec "$0" "$@"'


def stopped_child(*argv: str) -> subprocess.Popen[bytes]:
    """Start ``argv`` in a shell that stops itself before it executes it, as the oracle does."""
    return subprocess.Popen(
        [SHELL, "-c", STOPPED, *argv],
        stdout=subprocess.DEVNULL,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )


def run(tmp_path: Path, code: str) -> tuple[int, list[tuple[str, bytes]]]:
    """Trace a Python child that runs ``code`` in ``tmp_path``; return the status and record."""
    watched = tmp_path / "watched"
    watched.write_text(f"{tmp_path / 'a'}\n\n{tmp_path / 'b'}\n", encoding="utf-8")
    out = tmp_path / "out"
    child = stopped_child(sys.executable, "-I", "-S", "-c", code, str(tmp_path))
    try:
        status = sysctl_trace.main([str(child.pid), str(watched), str(out)])
    finally:
        child.kill()
        child.wait(timeout=30)
    record = [
        (Path(path).name, base64.b64decode(encoded))
        for path, _, encoded in (
            line.partition("\t") for line in out.read_text(encoding="utf-8").splitlines()
        )
    ]
    return status, record


def test_every_write_to_a_watched_file_is_recorded_in_order(tmp_path: Path) -> None:
    code = (
        "import os, sys\n"
        "d = sys.argv[1]\n"
        "for name, data in (('a', b'0\\n'), ('c', b'x\\n'), ('b', b'1\\n'), ('a', b'25\\n')):\n"
        "    with open(os.path.join(d, name), 'wb', buffering=0) as f:\n"
        "        f.write(data)\n"
        "fd = os.open(os.path.join(d, 'b'), os.O_WRONLY)\n"
        "os.pwrite(fd, b'7', 0)\n"
        "try:\n"
        "    os.write(987, b'nothing')\n"
        "except OSError:\n"
        "    pass\n"
        "os.writev(os.open(os.path.join(d, 'c'), os.O_WRONLY), [b'not watched'])\n"
        "sys.exit(4)\n"
    )
    status, record = run(tmp_path, code)
    assert status == 0
    assert record == [("a", b"0\n"), ("b", b"1\n"), ("a", b"25\n"), ("b", b"7")]


WRITEV = (
    "import os, sys\n"
    "fd = os.open(os.path.join(sys.argv[1], 'a'), os.O_WRONLY | os.O_CREAT)\n"
    "os.writev(fd, [b'0\\n'])\n"
)
FORK = "import os\nif os.fork() == 0:\n    os._exit(0)\n"


@pytest.mark.parametrize(
    ("code", "message"), [(WRITEV, "with writev"), (FORK, "the reader called clone")]
)
def test_a_write_or_a_process_that_the_record_would_miss_stops_the_tracing(
    tmp_path: Path, code: str, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    status, _ = run(tmp_path, code)
    assert status == sysctl_trace.FAILED
    assert message in capsys.readouterr().err


def test_a_signal_is_passed_on_and_an_exec_is_followed(tmp_path: Path) -> None:
    code = (
        "import os, signal, sys\n"
        "signal.signal(signal.SIGUSR1, lambda *_: open(os.path.join(sys.argv[1], 'a'), 'w')"
        ".write('1\\n'))\n"
        "os.kill(os.getpid(), signal.SIGUSR1)\n"
        "os.execv(sys.executable, [sys.executable, '-I', '-S', '-c',"
        ' \'import sys; open(sys.argv[1] + "/b", "w").write("2\\\\n")\', sys.argv[1]])\n'
    )
    status, record = run(tmp_path, code)
    assert status == 0
    assert record == [("a", b"1\n"), ("b", b"2\n")]


def test_a_reader_that_ends_before_it_is_traced_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_request(*_arguments: object) -> None:
        return None

    def ended(pid: int, _options: int) -> tuple[int, int]:
        return pid, 0

    monkeypatch.setattr(sysctl_trace, "ptrace", no_request)
    monkeypatch.setattr(os, "waitpid", ended)
    with pytest.raises(sysctl_trace.TraceError, match="ended before it could be traced"):
        sysctl_trace.trace(4242, frozenset(), tmp_path / "out")


def test_a_failed_request_is_an_error() -> None:
    with pytest.raises(sysctl_trace.TraceError, match="ptrace request 12"):
        sysctl_trace.registers(os.getpid())


@pytest.mark.parametrize("argv", [[], ["x", "w", "o"], ["1", "w"], ["1", "w", "o", "z"]])
def test_a_call_without_a_reader_is_refused(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert sysctl_trace.main(argv) == sysctl_trace.FAILED
    assert "usage" in capsys.readouterr().err


def test_another_machine_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(platform, "machine", lambda: "aarch64")
    assert sysctl_trace.main(["1", "w", "o"]) == sysctl_trace.FAILED
    assert "needs x86_64, not aarch64" in capsys.readouterr().err


def test_the_tool_runs_as_a_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    watched = tmp_path / "watched"
    watched.write_text(f"{tmp_path / 'a'}\n", encoding="utf-8")
    child = stopped_child(sys.executable, "-I", "-S", "-c", "pass")
    arguments = ["sysctl_trace", str(child.pid), str(watched), str(tmp_path / "out")]
    monkeypatch.setattr(sys, "argv", arguments)
    sys.modules.pop("tools.molecule.sysctl_trace", None)
    try:
        with pytest.raises(SystemExit) as exit_info:
            runpy.run_module("tools.molecule.sysctl_trace", run_name="__main__")
    finally:
        child.kill()
        child.wait(timeout=30)
    assert exit_info.value.code == 0
    assert (tmp_path / "out").read_text(encoding="utf-8") == ""
