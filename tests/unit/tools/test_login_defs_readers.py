"""The generator of the verdict table of the real login.defs readers (FREES-198)."""

from __future__ import annotations

import ctypes
import importlib
import json
import multiprocessing
import os
import runpy
import sys
import types
from typing import TYPE_CHECKING, ClassVar, Protocol, cast

import pytest

from tools.lint import login_defs_readers as readers

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

ECONF_NOKEY = 5


class Box(Protocol):
    """The target of a ctypes pointer: a C value."""

    value: object


class Pointer(Protocol):
    """A ctypes pointer that a fake C function writes through."""

    contents: Box


def function(method: Callable[..., object]) -> Callable[..., object]:
    """Return a plain function around ``method``, which takes ``argtypes`` like a C function."""

    def call(*arguments: object) -> object:
        return method(*arguments)

    return call


class FakeEconf:
    """Stands for libeconf 0.4.1: one configuration whose ``FAIL_DELAY`` is ``value``."""

    def __init__(self, value: bytes | None, *, readable: bool = True, present: bool = True) -> None:
        self.value = value
        self.readable = readable
        self.present = present
        self.freed = 0
        self.library = types.SimpleNamespace(
            econf_readDirs=function(self.read_dirs),
            econf_getStringValue=function(self.get_string),
            econf_getUInt64Value=function(self.get_number),
            econf_freeFile=function(self.free),
        )

    def read_dirs(self, handle: object, usr: object, *arguments: bytes) -> int:
        assert usr is None
        assert arguments == readers.ECONF_ARGUMENTS
        if not self.readable:
            return 1
        cast("Pointer", handle).contents.value = 1
        return 0

    def get_string(self, handle: object, group: object, key: bytes, out: object) -> int:
        assert isinstance(handle, ctypes.c_void_p)
        assert group is None
        assert key == readers.ECONF_KEY
        if not self.present:
            return ECONF_NOKEY
        cast("Pointer", out).contents.value = self.value
        return 0

    def get_number(self, handle: object, group: object, key: bytes, out: object) -> int:
        del handle, group, key
        digits = (self.value or b"").lstrip(b"-")
        number = int(digits or b"0")
        value = (-number if (self.value or b"").startswith(b"-") else number) % 2**64
        cast("Pointer", out).contents.value = value
        return 0

    def free(self, handle: object) -> None:
        assert isinstance(handle, ctypes.c_void_p)
        self.freed += 1

    def cdll(self) -> ctypes.CDLL:
        return cast("ctypes.CDLL", self.library)


def case(**extra: object) -> dict[str, object]:
    return {"name": "1 values case", "text": "PASS_MAX_DAYS 30\n", **extra}


def test_a_state_key_depends_on_the_text_the_drop_ins_and_the_links_only() -> None:
    one = readers.state_of("A b\n", {"b.defs": "x", "a.defs": "y"}, ["z.defs", "c.defs"])
    two = readers.state_of("A b\n", {"a.defs": "y", "b.defs": "x"}, ["c.defs", "z.defs"])
    assert readers.state_key(one) == readers.state_key(two)
    assert readers.state_key(one) != readers.state_key(readers.state_of("A c\n", {}, []))
    assert list(cast("dict[str, str]", one["dropins"])) == ["a.defs", "b.defs"]


def test_the_states_are_each_case_and_each_text_written_for_it() -> None:
    cases = [
        case(),
        case(name="2 values other", text="X\n", dropins={"a.defs": "y"}, links=["b.defs"]),
    ]
    decisions: dict[str, dict[str, object]] = {
        "1 values case": {"status": "applied", "written": "PASS_MAX_DAYS 30\nPASS_MIN_DAYS 1\n"},
        "2 values other": {"status": "compliant", "written": None},
    }
    states = readers.collect_states(cases, decisions)
    assert sorted(str(state["text"]) for state in states.values()) == [
        "PASS_MAX_DAYS 30\n",
        "PASS_MAX_DAYS 30\nPASS_MIN_DAYS 1\n",
        "X\n",
    ]


def test_a_state_is_written_and_installed_byte_for_byte(tmp_path: Path) -> None:
    states = {
        "plain": readers.state_of("A\r\nB\x00\n", {}, []),
        "dropins": readers.state_of("C\n", {"50-site.defs": "FAIL_DELAY 1\n"}, ["60-gone.defs"]),
        "links": readers.state_of("D\n", {}, ["70-gone.defs"]),
    }
    readers.write_states(states, tmp_path / "states")
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    readers.install(tmp_path / "states" / "dropins", root)
    dropins = root / "etc" / "login.defs.d"
    assert (root / "etc" / "login.defs").read_bytes() == b"C\n"
    assert (dropins / "50-site.defs").read_bytes() == b"FAIL_DELAY 1\n"
    assert str((dropins / "60-gone.defs").readlink()) == readers.BROKEN_LINK_TARGET
    readers.install(tmp_path / "states" / "links", root)
    assert sorted(path.name for path in dropins.iterdir()) == ["70-gone.defs"]
    readers.install(tmp_path / "states" / "plain", root)
    assert (root / "etc" / "login.defs").read_bytes() == b"A\r\nB\x00\n"
    assert not dropins.exists()
    assert not dropins.is_symlink()
    written = json.loads((tmp_path / "states" / readers.STATES_FILE).read_text(encoding="utf-8"))
    assert written == states


@pytest.mark.parametrize("kind", ["file", "link"])
def test_a_drop_in_directory_that_is_a_file_or_a_link_is_replaced(
    tmp_path: Path, kind: str
) -> None:
    readers.write_states(
        {"key": readers.state_of("A\n", {"a.defs": "B\n"}, [])}, tmp_path / "states"
    )
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    dropins = root / "etc" / "login.defs.d"
    if kind == "file":
        dropins.write_text("x", encoding="ascii")
    else:
        dropins.symlink_to(tmp_path)
    readers.install(tmp_path / "states" / "key", root)
    assert dropins.is_dir()
    assert not dropins.is_symlink()
    assert (dropins / "a.defs").read_text(encoding="ascii") == "B\n"


@pytest.mark.parametrize(
    ("fake", "expected"),
    [
        (FakeEconf(b"30"), 30),
        (FakeEconf(b"-1"), 2**32 - 1),
        (FakeEconf(None), "null"),
        (FakeEconf(b"30", present=False), "nokey"),
    ],
)
def test_libeconf_is_read_as_util_linux_login_reads_it(fake: FakeEconf, expected: object) -> None:
    readers.configure(fake.cdll())
    assert readers.read_econf(fake.cdll()) == expected
    assert fake.freed == 1


def test_a_configuration_that_libeconf_cannot_read_is_an_error() -> None:
    fake = FakeEconf(b"30", readable=False)
    assert readers.read_econf(fake.cdll()) == "error"
    assert fake.freed == 0


def test_the_shadow_output_is_parsed_with_the_versions() -> None:
    text = "#shadow\tpasswd 1:4.13\nkey\t0\t-1\t7\t700\tyes\nother\terror\terror\terror\tnone\tno\n"
    versions, readings = readers.parse_shadow(text)
    assert versions == {"shadow": "passwd 1:4.13"}
    assert readings == {
        "key": {
            "minimum": 0,
            "maximum": -1,
            "warning": 7,
            "home_mode": "700",
            "home_created": True,
        },
        "other": {
            "minimum": "error",
            "maximum": "error",
            "warning": "error",
            "home_mode": "none",
            "home_created": False,
        },
    }
    with pytest.raises(ValueError, match="malformed shadow reading"):
        readers.parse_shadow("key\t0\n")


def write_outputs(directory: Path, key: str) -> None:
    for platform in readers.PLATFORMS:
        line = f"#shadow\t{platform}\n{key}\t0\t365\t7\t750\tyes\n"
        (directory / f"{platform}-shadow.tsv").write_text(line, encoding="utf-8")
    (directory / "rocky-econf.json").write_text(json.dumps({key: 4}), encoding="utf-8")


def test_the_main_entry_prepares_installs_reads_and_merges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cases_file = tmp_path / "cases.json"
    cases_file.write_text(json.dumps({"cases": [case()]}), encoding="utf-8")
    decisions_file = tmp_path / "decisions.json"
    decisions_file.write_text(json.dumps({"1 values case": {"written": None}}), encoding="utf-8")
    directory = tmp_path / "states"
    assert readers.main(["prepare", str(cases_file), str(decisions_file), str(directory)]) == 0
    key = readers.state_key(readers.case_state(case()))
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    assert readers.main(["install", str(directory / key)], root=root) == 0
    assert (root / "etc" / "login.defs").read_text(encoding="utf-8") == "PASS_MAX_DAYS 30\n"
    fake = FakeEconf(b"4")

    def load_library(name: str) -> ctypes.CDLL:
        assert name == readers.LIBECONF
        return fake.cdll()

    monkeypatch.setattr(ctypes, "CDLL", load_library)
    assert readers.main(["econf", str(directory)], root=root) == 0
    assert json.loads(capsys.readouterr().out) == {key: 4}
    assert readers.main(["econf", str(directory)], library=FakeEconf(b"9").cdll(), root=root) == 0
    assert json.loads(capsys.readouterr().out) == {key: 9}
    write_outputs(directory, key)
    output = tmp_path / "verdicts.json"
    assert readers.main(["merge", str(directory), str(output)]) == 0
    table = json.loads(output.read_text(encoding="utf-8"))
    assert table["readers"] == {"ubuntu": {"shadow": "ubuntu"}, "rocky": {"shadow": "rocky"}}
    assert table["states"][key]["rocky"]["libeconf"] == 4
    assert table["states"][key]["ubuntu"]["maximum"] == 365
    assert "libeconf" not in table["states"][key]["ubuntu"]


def test_the_script_entry_point_runs_a_subcommand(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "verdicts.json"
    readers.write_states({"state": readers.state_of("A\n", {}, [])}, tmp_path)
    for platform in readers.PLATFORMS:
        reading = "state\t0\t1\t2\t700\tno\n"
        (tmp_path / f"{platform}-shadow.tsv").write_text(reading, encoding="utf-8")
    (tmp_path / "rocky-econf.json").write_text(json.dumps({"state": "nokey"}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["login_defs_readers.py", "merge", str(tmp_path), str(output)])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(readers.__file__, run_name="__main__")
    assert raised.value.code == 0
    table = json.loads(output.read_text(encoding="utf-8"))
    assert table["states"]["state"]["rocky"]["libeconf"] == "nokey"


class FakeProcess:
    """Stands for a spawned process that ends with ``exitcode`` or keeps running."""

    started: ClassVar[list[tuple[object, ...]]] = []

    def __init__(self, args: tuple[object, ...], *, alive: bool, exitcode: int) -> None:
        self.args = args
        self.alive = alive
        self.exitcode = exitcode
        self.killed = False

    def start(self) -> None:
        FakeProcess.started.append(self.args)

    def join(self, timeout: float | None = None) -> None:
        del timeout

    def is_alive(self) -> bool:
        return self.alive and not self.killed

    def kill(self) -> None:
        self.killed = True


@pytest.mark.parametrize(("alive", "exitcode"), [(False, 0), (True, -9), (False, 2)])
def test_the_decisions_run_in_a_spawned_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, alive: bool, exitcode: int
) -> None:
    def context(method: str) -> types.SimpleNamespace:
        assert method == "spawn"

        def process(target: object, args: tuple[object, ...]) -> FakeProcess:
            assert target is readers.run_playbook
            return FakeProcess(args, alive=alive, exitcode=exitcode)

        return types.SimpleNamespace(Process=process)

    monkeypatch.setattr(multiprocessing, "get_context", context)
    FakeProcess.started.clear()
    if exitcode == 0:
        readers.decide(tmp_path / "cases.json", tmp_path / "out.json")
        expected = "build/collections"
    else:
        with pytest.raises(RuntimeError, match="failed"):
            readers.decide(tmp_path / "cases.json", tmp_path / "out.json", tmp_path)
        expected = tmp_path.name
    arguments, environment = cast("tuple[list[str], dict[str, str]]", FakeProcess.started[0])
    assert arguments[-1].endswith("tests/fixtures/login_defs_readers/decide.yml")
    assert environment["ANSIBLE_COLLECTIONS_PATH"].endswith(expected)


def test_the_playbook_runs_with_only_the_environment_given(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    class PlaybookCLI:
        """Stands for the playbook CLI of ansible-core."""

        def __init__(self, arguments: list[str]) -> None:
            calls.append(arguments)

        def run(self) -> int:
            return 0

    def import_module(name: str) -> types.SimpleNamespace:
        assert name == "ansible.cli.playbook"
        return types.SimpleNamespace(PlaybookCLI=PlaybookCLI)

    environment: dict[str, str] = {"KEPT": "no"}
    monkeypatch.setattr(os, "environ", environment)
    monkeypatch.setattr(importlib, "import_module", import_module)
    with pytest.raises(SystemExit) as raised:
        readers.run_playbook(["ansible-playbook", "x.yml"], {"LC_ALL": "C"})
    assert raised.value.code == 0
    assert calls == [["ansible-playbook", "x.yml"]]
    assert environment == {"LC_ALL": "C"}


def test_the_decide_subcommand_decides_the_cases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[Path, Path]] = []

    def decide(cases: Path, output: Path) -> None:
        seen.append((cases, output))

    monkeypatch.setattr(readers, "decide", decide)
    assert readers.main(["decide", str(tmp_path / "c.json"), str(tmp_path / "d.json")]) == 0
    assert seen == [(tmp_path / "c.json", tmp_path / "d.json")]
