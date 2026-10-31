"""The generator of the pwquality verdict table and its probe, without a container (FREES-200)."""

from __future__ import annotations

import base64
import ctypes
import json
import runpy
import sys
from typing import TYPE_CHECKING, Protocol, cast

import pytest

from tools.lint import pwquality_readers as readers
from tools.lint import pwquality_readers_probe as probe

if TYPE_CHECKING:
    from pathlib import Path


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class IntPointer(Protocol):
    """A ctypes pointer to an int, as the probe passes it."""

    @property
    def contents(self) -> ctypes.c_int:
        """Return the int pointed to."""
        ...


class FakeFunction:
    """A function of the fake library, with the attributes that ``load`` sets."""

    def __init__(self, answer: object = 0) -> None:
        self.answer = answer
        self.restype: object = None
        self.argtypes: object = None
        self.calls: list[tuple[object, ...]] = []

    def __call__(self, *arguments: object) -> object:
        self.calls.append(arguments)
        return self.answer


class FakeGetInt(FakeFunction):
    """Stores 7 for every setting that the probe asks for."""

    def __call__(self, *arguments: object) -> object:
        settings, setting, value = arguments
        assert settings == 1
        assert setting in probe.SETTING_IDS.values()
        cast("IntPointer", value).contents.value = 7
        return 0


class FakeLibrary:
    """Holds every setting at 7 and records the options it is given."""

    def __init__(self, error: int = 0) -> None:
        self.pwquality_default_settings = FakeFunction(1)
        self.pwquality_read_config = FakeFunction(error)
        self.pwquality_set_option = FakeFunction(0)
        self.pwquality_free_settings = FakeFunction(None)
        self.pwquality_get_int_value = FakeGetInt()


def test_install_puts_every_kind_of_entry_in_place(tmp_path: Path) -> None:
    old = tmp_path / "etc/security/pwquality.conf.d/old.conf"
    old.parent.mkdir(parents=True)
    old.write_text("x")
    (tmp_path / "etc/security/pwquality.conf").write_text("old")
    state: dict[str, object] = {
        "main": b64("minlen = 14\n"),
        "dropins": [
            {"name": "10-a.conf", "type": "file", "content": b64("difok = 2\n")},
            {"name": "20-d.conf", "type": "directory"},
            {"name": "30-l.conf", "type": "link", "content": b64("minlen = 9\n")},
            {"name": "40-g.conf", "type": "dangling"},
        ],
    }
    probe.install(tmp_path, state)
    directory = tmp_path / "etc/security/pwquality.conf.d"
    assert (tmp_path / "etc/security/pwquality.conf").read_text() == "minlen = 14\n"
    assert sorted(path.name for path in directory.iterdir()) == [
        "10-a.conf",
        "20-d.conf",
        "30-l.conf",
        "40-g.conf",
    ]
    assert (directory / "20-d.conf").is_dir()
    assert (directory / "30-l.conf").read_text() == "minlen = 9\n"
    assert not (directory / "40-g.conf").exists()
    probe.install(tmp_path, {"main": None, "dropins": []})
    assert not (tmp_path / "etc/security/pwquality.conf").exists()
    assert list(directory.iterdir()) == []


def test_read_applies_the_arguments_and_returns_every_setting(tmp_path: Path) -> None:
    library = FakeLibrary(-4)
    found = probe.read(cast("probe.Library", library), [b64("minlen=9")])
    assert found == [-4, *([7] * len(probe.SETTING_IDS))]
    assert library.pwquality_set_option.calls == [(1, b"minlen=9")]
    assert library.pwquality_free_settings.calls == [(1,)]
    states = tmp_path / "states.json"
    states.write_text(json.dumps({"k": {"main": None, "dropins": [], "arguments": []}}))
    assert probe.probe(states, tmp_path, cast("probe.Library", library)) == {
        "k": [-4, *([7] * len(probe.SETTING_IDS))]
    }


def test_the_probe_loads_the_library_and_prints_the_readings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    library = FakeLibrary()

    def fake_cdll(name: str) -> FakeLibrary:
        assert name == "libpwquality.so.1"
        return library

    monkeypatch.setattr(ctypes, "CDLL", fake_cdll)
    states = tmp_path / "states.json"
    states.write_text(json.dumps({"k": {"main": b64("x"), "dropins": []}}))
    assert probe.main([str(states), "--root", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == {"k": [0, *([7] * len(probe.SETTING_IDS))]}
    assert library.pwquality_read_config.argtypes is not None


CASES = {
    "cases": [
        {
            "name": "plain",
            "main": "minlen = 9\n",
            "pam": "# password requisite pam_pwquality.so minlen=1\n\n"
            "password requisite pam_unix.so\npassword requisite pam_pwquality.so retry=3\n",
        },
        {
            "name": "dropins",
            "main": None,
            "dropins": [
                {"name": "10-a.conf", "type": "file", "content": "difok = 2\n"},
                {"name": "50-freesecdev-minlen.conf", "type": "file", "content": "minlen = 1\n"},
                {"name": "20-d.conf", "type": "directory"},
                {"name": "30-l.conf", "type": "link", "content": "minlen = 9\n"},
                {"name": "40-g.conf", "type": "dangling"},
            ],
        },
    ]
}


def test_prepare_and_merge_write_the_table(tmp_path: Path) -> None:
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps(CASES))
    work = tmp_path / "work"
    assert readers.main(["prepare", str(cases), str(work)]) == 0
    states = cast("dict[str, dict[str, object]]", json.loads((work / "states.json").read_text()))
    decisions = cast("list[dict[str, object]]", json.loads((work / "decisions.json").read_text()))
    assert len(decisions) == len(CASES["cases"]) * len(readers.RULES) * len(readers.METHODS)
    plain = states[cast("str", decisions[0]["state"])]
    assert plain["arguments"] == [b64("retry=3")]
    for platform in readers.PLATFORMS:
        (work / f"{platform}.json").write_text(json.dumps({key: [0] for key in states}))
        (work / f"{platform}.version").write_text(f"{platform} 1.4\n")
    table = tmp_path / "verdicts.json"
    assert readers.main(["merge", str(work), str(table)]) == 0
    document = json.loads(table.read_text())
    assert document["readers"] == {"rocky": "rocky 1.4", "ubuntu": "ubuntu 1.4"}
    assert document["settings"] == list(readers.SETTINGS)
    assert set(document["verdicts"]) == set(states)
    assert document["decisions"][0][:4] == ["plain", "minlen", "main_file", "applied"]


def test_the_cases_without_pam_pass_no_arguments() -> None:
    assert readers.arguments_of({"name": "x"}) == []
    assert readers.pam_of({"name": "x"}) == []


def test_both_scripts_run_as_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps({"cases": []}))
    monkeypatch.setattr(sys, "argv", ["pwquality_readers", "prepare", str(cases), str(tmp_path)])
    monkeypatch.delitem(sys.modules, "tools.lint.pwquality_readers", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.lint.pwquality_readers", run_name="__main__")
    assert raised.value.code == 0
    library = FakeLibrary()

    def fake_cdll(name: str) -> FakeLibrary:
        assert name == "libpwquality.so.1"
        return library

    monkeypatch.setattr(ctypes, "CDLL", fake_cdll)
    arguments = ["probe", str(tmp_path / "states.json"), "--root", str(tmp_path)]
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.delitem(sys.modules, "tools.lint.pwquality_readers_probe", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.lint.pwquality_readers_probe", run_name="__main__")
    assert raised.value.code == 0
    assert json.loads(capsys.readouterr().out) == {}


def test_two_states_never_share_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    states: dict[str, dict[str, object]] = {}
    first: dict[str, object] = {"main": None, "dropins": [], "arguments": []}
    assert readers.keep(states, first) == readers.state_key(first)
    assert readers.keep(states, dict(first)) == readers.state_key(first)

    def same_key(state: dict[str, object]) -> str:
        assert state
        return "0" * 16

    monkeypatch.setattr(readers, "state_key", same_key)
    other: dict[str, object] = {"main": "eA==", "dropins": [], "arguments": []}
    with pytest.raises(ValueError, match="share the key"):
        readers.keep({"0" * 16: first}, other)
