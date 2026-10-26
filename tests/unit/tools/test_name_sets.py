from __future__ import annotations

import importlib
import json
import os
import runpy
import subprocess
import sys
import types
from typing import TYPE_CHECKING

import pytest
import yaml

from tools.lint import check_repo_rules as rules
from tools.lint import generate_name_sets as generator
from tools.lint import name_set_probe as probe

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

PYTHON_VARIABLE = "FREESECDEV_NAME_SET_PYTHON"
PROBE_TIMEOUT_SECONDS = 120
WORKFLOW = rules.REPO_ROOT / ".github" / "workflows" / "ci.yml"


def target_python() -> str:
    return os.environ.get(PYTHON_VARIABLE) or sys.executable


def run_probe(python: str, modules: Sequence[str] | None = None) -> tuple[str, generator.Snapshot]:
    arguments = generator.probe_modules() if modules is None else modules
    result = subprocess.run(
        [python, "-I", "-S", str(generator.PROBE_SCRIPT), *arguments],
        capture_output=True,
        text=True,
        check=True,
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    return generator.parse_probe(result.stdout)


@pytest.fixture(scope="module")
def probed() -> tuple[str, generator.Snapshot]:
    return run_probe(target_python())


def test_checked_in_name_sets_cover_the_target_interpreter(
    probed: tuple[str, generator.Snapshot],
) -> None:
    _, snapshot = probed
    assert snapshot.stdlib_module_names <= rules.STDLIB_MODULE_NAMES
    assert snapshot.submodule_attributes <= rules.KNOWN_SUBMODULE_ATTRIBUTES
    assert {"annotationlib", "sre_compile", "errno", "_sysconfigdata"} <= rules.STDLIB_MODULE_NAMES
    assert {"annotationlib", "builtins", "bltns"} <= rules.KNOWN_SUBMODULE_ATTRIBUTES
    assert {"path", "expat", "parsers"} <= rules.SUBMODULE_ATTRIBUTES


def test_the_generator_reproduces_the_snapshot_of_the_target_interpreter(
    probed: tuple[str, generator.Snapshot],
) -> None:
    version, snapshot = probed
    recorded = generator.load_snapshots(generator.SNAPSHOT_FILE)[version]
    if snapshot.python != recorded.python:
        pytest.skip(
            f"the {version} snapshot was recorded on Python {recorded.python}, this is"
            f" {snapshot.python}; the name-sets CI job runs every recorded release"
        )
    assert snapshot.modules == recorded.modules
    assert snapshot.stdlib_module_names == recorded.stdlib_module_names
    assert snapshot.submodule_attributes == recorded.submodule_attributes


def test_the_ci_matrix_runs_every_recorded_supported_release() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["name-sets"]
    snapshots = generator.load_snapshots(generator.SNAPSHOT_FILE)
    supported = [snapshots[version].python for version in generator.SNAPSHOT_VERSIONS[:-1]]
    assert job["strategy"]["matrix"]["python"] == supported
    assert job["strategy"]["fail-fast"] is False
    assert "name-sets" in workflow["jobs"]["ci-gate"]["needs"]


def test_the_checked_in_constants_are_the_union_of_the_snapshots() -> None:
    snapshots = generator.load_snapshots(generator.SNAPSHOT_FILE)
    assert tuple(snapshots) == generator.SNAPSHOT_VERSIONS
    names, attributes = generator.union(snapshots)
    assert names == rules.STDLIB_MODULE_NAMES
    assert attributes == rules.KNOWN_SUBMODULE_ATTRIBUTES
    source = generator.GUARD_FILE.read_text(encoding="utf-8")
    assert generator.replace_constants(source, names, attributes) == source
    text = generator.SNAPSHOT_FILE.read_text(encoding="utf-8")
    assert generator.dump_snapshots(snapshots) == text


def test_every_snapshot_probed_the_current_module_list() -> None:
    for snapshot in generator.load_snapshots(generator.SNAPSHOT_FILE).values():
        assert snapshot.modules == generator.probe_modules()


def test_the_generator_check_mode_passes_on_the_repository() -> None:
    assert generator.main(["--check"]) == 0


def test_the_probe_does_not_see_modules_imported_by_the_test_session() -> None:
    tool = importlib.import_module("json.tool")
    assert isinstance(getattr(json, "tool", None), types.ModuleType)
    assert tool is sys.modules["json.tool"]
    assert "tool" not in rules.KNOWN_SUBMODULE_ATTRIBUTES
    _, snapshot = run_probe(sys.executable)
    assert "tool" not in snapshot.submodule_attributes


def test_the_probed_modules_include_parent_packages_but_not_reserved_ones() -> None:
    modules = generator.probe_modules()
    assert "collections" in modules
    assert "collections.abc" in modules
    assert "os" in modules
    assert "xml.parsers.expat" in modules
    assert "xml" not in modules
    assert "xml.parsers" not in modules
    assert {"collections", "functools", "itertools"}.isdisjoint(rules.ALLOWED_IMPORTS)
    assert dict(rules.RESERVED_ATTRIBUTES) == {
        "expat": "plugins/module_utils/compliance/xmlsafe.py",
        "parsers": "plugins/module_utils/compliance/xmlsafe.py",
    }


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("_sysconfigdata__linux_x86_64-linux-gnu", "_sysconfigdata"),
        ("_sysconfigdata__linux_aarch64-linux-gnu", "_sysconfigdata"),
        ("_sysconfigdata__darwin_darwin", "_sysconfigdata"),
        ("_sysconfigdata_m_linux_x86_64-linux-gnu", "_sysconfigdata"),
        ("_sysconfigdata", "_sysconfigdata"),
        ("_sysconfig", "_sysconfig"),
        ("sysconfig", "sysconfig"),
        ("json", "json"),
    ],
)
def test_platform_specific_names_are_normalised(name: str, expected: str) -> None:
    assert probe.normalise(name) == expected


def test_the_probe_falls_back_to_the_directories_without_stdlib_module_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(sys, "stdlib_module_names")
    names = probe.stdlib_module_names()
    assert {"json", "os", "sys", "_sysconfigdata"} <= set(names)
    assert not [name for name in names if name.startswith("_sysconfigdata_")]
    assert names == sorted(names)


def test_the_directory_enumeration_finds_builtin_pure_and_extension_modules() -> None:
    names = probe.enumerate_stdlib()
    assert {"sys", "json", "pathlib", "_json"} <= names


def test_the_probe_rereads_attributes_until_they_are_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rounds = iter([frozenset({"a"}), frozenset({"a", "b"}), frozenset({"a", "b"})])

    def next_round(_modules: Sequence[types.ModuleType]) -> frozenset[str]:
        return next(rounds)

    monkeypatch.setattr(probe, "module_attributes", next_round)
    assert probe.submodule_attributes(["json"]) == ["a", "b"]


def test_the_probe_resolves_attributes_through_getattr() -> None:
    module = types.ModuleType("fake")
    vars(module).update(child=types.ModuleType("fake.child"), value=1)
    assert probe.module_attributes([module]) == frozenset({"child"})


def test_the_probe_main_prints_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert probe.main(["json", "collections.abc"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["modules"] == ["collections.abc", "json"]
    assert data["version"] == f"{sys.version_info[0]}.{sys.version_info[1]}"
    assert "decoder" in data["submodule_attributes"]


def test_the_probe_main_reads_the_command_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["name_set_probe.py", "json"])
    assert probe.main() == 0
    assert json.loads(capsys.readouterr().out)["modules"] == ["json"]


def probe_text(**changes: object) -> str:
    data: dict[str, object] = {
        "python": "3.12.14",
        "version": "3.12",
        "modules": list(generator.probe_modules()),
        "stdlib_module_names": ["json", "os"],
        "submodule_attributes": ["decoder"],
    }
    data.update(changes)
    return json.dumps(data)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("not json", "not JSON"),
        ("[]", "must be a JSON object"),
        ('{"python": "3.12.0"}', "exactly the keys"),
        (probe_text(python=""), "python must be a non-empty string"),
        (probe_text(python=3), "python must be a non-empty string"),
        (probe_text(modules="json"), "modules must be a list of strings"),
        (probe_text(stdlib_module_names=[1]), "stdlib_module_names must be a list of strings"),
        (probe_text(submodule_attributes=None), "submodule_attributes must be a list"),
        (probe_text(version="3.8", python="3.8.20"), "Python 3.8 is not one of"),
        (probe_text(version="3.12", python="3.13.1"), "names Python 3.13.1 for version 3.12"),
        (probe_text(version="3.1", python="3.12.1"), "Python 3.1 is not one of"),
    ],
)
def test_invalid_probe_output_is_rejected(text: str, message: str) -> None:
    with pytest.raises(generator.NameSetError, match=message):
        generator.parse_probe(text)


def test_a_valid_probe_output_is_parsed() -> None:
    version, snapshot = generator.parse_probe(probe_text())
    assert version == "3.12"
    assert snapshot.python == "3.12.14"
    assert snapshot.stdlib_module_names == frozenset({"json", "os"})
    assert snapshot.submodule_attributes == frozenset({"decoder"})


def test_a_missing_snapshot_file_holds_no_snapshots(tmp_path: Path) -> None:
    assert generator.load_snapshots(tmp_path / "missing.json") == {}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("{", "is not JSON"),
        ("[]", "must be a JSON object"),
        ('{"2.7": {}}', "Python 2.7 is not one of"),
        ('{"3.12": []}', "3.12 must be a JSON object"),
        ('{"3.12": {"python": "3.12.1"}}', "exactly the keys"),
    ],
)
def test_an_invalid_snapshot_file_is_rejected(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "name_sets.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(generator.NameSetError, match=message):
        generator.load_snapshots(path)


def test_snapshots_round_trip_in_version_order(tmp_path: Path) -> None:
    _, newer = generator.parse_probe(probe_text())
    _, older = generator.parse_probe(probe_text(version="3.9", python="3.9.25"))
    path = tmp_path / "name_sets.json"
    path.write_text(generator.dump_snapshots({"3.12": newer, "3.9": older}), encoding="utf-8")
    loaded = generator.load_snapshots(path)
    assert list(loaded) == ["3.9", "3.12"]
    assert loaded["3.12"] == newer


def test_the_union_combines_every_snapshot() -> None:
    _, first = generator.parse_probe(probe_text(stdlib_module_names=["a"]))
    _, second = generator.parse_probe(
        probe_text(version="3.9", python="3.9.25", submodule_attributes=["b"])
    )
    names, attributes = generator.union({"3.12": first, "3.9": second})
    assert names == frozenset({"a", "json", "os"})
    assert attributes == frozenset({"decoder", "b"})


def test_a_constant_is_rendered_wrapped_sorted_and_unbroken() -> None:
    words = [f"name{index:03d}" for index in range(40)] + ["_sysconfigdata__linux_x86_64-linux-gnu"]
    text = generator.render_constant("NAMES", reversed(words))
    lines = text.splitlines()
    assert lines[0] == "NAMES: Final[frozenset[str]] = _words("
    assert lines[-1] == ")"
    assert all(len(line) <= 100 for line in lines)
    assert all(line.endswith(' "') for line in lines[1:-2])
    assert lines[1].startswith('    "_sysconfigdata__linux_x86_64-linux-gnu ')
    assert not lines[-2].endswith(' "')
    rendered = " ".join(line.strip().strip('"') for line in lines[1:-1]).split()
    assert rendered == sorted(words)


GUARD_SOURCE = (
    "from typing import Final\n"
    "\n"
    "def _words(text):\n"
    "    return frozenset(text.split())\n"
    "\n"
    'STDLIB_MODULE_NAMES: Final[frozenset[str]] = _words("old")\n'
    "OTHER = 1\n"
    "KNOWN_SUBMODULE_ATTRIBUTES: Final[frozenset[str]] = _words(\n"
    '    "x "\n'
    '    "y"\n'
    ")\n"
    "TAIL = 2\n"
)


def test_the_constants_are_replaced_in_place() -> None:
    result = generator.replace_constants(GUARD_SOURCE, ["json", "os"], ["decoder"])
    assert result == (
        "from typing import Final\n"
        "\n"
        "def _words(text):\n"
        "    return frozenset(text.split())\n"
        "\n"
        "STDLIB_MODULE_NAMES: Final[frozenset[str]] = _words(\n"
        '    "json os"\n'
        ")\n"
        "OTHER = 1\n"
        "KNOWN_SUBMODULE_ATTRIBUTES: Final[frozenset[str]] = _words(\n"
        '    "decoder"\n'
        ")\n"
        "TAIL = 2\n"
    )


@pytest.mark.parametrize(
    "source",
    [
        "OTHER = 1\n",
        (
            "STDLIB_MODULE_NAMES: int = 1\n"
            "STDLIB_MODULE_NAMES: int = 2\n"
            "KNOWN_SUBMODULE_ATTRIBUTES: int = 3\n"
        ),
        "def f():\n    STDLIB_MODULE_NAMES: int = 1\nKNOWN_SUBMODULE_ATTRIBUTES: int = 3\n",
        "STDLIB_MODULE_NAMES = 1\nKNOWN_SUBMODULE_ATTRIBUTES: int = 3\n",
        "x.STDLIB_MODULE_NAMES: int = 1\nKNOWN_SUBMODULE_ATTRIBUTES: int = 3\n",
    ],
)
def test_a_guard_without_exactly_one_assignment_is_rejected(source: str) -> None:
    with pytest.raises(generator.NameSetError, match="exactly once at module level"):
        generator.replace_constants(source, ["a"], ["b"])


def test_the_main_prints_the_modules(capsys: pytest.CaptureFixture[str]) -> None:
    assert generator.main(["--modules"]) == 0
    assert tuple(capsys.readouterr().out.split()) == generator.probe_modules()


def write_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    probe_file = tmp_path / "3.12.json"
    probe_file.write_text(probe_text(), encoding="utf-8")
    guard = tmp_path / "guard.py"
    guard.write_text(GUARD_SOURCE, encoding="utf-8")
    return probe_file, guard, tmp_path / "name_sets.json"


def test_the_main_writes_the_snapshot_and_the_guard(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    probe_file, guard, snapshot = write_inputs(tmp_path)
    arguments = ["--guard", str(guard), "--snapshot", str(snapshot)]
    assert generator.main([*arguments, "--check", str(probe_file)]) == 1
    assert "out of date" in capsys.readouterr().err
    assert not snapshot.exists()
    assert generator.main([*arguments, str(probe_file)]) == 0
    assert "Python 3.12" in capsys.readouterr().out
    assert list(generator.load_snapshots(snapshot)) == ["3.12"]
    assert '"json os"' in guard.read_text(encoding="utf-8")
    assert generator.main([*arguments, "--check"]) == 0
    assert generator.main([*arguments, "--check", str(probe_file)]) == 0
    assert generator.main(arguments) == 0


def test_the_main_rejects_a_probe_of_other_modules(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    probe_file, guard, snapshot = write_inputs(tmp_path)
    probe_file.write_text(probe_text(modules=["json"]), encoding="utf-8")
    arguments = ["--guard", str(guard), "--snapshot", str(snapshot), str(probe_file)]
    assert generator.main(arguments) == 1
    assert "probed ['json'], expected" in capsys.readouterr().err
    assert guard.read_text(encoding="utf-8") == GUARD_SOURCE


def test_the_main_reports_an_invalid_guard(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    probe_file, guard, snapshot = write_inputs(tmp_path)
    guard.write_text("OTHER = 1\n", encoding="utf-8")
    arguments = ["--guard", str(guard), "--snapshot", str(snapshot), str(probe_file)]
    assert generator.main(arguments) == 1
    assert "error: the guard source must assign" in capsys.readouterr().err
    assert not snapshot.exists()


def test_the_generator_script_entry_point(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["generate_name_sets", "--modules"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(generator.LINT_DIRECTORY / "generate_name_sets.py"), run_name="__main__")
    assert raised.value.code == 0
    assert tuple(capsys.readouterr().out.split()) == generator.probe_modules()


def test_the_probe_script_entry_point(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["name_set_probe.py", "json"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(generator.PROBE_SCRIPT), run_name="__main__")
    assert raised.value.code == 0
    assert json.loads(capsys.readouterr().out)["modules"] == ["json"]


def test_the_main_refuses_to_write_empty_name_sets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, guard, snapshot = write_inputs(tmp_path)
    assert generator.main(["--guard", str(guard), "--snapshot", str(snapshot)]) == 1
    assert "error: no snapshots" in capsys.readouterr().err
    assert guard.read_text(encoding="utf-8") == GUARD_SOURCE
