"""The writer of the auditd.conf cases and of the verdict table (FREES-110)."""

from __future__ import annotations

import json
import runpy
import sys
from typing import TYPE_CHECKING, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditconf,
)
from tools.molecule import auditd_conf_verdicts as verdicts

if TYPE_CHECKING:
    from pathlib import Path

BASE = "# auditd.conf\nlocal_events = yes\nSpace_Left = 75\nadmin_space_left = 50\nfreq = 50\n"
STARTED = "space_left_parser called with: 80\nCannot change priority (Operation not permitted)\n"


def test_without_and_setting_change_only_the_lines_of_the_keyword() -> None:
    assert "space_left" not in verdicts.without(BASE, "space_left").lower().replace(
        "admin_space", ""
    )
    changed = verdicts.setting(BASE, "space_left", "80")
    assert changed.endswith("space_left = 80\n")
    assert changed.count("space_left = ") == 2
    assert "admin_space_left = 50" in changed


def test_the_cases_cover_the_line_forms_and_every_keyword() -> None:
    cases = verdicts.all_cases(BASE)
    assert cases["as_built"] == BASE
    assert cases["no_final_newline"].endswith("space_left = 80")
    assert "\x00" in cases["nul_byte"]
    for keyword in auditconf.KEYWORDS:
        assert any(name.startswith(f"value_{keyword}_") for name in cases), keyword
    assert len(cases) == len(verdicts.structural(BASE)) + len(verdicts.keyword_cases(BASE))


@pytest.mark.parametrize(
    ("form", "expected"),
    [
        (auditconf.KEYWORDS["flush"], "frobnicate"),
        (auditconf.KEYWORDS["freq"], "1.5"),
        (auditconf.KEYWORDS["log_file"], "/a b"),
        (auditconf.KEYWORDS["space_left"], "99%"),
    ],
)
def test_each_form_has_valid_values_and_one_that_auditd_refuses(
    form: auditconf.Form, expected: str
) -> None:
    samples = verdicts.values(form)
    assert samples[-1] == expected
    assert len(samples) >= 3


def test_the_cases_are_written_as_files(tmp_path: Path) -> None:
    base = tmp_path / "base.conf"
    base.write_text(BASE, encoding="utf-8")
    names = verdicts.write_cases(base, tmp_path / "cases")
    assert names == sorted(verdicts.all_cases(BASE))
    assert (tmp_path / "cases" / "as_built.conf").read_text(encoding="utf-8") == BASE


@pytest.mark.parametrize(
    ("status", "output", "expected"),
    [
        (6, 'Unknown keyword "x" in line 3 of /etc/audit/auditd.conf\n', "refused"),
        (1, STARTED, "accepted"),
        (4, "You must be root or have capabilities to run this program.\n", "accepted"),
        (124, "", "unobservable"),
        (1, "something else\n", "unobservable"),
    ],
)
def test_the_verdict_follows_the_status_and_how_far_auditd_got(
    status: int, output: str, expected: str
) -> None:
    found = verdicts.verdict(status, output)
    assert found["verdict"] == expected
    assert found["status"] == status


def test_the_verdict_keeps_the_values_read_and_the_messages_but_no_notices() -> None:
    output = (
        "Config file /etc/audit/auditd.conf opened for parsing\n"
        "space_left_parser called with: 80\n"
        "Listener support is not enabled, ignoring value at line 28\n"
        "Skipping line 41 in /etc/audit/auditd.conf: too long\n"
        "Cannot change priority (Operation not permitted)\n"
        "The audit daemon is exiting.\n"
    )
    found = verdicts.verdict(1, output)
    assert found["read"] == [["space_left", "80"]]
    assert found["messages"] == [
        "Skipping line 41 in /etc/audit/auditd.conf: too long",
        "Cannot change priority (Operation not permitted)",
    ]


def results_directory(tmp_path: Path, names: list[str]) -> Path:
    results = tmp_path / "results"
    results.mkdir()
    for name in names:
        (results / f"{name}.out").write_text(STARTED, encoding="utf-8")
        (results / f"{name}.status").write_text("1\n", encoding="utf-8")
    return results


def test_the_results_are_read_per_case(tmp_path: Path) -> None:
    results = results_directory(tmp_path, ["a", "b"])
    found = verdicts.read_results(results, ["a", "b"])
    assert set(found) == {"a", "b"}
    assert found["a"]["verdict"] == "accepted"


def test_a_missing_table_is_empty_and_merging_replaces_one_platform(tmp_path: Path) -> None:
    table = verdicts.load_table(tmp_path / "missing.json")
    assert table == {"platforms": {}, "cases": {}}
    header: dict[str, object] = {"package": "auditd", "version": "1", "base": BASE}
    built = {"verdict": "accepted", "status": 1, "read": [["freq", "50"]], "messages": []}
    first = verdicts.merge(table, "ubuntu", header, {"as_built": built, "a": built})
    refused = {"verdict": "refused", "status": 6, "read": [], "messages": ["bad"]}
    second = verdicts.merge(
        first, "ubuntu", {**header, "version": "2"}, {"as_built": built, "b": refused}
    )
    cases = cast("dict[str, dict[str, dict[str, object]]]", second["cases"])
    assert "a" not in cases
    assert cases["b"]["ubuntu"] == {"verdict": "refused", "status": 6, "messages": ["bad"]}
    header_found = cast("dict[str, dict[str, object]]", second["platforms"])["ubuntu"]
    assert header_found["version"] == "2"
    assert header_found["read"] == {"freq": "50"}
    path = tmp_path / "table.json"
    path.write_text(json.dumps(second), encoding="utf-8")
    assert verdicts.load_table(path) == second


def test_a_case_keeps_only_the_values_that_differ_from_the_file_as_built() -> None:
    base = {"freq": "50", "flush": "INCREMENTAL_ASYNC", "num_logs": "5"}
    result = {
        "verdict": "accepted",
        "status": 1,
        "read": [["freq", "10"], ["freq", "60"], ["flush", "INCREMENTAL_ASYNC"]],
        "messages": [],
    }
    assert verdicts.compact(result, base) == {
        "verdict": "accepted",
        "status": 1,
        "read": {"freq": "60"},
        "unread": ["num_logs"],
    }
    unobservable = {**result, "verdict": "unobservable", "messages": ["x"]}
    assert verdicts.compact(unobservable, base) == {
        "verdict": "unobservable",
        "status": 1,
        "messages": ["x"],
    }


def test_main_writes_the_cases(tmp_path: Path) -> None:
    base = tmp_path / "base.conf"
    base.write_text(BASE, encoding="utf-8")
    lines: list[str] = []
    status = verdicts.main(
        ["cases", "--base", str(base), "--output", str(tmp_path / "cases")], out=lines.append
    )
    assert status == 0
    assert lines[0].startswith("wrote ")


def test_main_records_the_table_of_a_platform(tmp_path: Path) -> None:
    base = tmp_path / "base.conf"
    base.write_text(BASE, encoding="utf-8")
    results = results_directory(tmp_path, sorted(verdicts.all_cases(BASE)))
    output = tmp_path / "out" / "verdicts.json"
    lines: list[str] = []
    arguments = [
        "table",
        "--platform",
        "ubuntu",
        "--base",
        str(base),
        "--results",
        str(results),
        "--package",
        "auditd",
        "--version",
        "1:3.1.2",
        "--image",
        "freesecdev-molecule/ubuntu:x",
        "--log-megabytes",
        "1000",
        "--output",
        str(output),
    ]
    assert verdicts.main(arguments, out=lines.append) == 0
    table = json.loads(output.read_text(encoding="utf-8"))
    assert table["platforms"]["ubuntu"]["version"] == "1:3.1.2"
    assert table["platforms"]["ubuntu"]["base"] == BASE
    assert table["cases"]["as_built"]["ubuntu"]["verdict"] == "accepted"
    assert lines[-1].startswith("recorded ")


@pytest.mark.parametrize(
    "arguments",
    [
        ["table", "--platform", "Bad Platform"],
        ["table", "--platform", "ubuntu", "--results", "/nonexistent"],
    ],
)
def test_main_reports_bad_input(tmp_path: Path, arguments: list[str]) -> None:
    base = tmp_path / "base.conf"
    base.write_text(BASE, encoding="utf-8")
    common = ["--base", str(base), "--package", "p", "--version", "v", "--image", "i"]
    if "--results" not in arguments:
        common += ["--results", str(tmp_path)]
    lines: list[str] = []
    full = [*arguments, *common, "--log-megabytes", "1", "--output", str(tmp_path / "t.json")]
    assert verdicts.main(full, out=lines.append) == 2
    assert lines[0].startswith("error: ")


def test_the_module_runs_as_a_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path / "base.conf"
    base.write_text(BASE, encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["auditd_conf_verdicts", "cases", "--base", str(base), "--output", str(tmp_path)],
    )
    monkeypatch.delitem(sys.modules, "tools.molecule.auditd_conf_verdicts", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.molecule.auditd_conf_verdicts", run_name="__main__")
    assert raised.value.code == 0
