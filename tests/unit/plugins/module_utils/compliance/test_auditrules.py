from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditrules,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_normalise_reads_key_fields_and_unset_as_one_spelling() -> None:
    assert (
        auditrules.normalise(
            "-a  always,exit -F arch=b64 -S open -F auid!=4294967295 -F key=access"
        )
        == "-a always,exit -F arch=b64 -S open -F auid!=unset -k access"
    )
    assert auditrules.normalise("-a always,exit -F auid!=-1 -k x") == (
        "-a always,exit -F auid!=unset -k x"
    )
    assert auditrules.normalise("\t-w /etc/passwd   -p wa -k identity ") == (
        "-w /etc/passwd -p wa -k identity"
    )
    assert auditrules.normalise("-a always,exit -F") == "-a always,exit -F"


def test_rule_lines_leave_out_what_augenrules_leaves_out() -> None:
    text = (
        "## comment\n"
        "   # indented comment\n"
        "\n"
        "   \n"
        "-D\n"
        "-b 8192\n"
        "-f 1\n"
        "-e 2\n"
        "--backlog_wait_time 60000\n"
        "-D -k x\n"
        "-w /var/log/lastlog -p wa -k logins\r\n"
        "-a always,exit -F arch=b32 -S adjtimex -F key=time-change"
    )
    assert auditrules.rule_lines(text) == [
        "--backlog_wait_time 60000",
        "-D -k x",
        "-w /var/log/lastlog -p wa -k logins",
        "-a always,exit -F arch=b32 -S adjtimex -k time-change",
    ]


def test_rule_file_names_are_the_rules_files_without_a_leading_dot() -> None:
    assert auditrules.rule_file_names(
        ["b.rules", ".hidden.rules", "a.rules", "notes.txt", "c.rules.bak", "audit.rules"]
    ) == ["a.rules", "audit.rules", "b.rules"]


def test_read_rule_files_of_a_missing_directory_is_empty(tmp_path: Path) -> None:
    assert auditrules.read_rule_files(str(tmp_path / "missing")) == []


def test_read_rule_files_refuses_a_file_in_place_of_the_directory(tmp_path: Path) -> None:
    target = tmp_path / "rules.d"
    target.write_text("-w /x -p wa -k x\n", encoding="utf-8")
    with pytest.raises(auditrules.RulesFileError, match="not a directory"):
        auditrules.read_rule_files(str(target))


def test_read_rule_files_follows_links_to_files_and_lists_other_entries_without_lines(
    tmp_path: Path,
) -> None:
    base = tmp_path / "rules.d"
    base.mkdir()
    (base / "10-base.rules").write_text("-D\n-w /etc/passwd -p wa -k identity\n", encoding="utf-8")
    (base / "20-dir.rules").mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("-w /etc/group -p wa -k identity\n", encoding="utf-8")
    (base / "30-link.rules").symlink_to(outside)
    (base / "40-broken.rules").symlink_to(tmp_path / "nowhere")
    (base / ".50-hidden.rules").write_text("-w /etc/shadow -p wa -k identity\n", encoding="utf-8")
    (base / "README").write_text("text\n", encoding="utf-8")
    assert auditrules.read_rule_files(str(base)) == [
        {
            "path": str(base / "10-base.rules"),
            "regular": True,
            "lines": ["-w /etc/passwd -p wa -k identity"],
        },
        {"path": str(base / "20-dir.rules"), "regular": False, "lines": []},
        {
            "path": str(base / "30-link.rules"),
            "regular": True,
            "lines": ["-w /etc/group -p wa -k identity"],
        },
        {"path": str(base / "40-broken.rules"), "regular": False, "lines": []},
    ]


def test_read_rule_files_bounds_the_size_of_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "rules.d"
    base.mkdir()
    (base / "big.rules").write_text("-w /x -p wa -k x\n" * 4, encoding="utf-8")
    monkeypatch.setattr(auditrules, "MAX_FILE_BYTES", 16)
    with pytest.raises(auditrules.RulesFileError, match="larger than"):
        auditrules.read_rule_files(str(base))


def test_read_rule_files_bounds_the_number_of_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "rules.d"
    base.mkdir()
    for index in range(3):
        (base / f"{index}.rules").write_text("", encoding="utf-8")
    monkeypatch.setattr(auditrules, "MAX_FILES", 2)
    with pytest.raises(auditrules.RulesFileError, match="more than 2"):
        auditrules.read_rule_files(str(base))


def test_duplicates_find_a_rule_held_twice_across_and_within_files() -> None:
    files: list[dict[str, object]] = [
        {"path": "/r/a.rules", "lines": ["-w /x -p wa -k x", "-w /y -p wa -k y"]},
        {"path": "/r/b.rules", "lines": ["-w /x -p wa -k x"]},
        {"path": "/r/c.rules", "lines": ["-w /z -p wa -k z", "-w /z -p wa -k z"]},
        {"path": "/r/d.rules", "lines": "not a list"},
    ]
    assert auditrules.duplicates(files) == [
        {"line": "-w /x -p wa -k x", "paths": ["/r/a.rules", "/r/b.rules"]},
        {"line": "-w /z -p wa -k z", "paths": ["/r/c.rules", "/r/c.rules"]},
    ]
    assert auditrules.duplicates([]) == []


def test_parse_status_reads_the_numeric_fields() -> None:
    text = (
        "enabled 2\nfailure 1\npid 726\nloginuid_immutable 0 unlocked\n"
        "backlog_wait_time -1\nnoise\n"
    )
    assert auditrules.parse_status(text) == {
        "enabled": 2,
        "failure": 1,
        "pid": 726,
        "loginuid_immutable": 0,
        "backlog_wait_time": -1,
    }


def test_listed_rules_drop_no_rules_and_blank_lines() -> None:
    assert auditrules.listed_rules("No rules\n") == []
    assert auditrules.listed_rules("-w /x -p wa -k x\n\n" + "-" * 5000 + "\n") == [
        "-w /x -p wa -k x"
    ]


def test_missing_rules_compare_in_one_spelling_and_ignore_derived_system_calls() -> None:
    listed = [
        "-a always,exit -F arch=b64 -S adjtimex -F key=time-change",
        (
            "-a always,exit -F arch=b32 -S open,creat,openat -F path=/var/log/lastlog -F perm=wa "
            "-F key=logins"
        ),
        (
            "-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 "
            "-F key=privileged"
        ),
        "-w /etc/localtime -p wa -k time-change",
    ]
    expect = [
        "-a always,exit -F arch=b64 -S adjtimex -k time-change",
        "-a always,exit -F arch=b32 -S adjtimex -k time-change",
        "-a always,exit -F arch=b32 -F path=/var/log/lastlog -F perm=wa -k logins",
        "-a always,exit -F arch=b64 -F path=/var/log/lastlog -F perm=wa -k logins",
        (
            "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset "
            "-k privileged"
        ),
        "-w /etc/localtime -p wa -k time-change",
        "-w /etc/localtime -p wa -k other",
    ]
    assert auditrules.missing_rules(expect, listed) == [
        "-a always,exit -F arch=b32 -S adjtimex -k time-change",
        "-a always,exit -F arch=b64 -F path=/var/log/lastlog -F perm=wa -k logins",
        "-w /etc/localtime -p wa -k other",
    ]
    assert auditrules.missing_rules([], listed) == []
    assert auditrules.missing_rules(["-a always,exit -S"], ["-a always,exit -S"]) == []


def test_log_megabytes_measures_the_nearest_existing_directory(tmp_path: Path) -> None:
    size = auditrules.log_megabytes(str(tmp_path / "missing" / "audit"))
    assert isinstance(size, int)
    assert size > 0
    assert auditrules.log_megabytes(str(tmp_path)) == size


@pytest.mark.parametrize("directory", ["relative/audit", "/var/log/../../etc"])
def test_log_megabytes_refuses_relative_and_parent_paths(directory: str) -> None:
    assert auditrules.log_megabytes(directory) is None
