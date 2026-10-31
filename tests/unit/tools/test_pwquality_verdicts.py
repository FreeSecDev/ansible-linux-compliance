"""The pwquality reader and every decision against what the real libpwquality read (FREES-200)."""

from __future__ import annotations

import base64
import json
from functools import cache
from pathlib import Path
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pwquality,
)
from tools.lint import pwquality_readers as readers

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "pwquality_readers"
PLATFORMS = ("ubuntu", "rocky")


@cache
def table() -> dict[str, object]:
    return cast("dict[str, object]", json.loads((FIXTURES / "verdicts.json").read_text("utf-8")))


@cache
def cases() -> list[dict[str, object]]:
    document = json.loads((FIXTURES / "cases.json").read_text("utf-8"))
    return cast("list[dict[str, object]]", document["cases"])


def verdicts() -> dict[str, list[list[int]]]:
    return cast("dict[str, list[list[int]]]", table()["verdicts"])


def settings() -> list[str]:
    return cast("list[str]", table()["settings"])


def emulate(state: dict[str, object]) -> list[int]:
    """Return what the reader of the collection reads from a state, as the probe prints it."""
    files: list[tuple[str, bytes | None]] = []
    entries = cast("list[dict[str, str]]", state["dropins"])
    for entry in sorted(entries, key=lambda item: item["name"].encode("utf-8")):
        if not pwquality.is_dropin_name(entry["name"]) or entry["type"] == "directory":
            continue
        content = None if entry["type"] == "dangling" else base64.b64decode(entry["content"])
        files.append((entry["name"], content))
    main = state["main"]
    files.append(("main", None if main is None else base64.b64decode(cast("str", main))))
    reading = pwquality.read_config(files)
    values = {name: reading.value(name) for name in settings()}
    for argument in cast("list[str]", state["arguments"]):
        found = pwquality.option_value(base64.b64decode(argument))
        if found is not None and found[0] in values:
            values[found[0]] = found[1]
    return [reading.error, *[cast("int", values[name]) for name in settings()]]


def all_states() -> dict[str, dict[str, object]]:
    states: dict[str, dict[str, object]] = {}
    for case in cases():
        for setting, value in readers.RULES:
            for method in readers.METHODS:
                _decision, before, after = readers.decide_case(
                    case, readers.rule_of(setting, value, method)
                )
                states[readers.state_key(before)] = before
                if after is not None:
                    states[readers.state_key(after)] = after
    return states


def test_the_table_was_read_by_both_images_and_they_agree() -> None:
    readers_of = cast("dict[str, str]", table()["readers"])
    assert readers_of["ubuntu"].startswith("libpwquality1:amd64 1.4.5-")
    assert readers_of["rocky"].startswith("libpwquality-1.4.4-")
    assert settings() == list(readers.SETTINGS)
    for key, rows in verdicts().items():
        assert rows[0] == rows[1], key


def test_the_table_holds_every_state_of_the_cases_and_no_other() -> None:
    assert set(all_states()) == set(verdicts())


def test_the_reader_reads_every_state_as_libpwquality_does() -> None:
    mismatches = [
        key for key, state in all_states().items() if emulate(state) != verdicts()[key][0]
    ]
    assert mismatches == []


def test_every_decision_is_the_one_in_the_table() -> None:
    rows = cast("list[list[object]]", table()["decisions"])
    computed: list[list[object]] = []
    for case in cases():
        for setting, value in readers.RULES:
            for method in readers.METHODS:
                decision, before, after = readers.decide_case(
                    case, readers.rule_of(setting, value, method)
                )
                computed.append(
                    [
                        case["name"],
                        setting,
                        method,
                        decision["status"],
                        readers.state_key(before),
                        None if after is None else readers.state_key(after),
                    ]
                )
    assert computed == rows


@pytest.mark.parametrize("platform", range(len(PLATFORMS)))
def test_no_decision_claims_a_value_that_libpwquality_does_not_hold(platform: int) -> None:
    required = {setting: 1 if not value else int(value) for setting, value in readers.RULES}
    unsafe: list[list[object]] = []
    for row in cast("list[list[object]]", table()["decisions"]):
        _case, setting, _method, status, state, after = row
        index = 1 + settings().index(cast("str", setting))
        if status == "compliant":
            read = verdicts()[cast("str", state)][platform][index]
        elif status == "applied":
            read = verdicts()[cast("str", after)][platform][index]
        else:
            assert after is None
            continue
        if read != required[cast("str", setting)]:
            unsafe.append(row)
    assert unsafe == []


def test_the_table_covers_every_status_and_both_methods() -> None:
    seen = {(row[2], row[3]) for row in cast("list[list[object]]", table()["decisions"])}
    assert {
        ("main_file", "compliant"),
        ("main_file", "applied"),
        ("main_file", "overridden"),
        ("main_file", "duplicate_setting"),
        ("main_file", "unreadable_file"),
        ("main_file", "unreadable_value"),
        ("dropin", "compliant"),
        ("dropin", "applied"),
        ("dropin", "overridden"),
        ("dropin", "unreadable_file"),
    } <= seen


@pytest.mark.parametrize(
    ("name", "status"),
    [
        ("minlen_upper_looser_after", "duplicate_setting"),
        ("minlen_space_looser_after", "duplicate_setting"),
        ("minlen_crlf", "applied"),
        ("minlen_lone_cr_in_value", "applied"),
        ("minlen_lone_cr_in_comment", "compliant"),
        ("minlen_dropin_malformed_first", "unreadable_file"),
        ("minlen_long_comment_hides", "unreadable_file"),
        ("minlen_pam_override_looser", "overridden"),
        ("minlen_pam_override_equal", "compliant"),
        ("minlen_pam_commented", "compliant"),
        ("rocky_as_built_pam", "applied"),
        ("non_utf8_main", "unreadable_file"),
        ("vt_in_value_line", "unreadable_value"),
    ],
)
def test_the_main_file_decisions_of_the_divergences_found(name: str, status: str) -> None:
    rows = [
        row
        for row in cast("list[list[object]]", table()["decisions"])
        if row[0] == name and row[1] == "minlen" and row[2] == "main_file"
    ]
    assert [row[3] for row in rows] == [status]


@pytest.mark.parametrize(
    ("name", "status"),
    [
        ("minlen_dropin_upper_later", "overridden"),
        ("minlen_dropin_hidden_later", "unreadable_file"),
        ("minlen_dropin_link", "unreadable_file"),
        ("minlen_dropin_directory", "applied"),
        ("minlen_dropin_double_suffix", "applied"),
        ("minlen_own_dropin", "compliant"),
        ("minlen_own_dropin_later_looser", "overridden"),
        ("minlen_own_dropin_earlier_malformed", "unreadable_file"),
    ],
)
def test_the_dropin_decisions_of_the_divergences_found(name: str, status: str) -> None:
    rows = [
        row
        for row in cast("list[list[object]]", table()["decisions"])
        if row[0] == name and row[1] == "minlen" and row[2] == "dropin"
    ]
    assert [row[3] for row in rows] == [status]
