"""The auditd.conf reader against the verdict table of the real auditd (FREES-110).

The table and the cases written again from it live outside the collection, so this test runs with
the controller tests, not with ``ansible-test units``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditconf,
)
from tools.molecule import auditd_conf_verdicts as verdicts

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TABLE = REPOSITORY_ROOT / "tests" / "fixtures" / "auditd_conf" / "verdicts.json"
IMAGES = REPOSITORY_ROOT / "extensions" / "molecule" / "shared" / "images"
PINS = {
    "ubuntu": ("ubuntu.Dockerfile", "AUDITD_VERSION", "auditd"),
    "rhel_compatible": ("rhel-compatible.Dockerfile", "AUDIT_VERSION", "audit"),
}
PARSERS = {
    "max_log_file": "max_log_size",
    "max_log_file_action": "max_log_size_action",
    "space_left_action": "space_action",
    "end_of_event_timeout": "eoe_timeout",
    "dispatcher": "dispatch",
    "tcp_client_ports": "tcp_listen_queue",
}
UNLOGGED = frozenset({"disp_qos"})
KEYWORDS_OF_PARSER: dict[str, set[str]] = {}
for _keyword in auditconf.KEYWORDS:
    KEYWORDS_OF_PARSER.setdefault(PARSERS.get(_keyword, _keyword), set()).add(_keyword)
SKIPPED = re.compile(r"Skipping line (\d+) in .*: too long")
CONSERVATIVE = (
    "exec form",
    "outside ASCII",
    "cannot tell",
)


def table() -> dict[str, object]:
    return cast("dict[str, object]", json.loads(TABLE.read_text(encoding="utf-8")))


def platforms() -> dict[str, dict[str, object]]:
    return cast("dict[str, dict[str, object]]", table()["platforms"])


def table_cases() -> list[tuple[str, dict[str, object]]]:
    return list(cast("dict[str, dict[str, object]]", table()["cases"]).items())


def texts(platform: str) -> dict[str, str]:
    return verdicts.all_cases(cast("str", platforms()[platform]["base"]))


def results() -> list[tuple[str, str, bytes, dict[str, object]]]:
    found: list[tuple[str, str, bytes, dict[str, object]]] = []
    written = {platform: texts(platform) for platform in platforms()}
    for name, case in cast("dict[str, dict[str, dict[str, object]]]", table()["cases"]).items():
        for platform, result in case.items():
            found.append((name, platform, written[platform][name].encode("latin-1"), result))
    return found


CASES = results()


def last_read(platform: str, result: dict[str, object]) -> dict[str, str]:
    values = dict(cast("dict[str, str]", platforms()[platform]["read"]))
    values.update(cast("dict[str, str]", result.get("read", {})))
    for parser in cast("list[str]", result.get("unread", [])):
        del values[parser]
    return values


def test_the_table_holds_both_platforms_with_their_package_versions() -> None:
    found = platforms()
    assert set(found) == set(PINS)
    for platform, header in found.items():
        assert header["package"] == PINS[platform][2]
        assert isinstance(header["log_megabytes"], int)
        assert str(header["image"]).startswith(f"freesecdev-molecule/{platform}:")
        assert set(texts(platform)) == {name for name, case in table_cases() if platform in case}
    assert len(CASES) > 600


@pytest.mark.parametrize("platform", sorted(PINS))
def test_the_table_was_made_with_the_auditd_that_the_image_pins(platform: str) -> None:
    dockerfile, argument, _ = PINS[platform]
    text = (IMAGES / dockerfile).read_text(encoding="utf-8")
    pinned = re.search(rf"^ARG {argument}=(\S+)$", text, re.MULTILINE)
    assert pinned is not None
    assert platforms()[platform]["version"] == pinned.group(1), (
        f"{dockerfile} pins {argument}={pinned.group(1)}, but the verdict table was made with "
        f"{platforms()[platform]['version']}; run make auditd-conf-verdicts"
    )


@pytest.mark.parametrize(
    ("name", "platform", "data", "result"), CASES, ids=[f"{c[1]}-{c[0]}" for c in CASES]
)
def test_the_reader_never_accepts_what_auditd_does_not_read_as_it_does(
    name: str, platform: str, data: bytes, result: dict[str, object]
) -> None:
    size = cast("int", platforms()[platform]["log_megabytes"])
    reading = auditconf.read(data, size)
    if result["verdict"] != "accepted":
        assert reading.accepted is not True, f"{name}: auditd {result['verdict']} the file"
        return
    if reading.accepted is not True:
        conservative = reading.accepted is None or any(
            part in reading.reason for part in CONSERVATIVE
        )
        assert conservative or auditconf.START_REASON in reading.reason, (
            f"{name}: auditd accepted the file, but the reader refused it: {reading.reason}"
        )
        return
    values = last_read(platform, result)
    for parser, keywords in KEYWORDS_OF_PARSER.items():
        held = [
            setting
            for keyword in keywords - UNLOGGED
            for setting in reading.settings.get(keyword, [])
        ]
        if held:
            assert values.get(parser) == max(held, key=lambda setting: setting.line).value, name
    for parser in values:
        assert KEYWORDS_OF_PARSER.get(parser, set()) & set(reading.settings), (
            f"{name}: auditd read {parser}, which the reader does not hold"
        )
    skipped = sorted(
        int(found.group(1))
        for found in map(SKIPPED.search, cast("list[str]", result["messages"]))
        if found
    )
    assert reading.skipped == skipped, name


@pytest.mark.parametrize("platform", sorted(PINS))
def test_the_table_reaches_load_config_only_and_the_reader_adds_the_start_checks(
    platform: str,
) -> None:
    cases = cast("dict[str, dict[str, dict[str, object]]]", table()["cases"])
    assert cases["name_format_user_without_name"][platform]["verdict"] == "accepted"
    data = texts(platform)["name_format_user_without_name"].encode("latin-1")
    reading = auditconf.read(data, cast("int", platforms()[platform]["log_megabytes"]))
    assert reading.accepted is False
    assert auditconf.START_REASON in reading.reason


@pytest.mark.parametrize("platform", sorted(PINS))
def test_the_reader_accepts_the_file_as_built(platform: str) -> None:
    data = texts(platform)["as_built"].encode("latin-1")
    reading = auditconf.read(data, cast("int", platforms()[platform]["log_megabytes"]))
    assert reading.accepted is True, reading.reason
