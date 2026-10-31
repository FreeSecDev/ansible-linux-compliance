"""The auditd.conf reader on files that the verdict table does not hold (FREES-110)."""

from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditconf,
)


def test_a_large_file_is_unknown() -> None:
    reading = auditconf.read(b"#" * (auditconf.MAX_FILE_BYTES + 1))
    assert reading.accepted is None
    assert "larger than 1 MiB" in reading.reason


def test_mixed_units_without_the_size_are_unknown() -> None:
    reading = auditconf.read(b"space_left = 25%\nadmin_space_left = 50\n")
    assert reading.accepted is None
    assert "size of the file system of the log is unknown" in reading.reason


def test_mixed_units_are_converted_with_the_size() -> None:
    accepted = auditconf.read(b"space_left = 25%\nadmin_space_left = 50\n", 1000)
    refused = auditconf.read(b"space_left = 25%\nadmin_space_left = 50\n", 100)
    assert accepted.accepted is True
    assert refused.accepted is None
    assert "auditd only logs this when it starts" in refused.reason


def test_the_value_is_that_of_the_last_line() -> None:
    reading = auditconf.read(b"space_left = 80\nadmin_space_left = 50\nspace_left = 90\n")
    assert auditconf.value(reading, "space_left") == "90"
    assert auditconf.value(reading, "freq") is None
    assert [setting.line for setting in reading.settings["space_left"]] == [1, 3]


def test_a_nul_byte_is_refused_because_auditd_then_skips_the_next_line() -> None:
    reading = auditconf.read(b"# x\x00\nspace_left = 80\nadmin_space_left = 50\n")
    assert reading.accepted is None
    assert "NUL byte" in reading.reason


def test_a_zero_percentage_is_an_absolute_zero() -> None:
    reading = auditconf.read(b"space_left = 0%\nadmin_space_left = 50\n", 1000)
    assert reading.accepted is False


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (b"num_logs = 1000", False),
        (b"q_depth = 70000", None),
        (b"q_depth = 100000", False),
        (b"tcp_listen_queue = 0", None),
        (b"tcp_listen_queue = abc", None),
        (b"priority_boost = 0", None),
        (b"log_group = wheel", None),
        (b"action_mail_acct = admin@example.com", None),
        (b"space_left_action = exec /usr/bin/true", None),
        (b"max_log_file = 12345678901", None),
        (b"max_log_file = abc", False),
        (b"space_left = 1234567890%", False),
        (b"space_left = 1234567890", None),
    ],
)
def test_values_outside_what_the_table_shows_are_refused_or_unknown(
    line: bytes, expected: bool | None
) -> None:
    reading = auditconf.read(b"space_left = 80\nadmin_space_left = 50\n" + line + b"\n", 1000)
    assert reading.accepted is expected, reading.reason
