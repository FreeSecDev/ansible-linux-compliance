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


BASE = b"space_left = 80\nadmin_space_left = 50\n"


@pytest.mark.parametrize(
    ("lines", "expected", "reason"),
    [
        (b"log_group = adm\nlog_file = /var/log/audit.log\n", False, "directly in /var/log"),
        (b"log_group = root\nlog_file = /var/log/audit.log\n", None, "cannot tell"),
        (b"log_file = /x/audit.log\n", False, "too short"),
        (b"log_file = /nonexistent/audit/audit.log\n", None, "cannot tell"),
        (b"log_file = /var/log/audit/audit.log\nlog_group = adm\n", True, ""),
        (b"action_mail_acct = x\n", False, "fewer than two characters"),
        (b"verify_email = no\naction_mail_acct = x\n", True, ""),
        (b"action_mail_acct = x\nverify_email = no\n", False, "fewer than two characters"),
        (b"action_mail_acct = xy\n", True, ""),
        (b"name_format = user\n", False, "stops when it starts"),
        (b"name_format = user\nname = auditor\n", True, ""),
        (b"space_left_action = email extra\n", True, ""),
        (b"disk_full_action = halt extra\n", True, ""),
        (b"space_left_action = email a b\n", True, ""),
        (b"max_log_file_action = rotate extra\n", False, "more than one value"),
        (b"space_left_action = exec /usr/bin/true\n", None, "exec form"),
        (b"tcp_listen_port = 60\n", True, ""),
        (b"tcp_listen_port = abc\n", None, "cannot tell"),
        (b"tcp_client_ports = 1-1023\n", True, ""),
        (b"tcp_client_ports = 10-5\n", None, "cannot tell"),
        (b"tcp_client_ports = 70000\n", None, "cannot tell"),
        (b"krb5_key_file = /etc/audit/audit.key\n", True, ""),
        (b"dispatcher = /sbin/audispd\n", True, ""),
        (b"disp_qos = lossy\n", True, ""),
    ],
)
def test_the_start_rules_options_and_more_keywords(
    lines: bytes, expected: bool | None, reason: str
) -> None:
    reading = auditconf.read(BASE + lines, 1000)
    assert reading.accepted is expected, reading.reason
    assert reason in reading.reason


def test_an_option_does_not_change_the_value() -> None:
    reading = auditconf.read(BASE + b"space_left_action = email extra\n", 1000)
    assert auditconf.value(reading, "space_left_action") == "email"


@pytest.mark.parametrize(
    ("path", "directory"),
    [
        ("/var/log/audit/audit.log", "/var/log/audit"),
        ("/var/log/audit/", "/var/log"),
        ("/audit.log", "/"),
        ("audit.log", "."),
        ("//", "/"),
        ("/var//audit.log", "/var"),
    ],
)
def test_the_directory_is_named_as_the_c_library_names_it(path: str, directory: str) -> None:
    assert auditconf.c_dirname(path) == directory
