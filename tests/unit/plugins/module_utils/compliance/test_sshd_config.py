"""The sshd lexer of the ssh family, line by line (FREES-200)."""

from __future__ import annotations

from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import sshd_config_lines
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sshd_config,
)


@pytest.mark.parametrize(
    ("line", "keyword", "value"),
    [
        ("PermitRootLogin yes", "permitrootlogin", "yes"),
        ('Permit"RootLogin" yes', "permitrootlogin", "yes"),
        ('"PermitRootLogin" yes', "permitrootlogin", "yes"),
        ("=PermitRootLogin yes", "permitrootlogin", "yes"),
        (" = PermitRootLogin yes", "permitrootlogin", "yes"),
        ("\t=\tPermitRootLogin\tyes", "permitrootlogin", "yes"),
        ('="PermitRootLogin" yes', "permitrootlogin", "yes"),
        ("PermitRootLogin=yes", "permitrootlogin", "yes"),
        ("PermitRootLogin = yes", "permitrootlogin", "yes"),
        ("PermitRootLogin\ryes\r", "permitrootlogin", "yes"),
        ("\rPermitRootLogin yes", "permitrootlogin", "yes"),
        ("PermitRootLogin yes\f", "permitrootlogin", "yes"),
        ("PermitRootLogin yes # site", "permitrootlogin", "yes"),
        ('PermitRootLogin "yes"', "permitrootlogin", None),
        ("PermitRootLogin == yes", "permitrootlogin", None),
        ('Permit"Root"Login yes', "permitroot", None),
        ("DSAAuthentication no", "pubkeyauthentication", "no"),
        ('Ma"tch" User x', "match", None),
        ("Include /etc/a.conf /etc/b.conf", "include", None),
        ("==PermitRootLogin yes", None, None),
        ('Permit"RootLogin yes', None, None),
        ("#PermitRootLogin yes", None, None),
        ('"#PermitRootLogin" yes', None, None),
        ("", None, None),
        ("   ", None, None),
        ('""', None, None),
    ],
)
def test_lines_are_read_as_sshd_reads_them(
    line: str, keyword: str | None, value: str | None
) -> None:
    read = sshd_config.read_line(line)
    assert read["keyword"] == keyword
    assert read["value"] == value
    assert read["error"] is False


def test_the_arguments_are_kept_only_when_plain() -> None:
    assert sshd_config.read_line("Include /etc/a.conf /etc/b.conf")["arguments"] == [
        "/etc/a.conf",
        "/etc/b.conf",
    ]
    assert sshd_config.read_line('Include "/etc/a b.conf"')["arguments"] is None


@pytest.mark.parametrize("line", ["PermitRootLogin", "PermitRootLogin \t", "PermitRootLogin="])
def test_a_keyword_without_argument_is_an_error(line: str) -> None:
    assert sshd_config.read_line(line)["error"] is True


def test_strdelim_without_text_left() -> None:
    assert sshd_config.strdelim("x", None) == (None, None)
    assert sshd_config.strdelim("abc", 0) == ("abc", None)


def test_the_text_is_exact_only_without_nul_and_surrogates() -> None:
    assert sshd_config.read_lines("PermitRootLogin no\n")["exact"] is True
    assert sshd_config.read_lines("PermitRootLogin no\x00yes\n")["exact"] is False
    assert sshd_config.read_lines("# caf\udce9\n")["exact"] is False
    assert len(cast("list[object]", sshd_config.read_lines("a\nb\n")["lines"])) == 3


def test_the_filter_reads_the_text_and_refuses_anything_else() -> None:
    assert sshd_config_lines.sshd_config_lines("UsePAM yes")["lines"] == [
        {"keyword": "usepam", "error": False, "arguments": ["yes"], "value": "yes"}
    ]
    with pytest.raises(sshd_config_lines.SshdLinesInputError):
        sshd_config_lines.sshd_config_lines(1)
    assert sshd_config_lines.FilterModule().filters() == {
        "sshd_config_lines": sshd_config_lines.sshd_config_lines
    }
