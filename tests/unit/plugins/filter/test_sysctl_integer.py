"""The sysctl_integer filter reads a value as the kernel reads an integer (FREES-107)."""

from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import sysctl_integer


def test_the_filter_is_registered() -> None:
    filters = sysctl_integer.FilterModule().filters()
    assert filters == {"sysctl_integer": sysctl_integer.sysctl_integer}


@pytest.mark.parametrize(
    ("value", "integer"),
    [
        ("65536", 65536),
        ("065536", None),
        ("010", None),
        ("+1", None),
        ("-0", 0),
        ("0", 0),
        ("1234567890123456789", 1234567890123456789),
        ("000000000000000000001", None),
        ("0x10", None),
    ],
)
def test_only_the_plain_decimal_form_gives_an_integer(value: str, integer: int | None) -> None:
    assert sysctl_integer.sysctl_integer(value) == integer
