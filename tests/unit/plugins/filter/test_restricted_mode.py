from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import restricted_mode


def test_the_filter_is_registered() -> None:
    filters = restricted_mode.FilterModule().filters()
    assert filters == {"restricted_mode": restricted_mode.restricted_mode}


@pytest.mark.parametrize(
    ("current", "maximum", "expected"),
    [
        ("0644", "0600", "0600"),
        ("0600", "0600", "0600"),
        ("0400", "0600", "0400"),
        ("0000", "0600", "0000"),
        ("4755", "0600", "0600"),
        ("1777", "0600", "0600"),
        ("755", "644", "0644"),
        ("0777", "0777", "0777"),
    ],
)
def test_only_the_excess_bits_are_removed(current: str, maximum: str, expected: str) -> None:
    assert restricted_mode.restricted_mode(current, maximum) == expected


@pytest.mark.parametrize(
    ("current", "maximum", "message"),
    [
        (
            "0648",
            "0600",
            "the current mode must be an octal mode of three or four digits, got '0648'",
        ),
        (None, "0600", "the current mode must be an octal mode of three or four digits, got None"),
        (420, "0600", "the current mode must be an octal mode of three or four digits, got 420"),
        (
            "0644",
            "u-x",
            "the maximum mode must be an octal mode of three or four digits, got 'u-x'",
        ),
        ("0644", "06000", "the maximum mode must be an octal mode of three or four digits"),
        ("0644", "", "the maximum mode must be an octal mode of three or four digits, got ''"),
    ],
)
def test_anything_but_an_octal_mode_is_rejected(
    current: object, maximum: object, message: str
) -> None:
    with pytest.raises(ValueError, match="must be an octal mode") as caught:
        restricted_mode.restricted_mode(current, maximum)
    assert str(caught.value).startswith(message)
