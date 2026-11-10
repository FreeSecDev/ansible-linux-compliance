"""The sysctl_vector filter reads a value as the kernel reads an integer vector (FREES-107)."""

from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import sysctl_vector

PORT_RANGE = [32768, 65535]


def test_the_filter_is_registered() -> None:
    filters = sysctl_vector.FilterModule().filters()
    assert filters == {"sysctl_vector": sysctl_vector.sysctl_vector}


@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        ("32768 65535", True),
        ("32768\t65535", True),
        ("32768  65535", True),
        ("032768 65535", False),
        ("132768 65535", False),
        ("32768 655350", False),
        ("3276865535", False),
        ("-32768 65535", False),
        ("+32768 65535", False),
        ("32768\v65535", False),
        ("32768 65535x", False),
        ("65535 32768", False),
    ],
)
def test_only_the_accepted_fields_in_plain_decimal_equal_the_port_range(
    value: str, *, accepted: bool
) -> None:
    assert (sysctl_vector.sysctl_vector(value, 2) == PORT_RANGE) is accepted
