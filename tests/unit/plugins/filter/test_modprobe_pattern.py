from __future__ import annotations

import re

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import modprobe_pattern as mp

MODULES = (
    "cramfs",
    "hfs",
    "hfsplus",
    "jffs2",
    "usb_storage",
    "dramfs",
    "zramfs",
    "foobar",
    "fooax",
    "foo:x",
)


def matched(name: str) -> set[str]:
    pattern = mp.modprobe_pattern(name)
    assert pattern is not None, name
    return {module for module in MODULES if re.fullmatch(pattern, module)}


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("cramfs", {"cramfs"}),
        ("usb-storage", {"usb_storage"}),
        ("usb_storage", {"usb_storage"}),
        ("cram*", {"cramfs"}),
        ("hfs*", {"hfs", "hfsplus"}),
        ("hf?", {"hfs"}),
        ("*", set(MODULES)),
        ("[cdz]ramfs", {"cramfs", "dramfs", "zramfs"}),
        ("[a-d]ramfs", {"cramfs", "dramfs"}),
        ("[!c]ramfs", {"dramfs", "zramfs"}),
        ("[^c]ramfs", {"dramfs", "zramfs"}),
        ("[!x]ramfs", {"cramfs", "dramfs", "zramfs"}),
        ("[d-z]ramfs", {"dramfs", "zramfs"}),
        ("usb[_]storage", {"usb_storage"}),
        ("usb[-_]storage", {"usb_storage"}),
        ("usb[-]storage", set[str]()),
        ("usb-stor*", {"usb_storage"}),
        ("[z-a]ramfs", set[str]()),
        ("[z-ac]ramfs", {"cramfs"}),
        ("[!z-a]ramfs", {"cramfs", "dramfs", "zramfs"}),
        ("[-c]ramfs", {"cramfs"}),
        ("[c-]ramfs", {"cramfs"}),
        ("foo\\bar", {"foobar"}),
        ("fo\\o*", {"foobar", "fooax", "foo:x"}),
        ("foo[a:]x", {"fooax", "foo:x"}),
        ("foo[=]x", set[str]()),
        ("foo[\\a]x", {"fooax"}),
        ("cramfs\\", set[str]()),
        ("c.amfs", set[str]()),
    ],
)
def test_the_pattern_matches_what_kmod_matches(name: str, expected: set[str]) -> None:
    assert matched(name) == expected


@pytest.mark.parametrize(
    "name",
    [
        "c[!]]amfs",
        "c[^]]amfs",
        "c[]]amfs",
        "c[]amfs",
        "c[!]amfs",
        "[[:alpha:]]ramfs",
        "[[=c=]]ramfs",
        "cram]fs",
        "cram[fs",
    ],
)
def test_a_name_that_kmod_rejects_is_ignored(name: str) -> None:
    assert mp.modprobe_pattern(name) is None


@pytest.mark.parametrize("name", ["foo[a\\]x", "c[[:a]ramfs", "c[[.a]ramfs", "c[[=a]ramfs"])
def test_a_bracket_that_cannot_be_modelled_matches_every_module(name: str) -> None:
    assert mp.modprobe_pattern(name) == mp.MATCH_ALL


def test_a_bracket_may_hold_an_opening_bracket_as_a_literal() -> None:
    assert matched("c[[r]amfs") == {"cramfs"}


def test_a_reversed_range_never_raises_from_the_regular_expression_engine() -> None:
    for name in ("[z-a]", "[!z-a]", "x[9-0]y", "[z-a-c]"):
        pattern = mp.modprobe_pattern(name)
        assert pattern is not None
        re.fullmatch(pattern, "a")


@pytest.mark.parametrize("value", ["", None, 3])
def test_an_invalid_name_is_an_error(value: object) -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        mp.modprobe_pattern(value)


def test_the_filter_is_registered() -> None:
    assert mp.FilterModule().filters() == {"modprobe_pattern": mp.modprobe_pattern}
