from __future__ import annotations

import re
from pathlib import Path

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import modprobe_pattern as mp

FIXTURE = Path(__file__).resolve().parents[3] / "fixtures" / "kmod" / "install-names.tsv"
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
        ("*cramfs", {"cramfs"}),
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
        ("cr[]a[a]mfs", {"cramfs"}),
        ("cr[!]x[y]mfs", {"cramfs"}),
        ("c[]r[-]amfs", {"cramfs"}),
        ("c[]amfs", set[str]()),
        ("c[!]amfs", set[str]()),
        ("foo\\bar", {"foobar"}),
        ("fo\\o*", {"foobar", "fooax", "foo:x"}),
        ("c\\[r]amfs", set[str]()),
        ("foo[a:]x", {"fooax", "foo:x"}),
        ("foo[=]x", set[str]()),
        ("foo[\\a]x", {"fooax"}),
        ("foo[a\\]x", set[str]()),
        ("[\\a-\\d]ramfs", {"cramfs", "dramfs"}),
        ("cramfs\\", set[str]()),
        ("cr[]a\\", set[str]()),
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
        "[[:alpha:]]ramfs",
        "[[=c=]]ramfs",
        "cram]fs",
        "cram[fs",
    ],
)
def test_a_name_that_kmod_rejects_is_ignored(name: str) -> None:
    assert mp.modprobe_pattern(name) is None


@pytest.mark.parametrize(
    "name", ["c[[:a]ramfs", "c[[.a]ramfs", "c[[=a]ramfs", "[[:alpha:]c[]ramfs", "[a-[:b]x"]
)
def test_a_bracket_that_holds_a_class_matches_every_module(name: str) -> None:
    assert mp.modprobe_pattern(name) == mp.MATCH_ALL


def test_a_bracket_may_hold_an_opening_bracket_as_a_literal() -> None:
    assert matched("c[[r]amfs") == {"cramfs"}


def test_a_reversed_range_never_raises_from_the_regular_expression_engine() -> None:
    for name in ("[z-a]", "[!z-a]", "x[9-0]y", "[z-a-c]"):
        pattern = mp.modprobe_pattern(name)
        assert pattern is not None
        re.fullmatch(pattern, "a")


def test_the_filter_agrees_with_kmod_on_every_name_of_the_verdict_table() -> None:
    rows = [
        line.split("\t", 3)
        for line in FIXTURE.read_text(encoding="utf-8").splitlines()
        if not line.startswith("#")
    ]
    assert len(rows) > 5000
    broad = 0
    for module, verdict, name, raw in rows:
        assert verdict in {"MATCH", "NOMATCH", "REJECT"}, raw
        pattern = None if name == "-" else mp.modprobe_pattern(name)
        ours = pattern is not None and re.fullmatch(pattern, module.replace("-", "_")) is not None
        if verdict == "MATCH":
            assert ours, (module, name, raw)
        elif ours:
            assert pattern == mp.MATCH_ALL, (module, name, raw)
            broad += 1
    assert sum(1 for row in rows if row[1] == "MATCH") == 411
    assert broad == 1729


@pytest.mark.parametrize("value", ["", None, 3])
def test_an_invalid_name_is_an_error(value: object) -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        mp.modprobe_pattern(value)


def test_the_filter_is_registered() -> None:
    assert mp.FilterModule().filters() == {"modprobe_pattern": mp.modprobe_pattern}
