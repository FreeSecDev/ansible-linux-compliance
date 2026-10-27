from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING, Any

import pytest

from tools.reporting import stig_mapping
from tools.reporting.common import InvalidInputError

if TYPE_CHECKING:
    from pathlib import Path

RULE = "xccdf_org.ssgproject.content_rule_"
DOCUMENT: dict[str, Any] = {
    "schema_version": 1,
    "generator": "tools/content/generate_stig_mapping.py",
    "source": "ComplianceAsCode/content v0.1.82",
    "join_key": "STIG ID",
    "datastreams": [
        {
            "name": "synthetic",
            "file_name": "ssg-synthetic-ds.xml",
            "sha256": "c" * 64,
            "benchmark_id": "xccdf_org.ssgproject.content_benchmark_SYNTHETIC",
            "benchmark_version": "0.1.82",
            "profiles": [
                {
                    "profile_id": "xccdf_org.ssgproject.content_profile_stig",
                    "stig_release": "V1R2",
                    "stig_ids": {
                        "SYN-00-000001": [RULE + "a", RULE + "b"],
                        "SYN-00-000002": [RULE + "b"],
                    },
                    "rules_without_stig_id": [RULE + "c"],
                }
            ],
        }
    ],
}


def parse(document: object) -> stig_mapping.StigMapping:
    return stig_mapping.parse_mapping(json.dumps(document).encode("utf-8"), "map.json")


def test_a_valid_mapping_reads_with_lookups_in_both_directions() -> None:
    parsed = parse(DOCUMENT)
    profile = parsed.find(
        "xccdf_org.ssgproject.content_benchmark_SYNTHETIC",
        "xccdf_org.ssgproject.content_profile_stig",
    )
    assert profile is not None
    assert profile.rules_of("SYN-00-000001") == (RULE + "a", RULE + "b")
    assert profile.rules_of("SYN-00-000003") == ()
    assert profile.mapped_rules() == frozenset({RULE + "a", RULE + "b"})
    assert profile.unmapped_rules == (RULE + "c",)
    assert (profile.datastream, profile.stig_release) == ("synthetic", "V1R2")
    assert parsed.find("xccdf_org.ssgproject.content_benchmark_SYNTHETIC", "other") is None


def mutated(path: tuple[str | int, ...], value: object) -> dict[str, Any]:
    document = copy.deepcopy(DOCUMENT)
    target: Any = document
    for part in path[:-1]:
        target = target[part]
    if value is KeyError:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return document


PROFILE = ("datastreams", 0, "profiles", 0)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "the STIG mapping must be an object"),
        (mutated(("join_key",), KeyError), "the STIG mapping must have exactly the keys"),
        (mutated(("schema_version",), 2), "must have schema_version 1"),
        (mutated(("datastreams",), {}), "datastreams must be an array"),
        (mutated(("datastreams", 0, "sha256"), "C" * 64), "sha256 is not a valid identifier"),
        (mutated(("datastreams", 0, "name"), 3), "name is not a valid identifier"),
        (mutated((*PROFILE, "stig_release"), "1.0.0"), "stig_release is not a valid identifier"),
        (mutated((*PROFILE, "stig_ids"), {}), "must be a non-empty object with sorted STIG IDs"),
        (
            mutated(
                (*PROFILE, "stig_ids"),
                {"SYN-00-000002": [RULE + "a"], "SYN-00-000001": [RULE + "a"]},
            ),
            "must be a non-empty object with sorted STIG IDs",
        ),
        (mutated((*PROFILE, "stig_ids"), {"SYN-1": [RULE + "a"]}), "key 'SYN-1' is not a valid"),
        (mutated((*PROFILE, "stig_ids"), {"SYN-00-000001": []}), "must name at least one rule"),
        (
            mutated((*PROFILE, "stig_ids"), {"SYN-00-000001": [RULE + "b", RULE + "a"]}),
            "must be sorted and unique",
        ),
        (mutated((*PROFILE, "stig_ids", "SYN-00-000001"), [7]), r"SYN-00-000001\[0\] is not"),
        (
            mutated((*PROFILE, "rules_without_stig_id"), [RULE + "a"]),
            "listed both with and without a STIG ID",
        ),
        (
            mutated(
                ("datastreams", 0, "profiles"), [DOCUMENT["datastreams"][0]["profiles"][0]] * 2
            ),
            "lists a benchmark and profile more than once",
        ),
    ],
)
def test_an_invalid_mapping_is_refused(document: object, message: str) -> None:
    with pytest.raises(InvalidInputError, match=message):
        parse(document)


def test_a_mapping_file_is_read_with_its_name_in_errors(tmp_path: Path) -> None:
    path = tmp_path / "map.json"
    path.write_text(json.dumps(DOCUMENT), encoding="utf-8")
    assert stig_mapping.load_mapping(path).path == str(path)
    with pytest.raises(InvalidInputError, match=r"the STIG mapping .*missing.json: "):
        stig_mapping.load_mapping(tmp_path / "missing.json")
    path.write_text("{", encoding="utf-8")
    with pytest.raises(InvalidInputError, match="input is not valid JSON"):
        stig_mapping.load_mapping(path)


def test_the_default_mapping_is_the_committed_file() -> None:
    assert stig_mapping.DEFAULT_PATH.name == "stig-mapping.json"
    parsed = stig_mapping.load_mapping(stig_mapping.DEFAULT_PATH)
    assert {profile.datastream for profile in parsed.profiles} == {"ubuntu2404", "rhel9"}
    releases = {(profile.datastream, profile.stig_release) for profile in parsed.profiles}
    assert releases == {("ubuntu2404", "V1R5"), ("rhel9", "V2R9")}


@pytest.mark.parametrize(
    ("version", "release_info", "expected"),
    [
        ("001.005.007", "Enhanced Content 001.005.7, based on Release: 6", "V1R5"),
        ("002.009", "", "V2R9"),
        ("1", "Release: 5 Benchmark Date: 01 Oct 2026", "V1R5"),
        ("1", "", None),
        ("draft", "Release: 5", None),
        ("1.2.3.4.5", "", "V1R2"),
    ],
)
def test_the_release_of_disa_content(version: str, release_info: str, expected: str | None) -> None:
    assert stig_mapping.release_of(version, release_info) == expected
