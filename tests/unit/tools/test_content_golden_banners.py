from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
    xmlsafe,
)
from tests.unit.tools.test_content_golden import CONTENT_DIRECTORY, REQUIRE_CONTENT
from tools.content import fetch_content as fetch
from tools.roles import generate_toggles, profile_values

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
OVAL = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}"
OBJECT = f"{OVAL}textfilecontent54_object"
PATTERN = f"{OVAL}pattern"


class PatternCollector:
    """Keeps the pattern of every textfilecontent54 object of an OVAL document."""

    def __init__(self) -> None:
        self.patterns: dict[str, str] = {}
        self.current = ""
        self.inside = False
        self.parts: list[str] = []

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        if name == OBJECT:
            self.current = attributes.get("id", "")
        elif name == PATTERN and self.current:
            self.inside = True
            self.parts = []

    def end(self, name: str, /) -> None:
        if name == PATTERN and self.inside:
            self.patterns[self.current] = "".join(self.parts)
            self.inside = False
        elif name == OBJECT:
            self.current = ""

    def text(self, data: str, /) -> None:
        if self.inside:
            self.parts.append(data)


def pinned() -> list[tuple[str, str]]:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    paths = [
        (CONTENT_DIRECTORY / stream.file_name, stream.sha256) for stream in manifest.datastreams
    ]
    missing = [str(path) for path, _ in paths if not path.is_file()]
    if missing:
        if REQUIRE_CONTENT:
            pytest.fail(f"pinned content {missing} is missing but FREESECDEV_REQUIRE_CONTENT=1")
        pytest.skip(f"pinned content {missing} is not present; run make test-content-golden")
    return [(str(path.resolve()), sha256) for path, sha256 in paths]


def native_parameters() -> dict[str, dict[str, object]]:
    data = cast(
        "dict[str, object]",
        yaml.safe_load((REPOSITORY_ROOT / generate_toggles.CATALOGUE).read_text(encoding="utf-8")),
    )
    rules = cast("list[dict[str, object]]", data[generate_toggles.RULES_KEY])
    return {str(rule["rule_id"]): cast("dict[str, object]", rule["parameters"]) for rule in rules}


def test_the_default_banner_text_is_the_default_of_the_content() -> None:
    defaults = cast(
        "dict[str, object]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "roles" / "remediate" / "defaults" / "main.yml").read_text(
                encoding="utf-8"
            )
        ),
    )
    for path, sha256 in pinned():
        values = profile_values.read_values(path, sha256)
        text = values.values[profile_values.VALUE_PREFIX + "cis_banner_text"]
        assert (
            text[profile_values.DEFAULT_SELECTOR]
            == defaults["linux_compliance_remediate_banner_text"]
        )


def test_the_forbidden_patterns_cover_every_os_pattern_of_the_cis_banner_checks() -> None:
    forbidden = {
        rule_id: str(parameters["forbidden_pattern"])
        for rule_id, parameters in native_parameters().items()
        if "forbidden_pattern" in parameters
    }
    assert len(forbidden) == 3
    checked = 0
    for path, sha256 in pinned():
        profile_values.read_values(path, sha256)
        collector = PatternCollector()
        xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, profile_values.MAX_BYTES), collector)
        for rule_id, pattern in forbidden.items():
            short = toggles.rule_short_id(rule_id)
            content = collector.patterns[f"oval:ssg-obj_{short}:obj:1"]
            assert content.startswith("(")
            assert content.endswith(")")
            assert set(content[1:-1].split("|")) <= set(pattern[1:-1].split("|")), rule_id
            checked += 1
    assert checked == 6
