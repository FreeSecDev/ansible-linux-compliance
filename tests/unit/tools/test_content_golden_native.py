from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
    xmlsafe,
)
from tests.unit.tools.test_content_golden import CONTENT_DIRECTORY, REQUIRE_CONTENT
from tests.unit.tools.test_profile_values import (
    PINNED_TIMEOUT_RULE,
    PINNED_TIMEOUT_VALUE_ID,
    PINNED_TIMEOUT_VALUES,
)
from tools.content import fetch_content as fetch
from tools.roles import generate_catalogue, generate_toggles, profile_values

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
OVAL = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}"
OBJECT = f"{OVAL}textfilecontent54_object"
PATTERN = f"{OVAL}pattern"
FILEPATH = f"{OVAL}filepath"
FIELDS = {PATTERN: "pattern", FILEPATH: "filepath"}
MAIN_ONLY = "^/etc/security/pwquality.conf$"
WITH_DROPINS = r"^/etc/security/pwquality\.conf(\.d/[^/]+\.conf)?$"


class ObjectCollector:
    """Keeps the file path and the pattern of every textfilecontent54 object of an OVAL document."""

    def __init__(self) -> None:
        self.objects: dict[str, dict[str, str]] = {}
        self.current = ""
        self.field = ""
        self.parts: list[str] = []

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        if name == OBJECT:
            self.current = attributes.get("id", "")
            self.objects[self.current] = {}
        elif name in FIELDS and self.current:
            self.field = FIELDS[name]
            self.parts = []

    def end(self, name: str, /) -> None:
        if name in FIELDS and self.field:
            self.objects[self.current][self.field] = "".join(self.parts)
            self.field = ""
        elif name == OBJECT:
            self.current = ""

    def text(self, data: str, /) -> None:
        if self.field:
            self.parts.append(data)


def collected(path: str) -> dict[str, dict[str, str]]:
    collector = ObjectCollector()
    xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, profile_values.MAX_BYTES), collector)
    return collector.objects


def pinned() -> list[tuple[str, str]]:
    return [(path, sha256) for path, sha256, _ in pinned_benchmarks()]


def pinned_benchmarks() -> list[tuple[str, str, str]]:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    paths = [
        (CONTENT_DIRECTORY / stream.file_name, stream.sha256, stream.benchmark_id)
        for stream in manifest.datastreams
    ]
    missing = [str(path) for path, _, _ in paths if not path.is_file()]
    if missing:
        if REQUIRE_CONTENT:
            pytest.fail(f"pinned content {missing} is missing but FREESECDEV_REQUIRE_CONTENT=1")
        pytest.skip(f"pinned content {missing} is not present; run make test-content-golden")
    return [(str(path.resolve()), sha256, benchmark) for path, sha256, benchmark in paths]


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
        objects = collected(path)
        for rule_id, pattern in forbidden.items():
            short = toggles.rule_short_id(rule_id)
            content = objects[f"oval:ssg-obj_{short}:obj:1"]["pattern"]
            assert content.startswith("(")
            assert content.endswith(")")
            assert set(content[1:-1].split("|")) <= set(pattern[1:-1].split("|")), rule_id
            checked += 1
    assert checked == 6


def test_each_pwquality_rule_writes_where_the_content_of_each_platform_checks() -> None:
    rules = {
        rule_id: parameters
        for rule_id, parameters in native_parameters().items()
        if "main_file_benchmarks" in parameters
    }
    assert len(rules) == 14
    checked: dict[str, set[str]] = {}
    for path, sha256, benchmark in pinned_benchmarks():
        profile_values.read_values(path, sha256)
        objects = list(collected(path).values())
        for rule_id, parameters in rules.items():
            setting = str(parameters["setting"])
            pattern = (
                "^enforce_for_root$"
                if setting == "enforce_for_root"
                else rf"^\s*{setting}[\s]*=[\s]*(-?\d+)(?:[\s]|$)"
            )
            paths = {item.get("filepath") for item in objects if item.get("pattern") == pattern}
            if not paths:
                continue
            main_only = benchmark in cast("list[str]", parameters["main_file_benchmarks"])
            assert paths == ({MAIN_ONLY} if main_only else {WITH_DROPINS}), (
                rule_id,
                benchmark,
                paths,
            )
            checked.setdefault(benchmark, set()).add(rule_id)
    assert {benchmark: len(found) for benchmark, found in checked.items()} == {
        "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04": 12,
        "xccdf_org.ssgproject.content_benchmark_RHEL-9": 13,
    }


OVAL_DEFINITIONS = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
OVAL_UNIX = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#unix}"
OVAL_NAMESPACES = (OVAL, OVAL_UNIX, OVAL_DEFINITIONS)
SUDO_FIELDS = frozenset({"filepath", "path", "filename", "pattern", "filter"})
SUDO_MAIN = "/etc/sudoers"
MODE_BITS = {
    "suid": 0o4000,
    "sgid": 0o2000,
    "sticky": 0o1000,
    "uread": 0o400,
    "uwrite": 0o200,
    "uexec": 0o100,
    "gread": 0o40,
    "gwrite": 0o20,
    "gexec": 0o10,
    "oread": 0o4,
    "owrite": 0o2,
    "oexec": 0o1,
}


class OvalCollector:
    """Keeps the definitions, tests, objects and states of an OVAL document that sudo needs."""

    def __init__(self) -> None:
        self.definitions: dict[str, list[str]] = {}
        self.extends: dict[str, list[str]] = {}
        self.tests: dict[str, dict[str, str]] = {}
        self.objects: dict[str, dict[str, list[str]]] = {}
        self.states: dict[str, dict[str, str]] = {}
        self.definition = ""
        self.test = ""
        self.item = ""
        self.state = ""
        self.field = ""
        self.parts: list[str] = []

    @staticmethod
    def _local(name: str) -> tuple[str, str]:
        for namespace in OVAL_NAMESPACES:
            if name.startswith(namespace):
                return namespace, name[len(namespace) :]
        return "", name

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        namespace, local = self._local(name)
        if name == f"{OVAL_DEFINITIONS}definition":
            self.definition = attributes.get("id", "")
            self.definitions[self.definition] = []
            self.extends[self.definition] = []
        elif name == f"{OVAL_DEFINITIONS}criterion" and self.definition:
            self.definitions[self.definition].append(attributes.get("test_ref", ""))
        elif name == f"{OVAL_DEFINITIONS}extend_definition" and self.definition:
            self.extends[self.definition].append(attributes.get("definition_ref", ""))
        elif namespace and local.endswith("_test"):
            self.test = attributes.get("id", "")
            self.tests[self.test] = {"check_existence": attributes.get("check_existence", "")}
        elif namespace and self.test and local in {"object", "state"}:
            self.tests[self.test][local] = attributes.get(f"{local}_ref", "")
        elif namespace and local.endswith("_object"):
            self.item = attributes.get("id", "")
            self.objects[self.item] = {}
        elif namespace and local.endswith("_state"):
            self.state = attributes.get("id", "")
            self.states[self.state] = {}
        elif namespace and self.item and local in SUDO_FIELDS:
            self.field = local
            self.parts = []
        elif namespace and self.state:
            self.field = local
            self.parts = []
            self.states[self.state][local] = attributes.get("var_ref", "")

    def end(self, name: str, /) -> None:
        _, local = self._local(name)
        if self.field and self.item and local == self.field:
            self.objects[self.item].setdefault(self.field, []).append("".join(self.parts))
            self.field = ""
        elif self.field and self.state and local == self.field:
            text = "".join(self.parts).strip()
            if text:
                self.states[self.state][self.field] = text
            self.field = ""
        elif name == f"{OVAL_DEFINITIONS}definition":
            self.definition = ""
        elif local.endswith("_test"):
            self.test = ""
        elif local.endswith("_object"):
            self.item = ""
        elif local.endswith("_state"):
            self.state = ""

    def text(self, data: str, /) -> None:
        if self.field:
            self.parts.append(data)

    def tests_of(self, definition: str) -> list[dict[str, str]]:
        found = [self.tests[test] for test in self.definitions[definition]]
        for extended in self.extends[definition]:
            found.extend(self.tests_of(extended))
        return found


def oval(path: str) -> OvalCollector:
    collector = OvalCollector()
    xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, profile_values.MAX_BYTES), collector)
    return collector


def sudo_rules(method: str) -> dict[str, dict[str, object]]:
    return {
        rule_id: parameters
        for rule_id, parameters in native_parameters().items()
        if parameters.get("method") == method
        and str(parameters.get("path", "")).startswith(SUDO_MAIN)
    }


def reads(item: dict[str, list[str]], path: str) -> bool:
    if "filepath" in item:
        return any(re.search(pattern, path) is not None for pattern in item["filepath"])
    directory, _, name = path.rpartition("/")
    return item.get("path") == [directory] and any(
        re.search(pattern, name) is not None for pattern in item.get("filename", [])
    )


def dropin_contents(
    rule_id: str, parameters: dict[str, object], sha256: str
) -> list[tuple[str, str]]:
    entries = cast("list[dict[str, object]]", parameters.get("profile_values", []))
    values = [
        "".join(cast("list[str]", entry["value"]))
        for entry in entries
        if entry["content_sha256"] == sha256
    ] or ([""] if "value_id" not in parameters else [])
    header = (
        f"# Managed by freesecdev.linux_compliance for {rule_id}.\n"
        "# Switching the rule or the sudo topic off removes this file.\n"
    )
    lines = cast("list[str]", parameters["lines"])
    return [
        (value, header + "".join(line.replace("{value}", value) + "\n" for line in lines))
        for value in values
    ]


def satisfies(test: dict[str, str], item: dict[str, list[str]], value: str, content: str) -> bool:
    found = [
        match
        for pattern in item["pattern"]
        for match in re.finditer(pattern, content, re.MULTILINE)
    ]
    if test["check_existence"] == "none_exist":
        return found == []
    if test["check_existence"] == "only_one_exists" and len(found) != 1:
        return False
    if "state" in test and {match.group(1) for match in found} != {value}:
        return False
    return bool(found)


def test_each_sudo_drop_in_satisfies_the_checks_of_every_platform_that_selects_it() -> None:
    rules = sudo_rules("dropin")
    assert len(rules) == 4
    checked: dict[str, set[str]] = {}
    for path, sha256, benchmark in pinned_benchmarks():
        profile_values.read_values(path, sha256)
        collector = oval(path)
        for rule_id, parameters in rules.items():
            dropin = str(parameters["path"])
            assert "." not in dropin.rpartition("/")[2]
            assert not dropin.endswith("~")
            definition = f"oval:ssg-{toggles.rule_short_id(rule_id)}:def:1"
            if definition not in collector.definitions:
                continue
            contents = dropin_contents(rule_id, parameters, sha256)
            assert contents, (rule_id, benchmark)
            for test in collector.tests_of(definition):
                item = collector.objects[test["object"]]
                assert reads(item, dropin), (rule_id, benchmark, item)
                assert reads(item, SUDO_MAIN), (rule_id, benchmark, item)
                for value, content in contents:
                    assert satisfies(test, item, value, content), (rule_id, benchmark)
            checked.setdefault(benchmark, set()).add(rule_id)
    assert {benchmark: len(found) for benchmark, found in checked.items()} == {
        "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04": 3,
        "xccdf_org.ssgproject.content_benchmark_RHEL-9": 4,
    }


def test_each_sudo_attribute_rule_restricts_what_the_content_checks() -> None:
    rules = sudo_rules("attribute")
    assert len(rules) == 6
    checked = 0
    for path, sha256, _ in pinned_benchmarks():
        profile_values.read_values(path, sha256)
        collector = oval(path)
        for rule_id, parameters in rules.items():
            definition = f"oval:ssg-{toggles.rule_short_id(rule_id)}:def:1"
            if definition not in collector.definitions:
                continue
            (test,) = collector.tests_of(definition)
            assert test["check_existence"] == "none_exist"
            item = collector.objects[test["object"]]
            target = str(parameters["path"])
            if parameters["type"] == "file":
                assert item["filepath"] == [target], rule_id
            else:
                assert item["path"] == [target], rule_id
            states = [collector.states[state] for state in item["filter"]]
            assert any(state.get("type") == "symbolic link" for state in states), rule_id
            compared = [state for state in states if state.get("type") != "symbolic link"]
            assert len(compared) == 1, rule_id
            if parameters["attribute"] == "mode":
                denied = sum(
                    MODE_BITS[name] for name, flag in compared[0].items() if flag == "false"
                )
                assert 0o7777 & ~denied == int(str(parameters["max_mode"]), 8), rule_id
            else:
                field = "user_id" if parameters["attribute"] == "owner" else "group_id"
                assert field in compared[0], rule_id
                assert parameters["id"] == 0
            checked += 1
    assert checked == 6


def test_the_pinned_sudo_timeout_value_gives_every_selecting_profile_its_value() -> None:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    pinned_benchmarks()
    found: dict[str, dict[str, str]] = {}
    for stream in generate_catalogue.streams_of(manifest, CONTENT_DIRECTORY):
        rules = generate_catalogue.read_stream(stream)
        values = cast("profile_values.StreamValues", rules.values)
        assert PINNED_TIMEOUT_VALUE_ID in values.values, stream.name
        assert PINNED_TIMEOUT_VALUE_ID not in values.exports[PINNED_TIMEOUT_RULE], stream.name
        selecting = {
            profile_id: profile_values.profile_value(values, profile_id, PINNED_TIMEOUT_VALUE_ID)
            for profile_id, rule_ids in rules.profiles.items()
            if PINNED_TIMEOUT_RULE in rule_ids
        }
        if selecting:
            found[stream.name] = {
                profile_id.removeprefix(profile_values.PROFILE_PREFIX): value
                for profile_id, value in selecting.items()
            }
    assert found == PINNED_TIMEOUT_VALUES
