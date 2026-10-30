"""Golden tests that pin the kernel module drop-ins to the OVAL of both datastreams (FREES-190)."""

from __future__ import annotations

import functools
import re
from pathlib import PurePosixPath
from typing import cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
    xmlsafe,
)
from tests.unit.tools.test_content_golden_native import (
    REPOSITORY_ROOT,
    native_parameters,
    pinned_benchmarks,
)
from tools.roles import profile_values

XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"
DEF = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
IND = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}"
OVAL_SYSTEM = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
RHEL = "xccdf_org.ssgproject.content_benchmark_RHEL-9"
UBUNTU = "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04"
PROFILE = "xccdf_org.ssgproject.content_profile_"
RULE = "xccdf_org.ssgproject.content_rule_"
FAMILIES = ("filesystem_modules", "protocol_modules", "wireless_modules")
WITH_KERNEL = "#system_with_kernel"
MODULES_LOAD = frozenset({"/etc/modules-load.d", "/run/modules-load.d", "/usr/lib/modules-load.d"})
OBJECT_FIELDS = frozenset({"path", "filename", "pattern", "instance"})
PLATFORM_OF_BENCHMARK = {UBUNTU: "ubuntu", RHEL: "rhel_compatible"}
TOPICS = REPOSITORY_ROOT / "extensions" / "molecule" / "shared" / "vars" / "topics"
CLOSES = {
    f"{XCCDF}Profile": "profile",
    f"{XCCDF}Rule": "rule",
    f"{XCCDF}check": "check",
    f"{DEF}definition": "definition",
    f"{DEF}constant_variable": "variable",
    f"{IND}textfilecontent54_test": "test",
    f"{IND}textfilecontent54_object": "object",
}


class Content:
    """The XCCDF selections and the OVAL items that the kernel module checks use."""

    def __init__(self) -> None:
        self.profiles: dict[str, set[str]] = {}
        self.platforms: dict[str, list[str]] = {}
        self.definitions: dict[str, str] = {}
        self.exports: dict[str, set[str]] = {}
        self.criteria: dict[str, list[object]] = {}
        self.tests: dict[str, dict[str, object]] = {}
        self.objects: dict[str, dict[str, tuple[str, dict[str, str]]]] = {}
        self.variables: dict[str, list[str]] = {}


class Collector:
    """Collects the profiles, rules, definitions, tests, objects and constants of the content."""

    def __init__(self) -> None:
        self.content = Content()
        self.current: dict[str, str] = {}
        self.criteria: list[list[object]] = []
        self.stack: list[dict[str, str]] = []
        self.parts: list[str] = []

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        self.stack.append(attributes)
        self.parts = []
        if name.startswith(XCCDF):
            self.xccdf_start(name.removeprefix(XCCDF), attributes)
        elif name.startswith(DEF):
            self.definition_start(name.removeprefix(DEF), attributes)
        elif name.startswith(IND):
            self.independent_start(name.removeprefix(IND), attributes)

    def xccdf_start(self, local: str, attributes: dict[str, str]) -> None:
        content = self.content
        identifier = attributes.get("id", "")
        rule = self.current.get("rule", "")
        oval = self.current.get("check") == OVAL_SYSTEM
        if local == "Profile":
            self.current["profile"] = identifier
            content.profiles[identifier] = set()
        elif local == "select" and self.current.get("profile"):
            if attributes.get("selected") == "true":
                content.profiles[self.current["profile"]].add(attributes.get("idref", ""))
        elif local == "Rule":
            self.current["rule"] = identifier
            content.platforms[identifier] = []
        elif local == "platform" and rule:
            content.platforms[rule].append(attributes.get("idref", ""))
        elif local == "check" and rule:
            self.current["check"] = attributes.get("system", "")
        elif local == "check-export" and rule and oval:
            content.exports.setdefault(rule, set()).add(attributes.get("value-id", ""))
        elif local == "check-content-ref" and rule and oval:
            content.definitions[rule] = attributes.get("name", "")

    def definition_start(self, local: str, attributes: dict[str, str]) -> None:
        identifier = attributes.get("id", "")
        if local == "definition":
            self.current["definition"] = identifier
            self.criteria = []
        elif local == "criteria" and self.current.get("definition"):
            node: list[object] = [attributes.get("operator", "AND"), attributes.get("negate", "")]
            if self.criteria:
                self.criteria[-1].append(node)
            else:
                self.content.criteria[self.current["definition"]] = node
            self.criteria.append(node)
        elif local == "criterion" and self.criteria:
            self.criteria[-1].append(attributes.get("test_ref", "") + attributes.get("negate", ""))
        elif local == "constant_variable":
            self.current["variable"] = identifier
            self.content.variables[identifier] = []

    def independent_start(self, local: str, attributes: dict[str, str]) -> None:
        identifier = attributes.get("id", "")
        test = self.current.get("test", "")
        item = self.current.get("object", "")
        if local == "textfilecontent54_test":
            self.current["test"] = identifier
            self.content.tests[identifier] = {
                "check": attributes.get("check", ""),
                "existence": attributes.get("check_existence", "at_least_one_exists"),
                "operator": attributes.get("state_operator", "AND"),
                "objects": [],
                "states": [],
            }
        elif local == "object" and test:
            cast("list[str]", self.content.tests[test]["objects"]).append(
                attributes.get("object_ref", "")
            )
        elif local == "state" and test:
            cast("list[str]", self.content.tests[test]["states"]).append(
                attributes.get("state_ref", "")
            )
        elif local == "textfilecontent54_object":
            self.current["object"] = identifier
            self.content.objects[identifier] = {}
        elif local in OBJECT_FIELDS and item and "var_ref" in attributes:
            self.content.objects[item][local] = ("", attributes)

    def end(self, name: str, /) -> None:
        attributes = self.stack.pop()
        text = "".join(self.parts)
        self.parts = []
        local = name.rsplit("}", maxsplit=1)[-1]
        item = self.current.get("object", "")
        if name in CLOSES:
            self.current.pop(CLOSES[name], None)
        elif name == f"{DEF}criteria":
            self.criteria.pop()
        elif name == f"{DEF}value" and self.current.get("variable"):
            self.content.variables[self.current["variable"]].append(text)
        elif (
            name.startswith(IND)
            and item
            and local in OBJECT_FIELDS
            and local not in self.content.objects[item]
        ):
            self.content.objects[item][local] = (text, attributes)

    def text(self, data: str, /) -> None:
        self.parts.append(data)


@functools.cache
def read(path: str, sha256: str) -> Content:
    profile_values.read_values(path, sha256)
    collector = Collector()
    xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, profile_values.MAX_BYTES), collector)
    return collector.content


def module_rules() -> dict[str, dict[str, object]]:
    return {
        rule_id: parameters
        for rule_id, parameters in native_parameters().items()
        if "module" in parameters
    }


def constants() -> dict[str, object]:
    return cast(
        "dict[str, object]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "roles" / "remediate" / "vars" / "main.yml").read_text(
                encoding="utf-8"
            )
        ),
    )


def catalogue_families() -> dict[str, str]:
    data = cast(
        "dict[str, object]",
        yaml.safe_load((REPOSITORY_ROOT / "roles/remediate/vars/rules.yml").read_text("utf-8")),
    )
    rules = cast("list[dict[str, object]]", data["__linux_compliance_remediate_rules"])
    return {str(rule["rule_id"]): str(rule["family"]) for rule in rules}


def checked_pattern(name: str, module: str) -> str:
    template = str(constants()[f"__linux_compliance_remediate_modprobe_checked_{name}"])
    return template.removeprefix("(?m)").replace("{module}", module)


def dropin(rule_id: str, family: str, parameters: dict[str, object]) -> str:
    """Return the drop-in that kernel_modules_apply.yml writes for the rule."""
    module = str(parameters["module"])
    lines: list[str] = []
    if parameters.get("install") is not None:
        lines.append(f"install {module} {parameters['install']}")
    if parameters.get("blacklist"):
        lines.append(f"blacklist {module}")
    return (
        f"# Managed by freesecdev.linux_compliance for {rule_id}.\n"
        f"# Switching the rule or the {family} topic off removes this file.\n"
        + "\n".join(lines)
        + "\n"
    )


def expected_patterns(parameters: dict[str, object]) -> set[str]:
    module = str(parameters["module"])
    expected: set[str] = set()
    if parameters.get("install") is not None:
        expected.add(checked_pattern("install", module))
    if parameters.get("blacklist"):
        expected.add(checked_pattern("blacklist", module))
    return expected


def check_object(content: Content, reference: str, rule_id: str, text: str) -> str:
    """Check that an object reads the drop-in and return its pattern."""
    item = content.objects[reference]
    assert set(item) == OBJECT_FIELDS, rule_id
    _, path_attributes = item["path"]
    assert path_attributes.get("var_check") == "at least one", rule_id
    directories = content.variables[path_attributes["var_ref"]]
    assert "/etc/modprobe.d" in directories, rule_id
    read = cast(
        "list[str]", constants()["__linux_compliance_remediate_modprobe_checked_directories"]
    )
    assert set(directories) - set(read) == MODULES_LOAD, rule_id
    assert set(read) <= set(directories), rule_id
    filename, filename_attributes = item["filename"]
    assert filename_attributes.get("operation") == "pattern match", rule_id
    assert filename == constants()["__linux_compliance_remediate_modprobe_checked_name"], rule_id
    path = PurePosixPath(str(native_parameters()[rule_id]["path"]))
    assert re.search(filename, path.name), rule_id
    assert str(path.parent) == "/etc/modprobe.d", rule_id
    pattern, pattern_attributes = item["pattern"]
    assert pattern_attributes.get("operation") == "pattern match", rule_id
    assert re.search(pattern, text, re.MULTILINE), (rule_id, pattern)
    instance, instance_attributes = item["instance"]
    assert (instance, instance_attributes.get("datatype")) == ("1", "int"), rule_id
    return pattern


def checked_patterns(content: Content, rule_id: str, text: str) -> set[str]:
    """Check that the definition requires every test of one AND and return their patterns."""
    definition = content.criteria[content.definitions[rule_id]]
    assert definition[:2] == ["OR", ""], rule_id
    assert len(definition) == 3, rule_id
    inner = cast("list[object]", definition[2])
    assert inner[:2] == ["AND", ""], rule_id
    tests = cast("list[str]", inner[2:])
    assert all(isinstance(test, str) for test in tests), rule_id
    patterns: set[str] = set()
    for reference in tests:
        test = content.tests[reference]
        assert test["check"] == "all", rule_id
        assert test["existence"] == "at_least_one_exists", rule_id
        assert test["states"] == [], rule_id
        objects = cast("list[str]", test["objects"])
        assert len(objects) == 1, rule_id
        patterns.add(check_object(content, objects[0], rule_id, text))
    return patterns


def test_each_kernel_module_rule_writes_exactly_what_the_content_of_each_platform_checks() -> None:
    rules = module_rules()
    families = catalogue_families()
    assert len(rules) == 21
    assert {families[rule_id] for rule_id in rules} == set(FAMILIES)
    covered: dict[str, set[str]] = {}
    for path, sha256, benchmark in pinned_benchmarks():
        content = read(path, sha256)
        for rule_id, parameters in rules.items():
            if rule_id not in content.definitions:
                continue
            covered.setdefault(rule_id, set()).add(benchmark)
            assert rule_id not in content.exports, rule_id
            text = dropin(rule_id, families[rule_id], parameters)
            assert checked_patterns(content, rule_id, text) == expected_patterns(parameters)
    assert set(covered) == set(rules)


def test_only_the_protocol_modules_are_checked_in_containers() -> None:
    families = catalogue_families()
    for path, sha256, _ in pinned_benchmarks():
        content = read(path, sha256)
        for rule_id in module_rules():
            if rule_id not in content.platforms:
                continue
            expected = [] if families[rule_id] == "protocol_modules" else [WITH_KERNEL]
            assert content.platforms[rule_id] == expected, rule_id


def test_the_lifecycle_profiles_select_the_drop_ins_that_the_declarations_expect() -> None:
    rules = module_rules()
    families = catalogue_families()
    for path, sha256, benchmark in pinned_benchmarks():
        content = read(path, sha256)
        platform = PLATFORM_OF_BENCHMARK[benchmark]
        for family in FAMILIES:
            topic = cast(
                "dict[str, object]",
                yaml.safe_load((TOPICS / f"{family}.yml").read_text(encoding="utf-8")),
            )
            profiles = {
                str(item["platform"]): str(item["profile"])
                for item in cast("list[dict[str, object]]", topic.get("profiles", []))
            }
            selected = (
                content.profiles[PROFILE + profiles[platform]]
                if platform in profiles
                else set[str]()
            )
            expected = {
                str(rules[rule_id]["path"])
                for rule_id in rules
                if families[rule_id] == family and rule_id in selected
            }
            applied = cast("dict[str, list[dict[str, object]]]", topic["applied"])["files"]
            declared = {
                str(item["path"])
                for item in applied
                if item.get("exists") is True
                and platform in cast("list[str]", item.get("platforms", [platform]))
            }
            unselected = {
                str(item["platform"])
                for item in cast("list[dict[str, object]]", topic.get("unselected_platforms", []))
            }
            assert (not expected) is (platform in unselected), (family, platform)
            if platform not in unselected:
                assert declared == expected, (family, platform)


def test_the_module_names_are_those_of_the_checks() -> None:
    for rule_id, parameters in module_rules().items():
        short = toggles.rule_short_id(rule_id)
        module = str(parameters["module"])
        expected = (
            "overlay"
            if short == "kernel_module_overlayfs_disabled"
            else short.removeprefix("kernel_module_").removesuffix("_disabled")
        )
        assert module == expected, rule_id
        assert rule_id.startswith(RULE)
