"""Golden tests that pin the faillock and pwhistory method to the OVAL of both pinned datastreams.

The remediate role writes one line per setting into /etc/security/faillock.conf or
/etc/security/pwhistory.conf and refuses a setting that a module line of the PAM stack sets
(ADR 0025). These tests read the OVAL definitions of every native rule of both families in
both datastreams and check that the written line satisfies the object and the state that
read the file, that a commented line does not, that the value the state compares with is the
profile value of the catalogue, that ``stack_checked`` is true exactly when the check also
reads the setting on a module line of the stack, that the role's detector finds every module
line that the check's pattern finds, and that no other catalogued rule reads either file.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
    xmlsafe,
)
from tests.unit.tools.test_content_golden_native import pinned_benchmarks
from tools.roles import generate_toggles, profile_values

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DEFINITIONS = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
NAMESPACES = (
    "{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}",
    "{http://oval.mitre.org/XMLSchema/oval-definitions-5#unix}",
    "{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}",
    DEFINITIONS,
)
CONF = {
    "faillock": "/etc/security/faillock.conf",
    "pwhistory": "/etc/security/pwhistory.conf",
}
MODULE = {"faillock": ("auth", "pam_faillock"), "pwhistory": ("password", "pam_pwhistory")}
UBUNTU = "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04"
RHEL = "xccdf_org.ssgproject.content_benchmark_RHEL-9"
AUDIT_ONLY_READERS = frozenset(
    {
        "xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_dir",
        "xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_remember",
    }
)
COMPARISONS = {
    "at_most": [("less than or equal", True), ("greater than or equal", False)],
    "at_least": [("greater than or equal", True)],
}


class Oval:
    """Keeps the definitions, tests, objects, states and variables of an OVAL document."""

    def __init__(self) -> None:
        self.criteria: dict[str, list[str]] = {}
        self.extends: dict[str, list[str]] = {}
        self.tests: dict[str, dict[str, object]] = {}
        self.objects: dict[str, dict[str, list[str]]] = {}
        self.states: dict[str, list[dict[str, str]]] = {}
        self.variables: dict[str, list[tuple[str, str]]] = {}
        self.stack: list[tuple[str, str]] = []
        self.attributes: dict[str, str] = {}
        self.parts: list[str] = []

    @staticmethod
    def local(name: str) -> str:
        for namespace in NAMESPACES:
            if name.startswith(namespace):
                return name[len(namespace) :]
        return ""

    def owner(self, kind: str) -> str:
        return next((ident for found, ident in reversed(self.stack) if found == kind), "")

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        local = self.local(name)
        ident = attributes.get("id", "")
        kind = (
            "definition"
            if name == f"{DEFINITIONS}definition"
            else next(
                (
                    suffix
                    for suffix in ("test", "object", "state", "variable")
                    if local.endswith("_" + suffix) and ident
                ),
                "",
            )
        )
        self.stack.append((kind, ident))
        self.attributes = attributes
        self.parts = []
        if kind == "definition":
            self.criteria[ident] = []
            self.extends[ident] = []
        elif kind == "test":
            self.tests[ident] = {"existence": attributes.get("check_existence", ""), "states": []}
        elif kind == "object":
            self.objects[ident] = {}
        elif kind == "state":
            self.states[ident] = []
        elif kind == "variable":
            self.variables[ident] = []
        self._reference(local, attributes)

    def _reference(self, local: str, attributes: dict[str, str]) -> None:
        definition, test = self.owner("definition"), self.owner("test")
        if local == "criterion" and definition:
            self.criteria[definition].append(attributes.get("test_ref", ""))
        elif local == "extend_definition" and definition:
            self.extends[definition].append(attributes.get("definition_ref", ""))
        elif local == "object" and test and "object_ref" in attributes:
            self.tests[test]["object"] = attributes["object_ref"]
        elif local == "state" and test and "state_ref" in attributes:
            cast("list[str]", self.tests[test]["states"]).append(attributes["state_ref"])
        elif local == "variable_component" and self.owner("variable"):
            self.variables[self.owner("variable")].append(("ref", attributes.get("var_ref", "")))

    def end(self, name: str, /) -> None:
        local = self.local(name)
        kind, _ = self.stack.pop()
        text = "".join(self.parts)
        item, state, variable = self.owner("object"), self.owner("state"), self.owner("variable")
        if kind:
            return
        if item and local in {"filepath", "pattern", "filter"}:
            reference = self.attributes.get("var_ref")
            self.objects[item].setdefault(local, []).append(
                "ref:" + reference if reference else text
            )
        elif state and local == "subexpression":
            self.states[state].append(
                {
                    "operation": self.attributes.get("operation", "equals"),
                    "var_ref": self.attributes.get("var_ref", ""),
                    "value": text.strip(),
                }
            )
        elif variable and local in {"value", "literal_component"}:
            self.variables[variable].append(("text", text))

    def text(self, data: str, /) -> None:
        self.parts.append(data)

    def resolve(self, value: str) -> str:
        if not value.startswith("ref:"):
            return value
        return "".join(
            part if kind == "text" else self.resolve("ref:" + part)
            for kind, part in self.variables[value[4:]]
        )

    def tests_of(self, definition: str) -> list[dict[str, object]]:
        found = [self.tests[test] for test in self.criteria[definition]]
        for extended in self.extends[definition]:
            found.extend(self.tests_of(extended))
        return found


def collect(path: str) -> Oval:
    collector = Oval()
    xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, profile_values.MAX_BYTES), collector)
    return collector


def catalogue() -> dict[str, object]:
    return cast(
        "dict[str, object]",
        yaml.safe_load((REPOSITORY_ROOT / generate_toggles.CATALOGUE).read_text(encoding="utf-8")),
    )


def native_rules() -> dict[str, dict[str, object]]:
    rules = cast("list[dict[str, object]]", catalogue()[generate_toggles.RULES_KEY])
    return {
        str(rule["rule_id"]): rule for rule in rules if rule["family"] in {"faillock", "pwhistory"}
    }


def catalogued_rule_ids() -> set[str]:
    data = catalogue()
    native = {
        str(rule["rule_id"])
        for rule in cast("list[dict[str, object]]", data["__linux_compliance_remediate_rules"])
    }
    audit_only = cast("dict[str, list[str]]", data[generate_toggles.AUDIT_ONLY_KEY])
    return native | {rule for rules in audit_only.values() for rule in rules}


def option_pattern(family: str, option: str) -> str:
    variables = cast(
        "dict[str, object]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "roles" / "remediate" / "vars" / "main.yml").read_text(
                encoding="utf-8"
            )
        ),
    )
    kind, module = MODULE[family]
    return (
        str(variables["__linux_compliance_remediate_pam_option_pattern"])
        .replace("{type}", kind)
        .replace("{module}", module)
        .replace("{option}", option)
    )


def stack_files() -> list[str]:
    variables = cast(
        "dict[str, object]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "roles" / "remediate" / "vars" / "main.yml").read_text(
                encoding="utf-8"
            )
        ),
    )
    return cast("list[str]", variables["__linux_compliance_remediate_pam_stack_files"])


def reads_file(collector: Oval, item: dict[str, list[str]], path: str) -> bool:
    for entry in item.get("filepath", []):
        value = collector.resolve(entry)
        if value == path or (value.startswith("^") and re.fullmatch(value, path)):
            return True
        if "|" in value and path in value.split("|"):
            return True
    return False


def patterns(collector: Oval, item: dict[str, list[str]]) -> list[str]:
    return [collector.resolve(entry) for entry in item.get("pattern", [])]


def written_line(parameters: dict[str, object], value: str) -> str:
    setting = str(parameters["setting"])
    return setting if parameters["comparison"] == "present" else f"{setting} = {value}"


def rule_definitions(collector: Oval, rule_id: str) -> str | None:
    definition = f"oval:ssg-{toggles.rule_short_id(rule_id)}:def:1"
    return definition if definition in collector.criteria else None


def mentions(pattern: str, setting: str) -> bool:
    plain = pattern.replace("\\b", " ")
    return re.search(r"(?<![a-z_])" + re.escape(setting) + r"(?![a-z_])", plain) is not None


def conf_objects(
    collector: Oval, definition: str, family: str, setting: str
) -> list[tuple[dict[str, object], dict[str, list[str]]]]:
    return [
        (test, collector.objects[str(test["object"])])
        for test in collector.tests_of(definition)
        if reads_file(collector, collector.objects[str(test["object"])], CONF[family])
        and any(
            mentions(pattern, setting)
            for pattern in patterns(collector, collector.objects[str(test["object"])])
        )
    ]


def stack_patterns(collector: Oval, definition: str, family: str, setting: str) -> list[str]:
    _, module = MODULE[family]
    found = []
    for test in collector.tests_of(definition):
        item = collector.objects[str(test["object"])]
        if not any(reads_file(collector, item, path) for path in stack_files()):
            continue
        found.extend(
            pattern
            for pattern in patterns(collector, item)
            if module in pattern and mentions(pattern.split(module, 1)[1], setting)
        )
    return found


def values_of(rule: dict[str, object], sha256: str) -> list[str]:
    parameters = cast("dict[str, object]", rule["parameters"])
    entries = cast("list[dict[str, object]]", parameters.get("profile_values", []))
    found = [
        "".join(cast("list[str]", entry["value"]))
        for entry in entries
        if entry["content_sha256"] == sha256
    ]
    return found if "value_id" in parameters else [""]


def test_every_written_line_satisfies_the_checks_that_read_the_configuration_file() -> None:
    rules = native_rules()
    assert len(rules) == 11
    checked: dict[str, set[str]] = {}
    for path, sha256, benchmark in pinned_benchmarks():
        profile_values.read_values(path, sha256)
        collector = collect(path)
        for rule_id, rule in rules.items():
            definition = rule_definitions(collector, rule_id)
            values = values_of(rule, sha256)
            if definition is None or not values:
                continue
            family = str(rule["family"])
            parameters = cast("dict[str, object]", rule["parameters"])
            setting = str(parameters["setting"])
            found = conf_objects(collector, definition, family, setting)
            assert found, (rule_id, benchmark)
            for test, item in found:
                for pattern in patterns(collector, item):
                    for value in values:
                        line = written_line(parameters, value)
                        match = re.search(pattern, f"# comment\n{line}\n", re.MULTILINE)
                        assert match is not None, (rule_id, benchmark, pattern, line)
                        assert re.search(pattern, f"# {line}\n", re.MULTILINE) is None, (
                            rule_id,
                            pattern,
                        )
                        if parameters["comparison"] != "present":
                            assert match.group(1) == value, (rule_id, pattern)
                states = [
                    entry
                    for state in cast("list[str]", test["states"])
                    for entry in collector.states[state]
                ]
                if test["existence"] == "none_exist":
                    continue
                if parameters["comparison"] == "present":
                    assert states == [], (rule_id, benchmark)
                    continue
                expected = COMPARISONS[str(parameters["comparison"])]
                assert [
                    (entry["operation"], bool(entry["var_ref"])) for entry in states
                ] == expected, (rule_id, benchmark, states)
                assert all(
                    entry["var_ref"] == f"oval:ssg-{parameters['value_id']}:var:1"
                    for entry in states
                    if entry["var_ref"]
                ), (rule_id, states)
                assert all(entry["value"] == "1" for entry in states if not entry["var_ref"])
            checked.setdefault(benchmark, set()).add(rule_id)
    assert {benchmark: len(found) for benchmark, found in checked.items()} == {
        UBUNTU: 6,
        RHEL: 10,
    }


def test_stack_checked_is_true_exactly_when_the_check_reads_the_module_line_and_detects_it() -> (
    None
):
    checked = 0
    for path, sha256, benchmark in pinned_benchmarks():
        profile_values.read_values(path, sha256)
        collector = collect(path)
        for rule_id, rule in native_rules().items():
            definition = rule_definitions(collector, rule_id)
            if definition is None or not values_of(rule, sha256):
                continue
            family = str(rule["family"])
            parameters = cast("dict[str, object]", rule["parameters"])
            options = [str(parameters["setting"])] + (
                [str(parameters["alternative"])] if "alternative" in parameters else []
            )
            found = {
                option: stack_patterns(collector, definition, family, option) for option in options
            }
            assert bool(found[options[0]]) is parameters["stack_checked"], (rule_id, benchmark)
            kind, module = MODULE[family]
            for option, oval_patterns in found.items():
                argument = (
                    option
                    if parameters["comparison"] == "present" or option != options[0]
                    else f"{option}=5"
                )
                lines = [
                    f"{kind} required {module}.so preauth {argument}",
                    f"{kind} requisite {module}.so preauth silent {argument}",
                    f"{kind} [default=die] {module}.so authfail {argument}",
                    f"{kind} requisite /usr/lib64/security/{module}.so use_authtok {argument}",
                ]
                detector = option_pattern(family, argument if "=" not in argument else option + "=")
                for pattern in oval_patterns:
                    for line in lines:
                        if re.search(pattern, line + "\n", re.MULTILINE):
                            assert re.search(detector, line + "\n"), (
                                rule_id,
                                benchmark,
                                pattern,
                                line,
                            )
                            checked += 1
    assert checked > 0


def test_the_role_reads_every_stack_file_in_which_the_checks_read_a_setting() -> None:
    names = set(stack_files())
    checked = 0
    for path, sha256, _ in pinned_benchmarks():
        profile_values.read_values(path, sha256)
        collector = collect(path)
        for rule_id, rule in native_rules().items():
            definition = rule_definitions(collector, rule_id)
            if definition is None:
                continue
            setting = str(cast("dict[str, object]", rule["parameters"])["setting"])
            _, module = MODULE[str(rule["family"])]
            for test in collector.tests_of(definition):
                item = collector.objects[str(test["object"])]
                if not any(
                    module in pattern and mentions(pattern.split(module, 1)[1], setting)
                    for pattern in patterns(collector, item)
                ):
                    continue
                for entry in item.get("filepath", []):
                    value = collector.resolve(entry)
                    assert any(reads_file(collector, item, name) for name in names), (
                        rule_id,
                        value,
                    )
                    assert set(re.findall(r"/etc/pam\.d/[a-z-]+", value)) <= names, (rule_id, value)
                    checked += 1
    assert checked > 0


def test_no_other_catalogued_rule_reads_either_configuration_file() -> None:
    readers: set[str] = set()
    catalogued = catalogued_rule_ids()
    for path, sha256, _ in pinned_benchmarks():
        profile_values.read_values(path, sha256)
        collector = collect(path)
        for rule_id in catalogued:
            definition = rule_definitions(collector, rule_id)
            if definition is None:
                continue
            for test in collector.tests_of(definition):
                item = collector.objects.get(str(test.get("object", "")), {})
                if any(reads_file(collector, item, conf) for conf in CONF.values()):
                    readers.add(rule_id)
    assert readers == set(native_rules()) | AUDIT_ONLY_READERS


def test_the_ubuntu_pwhistory_rules_read_only_the_module_line_of_common_password() -> None:
    data = catalogue()
    audit_only = cast("dict[str, list[str]]", data[generate_toggles.AUDIT_ONLY_KEY])["pwhistory"]
    checked = 0
    for path, sha256, benchmark in pinned_benchmarks():
        if benchmark != UBUNTU:
            continue
        profile_values.read_values(path, sha256)
        collector = collect(path)
        for rule_id in audit_only:
            definition = rule_definitions(collector, rule_id)
            if definition is None:
                continue
            files = {
                collector.resolve(entry)
                for test in collector.tests_of(definition)
                for entry in collector.objects[str(test["object"])].get("filepath", [])
            }
            assert files == {"/etc/pam.d/common-password"}, (rule_id, files)
            checked += 1
    assert checked == 4
