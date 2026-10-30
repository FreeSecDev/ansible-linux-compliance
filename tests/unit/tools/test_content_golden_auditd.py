"""Golden tests that pin the native auditd rules against the OVAL checks of the pinned content.

The collection writes its own audit rule lines and auditd.conf lines (ADR 0024); the content is
only read here, to prove that what the role writes satisfies the check of every pinned profile
that selects the rule.
"""

from __future__ import annotations

import re
from typing import cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    xmlsafe,
)
from tests.unit.tools.test_content_golden_native import REPOSITORY_ROOT, pinned_benchmarks
from tools.roles import profile_values

XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"
DEF = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
IND = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}"
OVAL_SYSTEM = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
PROFILE_PREFIX = "xccdf_org.ssgproject.content_profile_"
RULES_DIRECTORY_FILE = re.compile(r"/etc/audit/rules\.d/50-freesecdev-[a-z0-9-]+\.rules")
CONF = "/etc/audit/auditd.conf"
HEADER = "# Managed by freesecdev.linux_compliance for {rule}."


class Oval:
    """What the checks of the auditd rules use, read through the bounded parser."""

    def __init__(self) -> None:
        self.profiles: dict[str, set[str]] = {}
        self.definitions: dict[str, str] = {}
        self.criteria: dict[str, list[str]] = {}
        self.operators: dict[str, str] = {}
        self.tests: dict[str, dict[str, list[str]]] = {}
        self.objects: dict[str, dict[str, tuple[str, str, str]]] = {}
        self.states: dict[str, list[tuple[str, str, str]]] = {}
        self.variables: dict[str, list[tuple[str, str]]] = {}
        self.stack: list[dict[str, str]] = []
        self.parts: list[str] = []
        self.current: dict[str, str] = {}

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        self.stack.append(attributes)
        self.parts = []
        if name.startswith(XCCDF):
            self.benchmark(name, attributes)
        elif name.startswith(IND):
            self.independent(name.rsplit("}", maxsplit=1)[-1], attributes.get("id", ""), attributes)
        else:
            self.definition(name, attributes)

    def benchmark(self, name: str, attributes: dict[str, str]) -> None:
        identifier = attributes.get("id", "")
        if name == f"{XCCDF}Profile":
            self.current["profile"] = identifier
            self.profiles[identifier] = set()
        elif name == f"{XCCDF}select" and self.current.get("profile"):
            if attributes.get("selected") == "true":
                self.profiles[self.current["profile"]].add(attributes.get("idref", ""))
        elif name == f"{XCCDF}Rule":
            self.current["rule"] = identifier
        elif name == f"{XCCDF}check" and self.current.get("rule"):
            self.current["system"] = attributes.get("system", "")
        elif name == f"{XCCDF}check-content-ref" and self.current.get("system") == OVAL_SYSTEM:
            self.definitions[self.current["rule"]] = attributes.get("name", "")

    def definition(self, name: str, attributes: dict[str, str]) -> None:
        identifier = attributes.get("id", "")
        if name == f"{DEF}definition":
            self.current["definition"] = identifier
            self.criteria[identifier] = []
        elif name == f"{DEF}criteria" and self.current.get("definition"):
            self.operators.setdefault(self.current["definition"], attributes.get("operator", "AND"))
        elif name == f"{DEF}criterion" and self.current.get("definition"):
            self.criteria[self.current["definition"]].append(attributes.get("test_ref", ""))
        elif name == f"{DEF}local_variable":
            self.current["variable"] = identifier
            self.variables[identifier] = []
        elif name == f"{DEF}variable_component" and self.current.get("variable"):
            self.variables[self.current["variable"]].append(("var", attributes.get("var_ref", "")))

    def independent(self, local: str, identifier: str, attributes: dict[str, str]) -> None:
        if local == "textfilecontent54_test":
            self.current["test"] = identifier
            self.tests[identifier] = {"objects": [], "states": []}
        elif local == "object" and self.current.get("test"):
            self.tests[self.current["test"]]["objects"].append(attributes.get("object_ref", ""))
        elif local == "state" and self.current.get("test"):
            self.tests[self.current["test"]]["states"].append(attributes.get("state_ref", ""))
        elif local == "textfilecontent54_object":
            self.current["object"] = identifier
            self.objects[identifier] = {}
        elif local == "textfilecontent54_state":
            self.current["state"] = identifier
            self.states[identifier] = []

    def end(self, name: str, /) -> None:
        attributes = self.stack.pop()
        text = "".join(self.parts)
        self.parts = []
        local = name.rsplit("}", maxsplit=1)[-1]
        closes = {
            f"{XCCDF}Profile": "profile",
            f"{XCCDF}Rule": "rule",
            f"{XCCDF}check": "system",
            f"{DEF}definition": "definition",
            f"{DEF}local_variable": "variable",
            f"{IND}textfilecontent54_test": "test",
            f"{IND}textfilecontent54_object": "object",
            f"{IND}textfilecontent54_state": "state",
        }
        if name in closes:
            self.current.pop(closes[name], None)
            return
        if name == f"{DEF}literal_component" and self.current.get("variable"):
            self.variables[self.current["variable"]].append(("literal", text))
        elif (
            name.startswith(IND) and self.current.get("object") and local in {"filepath", "pattern"}
        ):
            self.objects[self.current["object"]][local] = (
                text,
                attributes.get("operation", "equals"),
                attributes.get("var_ref", ""),
            )
        elif name == f"{IND}subexpression" and self.current.get("state"):
            self.states[self.current["state"]].append(
                (text, attributes.get("operation", "equals"), attributes.get("var_ref", ""))
            )

    def text(self, data: str, /) -> None:
        self.parts.append(data)


def pcre(pattern: str) -> str:
    """Return a POSIX/PCRE pattern of the content with its inline flags scoped, for Python.

    The checks switch case-insensitive matching on and off in the middle of a pattern,
    ``(?i)freq(?-i)``, which Python accepts only as a scoped group, ``(?i:freq)``.
    """
    scoped = re.sub(r"\(\?i\)(.*?)\(\?-i\)", r"(?i:\1)", pattern)
    head, flag, tail = scoped.partition("(?i)")
    return head + (f"(?i:{tail})" if flag and head else flag + tail)


def read(path: str, sha256: str) -> Oval:
    profile_values.read_values(path, sha256)
    collector = Oval()
    xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, profile_values.MAX_BYTES), collector)
    return collector


def catalogue_rules(method: str) -> dict[str, dict[str, object]]:
    data = cast(
        "dict[str, object]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "roles/remediate/vars/rules.yml").read_text(encoding="utf-8")
        ),
    )
    rules = cast("list[dict[str, object]]", data["__linux_compliance_remediate_rules"])
    return {
        str(rule["rule_id"]): rule
        for rule in rules
        if cast("dict[str, object]", rule["parameters"]).get("method") == method
    }


def role_constants() -> dict[str, object]:
    return cast(
        "dict[str, object]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "roles/remediate/vars/main.yml").read_text(encoding="utf-8")
        ),
    )


def profile_groups(
    parameters: dict[str, object], sha256: str, profiles: set[str]
) -> list[tuple[str, set[str]]]:
    """Return, for the profiles that select a rule, each value of the profile and its profiles."""
    if "value_id" not in parameters:
        return [("", profiles)]
    groups: list[tuple[str, set[str]]] = []
    for entry in cast("list[dict[str, object]]", parameters["profile_values"]):
        chosen = {f"{PROFILE_PREFIX}{name}" for name in cast("list[str]", entry["profiles"])}
        if entry["content_sha256"] == sha256 and chosen & profiles:
            groups.append(("".join(cast("list[str]", entry["value"])), chosen & profiles))
    return groups


def resolve(oval: Oval, field: tuple[str, str, str], value: str) -> str:
    """Return the text of a pattern, joining a local variable with the profile's value."""
    text, _, reference = field
    if not reference:
        return text
    joined = ""
    for kind, part in oval.variables[reference]:
        joined += part if kind == "literal" else value
    return joined


def selecting(oval: Oval, rule_id: str) -> set[str]:
    return {profile for profile, rules in oval.profiles.items() if rule_id in rules}


def definition_tests(oval: Oval, rule_id: str, filepath: str) -> list[str]:
    tests = []
    for test in oval.criteria[oval.definitions[rule_id]]:
        if test not in oval.tests:
            continue
        for reference in oval.tests[test]["objects"]:
            path, operation, _ = oval.objects[reference].get("filepath", ("", "equals", ""))
            reads = (
                re.search(path, filepath) is not None
                if operation == "pattern match"
                else path == filepath
            )
            if reads:
                tests.append(test)
    return tests


def check_drop_in(
    oval: Oval, sha256: str, benchmark: str, rule_id: str, rule: dict[str, object]
) -> int:
    """Check the drop-in of a rule against a datastream; return how many values it covered."""
    pattern = str(role_constants()["__linux_compliance_remediate_audit_line_pattern"])
    parameters = cast("dict[str, object]", rule["parameters"])
    profiles = selecting(oval, rule_id)
    lines = cast("dict[str, list[str]]", parameters["lines"])
    if not profiles:
        assert benchmark not in lines, rule_id
        return 0
    assert benchmark in lines, f"{rule_id} has no lines for {benchmark}"
    assert RULES_DIRECTORY_FILE.fullmatch(str(parameters["path"])), parameters["path"]
    tests = definition_tests(oval, rule_id, str(parameters["path"]))
    assert tests, f"{rule_id}: the check of {benchmark} reads no file of /etc/audit/rules.d"
    groups = profile_groups(parameters, sha256, profiles)
    for value, _ in groups:
        written = [line.replace("{value}", value) for line in lines[benchmark]]
        assert all(re.fullmatch(pattern, line) for line in written), written
        wanted = [
            resolve(oval, oval.objects[reference]["pattern"], value)
            for test in tests
            for reference in oval.tests[test]["objects"]
        ]
        for expression in wanted:
            assert any(re.search(expression, line) for line in written), (
                f"{rule_id} on {benchmark}: no line of {written} matches {expression}"
            )
    return len(groups)


def test_each_audit_rule_drop_in_satisfies_every_check_of_the_files_that_augenrules_reads() -> None:
    rules = catalogue_rules("rules_file")
    assert len(rules) == 5
    checked = 0
    for path, sha256, benchmark in pinned_benchmarks():
        oval = read(path, sha256)
        for rule_id, rule in rules.items():
            checked += check_drop_in(oval, sha256, benchmark, rule_id, rule)
    assert checked >= 9


def test_each_audit_rule_writes_one_drop_in_of_its_own() -> None:
    paths = [
        str(cast("dict[str, object]", rule["parameters"])["path"])
        for rule in catalogue_rules("rules_file").values()
    ]
    assert len(paths) == len(set(paths))
    for rule_id, rule in catalogue_rules("rules_file").items():
        short = rule_id.removeprefix(RULE_PREFIX).replace("_", "-")
        assert cast("dict[str, object]", rule["parameters"])["path"] == (
            f"/etc/audit/rules.d/50-freesecdev-{short}.rules"
        )


def satisfied(state: list[tuple[str, str, str]], captured: str, value: str) -> bool:
    for text, operation, reference in state:
        wanted = value if reference else text
        if operation == "pattern match":
            expression = ("(?i)" + value) if reference else text
            if re.search(pcre(expression), captured) is None:
                return False
        elif operation == "case insensitive equals":
            if captured.lower() != wanted.lower():
                return False
        elif operation == "equals":
            if captured != wanted:
                return False
        elif operation == "greater than or equal":
            if int(captured) < int(wanted):
                return False
        else:
            return False
    return True


def written_value(parameters: dict[str, object], value: str, order: list[str]) -> str:
    if parameters["compare"] == "choice":
        choices = value.split("|")
        if len(choices) == 1:
            return choices[0]
        return next(choice for choice in order if choice in [item.lower() for item in choices])
    return value + ("%" if parameters["compare"] == "percent" else "")


def oval_results(oval: Oval, test: str, line: str, value: str) -> list[bool]:
    """Return, per object of an OVAL test, whether ``line`` matches it and satisfies its states."""
    results = []
    states = [oval.states[state] for state in oval.tests[test]["states"]]
    for reference in oval.tests[test]["objects"]:
        found = re.search(pcre(oval.objects[reference]["pattern"][0]), line)
        captured = (found.group(1) if found.groups() else "") if found is not None else None
        results.append(
            captured is not None and all(satisfied(state, captured, value) for state in states)
        )
    return results


def test_each_auditd_setting_satisfies_the_check_of_every_profile_that_selects_it() -> None:
    rules = catalogue_rules("conf_line")
    order = cast("list[str]", role_constants()["__linux_compliance_remediate_auditd_choice_order"])
    assert len(rules) == 20
    checked = 0
    for path, sha256, _ in pinned_benchmarks():
        oval = read(path, sha256)
        for rule_id, rule in rules.items():
            parameters = cast("dict[str, object]", rule["parameters"])
            profiles = selecting(oval, rule_id)
            tests = definition_tests(oval, rule_id, CONF) if profiles else []
            assert tests or not profiles, f"{rule_id} reads no {CONF}"
            groups = (
                profile_groups(parameters, sha256, profiles)
                if "value_id" in parameters
                else [(str(parameters["value"]), profiles)]
            )
            for value, _ in groups if profiles else []:
                line = f"{parameters['setting']} = {written_value(parameters, value, order)}"
                results = [item for test in tests for item in oval_results(oval, test, line, value)]
                assert (
                    any(results)
                    if oval.operators[oval.definitions[rule_id]] == "OR"
                    else all(results)
                ), f"{rule_id}: {line} fails the check ({results})"
                checked += 1
    assert checked >= 30


def test_no_pinned_profile_selects_two_native_auditd_rules_that_set_one_setting() -> None:
    rules = catalogue_rules("conf_line")
    for path, sha256, _ in pinned_benchmarks():
        oval = read(path, sha256)
        for profile, selected in oval.profiles.items():
            settings = [
                str(cast("dict[str, object]", rule["parameters"])["setting"])
                for rule_id, rule in rules.items()
                if rule_id in selected
            ]
            assert len(settings) == len(set(settings)), f"{profile}: {settings}"


def test_every_choice_of_a_profile_has_a_value_that_the_role_writes() -> None:
    order = cast("list[str]", role_constants()["__linux_compliance_remediate_auditd_choice_order"])
    for rule_id, rule in catalogue_rules("conf_line").items():
        parameters = cast("dict[str, object]", rule["parameters"])
        if parameters["compare"] != "choice":
            continue
        values = (
            [
                "".join(cast("list[str]", entry["value"]))
                for entry in cast("list[dict[str, object]]", parameters["profile_values"])
            ]
            if "value_id" in parameters
            else [str(parameters["value"])]
        )
        for value in values:
            choices = [item.lower() for item in value.split("|")]
            assert len(choices) == 1 or any(choice in choices for choice in order), (rule_id, value)


def test_the_drop_ins_carry_the_header_that_cleanup_looks_for() -> None:
    task = (REPOSITORY_ROOT / "roles/remediate/tasks/auditd_rules_dropins.yml").read_text(
        encoding="utf-8"
    )
    assert "'# Managed by freesecdev.linux_compliance for ' ~ rule.rule_id ~ '.'" in task
    assert HEADER.format(rule="x") == "# Managed by freesecdev.linux_compliance for x."


def test_the_role_line_pattern_refuses_what_could_break_a_rule_set() -> None:
    pattern = str(role_constants()["__linux_compliance_remediate_audit_line_pattern"])
    for line in (
        "-D",
        "-e 2",
        "-e 0",
        "-f 2",
        "-b 1",
        "-w /etc/passwd -p wa -k identity; reboot",
        "-a never,exit -S all",
        "-a always,exit -S all -k x\n-D",
        "-w relative -p wa -k x",
        "-a always,exit -F arch=b64 -S adjtimex",
    ):
        assert re.fullmatch(pattern, line) is None, line


def test_inline_flags_of_the_content_are_scoped_for_python() -> None:
    assert pcre("^[ ]*(?i)freq(?-i)[ ]*=") == "^[ ]*(?i:freq)[ ]*="
    assert pcre("(?i)yes") == "(?i)yes"
    assert pcre("^x(?i)yes") == "^x(?i:yes)"
    assert pcre("^plain$") == "^plain$"
