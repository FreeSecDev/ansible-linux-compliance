from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
    xmlsafe,
)
from tests.unit.tools.test_content_golden_native import (
    REPOSITORY_ROOT,
    native_parameters,
    pinned_benchmarks,
)
from tools.content import fetch_content as fetch
from tools.roles import profile_values

XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"
DEF = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
IND = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}"
OVAL_SYSTEM = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
MAIN = "/etc/ssh/sshd_config"
RHEL = "xccdf_org.ssgproject.content_benchmark_RHEL-9"
UBUNTU = "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04"
CRYPTO_KEYWORDS = frozenset({"ciphers", "macs", "kexalgorithms"})
OBJECT_FIELDS = frozenset({"filepath", "path", "filename", "pattern", "var_ref"})
STATE_FIELDS = frozenset({"subexpression", "value"})
SCOPES = frozenset({"test", "object", "state"})


class OvalTest:
    """A test of an OVAL definition: its check, its existence check, its objects and states."""

    def __init__(self, check: str, existence: str) -> None:
        self.check = check
        self.existence = existence
        self.objects: list[str] = []
        self.states: list[str] = []


class Content:
    """The XCCDF selections and the OVAL items that the ssh checks use."""

    def __init__(self) -> None:
        self.profiles: dict[str, set[str]] = {}
        self.definitions: dict[str, str] = {}
        self.exports: dict[str, set[str]] = {}
        self.criteria: dict[str, list[str]] = {}
        self.tests: dict[str, OvalTest] = {}
        self.objects: dict[str, dict[str, tuple[str, str]]] = {}
        self.sets: dict[str, list[str]] = {}
        self.variables: dict[str, list[str]] = {}
        self.states: dict[str, list[tuple[str, str, str]]] = {}


class Collector:
    """Collects what the checks of the ssh rules read, through the bounded parser."""

    def __init__(self) -> None:
        self.content = Content()
        self.stack: list[dict[str, str]] = []
        self.parts: list[str] = []
        self.current: dict[str, str] = {}

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        self.stack.append(attributes)
        self.parts = []
        if name.startswith(XCCDF):
            self.xccdf_start(name.removeprefix(XCCDF), attributes)
        elif name.startswith(IND):
            self.independent_start(name.removeprefix(IND), attributes)
        elif name.startswith(DEF):
            self.definition_start(name.removeprefix(DEF), attributes)

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
        elif local == "check" and rule:
            self.current["check"] = attributes.get("system", "")
        elif local == "check-export" and rule and oval:
            content.exports.setdefault(rule, set()).add(attributes.get("value-id", ""))
        elif local == "check-content-ref" and rule and oval:
            content.definitions[rule] = attributes.get("name", "")

    def independent_start(self, local: str, attributes: dict[str, str]) -> None:
        content = self.content
        identifier = attributes.get("id", "")
        test = self.current.get("test", "")
        if local.endswith("_test") and identifier:
            self.current["test"] = identifier
            content.tests[identifier] = OvalTest(
                attributes.get("check", ""),
                attributes.get("check_existence", "at_least_one_exists"),
            )
        elif local == "object" and test:
            content.tests[test].objects.append(attributes.get("object_ref", ""))
        elif local == "state" and test:
            content.tests[test].states.append(attributes.get("state_ref", ""))
        elif local.endswith("_object") and identifier:
            self.current["object"] = identifier
            content.objects[identifier] = {}
        elif local.endswith("_state") and identifier:
            self.current["state"] = identifier
            content.states[identifier] = []

    def definition_start(self, local: str, attributes: dict[str, str]) -> None:
        content = self.content
        identifier = attributes.get("id", "")
        definition = self.current.get("definition", "")
        variable = self.current.get("variable", "")
        if local == "definition":
            self.current["definition"] = identifier
            content.criteria[identifier] = []
        elif local == "criterion" and definition:
            content.criteria[definition].append(attributes.get("test_ref", ""))
        elif local == "local_variable":
            self.current["variable"] = identifier
            content.variables[identifier] = []
        elif local == "object_component" and variable:
            content.variables[variable].append(attributes.get("object_ref", ""))
        elif local == "variable_component" and variable:
            content.variables[variable].append(attributes.get("var_ref", ""))

    def end(self, name: str, /) -> None:
        attributes = self.stack.pop()
        text = "".join(self.parts)
        self.parts = []
        local = name.rsplit("}", maxsplit=1)[-1]
        closes = {
            f"{XCCDF}Profile": "profile",
            f"{XCCDF}Rule": "rule",
            f"{XCCDF}check": "check",
            f"{DEF}definition": "definition",
            f"{DEF}local_variable": "variable",
        }
        if name in closes:
            self.current.pop(closes[name], None)
        elif name.startswith(IND) and local.rsplit("_", maxsplit=1)[-1] in SCOPES:
            if "_" in local:
                self.current.pop(local.rsplit("_", maxsplit=1)[-1], None)
        else:
            self.field_end(name, local, text, attributes)

    def field_end(self, name: str, local: str, text: str, attributes: dict[str, str]) -> None:
        content = self.content
        item = self.current.get("object", "")
        state = self.current.get("state", "")
        if name == f"{DEF}object_reference" and item:
            content.sets.setdefault(item, []).append(text.strip())
        elif item and local in OBJECT_FIELDS:
            content.objects[item][local] = (text, attributes.get("operation", "equals"))
        elif state and local in STATE_FIELDS:
            content.states[state].append(
                (text, attributes.get("operation", "equals"), attributes.get("var_ref", ""))
            )

    def text(self, data: str, /) -> None:
        self.parts.append(data)


def read(path: str, sha256: str) -> Content:
    profile_values.read_values(path, sha256)
    collector = Collector()
    xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, profile_values.MAX_BYTES), collector)
    return collector.content


def textfile_objects(content: Content, reference: str) -> list[str]:
    """Return the textfilecontent54 objects behind an object, a set or a variable object."""
    if reference in content.sets:
        return [item for ref in content.sets[reference] for item in textfile_objects(content, ref)]
    item = content.objects.get(reference, {})
    if "var_ref" in item and "pattern" not in item:
        return [
            found
            for ref in content.variables.get(item["var_ref"][0], [])
            for found in textfile_objects(content, ref)
        ]
    return [reference] if "pattern" in item else []


def reads(item: dict[str, tuple[str, str]], target: str) -> bool:
    """Whether a textfilecontent54 object reads the file ``target``."""

    def matches(value: tuple[str, str], subject: str) -> bool:
        text, operation = value
        return (
            re.search(text, subject) is not None
            if operation == "pattern match"
            else text == subject
        )

    if "filepath" in item:
        return matches(item["filepath"], target)
    path = PurePosixPath(target)
    return matches(item["path"], str(path.parent)) and matches(item["filename"], path.name)


def selected_rules(content: Content, benchmark_profiles: set[str]) -> set[str]:
    return {rule for profile in benchmark_profiles for rule in content.profiles.get(profile, set())}


def manifest_profiles() -> dict[str, set[str]]:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    return {
        stream.benchmark_id: {profile.profile_id for profile in stream.profiles}
        for stream in manifest.datastreams
    }


def ssh_rules() -> dict[str, dict[str, object]]:
    return {
        rule_id: parameters
        for rule_id, parameters in native_parameters().items()
        if "keyword" in parameters
    }


def fixed_value(parameters: dict[str, object]) -> str | None:
    value = parameters.get("value")
    if value is None:
        return None
    return value if isinstance(value, str) else "".join(cast("list[str]", value))


def covered_files(content: Content, rule_id: str, parameters: dict[str, object]) -> dict[str, bool]:
    """Return whether the value tests of the rule read the main file and the rule's drop-in."""
    keyword = str(parameters["keyword"]).lower()
    covered = {MAIN: False, str(parameters["path"]): False}
    tests = [content.tests[ref] for ref in content.criteria[content.definitions[rule_id]]]
    for test in (test for test in tests if test.states):
        objects = [
            content.objects[item] for ref in test.objects for item in textfile_objects(content, ref)
        ]
        for item in (item for item in objects if keyword in item["pattern"][0].lower()):
            for target in (target for target in covered if reads(item, target)):
                assert test.check == "all", rule_id
                assert test.existence != "none_exist", rule_id
                covered[target] = True
                check_state(content, test, rule_id, parameters)
    return covered


def test_each_ssh_rule_writes_a_drop_in_that_the_content_of_each_platform_reads() -> None:
    rules = ssh_rules()
    assert len(rules) == 34
    profiles = manifest_profiles()
    checked: dict[str, set[str]] = {}
    for path, sha256, benchmark in pinned_benchmarks():
        content = read(path, sha256)
        selected = selected_rules(content, profiles[benchmark])
        for rule_id, parameters in rules.items():
            if rule_id not in selected:
                continue
            covered = covered_files(content, rule_id, parameters)
            assert set(covered.values()) == {True}, (rule_id, benchmark, covered)
            checked.setdefault(benchmark, set()).add(rule_id)
    assert {benchmark: len(found) for benchmark, found in checked.items()} == {
        UBUNTU: 25,
        RHEL: 28,
    }


def check_state(
    content: Content, test: OvalTest, rule_id: str, parameters: dict[str, object]
) -> None:
    """Check that the value written satisfies the state, or that the state reads the value."""
    value = fixed_value(parameters)
    entries = [entry for ref in test.states for entry in content.states[ref]]
    assert entries, rule_id
    if value is None:
        assert any(variable for _, _, variable in entries), rule_id
        assert (
            profile_values.VALUE_PREFIX + str(parameters["value_id"]) in content.exports[rule_id]
        ), rule_id
        return
    for text, operation, variable in entries:
        assert not variable, rule_id
        if operation == "pattern match":
            assert re.search(text, value), (rule_id, text, value)
        else:
            assert operation == "equals", (rule_id, operation)
            assert text == value, (rule_id, text, value)


def test_no_pinned_profile_selects_two_native_ssh_rules_that_set_one_keyword() -> None:
    rules = ssh_rules()
    profiles = manifest_profiles()
    for path, sha256, benchmark in pinned_benchmarks():
        content = read(path, sha256)
        for profile in profiles[benchmark]:
            keywords = [
                str(rules[rule_id]["keyword"]).lower()
                for rule_id in content.profiles.get(profile, set())
                if rule_id in rules
            ]
            assert len(keywords) == len(set(keywords)), (benchmark, profile)


def test_the_crypto_rules_are_refused_where_the_crypto_policy_governs_them() -> None:
    for rule_id, parameters in ssh_rules().items():
        crypto = str(parameters["keyword"]).lower() in CRYPTO_KEYWORDS
        benchmarks = parameters.get("crypto_policy_benchmarks", [])
        assert (benchmarks == [RHEL]) is crypto, rule_id


def test_the_drop_ins_sort_before_every_drop_in_of_the_distributions() -> None:
    names = {PurePosixPath(str(parameters["path"])).name for parameters in ssh_rules().values()}
    assert len(names) == 34
    for name in names:
        assert name.startswith("00-freesecdev-")
        assert name < "50-redhat.conf"
        assert name < "50-cloud-init.conf"
        assert name > "00-complianceascode-hardening.conf"
        short = name.removeprefix("00-freesecdev-").removesuffix(".conf").replace("-", "_")
        assert (
            toggles.rule_short_id(
                next(
                    rule_id
                    for rule_id, parameters in ssh_rules().items()
                    if str(parameters["path"]).endswith(name)
                )
            )
            == short
        )


def test_the_rekey_limit_stays_audit_only_because_its_check_refuses_every_drop_in() -> None:
    rule_id = "xccdf_org.ssgproject.content_rule_sshd_rekey_limit"
    assert rule_id not in native_parameters()
    for path, sha256, benchmark in pinned_benchmarks():
        if benchmark != RHEL:
            continue
        content = read(path, sha256)
        tests = [content.tests[ref] for ref in content.criteria[content.definitions[rule_id]]]
        refused = [
            test
            for test in tests
            if test.existence == "none_exist"
            and any(
                reads(content.objects[item], "/etc/ssh/sshd_config.d/00-freesecdev-x.conf")
                for ref in test.objects
                for item in textfile_objects(content, ref)
            )
        ]
        assert refused
        assert {
            profile_values.VALUE_PREFIX + "var_rekey_limit_size",
            profile_values.VALUE_PREFIX + "var_rekey_limit_time",
        } <= content.exports[rule_id]
