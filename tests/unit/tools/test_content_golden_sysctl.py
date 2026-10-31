from __future__ import annotations

import re
from typing import TYPE_CHECKING, cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
    xmlsafe,
)
from tests.unit.tools.test_content_golden_native import (
    REPOSITORY_ROOT,
    pinned_benchmarks,
)
from tools.roles import generate_toggles, profile_values

if TYPE_CHECKING:
    from collections.abc import Iterator

FAMILIES = ("sysctl", "ipv4_parameters", "ipv6_parameters")
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
RHEL = "xccdf_org.ssgproject.content_benchmark_RHEL-9"
UBUNTU = "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04"
IPV6_DISABLED = "oval:ssg-sysctl_kernel_ipv6_disable:def:1"
CONF_NAMES = r"^.*\.conf$"
UBUNTU_MAIN_FILES = "/etc(/ufw){0,1}/sysctl.conf$"
EXPECTED_AUDIT_ONLY: dict[str, set[str]] = {
    "sysctl": {
        "coredump_disable_backtraces",
        "coredump_disable_storage",
        "disable_users_coredumps",
        "service_systemd-coredump_disabled",
        "sysctl_kernel_exec_shield",
        "sysctl_kernel_kexec_load_disabled",
        "sysctl_kernel_modules_disabled",
        "sysctl_kernel_pid_max",
        "sysctl_kernel_unprivileged_bpf_disabled",
        "sysctl_user_max_user_namespaces",
        "sysctl_user_max_user_namespaces_no_remediation",
    },
    "ipv4_parameters": set(),
    "ipv6_parameters": set(),
}
VENDOR_NAMES = (
    "10-bufferbloat.conf",
    "10-console-messages.conf",
    "10-default-yama-scope.conf",
    "10-ipv6-privacy.conf",
    "10-kernel-hardening.conf",
    "10-magic-sysrq.conf",
    "10-map-count.conf",
    "10-network-security.conf",
    "10-ptrace.conf",
    "10-zeropage.conf",
    "50-coredump.conf",
    "50-default.conf",
    "50-libkcapi-optmem_max.conf",
    "50-pid-max.conf",
    "50-redhat.conf",
    "99-cloudimg-ipv6.conf",
    "99-protect-links.conf",
    "99-sysctl.conf",
)


class Node:
    """An OVAL element with its attributes, its text and its child elements."""

    def __init__(self, tag: str, attributes: dict[str, str]) -> None:
        self.tag = tag
        self.attributes = attributes
        self.text = ""
        self.children: list[Node] = []

    def walk(self) -> Iterator[Node]:
        yield self
        for child in self.children:
            yield from child.walk()

    def child(self, tag: str) -> Node | None:
        return next((item for item in self.children if item.tag == tag), None)

    def all(self, tag: str) -> list[Node]:
        return [item for item in self.children if item.tag == tag]


class Collector:
    """Keeps every OVAL element whose identifier names a kernel parameter, with its subtree."""

    def __init__(self) -> None:
        self.items: dict[str, Node] = {}
        self.stack: list[Node | None] = []

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        tag = name.rpartition("}")[2]
        parent = self.stack[-1] if self.stack else None
        node: Node | None = None
        identifier = attributes.get("id", "")
        if parent is not None:
            node = Node(tag, dict(attributes))
            parent.children.append(node)
        elif identifier.startswith("oval:") and "sysctl" in identifier:
            node = Node(tag, dict(attributes))
            self.items[identifier] = node
        self.stack.append(node)

    def end(self, _name: str, /) -> None:
        self.stack.pop()

    def text(self, data: str, /) -> None:
        if self.stack and self.stack[-1] is not None:
            self.stack[-1].text += data


def oval(path: str) -> dict[str, Node]:
    collector = Collector()
    xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, profile_values.MAX_BYTES), collector)
    return collector.items


def catalogue() -> dict[str, object]:
    path = REPOSITORY_ROOT / generate_toggles.CATALOGUE
    return cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))


def role_vars() -> dict[str, object]:
    path = REPOSITORY_ROOT / "roles" / "remediate" / "vars" / "main.yml"
    return cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))


def native_rules() -> dict[str, dict[str, object]]:
    rules = cast("list[dict[str, object]]", catalogue()[generate_toggles.RULES_KEY])
    return {
        str(rule["rule_id"]): rule
        for rule in rules
        if rule["family"] in FAMILIES and rule["revert_strategy"] != toggles.AUDIT_ONLY
    }


def refs(node: Node, attribute: str) -> list[str]:
    return [item.attributes[attribute] for item in node.walk() if attribute in item.attributes]


def leaves(items: dict[str, Node], identifier: str) -> list[Node]:
    node = items[identifier]
    sets = [item for item in node.walk() if item.tag == "object_reference"]
    if not sets:
        return [node]
    found: list[Node] = []
    for reference in sets:
        found.extend(leaves(items, reference.text.strip()))
    return found


def state_values(items: dict[str, Node], test: Node, field: str) -> list[tuple[str, str, str, str]]:
    found: list[tuple[str, str, str, str]] = []
    for reference in test.all("state"):
        state = items[reference.attributes["state_ref"]]
        (value,) = state.all(field)
        found.append(
            (
                value.attributes.get("datatype", ""),
                value.attributes.get("operation", ""),
                value.attributes.get("var_ref", ""),
                value.text.strip(),
            )
        )
    return found


def line_pattern(parameters: dict[str, object]) -> str:
    constants = role_vars()
    key = "__linux_compliance_remediate_sysctl_" + (
        "empty_line_pattern" if parameters.get("empty_value") else "line_pattern"
    )
    return str(constants[key]).replace("{key}", str(parameters["key"]))


def oval_pattern(text: str) -> str:
    return text.replace("[[:blank:]]", "[ \\t]")


def accepts(states: list[tuple[str, str, str, str]], value: str, wanted: str) -> bool:
    for datatype, operation, variable, literal in states:
        expected = wanted if variable else literal
        if operation == "pattern match" and re.search(literal, value):
            return True
        if operation == "equals" and datatype == "int" and int(value) == int(expected):
            return True
        if operation == "equals" and datatype == "string" and value == expected:
            return True
    return False


def written_values(parameters: dict[str, object], sha256: str) -> list[str]:
    if "value_id" not in parameters:
        return [str(parameters["value"])]
    entries = cast("list[dict[str, object]]", parameters["profile_values"])
    return [
        "".join(cast("list[str]", entry["value"]))
        for entry in entries
        if entry["content_sha256"] == sha256
    ]


def dropin(rule_id: str, family: str, parameters: dict[str, object], value: str) -> str:
    line = f"{parameters['key']} =" + (f" {value}" if value else "")
    return (
        f"# Managed by freesecdev.linux_compliance for {rule_id}.\n"
        f"# Switching the rule or the {family} topic off removes this file.\n{line}\n"
    )


def check_files(leaf_nodes: list[Node], benchmark: str, pattern: str) -> None:
    checked = cast(
        "dict[str, dict[str, list[str]]]",
        role_vars()["__linux_compliance_remediate_sysctl_checked"],
    )[benchmark]
    files: set[str] = set()
    directories: set[str] = set()
    for leaf in leaf_nodes:
        found = leaf.child("pattern")
        assert found is not None
        assert oval_pattern(found.text) == pattern
        instance = leaf.child("instance")
        assert instance is not None
        assert instance.attributes == {"datatype": "int", "operation": "greater than or equal"}
        assert instance.text.strip() == "1"
        filepath = leaf.child("filepath")
        if filepath is not None:
            if filepath.attributes.get("operation") == "pattern match":
                assert filepath.text == UBUNTU_MAIN_FILES
                assert benchmark == UBUNTU
                files.update(
                    path for path in checked["files"] if re.search(filepath.text, path) is not None
                )
            else:
                files.add(filepath.text)
            continue
        path = leaf.child("path")
        name = leaf.child("filename")
        assert path is not None
        assert name is not None
        assert name.text == CONF_NAMES
        directories.add(path.text)
    assert files == set(checked["files"])
    assert directories == set(checked["directories"])


States = list[tuple[str, str, str, str]]


def check_definition(items: dict[str, Node], rule: dict[str, object]) -> tuple[str, str]:
    rule_id = str(rule["rule_id"])
    short = toggles.rule_short_id(rule_id)
    static = f"oval:ssg-{short}_static:def:1"
    runtime = f"oval:ssg-{short}_runtime:def:1"
    definition = items[f"oval:ssg-{short}:def:1"]
    extended = refs(definition, "definition_ref")
    (top,) = definition.all("criteria")
    if rule["family"] == "ipv6_parameters":
        assert extended == [IPV6_DISABLED, static, runtime], rule_id
        assert top.attributes["operator"] == "OR"
    else:
        assert extended == [static, runtime], rule_id
        assert top.attributes["operator"] == "AND"
    return static, runtime


def check_runtime(items: dict[str, Node], runtime: str, parameters: dict[str, object]) -> States:
    (runtime_test_id,) = refs(items[runtime], "test_ref")
    runtime_test = items[runtime_test_id]
    assert runtime_test.tag == "sysctl_test"
    assert runtime_test.attributes["check"] == "all"
    assert runtime_test.attributes["check_existence"] == "all_exist"
    (runtime_object,) = runtime_test.all("object")
    name = items[runtime_object.attributes["object_ref"]].child("name")
    assert name is not None
    assert name.text == parameters["key"]
    return state_values(items, runtime_test, "value")


def check_static(
    items: dict[str, Node], static: str, parameters: dict[str, object], benchmark: str
) -> States:
    user, missing, package = refs(items[static], "test_ref")
    assert user.endswith("_static_user:tst:1")
    assert missing.endswith("_static_user_missing:tst:1")
    user_test = items[user]
    assert user_test.attributes["check"] == "all"
    assert user_test.attributes["check_existence"] == "all_exist"
    assert items[missing].attributes["check_existence"] == "none_exist"
    (user_object,) = user_test.all("object")
    (missing_object,) = items[missing].all("object")
    assert missing_object.attributes == user_object.attributes
    static_states = state_values(items, user_test, "subexpression")
    check_files(
        leaves(items, user_object.attributes["object_ref"]), benchmark, line_pattern(parameters)
    )
    check_package(items, package, parameters, benchmark, static_states)
    return static_states


def check_package(
    items: dict[str, Node],
    package: str,
    parameters: dict[str, object],
    benchmark: str,
    static_states: States,
) -> None:
    package_test = items[package]
    assert bool(parameters.get("absent_accepted")) is package.endswith("_pkg_not_wrong:tst:1")
    if not parameters.get("absent_accepted"):
        assert package.endswith("_static_pkg_correct:tst:1")
        assert package_test.attributes["check_existence"] == "all_exist"
    assert state_values(items, package_test, "subexpression") == static_states
    (package_object,) = package_test.all("object")
    (package_leaf,) = leaves(items, package_object.attributes["object_ref"])
    found_path = package_leaf.child("path")
    assert found_path is not None
    checked = cast(
        "dict[str, dict[str, list[str]]]",
        role_vars()["__linux_compliance_remediate_sysctl_checked"],
    )[benchmark]
    assert [found_path.text] == checked["package_directories"]


def check_accepted(states: States, parameters: dict[str, object], benchmark: str) -> None:
    assert {datatype for datatype, _, _, _ in states} == {parameters["datatype"]}
    variables = {variable for _, _, variable, _ in states}
    if "value_id" in parameters:
        assert variables == {f"oval:ssg-{parameters['value_id']}:var:1"}, variables
    elif "accepted_pattern" in parameters:
        assert [(o, t) for _, o, _, t in states] == [
            ("pattern match", parameters["accepted_pattern"])
        ]
    else:
        accepted = cast("dict[str, list[str]]", parameters["accepted"])[benchmark]
        assert [(o, t) for _, o, _, t in states] == [("equals", value) for value in accepted]
        assert parameters["value"] in accepted


def check_rule(
    items: dict[str, Node], rule: dict[str, object], benchmark: str, sha256: str
) -> None:
    rule_id = str(rule["rule_id"])
    parameters = cast("dict[str, object]", rule["parameters"])
    static, runtime = check_definition(items, rule)
    runtime_states = check_runtime(items, runtime, parameters)
    static_states = check_static(items, static, parameters, benchmark)
    assert static_states == runtime_states, rule_id
    check_accepted(runtime_states, parameters, benchmark)
    values = written_values(parameters, sha256)
    assert values, (rule_id, benchmark)
    for value in values:
        content = dropin(rule_id, str(rule["family"]), parameters, value)
        captured = re.findall(line_pattern(parameters), content, re.MULTILINE)
        assert captured == [value], (rule_id, captured)
        assert accepts(static_states, value, value), (rule_id, value)


def test_every_native_kernel_parameter_rule_writes_what_the_checks_of_both_datastreams_read() -> (
    None
):
    rules = native_rules()
    assert len(rules) == 65
    checked: dict[str, set[str]] = {}
    for path, sha256, benchmark in pinned_benchmarks():
        items = oval(path)
        for rule_id, rule in rules.items():
            if f"oval:ssg-{toggles.rule_short_id(rule_id)}:def:1" not in items:
                continue
            check_rule(items, rule, benchmark, sha256)
            checked.setdefault(benchmark, set()).add(rule_id)
    assert {benchmark: len(found) for benchmark, found in checked.items()} == {
        UBUNTU: 27,
        RHEL: 65,
    }


def test_the_line_patterns_reproduce_the_content_patterns() -> None:
    constants = role_vars()
    standard = str(constants["__linux_compliance_remediate_sysctl_line_pattern"])
    empty = str(constants["__linux_compliance_remediate_sysctl_empty_line_pattern"])
    assert standard == r"^[\s]*{key}[\s]*=[\s]*(.*\S)[\s]*$"
    assert empty == r"^[ \t]*{key}[ \t]*=[ \t]*(.*)$"
    assert re.findall(standard.replace("{key}", "kernel.x"), "kernel.x = 1\n", re.MULTILINE) == [
        "1"
    ]
    assert re.findall(empty.replace("{key}", "kernel.x"), "kernel.x =\n", re.MULTILINE) == [""]


def test_every_drop_in_sorts_after_the_distribution_files() -> None:
    for rule_id, rule in native_rules().items():
        parameters = cast("dict[str, object]", rule["parameters"])
        path = str(parameters["path"])
        directory, _, name = path.rpartition("/")
        assert directory == "/etc/sysctl.d", rule_id
        assert re.fullmatch(r"999-freesecdev-[a-z0-9-]+\.conf", name), rule_id
        assert (
            name == "999-freesecdev-" + toggles.rule_short_id(rule_id).replace("_", "-") + ".conf"
        )
        assert all(name > vendor for vendor in VENDOR_NAMES), rule_id


def test_the_audit_only_rules_of_the_kernel_parameter_families_are_the_documented_ones() -> None:
    audit_only = cast(
        "dict[str, list[str]]", catalogue()["__linux_compliance_remediate_audit_only"]
    )
    for family, expected in EXPECTED_AUDIT_ONLY.items():
        found = {rule.removeprefix(RULE_PREFIX) for rule in audit_only.get(family, [])}
        assert found == expected, family


def test_the_propagating_parameters_are_keys_of_native_rules() -> None:
    propagating = cast(
        "dict[str, str]", role_vars()["__linux_compliance_remediate_sysctl_propagating"]
    )
    keys = {
        str(cast("dict[str, object]", rule["parameters"])["key"])
        for rule in native_rules().values()
    }
    assert set(propagating) <= keys
    for key, pattern in propagating.items():
        prefix, _, field = pattern.partition(".*.")
        assert key.startswith(prefix.rsplit(".", 1)[0])
        assert key.endswith(field) or key == "net.ipv4.ip_forward"


def test_only_ipv4_forwarding_resets_the_accept_redirects_of_all_interfaces() -> None:
    """The kernel sets ``conf.all.accept_redirects`` to the opposite of IPv4 forwarding.

    ``inet_forward_change`` runs when ``net.ipv4.ip_forward`` or ``net.ipv4.conf.all.forwarding``
    changes; the role records and restores that parameter around such a change.
    """
    side_effects = cast(
        "dict[str, list[str]]", role_vars()["__linux_compliance_remediate_sysctl_side_effects"]
    )
    propagating = cast(
        "dict[str, str]", role_vars()["__linux_compliance_remediate_sysctl_propagating"]
    )
    assert side_effects == {
        "net.ipv4.ip_forward": ["net.ipv4.conf.all.accept_redirects"],
        "net.ipv4.conf.all.forwarding": ["net.ipv4.conf.all.accept_redirects"],
    }
    assert set(side_effects) <= set(propagating)
