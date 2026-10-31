"""Golden tests of the native login_defs rules against the pinned OVAL (FREES-185).

The family file ``roles/remediate/tasks/login_defs.yml`` writes one line per setting into
``/etc/login.defs`` and decides ``compliant`` by mirroring each check: the comparison of the
rule's parameters must be the operation of the check's state, the value must be the external
variable that the check reads, and the only files read must be ``/etc/login.defs`` (and, for
``CREATE_HOME``, the drop-in directory ``/etc/login.defs.d``). The object patterns are pinned
literally, so a content update that changes what a check reads fails here until the family and
ADR 0024 follow. The set of rules whose checks read ``/etc/login.defs`` is pinned as well, so a
new rule of the content is either made native or documented as ``audit_only``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
    xmlsafe,
)
from tests.unit.tools.test_content_golden_native import native_parameters, pinned_benchmarks
from tools.roles import profile_values

OVAL_DEF = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
OVAL_IND = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}"
XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"
OVAL_NAMESPACES = (OVAL_DEF, OVAL_IND, "{http://oval.mitre.org/XMLSchema/oval-definitions-5#unix}")
REFERENCE_ATTRIBUTES = ("object_ref", "state_ref", "var_ref", "test_ref", "definition_ref")
LOGIN_DEFS = "/etc/login.defs"
DROPIN_DIRECTORY = "/etc/login.defs.d"
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
VALUE_PREFIX = "oval:ssg-"
OPERATIONS = {
    "at_most": "less than or equal",
    "at_least": "greater than or equal",
    "umask": "bitwise and",
}
PATTERNS = {
    "PASS_MAX_DAYS": r"^[\s]*(?i)(PASS_MAX_DAYS[\s]+\d+)",
    "PASS_MIN_DAYS": r"^[\s]*(?i)(PASS_MIN_DAYS[\s]+\d+)",
    "PASS_MIN_LEN": r"^[\s]*(?i)(PASS_MIN_LEN[\s]+\d+)",
    "PASS_WARN_AGE": r"^[\s]*(?i)(PASS_WARN_AGE[\s]+\d+)[\s]*(?:#.*)?$",
    "UMASK": r"^[\s]*UMASK[\s]+([^#\s]*)",
    "FAIL_DELAY": r"^[\s]*(?i)FAIL_DELAY(?-i)[\s]+([^#\s]*)",
    "CREATE_HOME": r"^[\s]*(?i)CREATE_HOME(?-i)[\s]+yes[\s]*(?:#.*)?$",
}
AUDIT_ONLY_READERS = {
    "set_password_hashing_algorithm_logindefs",
    "no_shelllogin_for_systemaccounts",
}
NATIVE_PER_BENCHMARK = {
    "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04": 4,
    "xccdf_org.ssgproject.content_benchmark_RHEL-9": 7,
}


@dataclass
class Element:
    """One OVAL element with an identifier: its tag, attributes and the leaves below it."""

    tag: str
    attributes: dict[str, str]
    leaves: list[tuple[str, dict[str, str], str]] = field(
        default_factory=list[tuple[str, dict[str, str], str]]
    )
    references: set[str] = field(default_factory=set[str])


class OvalCollector:
    """Keeps every OVAL element with an id, the checks of every rule and the selected rules."""

    def __init__(self) -> None:
        self.elements: dict[str, Element] = {}
        self.rule_checks: dict[str, set[str]] = {}
        self.selected: set[str] = set()
        self.stack: list[str] = []
        self.owner: list[Element] = []
        self.rule = ""
        self.parts: list[str] = []
        self.leaf: tuple[str, dict[str, str]] | None = None

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        self.stack.append(name)
        if name == f"{XCCDF}Rule":
            self.rule = attributes.get("id", "")
        elif name == f"{XCCDF}check-content-ref" and self.rule:
            self.rule_checks.setdefault(self.rule, set()).add(attributes.get("name", ""))
        elif name == f"{XCCDF}select" and attributes.get("selected") == "true":
            self.selected.add(attributes.get("idref", ""))
        if name.startswith(OVAL_NAMESPACES):
            if "id" in attributes and name != f"{OVAL_DEF}definitions":
                element = Element(name, dict(attributes))
                self.elements[attributes["id"]] = element
                self.owner.append(element)
            elif self.owner:
                self.owner[-1].references.update(
                    attributes[key] for key in REFERENCE_ATTRIBUTES if key in attributes
                )
                self.leaf = (name, dict(attributes))
                self.parts = []

    def end(self, name: str, /) -> None:
        self.stack.pop()
        if name == f"{XCCDF}Rule":
            self.rule = ""
        if self.owner and self.leaf is not None and self.leaf[0] == name:
            text = "".join(self.parts)
            self.owner[-1].leaves.append((name, self.leaf[1], text))
            if name.endswith("}var_ref"):
                self.owner[-1].references.add(text.strip())
            self.leaf = None
        elif self.owner and self.owner[-1].tag == name and "id" in self.owner[-1].attributes:
            self.owner.pop()

    def text(self, data: str, /) -> None:
        if self.leaf is not None:
            self.parts.append(data)


@dataclass(frozen=True)
class Check:
    """What the definition of one rule reaches: file objects, state operations and values."""

    files: frozenset[tuple[str, str, str]]
    operations: frozenset[str]
    externals: frozenset[str]


def collected(path: str) -> OvalCollector:
    collector = OvalCollector()
    xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, profile_values.MAX_BYTES), collector)
    return collector


def reach(collector: OvalCollector, definition: str) -> Check:
    seen: set[str] = set()
    queue = deque([definition])
    files: set[tuple[str, str, str]] = set()
    operations: set[str] = set()
    externals: set[str] = set()
    while queue:
        current = queue.popleft()
        element = collector.elements.get(current)
        if current in seen or element is None:
            continue
        seen.add(current)
        queue.extend(sorted(element.references))
        if element.tag == f"{OVAL_IND}textfilecontent54_object":
            leaves = {tag.removeprefix(OVAL_IND): text for tag, _, text in element.leaves}
            location = leaves.get("filepath") or leaves.get("path", "")
            files.add((location, leaves.get("filename", ""), leaves.get("pattern", "")))
        elif element.tag.endswith("_state"):
            operations.update(
                attributes["operation"]
                for _, attributes, _ in element.leaves
                if "operation" in attributes and "var_ref" in attributes
            )
        elif element.tag == f"{OVAL_DEF}external_variable":
            externals.add(current)
    return Check(frozenset(files), frozenset(operations), frozenset(externals))


def reads_login_defs(check: Check) -> bool:
    return any(location == LOGIN_DEFS for location, _, _ in check.files)


def login_defs_rules() -> dict[str, dict[str, object]]:
    return {
        rule_id: parameters
        for rule_id, parameters in native_parameters().items()
        if parameters.get("comparison") is not None
    }


def assert_mirrors(rule_id: str, parameters: dict[str, object], check: Check) -> None:
    setting = str(parameters["setting"])
    main = {item for item in check.files if item[0] == LOGIN_DEFS}
    assert main == {(LOGIN_DEFS, "", PATTERNS[setting])}, (rule_id, main)
    others = {item[:2] for item in check.files} - {(LOGIN_DEFS, "")}
    expected_others: set[tuple[str, str]] = (
        {(DROPIN_DIRECTORY, r".*\.defs$")} if setting == "CREATE_HOME" else set()
    )
    assert others == expected_others, (rule_id, others)
    assert parameters.get("reads_dropins", False) is bool(expected_others), rule_id
    comparison = str(parameters["comparison"])
    if comparison == "equal":
        assert check.operations == frozenset(), (rule_id, check.operations)
        assert check.externals == frozenset()
        assert "value_id" not in parameters
        return
    assert check.operations == {OPERATIONS[comparison]}, (rule_id, check.operations)
    value_id = str(parameters["value_id"])
    assert check.externals == {f"{VALUE_PREFIX}{value_id}:var:1"}, rule_id


def test_every_native_login_defs_rule_mirrors_the_check_of_each_pinned_datastream() -> None:
    rules = login_defs_rules()
    assert {str(parameters["setting"]) for parameters in rules.values()} == set(PATTERNS)
    checked: dict[str, int] = {}
    for path, sha256, benchmark in pinned_benchmarks():
        profile_values.read_values(path, sha256)
        collector = collected(path)
        for rule_id, parameters in rules.items():
            if rule_id not in collector.selected:
                continue
            short = toggles.rule_short_id(rule_id)
            check = reach(collector, f"oval:ssg-{short}:def:1")
            assert collector.rule_checks[rule_id] >= {f"oval:ssg-{short}:def:1"}
            assert_mirrors(rule_id, parameters, check)
            checked[benchmark] = checked.get(benchmark, 0) + 1
    assert checked == NATIVE_PER_BENCHMARK


def test_every_rule_whose_check_reads_login_defs_is_native_or_a_documented_exception() -> None:
    native = {toggles.rule_short_id(rule_id) for rule_id in login_defs_rules()}
    found: set[str] = set()
    for path, sha256, _ in pinned_benchmarks():
        profile_values.read_values(path, sha256)
        collector = collected(path)
        for rule_id in collector.selected & set(collector.rule_checks):
            if not rule_id.startswith(RULE_PREFIX):
                continue
            for definition in collector.rule_checks[rule_id]:
                if reads_login_defs(reach(collector, definition)):
                    found.add(toggles.rule_short_id(rule_id))
    assert found == native | AUDIT_ONLY_READERS
    catalogue = native_parameters()
    assert not {RULE_PREFIX + short for short in AUDIT_ONLY_READERS} & set(catalogue)
