"""Render the real cleanup and plan tasks of the kernel parameter families (FREES-107, FREES-208).

The model of the readers is unit-tested in ``test_sysctl_config.py``; this module runs the role's
own Jinja around it, taken unchanged from ``roles/remediate/tasks/sysctl_parameters.yml``: the
tasks that resolve each rule's value from the profile or the catalogue and compose its drop-in and
ledger record, plan the cleanup, refuse a cleanup whose vendor file changed since it was read,
name the reverted rules, keep the texts and running values as the cleanup leaves them, decide
every rule to apply and refuse them all when a vendor file to edit changed since it was read.
Each scenario is one play on a host of its own with mocked inputs, run in check mode on the
local machine; nothing is read from or written to the host's configuration. The role's two
``stat`` tasks that read the vendor files again before a write are replaced by tasks that build
the same registered result, over the role's own loop, from the bytes that the scenario puts on
the disk. The ``tree`` callback records the result of the last task of each host, which shows the
plan, the cleanup plan and the values that the role resolved.

The test needs ``ansible-playbook`` and the collection link (``make collection-link``); without
them it is skipped on a workstation and fails when the environment variable ``CI`` is set.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
import yaml

from tests.unit import yaml_cache

if TYPE_CHECKING:
    from collections.abc import Mapping

REPOSITORY = Path(__file__).resolve().parents[3]
ROLE = REPOSITORY / "roles" / "remediate"
COLLECTIONS = REPOSITORY / "build" / "collections"
PLAYBOOK = Path(sys.executable).parent / "ansible-playbook"
TIMEOUT_SECONDS = 600
RHEL = "xccdf_org.ssgproject.content_benchmark_RHEL-9"
UBUNTU = "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04"
RESTORE_STAT = "Kernel parameters | Inspect the vendor files to write back again"
EDIT_STAT = "Kernel parameters | Inspect every file that the rules were decided on again"
TASKS = (
    "Kernel parameters | Resolve the value that the profile or the content requires",
    "Kernel parameters | Compose the drop-in of every rule to apply and read the record",
    "Kernel parameters | Compose the content and the SHA-256 of every drop-in to apply",
    "Kernel parameters | Name why each rule that is no longer effective",
    RESTORE_STAT,
    "Kernel parameters | Name the vendor files to write back that changed since they were read",
    "Kernel parameters | Refuse the cleanup of the rules whose vendor file changed",
    "Kernel parameters | Name the rules whose prior state can be restored",
    "Kernel parameters | Keep the running values and the texts",
    "Kernel parameters | Decide for every rule to apply",
    EDIT_STAT,
    "Kernel parameters | Refuse every rule when a file that it was decided on changed",
)
STATS = (RESTORE_STAT, EDIT_STAT)
CONTENT = {
    "xccdf_org.ssgproject.content_benchmark_RHEL-9": "rhel9",
    "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04": "ubuntu2404",
}
PROFILES = {
    "xccdf_org.ssgproject.content_benchmark_RHEL-9": "cis",
    "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04": "cis_level1_server",
}
SAMPLE = "kernel.perf_event_max_sample_rate"
CPU = "kernel.perf_cpu_time_max_percent"
PORTS = "net.ipv4.ip_local_port_range"
SEND = "net.ipv4.conf.all.send_redirects"
KPTR = "kernel.kptr_restrict"
ACCEPT = "net.ipv4.conf.all.accept_redirects"
HARDENING = "/etc/sysctl.d/10-kernel-hardening.conf"
UFW = "/etc/ufw/sysctl.conf"
UFW_ON = {
    "/etc/ufw/ufw.conf": "ENABLED=yes\n",
    "/etc/default/ufw": "IPT_SYSCTL=/etc/ufw/sysctl.conf\n",
}
RUNNING = {SAMPLE: "100000", CPU: "25", PORTS: "32768\t60999"}

Rule = dict[str, object]


def rules_by_key() -> dict[str, Rule]:
    """Return the kernel parameter rules of the catalogue by key (the last rule of a key wins)."""
    catalogue = cast("dict[str, object]", yaml_cache.load(ROLE / "vars" / "rules.yml"))
    rules = cast("list[Rule]", catalogue["__linux_compliance_remediate_rules"])
    return {
        str(parameters(rule)["key"]): rule
        for rule in rules
        if rule.get("family") in {"sysctl", "ipv4_parameters", "ipv6_parameters"}
    }


def parameters(rule: Rule) -> dict[str, object]:
    """Return the parameters of ``rule``."""
    return cast("dict[str, object]", rule["parameters"])


def dropin(rule: Rule, value: str) -> str:
    """Return the drop-in that the collection writes for ``rule`` with ``value``."""
    return (
        f"# Managed by freesecdev.linux_compliance for {rule['rule_id']}.\n"
        f"# Switching the rule or the {rule['family']} topic off removes this file.\n"
        f"{parameters(rule)['key']} = {value}\n"
    )


def digest(text: str) -> str:
    """Return the SHA-256 of ``text``."""
    return hashlib.sha256(text.encode()).hexdigest()


def regular(text: str) -> dict[str, object]:
    """Return the entry of a regular file with ``text``."""
    return {
        "isreg": True,
        "islnk": False,
        "isdir": False,
        "readable": True,
        "target": "other",
        "checksum": digest(text),
    }


def linked(text: str) -> dict[str, object]:
    """Return the entry of a symbolic link to a regular file with ``text``."""
    return {**regular(text), "isreg": False, "islnk": True, "target": "file", "checksum": ""}


@dataclass(frozen=True)
class Cleanup:
    """A rule that the run cleans up, which had written a vendor line."""

    key: str
    value: str
    vendor: str
    original: str
    written: str
    runtime: dict[str, str] = field(default_factory=dict[str, str])


@dataclass(frozen=True)
class Scenario:
    """The inputs of one play and the statuses expected of the rules to apply, in order.

    ``disk`` holds the bytes of a file on the disk when they are no longer those that the role
    read (``files``), as after a concurrent write between the read and the write, or ``None``
    when the file is gone. ``links`` names the files of ``files`` that are symbolic links to a
    regular file with that text.
    """

    name: str
    keys: list[str]
    files: dict[str, str]
    statuses: list[str]
    running: dict[str, str] = field(default_factory=lambda: dict(RUNNING))
    runtime: bool = True
    exact: list[str] = field(default_factory=list[str])
    cleanup: Cleanup | None = None
    cleanup_reason: str | None = None
    cleanup_detail: str | None = None
    reason: str | None = None
    benchmark: str = RHEL
    disk: dict[str, str | None] = field(default_factory=dict[str, str | None])
    links: list[str] = field(default_factory=list[str])


def content_sha256(benchmark: str) -> str:
    """Return the SHA-256 of the pinned datastream of ``benchmark``."""
    manifest = cast("dict[str, object]", yaml_cache.load(REPOSITORY / "content" / "manifest.yml"))
    streams = cast("list[dict[str, object]]", manifest["datastreams"])
    return next(str(stream["sha256"]) for stream in streams if stream["name"] == CONTENT[benchmark])


def resolved_value(rule: Rule, benchmark: str) -> str:
    """Return the value of ``rule`` for the scenario's profile, as the role resolves it.

    The role resolves it itself (its resolution task runs in every play); the harness needs it
    only to place an exact drop-in on the host, and the test compares both.
    """
    found = parameters(rule)
    if "value_id" not in found:
        return str(found["value"])
    entries = cast("list[dict[str, object]]", found["profile_values"])
    return next(
        "".join(cast("list[str]", entry["value"]))
        for entry in entries
        if entry["content_sha256"] == content_sha256(benchmark)
        and PROFILES[benchmark] in cast("list[str]", entry["profiles"])
    )


def ledger_entry(values: dict[str, object] | None) -> dict[str, object] | None:
    """Return a ledger entry as ``control_state`` lists it, with ``values`` as its prior values."""
    if values is None:
        return None
    return {"prior_values": [{"name": name, "value": value} for name, value in values.items()]}


@dataclass
class Host:
    """The configuration entries, texts and ledger records of a scenario's host."""

    entries: dict[str, object] = field(default_factory=dict[str, object])
    texts: dict[str, object] = field(default_factory=dict[str, object])
    records: dict[str, dict[str, object]] = field(default_factory=dict[str, dict[str, object]])

    def add(self, path: str, text: str) -> None:
        """Add a regular file with ``text``."""
        self.entries[path] = regular(text)
        self.texts[path] = text


def host_state(
    scenario: Scenario, by_key: dict[str, Rule], contents: dict[str, str]
) -> tuple[Host, list[Rule]]:
    """Return the host of ``scenario`` and the rules that its run cleans up."""
    host = Host()
    for path, text in scenario.files.items():
        host.add(path, text)
    for path in scenario.links:
        host.entries[path] = linked(scenario.files[path])
    for key in scenario.exact:
        rule_id = str(by_key[key]["rule_id"])
        host.add(str(parameters(by_key[key])["path"]), contents[rule_id])
        host.records[rule_id] = {"method": "dropin", "dropin_sha256": digest(contents[rule_id])}
    if scenario.cleanup is None:
        return host, []
    spec = scenario.cleanup
    rule = by_key[spec.key]
    text = dropin(rule, spec.value)
    host.add(str(parameters(rule)["path"]), text)
    host.records[str(rule["rule_id"])] = {
        "method": "dropin",
        "dropin_sha256": digest(text),
        f"vendor_line:{spec.vendor}": spec.original,
        f"vendor_written:{spec.vendor}": spec.written,
        **spec.runtime,
    }
    return host, [rule]


def with_ledger(rules: list[Rule], host: Host) -> list[Rule]:
    """Return ``rules`` as the dispatcher hands them over, each with its ledger entry."""
    return [
        {**rule, "ledger_entry": ledger_entry(host.records.get(str(rule["rule_id"])))}
        for rule in rules
    ]


def harness_contents(scenario: Scenario, by_key: dict[str, Rule]) -> dict[str, str]:
    """Return the drop-ins that the harness expects the role to compose for the rules to apply."""
    return {
        str(by_key[key]["rule_id"]): dropin(
            by_key[key], resolved_value(by_key[key], scenario.benchmark)
        )
        for key in scenario.keys
    }


def scenario_vars(scenario: Scenario, by_key: dict[str, Rule]) -> dict[str, object]:
    """Return the variables of the play of ``scenario``."""
    contents = harness_contents(scenario, by_key)
    host, cleanup = host_state(scenario, by_key, contents)
    apply = with_ledger([by_key[key] for key in scenario.keys], host)
    cleanup = with_ledger(cleanup, host)
    main = cast("dict[str, object]", yaml_cache.load(ROLE / "vars" / "main.yml"))
    checked = cast("dict[str, object]", main["__linux_compliance_remediate_sysctl_checked"])
    return {
        "linux_compliance_discovered": {
            "benchmark_id": scenario.benchmark,
            "content_sha256": content_sha256(scenario.benchmark),
        },
        "linux_compliance_remediate_profile": PROFILES[scenario.benchmark],
        "__linux_compliance_remediate_kp_benchmark": scenario.benchmark,
        "__linux_compliance_remediate_kp_checked": checked[scenario.benchmark],
        "__linux_compliance_remediate_kp_entries": host.entries,
        "__linux_compliance_remediate_kp_texts": host.texts,
        "__linux_compliance_remediate_kp_directory_stat": {"exists": True, "isdir": True},
        "__linux_compliance_remediate_kp_removed": [
            str(parameters(rule)["path"]) for rule in cleanup
        ],
        "__linux_compliance_remediate_family": {"apply": apply, "cleanup": cleanup},
        "__linux_compliance_remediate_kp_rules": cleanup + apply,
        "__linux_compliance_remediate_kp_running_values": scenario.running,
        "__linux_compliance_remediate_kp_runtime": scenario.runtime,
        "__linux_compliance_remediate_kp_writable": dict.fromkeys(scenario.running, True),
        "harness_disk": {
            path: text for path, text in {**host.texts, **scenario.disk}.items() if text is not None
        },
    }


def mocked_stat(task: dict[str, object]) -> dict[str, object]:
    """Return a task that registers what the role's ``stat`` task would, from the scenario's disk.

    The role's own loop expression names the paths, and each result carries the role's loop
    variable and the SHA-256 of the bytes that ``harness_disk`` holds for the path.
    """
    loop_control = cast("dict[str, str]", task["loop_control"])
    loop_var = loop_control["loop_var"]
    template = (
        "{%- set results = [] -%}{%- for path in harness_paths -%}"
        "{%- set _ = results.append({'" + loop_var + "': path, 'stat': {"
        "'exists': path in harness_disk, 'isreg': path in harness_disk,"
        " 'checksum': harness_disk[path] | default('') | hash('sha256')}}) -%}"
        "{%- endfor -%}{{ {'results': results} }}"
    )
    return {
        "name": f"Harness | {task['name']}",
        "vars": {"harness_paths": task["loop"]},
        "ansible.builtin.set_fact": {str(task["register"]): template},
    }


def role_tasks() -> list[dict[str, object]]:
    """Return the tasks of the role that the scenarios run, without their tags.

    The ``stat`` tasks that read the vendor files again are replaced by :func:`mocked_stat`.
    """
    tasks = cast(
        "list[dict[str, object]]", yaml_cache.load(ROLE / "tasks" / "sysctl_parameters.yml")
    )
    chosen: list[dict[str, object]] = []
    for prefix in TASKS:
        task = next(task for task in tasks if str(task["name"]).startswith(prefix))
        found = {name: value for name, value in copy.deepcopy(task).items() if name != "tags"}
        chosen.append(mocked_stat(found) if prefix in STATS else found)
    return chosen


CR_UFW = "net/ipv4/conf/all/send_redirects=1\nnet/ipv4/tcp_syncookies=1\rkernel/kptr_restrict=0\n"
CR_UFW_RESTORE = (
    "net/ipv4/conf/all/send_redirects=0\nnet/ipv4/tcp_syncookies=1\rkernel/kptr_restrict=0\n"
)
COMPANION_CLEANUP = Cleanup(
    key=CPU,
    value="1",
    vendor=HARDENING,
    original=f"{CPU} = 0",
    written=f"{CPU} = 1",
    runtime={"runtime_prior": "0", "runtime_written": "1"},
)
SCENARIOS = [
    Scenario(
        "a selected companion that conflicts refuses the sample rate",
        [CPU, SAMPLE],
        {"/etc/sysctl.d/50-perf.conf": f"{CPU} = 0\n"},
        ["conflicting_setting", "overridden"],
    ),
    Scenario("a selected companion that is applied", [CPU, SAMPLE], {}, ["applied", "applied"]),
    Scenario(
        "an unselected companion at 0",
        [SAMPLE],
        {"/etc/sysctl.d/50-perf.conf": f"{CPU} = 0\n"},
        ["overridden"],
    ),
    Scenario(
        "an unselected companion at 1",
        [SAMPLE],
        {"/etc/sysctl.d/50-perf.conf": f"{CPU} = 1\n"},
        ["applied"],
    ),
    Scenario(
        "procps writes the sample rate while the companion is 0",
        [SAMPLE],
        {"/etc/sysctl.d/10-a.conf": f"{CPU} = 0\n", "/etc/sysctl.d/9999-z.conf": f"{CPU} = 25\n"},
        ["overridden"],
    ),
    Scenario(
        "the companion is 1 again before procps writes the sample rate",
        [SAMPLE],
        {"/etc/sysctl.d/10-a.conf": f"{CPU} = 0\n", "/etc/sysctl.d/20-b.conf": f"{CPU} = 1\n"},
        ["applied"],
    ),
    Scenario(
        "the companion's cleanup writes 0 back into a vendor file",
        [SAMPLE],
        {HARDENING: f"kernel.kptr_restrict = 1\n{CPU} = 1\n"},
        ["overridden"],
        running={**RUNNING, SAMPLE: "1", CPU: "1"},
        exact=[SAMPLE],
        cleanup=COMPANION_CLEANUP,
    ),
    Scenario(
        "a 0 that only systemd reads, with ufw setting 1",
        [SAMPLE],
        {
            **UFW_ON,
            "/etc/sysctl.d/10-a.conf": "kernel/perf_cpu_time_max_percent/ = 0\n",
            UFW: f"{CPU} = 1\n",
        },
        ["overridden"],
    ),
    Scenario(
        "a vendor edit in a file with a lone carriage return is refused",
        [SEND],
        {**UFW_ON, UFW: CR_UFW},
        ["unparsed_configuration"],
        running={**RUNNING, SEND: "1", "net.ipv4.conf.default.send_redirects": "0"},
        reason=f"{UFW} holds a carriage return",
        benchmark=UBUNTU,
    ),
    Scenario(
        "a vendor edit in a file with CR LF line ends is refused",
        [SEND],
        {**UFW_ON, UFW: "net/ipv4/conf/all/send_redirects=1\r\nnet/ipv4/tcp_syncookies=1\r\n"},
        ["unparsed_configuration"],
        running={**RUNNING, SEND: "1", "net.ipv4.conf.default.send_redirects": "0"},
        reason=f"{UFW} holds a carriage return",
        benchmark=UBUNTU,
    ),
    Scenario(
        "a cleanup restore in a file with a lone carriage return is not made",
        [KPTR],
        {**UFW_ON, UFW: CR_UFW_RESTORE},
        ["applied"],
        running={**RUNNING, SEND: "0", KPTR: "1"},
        cleanup=Cleanup(
            key=SEND,
            value="0",
            vendor=UFW,
            original="net/ipv4/conf/all/send_redirects=1",
            written="net/ipv4/conf/all/send_redirects=0",
        ),
        cleanup_reason="unparsed_configuration",
        cleanup_detail="carriage return",
    ),
    Scenario(
        "a cleanup restore in a file with CR LF line ends is not made",
        [SAMPLE],
        {HARDENING: f"kernel.kptr_restrict = 1\r\n{CPU} = 1\r\n"},
        ["compliant"],
        running={**RUNNING, SAMPLE: "1", CPU: "1"},
        exact=[SAMPLE],
        cleanup=COMPANION_CLEANUP,
        cleanup_reason="unparsed_configuration",
        cleanup_detail="carriage return",
    ),
    Scenario(
        "a port range in octal is not accepted",
        [PORTS],
        {"/etc/sysctl.d/50-p.conf": f"{PORTS} = 032768 65535\n"},
        ["conflicting_setting"],
    ),
    Scenario(
        "a value from the profile is resolved as the role resolves it",
        [ACCEPT],
        {},
        ["applied"],
        running={**RUNNING, ACCEPT: "1"},
    ),
    Scenario(
        "a vendor file to edit that gained a carriage return after it was read is not written",
        [SEND],
        {**UFW_ON, UFW: "net/ipv4/conf/all/send_redirects=1\nnet/ipv4/tcp_syncookies=1\n"},
        ["modified_since_read"],
        running={**RUNNING, SEND: "1", "net.ipv4.conf.default.send_redirects": "0"},
        reason=f"{UFW} changed after the collection read it",
        benchmark=UBUNTU,
        disk={UFW: CR_UFW},
    ),
    Scenario(
        "a companion's vendor file as it was read",
        [CPU, SAMPLE],
        {HARDENING: f"{KPTR} = 1\n{CPU} = 0\n"},
        ["applied", "applied"],
    ),
    Scenario(
        "a companion's vendor file that changed after it was read refuses every rule",
        [CPU, SAMPLE],
        {HARDENING: f"{KPTR} = 1\n{CPU} = 0\n"},
        ["modified_since_read", "modified_since_read"],
        reason=f"{HARDENING} changed after the collection read it",
        disk={HARDENING: f"{KPTR} = 0\n{CPU} = 0\n"},
    ),
    Scenario(
        "a cleanup restore into a vendor file that changed after it was read is not made",
        [SAMPLE],
        {HARDENING: f"{KPTR} = 1\n{CPU} = 1\n"},
        ["modified_since_read"],
        running={**RUNNING, SAMPLE: "1", CPU: "1"},
        exact=[SAMPLE],
        cleanup=COMPANION_CLEANUP,
        cleanup_reason="modified_since_read",
        cleanup_detail=f"{HARDENING} changed after the collection read it",
        reason=f"{HARDENING} changed after the collection read it",
        disk={HARDENING: f"{KPTR} = 2\n{CPU} = 1\n"},
    ),
    Scenario(
        "the cleanup's changed vendor file refuses a sample rate decided on its old bytes",
        [SAMPLE],
        {HARDENING: f"{KPTR} = 1\n{CPU} = 1\n"},
        ["modified_since_read"],
        running={**RUNNING, SAMPLE: "1", CPU: "1"},
        exact=[SAMPLE],
        cleanup=COMPANION_CLEANUP,
        cleanup_reason="modified_since_read",
        cleanup_detail=f"{HARDENING} changed after the collection read it",
        reason=f"{HARDENING} changed after the collection read it",
        disk={HARDENING: f"{KPTR} = 1\n{CPU} = 0\n"},
    ),
    Scenario(
        "the cleanup's changed vendor file refuses a compliant rule that the file now contradicts",
        [KPTR],
        {HARDENING: f"{KPTR} = 1\n{CPU} = 1\n"},
        ["modified_since_read"],
        running={**RUNNING, SAMPLE: "1", CPU: "1", KPTR: "1"},
        cleanup=COMPANION_CLEANUP,
        cleanup_reason="modified_since_read",
        cleanup_detail=f"{HARDENING} changed after the collection read it",
        reason=f"{HARDENING} changed after the collection read it",
        disk={HARDENING: f"{KPTR} = 0\n{CPU} = 1\n"},
    ),
    Scenario(
        "a file that no rule edits but that the rules were decided on changed after it was read",
        [KPTR],
        {"/etc/sysctl.d/50-x.conf": f"{SEND} = 1\n"},
        ["modified_since_read"],
        running={**RUNNING, KPTR: "0"},
        reason="/etc/sysctl.d/50-x.conf changed after the collection read it",
        disk={"/etc/sysctl.d/50-x.conf": f"{KPTR} = 0\n"},
    ),
    Scenario(
        "a cleanup restore and an apply edit of one vendor file are compared with the bytes read",
        [KPTR],
        {HARDENING: f"{KPTR} = 0\n{CPU} = 1\n"},
        ["applied"],
        running={**RUNNING, SAMPLE: "1", CPU: "1", KPTR: "0"},
        cleanup=COMPANION_CLEANUP,
    ),
    Scenario(
        "a vendor file to edit that is gone before the write",
        [KPTR],
        {HARDENING: f"{KPTR} = 0\n"},
        ["modified_since_read"],
        running={**RUNNING, KPTR: "0"},
        reason=f"{HARDENING} changed after the collection read it",
        disk={HARDENING: None},
    ),
    Scenario(
        "a vendor file to edit that is a symbolic link is not edited through it",
        [KPTR],
        {HARDENING: f"{KPTR} = 0\n"},
        ["not_regular_file"],
        running={**RUNNING, KPTR: "0"},
        reason=f"{HARDENING} is not a regular file (a symbolic link)",
        links=[HARDENING],
    ),
    Scenario(
        "a vendor file to write back that is a symbolic link is not written through it",
        [SAMPLE],
        {HARDENING: f"{KPTR} = 1\n{CPU} = 1\n"},
        ["compliant"],
        running={**RUNNING, SAMPLE: "1", CPU: "1"},
        exact=[SAMPLE],
        cleanup=COMPANION_CLEANUP,
        cleanup_reason="not_regular_file",
        cleanup_detail=f"{HARDENING} is not a regular file (a symbolic link)",
        links=[HARDENING],
    ),
]


def render(tmp: Path) -> dict[str, dict[str, object]]:
    """Run every scenario and return the plan and cleanup plan of each, by scenario name."""
    by_key = rules_by_key()
    tasks = role_tasks()
    show: dict[str, object] = {
        "name": "Show the plans",
        "ansible.builtin.debug": {
            "msg": (
                "{{ {'plan': __linux_compliance_remediate_kp_plan,"
                " 'cleanup': __linux_compliance_remediate_kp_cleanup_plan,"
                " 'contents': __linux_compliance_remediate_kp_contents} }}"
            )
        },
    }
    plays = [
        {
            "name": scenario.name,
            "hosts": f"scenario{number}",
            "gather_facts": False,
            "vars_files": [str(ROLE / "vars" / "main.yml")],
            "vars": scenario_vars(scenario, by_key),
            "tasks": [*copy.deepcopy(tasks), show],
        }
        for number, scenario in enumerate(SCENARIOS)
    ]
    playbook = tmp / "play.yml"
    playbook.write_text("---\n" + yaml.safe_dump(plays, sort_keys=False), encoding="utf-8")
    inventory = tmp / "inventory.ini"
    inventory.write_text(
        "[all]\n"
        + "".join(
            f"scenario{number} ansible_connection=local"
            f" ansible_python_interpreter={sys.executable}\n"
            for number in range(len(SCENARIOS))
        ),
        encoding="utf-8",
    )
    tree = tmp / "tree"
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp),
        "LC_ALL": "C.UTF-8",
        "ANSIBLE_HOME": str(tmp / "ansible-home"),
        "ANSIBLE_COLLECTIONS_PATH": str(COLLECTIONS),
        "ANSIBLE_CALLBACKS_ENABLED": "ansible.builtin.tree",
        "ANSIBLE_CALLBACK_TREE_DIR": str(tree),
        "ANSIBLE_STDOUT_CALLBACK": "ansible.builtin.minimal",
        "ANSIBLE_LOCALHOST_WARNING": "false",
        "ANSIBLE_NOCOLOR": "true",
    }
    completed = run_playbook(
        [str(PLAYBOOK), "-i", str(inventory), "--check", str(playbook)], environment
    )
    assert completed.returncode == 0, completed.stdout[-4000:] + completed.stderr[-4000:]
    results: dict[str, dict[str, object]] = {}
    for number, scenario in enumerate(SCENARIOS):
        found = cast("dict[str, object]", json.loads((tree / f"scenario{number}").read_text()))
        results[scenario.name] = cast("dict[str, object]", found["msg"])
    return results


def run_playbook(
    arguments: list[str], environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run ``ansible-playbook`` with an explicit argument list, environment and timeout."""
    return subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        env=environment,
    )


def in_ci(environment: Mapping[str, str]) -> bool:
    """Return whether ``environment`` is a CI run (``CI`` set to anything but empty, 0 or false)."""
    return environment.get("CI", "").strip().lower() not in {"", "0", "false"}


def require_tools(environment: Mapping[str, str], playbook: Path, collections: Path) -> None:
    """Skip the render test without its tools on a workstation, and fail it in CI."""
    if playbook.exists() and (collections / "ansible_collections").is_dir():
        return
    reason = "ansible-playbook or the collection link (make collection-link) is missing"
    if in_ci(environment):
        pytest.fail(f"{reason}; CI is set, so the render test may not be skipped")
    pytest.skip(reason)


@pytest.fixture(scope="module")
def rendered(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, object]]:
    """Render every scenario once."""
    require_tools(os.environ, PLAYBOOK, COLLECTIONS)
    return render(tmp_path_factory.mktemp("sysctl-render"))


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[scenario.name for scenario in SCENARIOS])
def test_the_role_decides_each_scenario_as_the_readers_would(
    rendered: dict[str, dict[str, object]], scenario: Scenario
) -> None:
    result = rendered[scenario.name]
    plan = cast("dict[str, dict[str, object]]", result["plan"])
    by_key = rules_by_key()
    statuses = [plan[str(by_key[key]["rule_id"])]["status"] for key in scenario.keys]
    assert statuses == scenario.statuses
    if scenario.reason is not None:
        first = plan[str(by_key[scenario.keys[0]]["rule_id"])]
        assert scenario.reason in str(first["reason"])
    for key in scenario.keys:
        planned = plan[str(by_key[key]["rule_id"])]
        if planned["status"] not in {"applied", "compliant"}:
            assert planned["reason"]
            assert planned["edits"] == []
            assert planned["runtime"] == []
            assert planned["write"] is False
    cleanup = cast("dict[str, dict[str, object]]", result["cleanup"])
    if scenario.cleanup is not None:
        planned = cleanup[str(by_key[scenario.cleanup.key]["rule_id"])]
        assert planned["reason"] == scenario.cleanup_reason
        if scenario.cleanup_reason is not None:
            assert planned["restores"] == []
            assert planned["runtime"] == []
            assert str(scenario.cleanup_detail) in str(planned["detail"])


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[scenario.name for scenario in SCENARIOS])
def test_the_role_composes_each_drop_in_with_the_value_that_it_resolves(
    rendered: dict[str, dict[str, object]], scenario: Scenario
) -> None:
    contents = cast("dict[str, str]", rendered[scenario.name]["contents"])
    assert contents == harness_contents(scenario, rules_by_key())


def test_a_profile_value_is_written_as_the_profile_sets_it(
    rendered: dict[str, dict[str, object]],
) -> None:
    by_key = rules_by_key()
    assert "value_id" in parameters(by_key[ACCEPT])
    contents = cast(
        "dict[str, str]",
        rendered["a value from the profile is resolved as the role resolves it"]["contents"],
    )
    assert contents[str(by_key[ACCEPT]["rule_id"])].endswith(f"\n{ACCEPT} = 0\n")


def test_every_mocked_task_replaces_a_stat_of_the_role() -> None:
    tasks = cast(
        "list[dict[str, object]]", yaml_cache.load(ROLE / "tasks" / "sysctl_parameters.yml")
    )
    for prefix in STATS:
        task = next(task for task in tasks if str(task["name"]).startswith(prefix))
        stat = cast("dict[str, object]", task["ansible.builtin.stat"])
        assert stat["follow"] is False or "islnk" in str(stat["follow"])
        assert stat["get_checksum"] is True
        assert stat["checksum_algorithm"] == "sha256"
        mocked = mocked_stat(task)
        assert mocked["vars"] == {"harness_paths": task["loop"]}
        assert list(cast("dict[str, object]", mocked["ansible.builtin.set_fact"])) == [
            task["register"]
        ]


@pytest.mark.parametrize("value", ["true", "1", "yes", " True "])
def test_missing_tools_fail_the_render_test_in_ci(tmp_path: Path, value: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="CI is set"):
        require_tools({"CI": value}, tmp_path / "ansible-playbook", tmp_path)


@pytest.mark.parametrize("environment", [{}, {"CI": ""}, {"CI": "false"}, {"CI": "0"}])
def test_missing_tools_skip_the_render_test_on_a_workstation(
    tmp_path: Path, environment: dict[str, str]
) -> None:
    with pytest.raises(pytest.skip.Exception):
        require_tools(environment, tmp_path / "ansible-playbook", tmp_path)


def test_present_tools_neither_skip_nor_fail(tmp_path: Path) -> None:
    playbook = tmp_path / "ansible-playbook"
    playbook.write_text("", encoding="utf-8")
    (tmp_path / "ansible_collections").mkdir()
    require_tools({"CI": "true"}, playbook, tmp_path)
