"""Render the real cleanup and plan tasks of the kernel parameter families (FREES-107).

The model of the readers is unit-tested in ``test_sysctl_config.py``; this module runs the role's
own Jinja around it: the tasks that plan the cleanup, name the reverted rules, keep the texts and
running values as the cleanup leaves them, and decide every rule to apply, taken unchanged from
``roles/remediate/tasks/sysctl_parameters.yml``. Each scenario is one play on a host of its own
with mocked inputs, run in check mode on the local machine; nothing is read from or written to
the host's configuration. The ``tree`` callback records the result of the last task of each host,
which shows the plan and the cleanup plan.
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
from typing import cast

import pytest
import yaml

REPOSITORY = Path(__file__).resolve().parents[3]
ROLE = REPOSITORY / "roles" / "remediate"
COLLECTIONS = REPOSITORY / "build" / "collections"
PLAYBOOK = Path(sys.executable).parent / "ansible-playbook"
TIMEOUT_SECONDS = 600
RHEL = "xccdf_org.ssgproject.content_benchmark_RHEL-9"
UBUNTU = "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04"
TASKS = (
    "Kernel parameters | Name why each rule that is no longer effective",
    "Kernel parameters | Name the rules whose prior state can be restored",
    "Kernel parameters | Keep the running values and the texts",
    "Kernel parameters | Decide for every rule to apply",
)
SAMPLE = "kernel.perf_event_max_sample_rate"
CPU = "kernel.perf_cpu_time_max_percent"
PORTS = "net.ipv4.ip_local_port_range"
SEND = "net.ipv4.conf.all.send_redirects"
KPTR = "kernel.kptr_restrict"
HARDENING = "/etc/sysctl.d/10-kernel-hardening.conf"
UFW = "/etc/ufw/sysctl.conf"
UFW_ON = {
    "/etc/ufw/ufw.conf": "ENABLED=yes\n",
    "/etc/default/ufw": "IPT_SYSCTL=/etc/ufw/sysctl.conf\n",
}
RUNNING = {SAMPLE: "100000", CPU: "25", PORTS: "32768\t60999"}

Rule = dict[str, object]


def load(path: Path) -> object:
    """Return the YAML document of ``path``."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def rules_by_key() -> dict[str, Rule]:
    """Return the kernel parameter rules of the catalogue by key (the last rule of a key wins)."""
    catalogue = cast("dict[str, object]", load(ROLE / "vars" / "rules.yml"))
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
    """The inputs of one play and the statuses expected of the rules to apply, in order."""

    name: str
    keys: list[str]
    files: dict[str, str]
    statuses: list[str]
    running: dict[str, str] = field(default_factory=lambda: dict(RUNNING))
    runtime: bool = True
    exact: list[str] = field(default_factory=list[str])
    cleanup: Cleanup | None = None
    cleanup_reason: str | None = None
    reason: str | None = None
    benchmark: str = RHEL


def wanted_values(scenario: Scenario, apply: list[Rule]) -> dict[str, object]:
    """Return the values that the rules to apply require, as the role resolves them."""
    values: dict[str, object] = {}
    for rule in apply:
        found = parameters(rule)
        accepted = cast("dict[str, list[str]]", found.get("accepted", {}))
        values[str(rule["rule_id"])] = {
            "value": found["value"],
            "accepted": accepted.get(scenario.benchmark),
            "pattern": found.get("accepted_pattern"),
            "vector": found.get("accepted_vector"),
        }
    return values


@dataclass
class Host:
    """The configuration entries, texts and ledger records of a scenario's host."""

    entries: dict[str, object] = field(default_factory=dict[str, object])
    texts: dict[str, object] = field(default_factory=dict[str, object])
    records: dict[str, object] = field(default_factory=dict[str, object])

    def add(self, path: str, text: str) -> None:
        """Add a regular file with ``text``."""
        self.entries[path] = regular(text)
        self.texts[path] = text


def host_state(
    scenario: Scenario, by_key: dict[str, Rule], contents: dict[str, str]
) -> tuple[Host, list[Rule]]:
    """Return the host of ``scenario`` and the rules that its run cleans up."""
    records = dict.fromkeys(contents, cast("object", None))
    host = Host(records=records)
    for path, text in scenario.files.items():
        host.add(path, text)
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


def scenario_vars(scenario: Scenario, by_key: dict[str, Rule]) -> dict[str, object]:
    """Return the variables of the play of ``scenario``."""
    apply = [by_key[key] for key in scenario.keys]
    contents = {
        str(rule["rule_id"]): dropin(rule, str(parameters(rule)["value"])) for rule in apply
    }
    host, cleanup = host_state(scenario, by_key, contents)
    main = cast("dict[str, object]", load(ROLE / "vars" / "main.yml"))
    checked = cast("dict[str, object]", main["__linux_compliance_remediate_sysctl_checked"])
    return {
        "__linux_compliance_remediate_kp_checked": checked[scenario.benchmark],
        "__linux_compliance_remediate_kp_entries": host.entries,
        "__linux_compliance_remediate_kp_texts": host.texts,
        "__linux_compliance_remediate_kp_directory_stat": {"exists": True, "isdir": True},
        "__linux_compliance_remediate_kp_removed": [
            str(parameters(rule)["path"]) for rule in cleanup
        ],
        "__linux_compliance_remediate_family": {"apply": apply, "cleanup": cleanup},
        "__linux_compliance_remediate_kp_values": wanted_values(scenario, apply),
        "__linux_compliance_remediate_kp_records": host.records,
        "__linux_compliance_remediate_kp_contents": contents,
        "__linux_compliance_remediate_kp_running_values": scenario.running,
        "__linux_compliance_remediate_kp_runtime": scenario.runtime,
        "__linux_compliance_remediate_kp_writable": dict.fromkeys(scenario.running, True),
    }


def role_tasks() -> list[dict[str, object]]:
    """Return the tasks of the role that the scenarios run, without their tags."""
    tasks = cast("list[dict[str, object]]", load(ROLE / "tasks" / "sysctl_parameters.yml"))
    chosen: list[dict[str, object]] = []
    for prefix in TASKS:
        task = next(task for task in tasks if str(task["name"]).startswith(prefix))
        chosen.append(
            {name: value for name, value in copy.deepcopy(task).items() if name != "tags"}
        )
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
    ),
    Scenario(
        "a port range in octal is not accepted",
        [PORTS],
        {"/etc/sysctl.d/50-p.conf": f"{PORTS} = 032768 65535\n"},
        ["conflicting_setting"],
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
                " 'cleanup': __linux_compliance_remediate_kp_cleanup_plan} }}"
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


@pytest.fixture(scope="module")
def rendered(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, object]]:
    """Render every scenario once."""
    if not PLAYBOOK.exists() or not (COLLECTIONS / "ansible_collections").is_dir():
        pytest.skip("ansible-playbook or the collection link (make collection-link) is missing")
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
    cleanup = cast("dict[str, dict[str, object]]", result["cleanup"])
    if scenario.cleanup is not None:
        planned = cleanup[str(by_key[scenario.cleanup.key]["rule_id"])]
        assert planned["reason"] == scenario.cleanup_reason
        if scenario.cleanup_reason is not None:
            assert planned["restores"] == []
            assert "carriage return" in str(planned["detail"])
