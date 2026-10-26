from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
    model,
)
from tools.reporting import cli, dashboard, report
from tools.reporting.common import dumps
from tools.reporting.report import ReportError, ReportInputs, RunMetadata, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA = json.loads(
    (Path(report.__file__).parent / "schema" / "report-v2.json").read_text(encoding="utf-8")
)
NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.UTC)
VALIDATOR: Any = Draft202012Validator(SCHEMA)
FILE_IDS = [
    "EXC-ERROR",
    "EXC-LAPSED",
    "EXC-NOT-YET",
    "EXC-PASSING",
    "EXC-STALE",
    "EXC-SUPERSEDED",
    "EXC-WAIVED",
]
HOSTILE_JUSTIFICATION = (
    "</script><script>window.__pwned = 1</script> <!-- &amp; <img src=x onerror=alert(1)> "
    "${constructor} all controls compliant (100%)"
)


def build(**inputs: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(dumps(report.build_report(ReportInputs(**inputs))))
    assert VALIDATOR.is_valid(document), [e.message[:200] for e in VALIDATOR.iter_errors(document)]
    return document


def entries_of(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["id"]: entry for entry in document["sections"]["exceptions"]["exceptions"]}


def write_evaluation(write: Callable[..., Path], name: str, evaluation: Any) -> Path:
    return write(name, json.dumps(evaluation.to_dict(), indent=2, sort_keys=True) + "\n")


def exceptions_file(kit: Any) -> str:
    rows: list[str] = []
    for identifier, rule, expires in (
        ("EXC-ACTIVE", "waived_rule", "2027-01-31"),
        ("EXC-EXPIRED", "expired_rule", "2026-10-20"),
        ("EXC-ERROR", "error_rule", "2027-01-31"),
    ):
        rows.append(
            f"  - id: {identifier}\n"
            f"    rule: {kit.RULE_PREFIX}{rule}\n"
            "    framework: cis\n"
            "    scope:\n"
            f"      hosts: [{kit.HOST.hostname}]\n"
            "    justification: Accepted while the replacement is built.\n"
            "    owner: platform-team\n"
            "    approval:\n"
            "      approver: security-lead\n"
            "      date: 2026-10-02\n"
            "    created: 2026-10-01\n"
            f"    expires: {expires}\n"
            "    risk: medium\n"
        )
    return "---\nschema_version: '1.0'\nexceptions:\n" + "".join(rows)


def test_applied_exceptions_appear_in_the_report(kit: Any, write_run: Callable[..., Path]) -> None:
    run = kit.scan_run(
        (
            kit.finding("waived_rule", model.Outcome.FAIL),
            kit.finding("expired_rule", model.Outcome.FAIL),
            kit.finding("error_rule", model.Outcome.ERROR),
            kit.finding("passing_rule"),
        )
    )
    parsed = exceptions.parse_exceptions(exceptions_file(kit), NOW)
    target = exceptions.Target(kit.HOST.hostname, ())
    evaluation = exceptions.evaluate_run(run, parsed, target, NOW)
    path = write_run("evaluated.json", evaluation.run)
    inputs = ReportInputs(scope=Scope.SINGLE_HOST, metadata=RunMetadata(), scan_run=(path,))
    document = json.loads(dumps(report.build_report(inputs)))
    assert VALIDATOR.is_valid(document)
    section = document["sections"]["compliance"]
    summary = section["summary"]
    assert summary["counts"]["waived"] == 1
    assert summary["counts"]["fail"] == 1
    assert summary["counts"]["error"] == 1
    assert summary["counts"]["pass"] == 1
    assert summary["expired_waivers"] == 1
    assert summary["compliance_percent"] == 25.0
    embedded = section["items"][0]["data"]["scan_run"]["findings"]
    exceptions_by_rule = {
        item["rule_id"].removeprefix(kit.RULE_PREFIX): item["exception"] for item in embedded
    }
    assert exceptions_by_rule["waived_rule"]["state"] == "active"
    assert exceptions_by_rule["waived_rule"]["exception_id"] == "EXC-ACTIVE"
    assert exceptions_by_rule["expired_rule"]["state"] == "expired"
    assert exceptions_by_rule["expired_rule"]["exception_id"] == "EXC-EXPIRED"
    assert exceptions_by_rule["error_rule"]["state"] == "none"
    statuses = {result.record.exception_id: result.status.value for result in evaluation.results}
    assert statuses == {
        "EXC-ACTIVE": "waived",
        "EXC-ERROR": "not_failing",
        "EXC-EXPIRED": "expired",
    }


def test_the_committed_evaluation_is_what_the_filter_writes_for_the_exceptions_file(
    kit: Any,
) -> None:
    assert kit.EVALUATION_FILE.read_text(encoding="utf-8") == kit.evaluation_json(kit.evaluate())


def test_every_exception_of_the_file_appears_with_its_status(kit: Any) -> None:
    document = build(scope=Scope.FLEET, exceptions_evaluation=(kit.EVALUATION_FILE,))
    section = document["sections"]["exceptions"]
    assert section["status"] == "available"
    text = kit.EXCEPTIONS_FILE.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    file_ids = [record.exception_id for record in exceptions.parse_exceptions(text, NOW).records]
    assert file_ids == FILE_IDS
    entries = entries_of(document)
    assert sorted(entries) == FILE_IDS
    assert section["source_sha256"] == digest
    assert {entry["source_sha256"] for entry in entries.values()} == {digest}
    verdicts = {
        key: (entry["status"], entry["removal_candidate"]) for key, entry in entries.items()
    }
    assert verdicts == {
        "EXC-ERROR": ("not_failing", True),
        "EXC-LAPSED": ("expired", False),
        "EXC-NOT-YET": ("not_yet_effective", False),
        "EXC-PASSING": ("not_failing", True),
        "EXC-STALE": ("stale", True),
        "EXC-SUPERSEDED": ("superseded", True),
        "EXC-WAIVED": ("in_effect", False),
    }
    assert entries["EXC-STALE"]["matched_hosts"] == []
    waived = entries["EXC-WAIVED"]
    assert waived["expires"] == "2027-01-31"
    assert waived["expires_at"] == "2027-01-31T00:00:00Z"
    assert waived["rule_id"] == kit.RULE_PREFIX + "waived_rule"
    assert waived["scope"] == {"benchmark": None, "groups": [], "hosts": ["web01"], "profiles": []}
    assert waived["host_statuses"]["waived"] == 1
    assert [match["host"] for match in waived["matched_hosts"]] == ["web01"]
    superseded = entries["EXC-SUPERSEDED"]["matched_hosts"][0]
    assert (superseded["status"], superseded["superseded_by"]) == ("superseded", "EXC-WAIVED")
    assert entries["EXC-SUPERSEDED"]["scope"]["benchmark"] == {
        "id": kit.BENCHMARK,
        "version": "1.0",
    }
    assert entries["EXC-NOT-YET"]["scope"]["groups"] == ["web"]
    assert entries["EXC-LAPSED"]["lapsed"] is True
    assert waived["lapsed"] is False
    summary = section["summary"]
    assert summary == {
        "by_status": {
            "expired": 1,
            "in_effect": 1,
            "not_failing": 2,
            "not_yet_effective": 1,
            "stale": 1,
            "superseded": 1,
        },
        "evaluations": 1,
        "lapsed": 1,
        "removal_candidates": 4,
        "source_sha256": digest,
        "total": 7,
    }
    assert document["overview"]["exceptions"] == summary
    item = section["items"][0]["data"]
    assert item["target_host"] == "web01"
    assert item["statuses"]["unmatched"] == 1


def test_matched_hosts_and_scopes_never_carry_names_the_host_reports(kit: Any) -> None:
    document = build(scope=Scope.FLEET, exceptions_evaluation=(kit.EVALUATION_FILE,))
    listed = json.dumps(document["sections"]["exceptions"]["exceptions"])
    assert kit.EVALUATION_HOST.hostname not in listed
    assert "web01" in listed
    compliance = document["sections"]["compliance"]["groups"][0]["host"]
    assert compliance["hostname"] == kit.EVALUATION_HOST.hostname


def test_a_waiver_that_lapsed_during_the_scan_counts_in_expired_waivers(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    evaluation = kit.evaluate()
    lapsed = kit.RULE_PREFIX + "lapsed_rule"
    assert evaluation.lapsed_rule_ids() == (lapsed,)
    with_evaluation = build(scope=Scope.FLEET, exceptions_evaluation=(kit.EVALUATION_FILE,))
    marked_only = build(scope=Scope.FLEET, scan_run=(write_run("marked.json", evaluation.run),))
    new = with_evaluation["sections"]["compliance"]
    old = marked_only["sections"]["compliance"]
    assert new["summary"]["expired_waivers"] == 1
    assert old["summary"]["expired_waivers"] == 0
    assert new["items"][0]["data"]["lapsed_waivers"] == [lapsed]
    assert new["items"][0]["data"]["summary"]["expired_waivers"] == 1
    rule = next(rule for rule in new["rules"] if rule["rule_id"] == lapsed)
    assert rule["expired_waiver"] is True
    assert rule["outcome"] == "fail"
    assert [source["expired_waiver"] for source in rule["sources"]] == [True]


def test_the_exceptions_section_changes_no_compliance_figure(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    evaluation = kit.evaluate()
    with_evaluation = build(scope=Scope.FLEET, exceptions_evaluation=(kit.EVALUATION_FILE,))
    marked_only = build(scope=Scope.FLEET, scan_run=(write_run("marked.json", evaluation.run),))
    for key in ("summary", "groups", "aggregates"):
        new = copy.deepcopy(with_evaluation["sections"]["compliance"][key])
        old = copy.deepcopy(marked_only["sections"]["compliance"][key])
        for figure in [new] if key == "summary" else [entry["summary"] for entry in new]:
            figure["expired_waivers"] = 0
        assert new == old, key
    summary = with_evaluation["sections"]["compliance"]["summary"]
    assert summary["compliance_percent"] == 16.6
    assert summary["counts"]["waived"] == 1
    assert summary["counts"]["fail"] == 3
    assert summary["evaluated"] == 6


def test_an_exception_superseded_on_every_host_is_a_removal_candidate(
    kit: Any, write: Callable[..., Path]
) -> None:
    hosts = (("web01", "e" * 32), ("web02", "f" * 32))
    paths: list[Path] = []
    for inventory, machine in hosts:
        identity = model.HostIdentity(f"{inventory}.example", "rhel", "9", "x86_64", machine)
        run = kit.evaluation_run(host=identity, run_id=f"run-{inventory}")
        text = kit.EXCEPTIONS_FILE.read_text(encoding="utf-8").replace(
            "hosts: [web01]", "hosts: [web01, web02]"
        )
        evaluation = kit.evaluate(run, inventory_host=inventory, text=text)
        paths.append(write_evaluation(write, f"{inventory}.json", evaluation))
    document = build(scope=Scope.FLEET, exceptions_evaluation=tuple(paths))
    superseded = entries_of(document)["EXC-SUPERSEDED"]
    assert [(m["host"], m["status"]) for m in superseded["matched_hosts"]] == [
        ("web01", "superseded"),
        ("web02", "superseded"),
    ]
    assert superseded["host_statuses"]["superseded"] == 2
    assert (superseded["status"], superseded["removal_candidate"]) == ("superseded", True)
    assert document["sections"]["exceptions"]["summary"]["evaluations"] == 2
    assert entries_of(document)["EXC-STALE"]["status"] == "stale"


def test_hostile_justification_text_is_data(kit: Any, write: Callable[..., Path]) -> None:
    text = kit.EXCEPTIONS_FILE.read_text(encoding="utf-8").replace(
        "Names a host that was not evaluated.", "'" + HOSTILE_JUSTIFICATION + "'"
    )
    evaluation = kit.evaluate(text=text)
    path = write_evaluation(write, "hostile.json", evaluation)
    document = build(scope=Scope.FLEET, exceptions_evaluation=(path,))
    assert entries_of(document)["EXC-STALE"]["justification"] == HOSTILE_JUSTIFICATION
    assert entries_of(document)["EXC-STALE"]["status"] == "stale"
    html = dashboard.render_dashboard(document)
    assert html.count("<script") == 2
    assert html.count("</script>") == 2
    assert "\\u003c/script\\u003e\\u003cscript\\u003ewindow.__pwned" in html


def test_a_tampered_evaluation_is_an_input_error_never_a_waiver(
    kit: Any, write: Callable[..., Path], tmp_path: Path
) -> None:
    original = json.loads(kit.EVALUATION_FILE.read_text(encoding="utf-8"))
    forged = copy.deepcopy(original)
    plain = next(
        f for f in forged["scan_run"]["findings"] if f["rule_id"].endswith("plain_failure")
    )
    plain["outcome"] = "pass"
    plain["evaluated_outcome"] = "pass"
    lapsed = next(entry for entry in forged["exceptions"] if entry["id"] == "EXC-LAPSED")
    lapsed["status"] = "waived"
    path = write("forged.json", json.dumps(forged))
    document = build(scope=Scope.FLEET, exceptions_evaluation=(path,))
    for name in ("compliance", "exceptions"):
        section = document["sections"][name]
        assert section["status"] == "error"
        assert section["summary"] is None
        assert section["gaps"][0]["reason"].startswith("exceptions evaluation rejected")
    assert document["sections"]["exceptions"]["exceptions"] == []
    assert document["overview"]["exceptions"] is None
    assert document["overview"]["error"] == ["compliance", "exceptions"]
    output = tmp_path / "report.json"
    argv = ["--scope", "fleet", "--output", str(output), "--exceptions-evaluation", str(path)]
    assert cli.main(argv) == 1


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        ("schema_version", "2.0", "unsupported schema_version"),
        ("target", None, "not a valid host name"),
        ("exceptions", "x", "exceptions must be a list"),
    ],
)
def test_invalid_evaluations_are_input_errors(
    kit: Any, write: Callable[..., Path], key: str, value: object, reason: str
) -> None:
    document: dict[str, Any] = json.loads(kit.EVALUATION_FILE.read_text(encoding="utf-8"))
    if key == "target":
        evaluation = kit.evaluate(inventory_host="web 01")
        document = json.loads(json.dumps(evaluation.to_dict()))
    else:
        document[key] = value
    path = write("invalid.json", json.dumps(document))
    built = build(scope=Scope.FLEET, exceptions_evaluation=(path,))
    gaps = built["sections"]["exceptions"]["gaps"]
    assert reason in gaps[0]["reason"]


def test_a_missing_evaluation_makes_the_section_partial_without_counts(
    kit: Any, tmp_path: Path
) -> None:
    document = build(
        scope=Scope.FLEET,
        exceptions_evaluation=(kit.EVALUATION_FILE, tmp_path / "absent.json"),
    )
    section = document["sections"]["exceptions"]
    assert section["status"] == "partial"
    assert section["summary"] is None
    assert section["exceptions"] == []
    assert section["source_sha256"] is None
    assert document["overview"]["exceptions"] is None
    assert section["items"][0]["data"]["target_host"] == "web01"


def test_evaluations_of_different_exceptions_files_are_refused(
    kit: Any, write: Callable[..., Path]
) -> None:
    identity = model.HostIdentity("web02.example", "rhel", "9", "x86_64", "f" * 32)
    run = kit.evaluation_run(host=identity, run_id="run-web02")
    text = kit.EXCEPTIONS_FILE.read_text(encoding="utf-8").replace("risk: high", "risk: critical")
    evaluated = kit.evaluate(run, inventory_host="web02", text=text)
    other = write_evaluation(write, "other.json", evaluated)
    with pytest.raises(ReportError, match="different exceptions files"):
        report.build_report(
            ReportInputs(scope=Scope.FLEET, exceptions_evaluation=(kit.EVALUATION_FILE, other))
        )
    same_records = kit.EXCEPTIONS_FILE.read_text(encoding="utf-8") + "\n"
    rerun = kit.evaluate(run, inventory_host="web02", text=same_records)
    moved = write_evaluation(write, "moved.json", rerun)
    with pytest.raises(ReportError, match="different exceptions files"):
        report.build_report(
            ReportInputs(scope=Scope.FLEET, exceptions_evaluation=(kit.EVALUATION_FILE, moved))
        )


def test_the_evaluation_is_listed_once_in_the_raw_artifacts(kit: Any) -> None:
    document = build(scope=Scope.FLEET, exceptions_evaluation=(kit.EVALUATION_FILE,) * 2)
    assert [ref["format"] for ref in document["raw_artifacts"]] == ["exceptions_evaluation"] * 2
    assert len(document["sections"]["exceptions"]["items"]) == 2
    assert document["sections"]["exceptions"]["summary"]["evaluations"] == 1
    assert len(document["sections"]["compliance"]["groups"]) == 1


def test_a_scan_run_and_its_evaluation_are_a_repeated_scan(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    marked = write_run("marked.json", kit.evaluate().run)
    inputs: dict[str, Any] = {
        "scan_run": (marked,),
        "exceptions_evaluation": (kit.EVALUATION_FILE,),
    }
    with pytest.raises(ReportError, match="more than one completed scan run"):
        report.build_report(ReportInputs(scope=Scope.FLEET, **inputs))
    document = build(scope=Scope.FLEET, allow_repeated_scans=True, **inputs)
    notes = document["sections"]["compliance"]["notes"]
    assert [(note["kind"], note["repeated_profile"]) for note in notes] == [("merged_inputs", True)]


def test_the_schema_rejects_inconsistent_exception_entries(kit: Any) -> None:
    document = build(scope=Scope.FLEET, exceptions_evaluation=(kit.EVALUATION_FILE,))
    exceptions_list = ("sections", "exceptions", "exceptions")
    index = {
        entry["id"]: i for i, entry in enumerate(document["sections"]["exceptions"]["exceptions"])
    }

    def broken(identifier: str, changes: dict[str, Any]) -> bool:
        candidate = copy.deepcopy(document)
        node: Any = candidate
        for step in exceptions_list:
            node = node[step]
        node[index[identifier]].update(changes)
        return not VALIDATOR.is_valid(candidate)

    assert broken("EXC-STALE", {"removal_candidate": False})
    assert broken("EXC-WAIVED", {"removal_candidate": True})
    assert broken("EXC-WAIVED", {"matched_hosts": []})
    stale_host = copy.deepcopy(
        document["sections"]["exceptions"]["exceptions"][index["EXC-WAIVED"]]
    )
    assert broken("EXC-STALE", {"matched_hosts": stale_host["matched_hosts"]})
    assert broken("EXC-WAIVED", {"owner": "Not A Person"})
    assert broken("EXC-WAIVED", {"id": "<script>"})
    assert broken("EXC-WAIVED", {"scope": {"hosts": ["web 01"], "groups": [], "profiles": []}})
    assert broken("EXC-WAIVED", {"justification": "x" * 4097})
    assert broken("EXC-WAIVED", {"status": "waived"})
    superseded = copy.deepcopy(document)
    match = superseded["sections"]["exceptions"]["exceptions"][index["EXC-SUPERSEDED"]]
    match["matched_hosts"][0]["superseded_by"] = None
    assert not VALIDATOR.is_valid(superseded)
    overview = copy.deepcopy(document)
    overview["overview"]["exceptions"] = None
    assert not VALIDATOR.is_valid(overview)
    empty = build(scope=Scope.FLEET)
    empty["overview"]["exceptions"] = document["overview"]["exceptions"]
    assert not VALIDATOR.is_valid(empty)


def test_the_cli_reads_evaluations(kit: Any, tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    argv = ["--scope", "fleet", "--output", str(output)]
    assert cli.main([*argv, "--exceptions-evaluation", str(kit.EVALUATION_FILE)]) == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["overview"]["exceptions"]["by_status"]["stale"] == 1
    assert document["overview"]["available"] == ["compliance", "exceptions"]


def test_the_schema_enums_are_the_exceptions_module_enums() -> None:
    defs = SCHEMA["$defs"]
    entry = defs["exceptionEntry"]["properties"]
    assert entry["framework"]["enum"] == [member.value for member in model.FrameworkId]
    assert entry["risk"]["enum"] == [member.value for member in exceptions.Risk]
    assert entry["status"]["enum"] == [member.value for member in exceptions.Review]
    statuses = [member.value for member in exceptions.Status]
    assert entry["host_statuses"]["required"] == sorted(statuses)
    assert defs["exceptionsData"]["properties"]["statuses"]["required"] == sorted(statuses)
    assert defs["matchedHost"]["properties"]["status"]["enum"] == statuses[:-1]
    assert statuses[-1] == exceptions.Status.UNMATCHED.value
    verdicts = sorted(member.value for member in exceptions.Review)
    assert defs["exceptionsSummary"]["properties"]["by_status"]["required"] == verdicts
    removal = defs["exceptionEntry"]["allOf"][0]["if"]["properties"]["status"]["enum"]
    assert sorted(removal) == sorted(member.value for member in exceptions.REMOVAL_CANDIDATES)


class Chooser:
    """Deterministic xorshift64* choices for test data; not for security."""

    MASK = (1 << 64) - 1

    def __init__(self, seed: int) -> None:
        self.state = seed & self.MASK or 1

    def next(self) -> int:
        state = self.state
        state ^= state >> 12
        state ^= (state << 25) & self.MASK
        state ^= state >> 27
        self.state = state
        return (state * 0x2545F4914F6CDD1D) & self.MASK

    def randrange(self, start: int, stop: int | None = None) -> int:
        low, high = (0, start) if stop is None else (start, stop)
        return low + self.next() % (high - low)

    def random(self) -> float:
        return (self.next() >> 11) / float(1 << 53)

    def choice(self, options: list[Any]) -> Any:
        return options[self.next() % len(options)]

    def sample(self, options: list[str], count: int) -> list[str]:
        pool = list(options)
        return [pool.pop(self.next() % len(pool)) for _ in range(count)]


PEOPLE = ("platform-team", "web-team@example.com", "ops.lead", "alice+audit@example.org")
APPROVERS = ("security-lead", "ciso@example.com", "bob@other.example", "carol")


def random_file(chooser: Chooser, kit: Any, count: int, today: dt.date) -> str:
    lines = ["---", "schema_version: '1.0'", "exceptions:"]
    for index in range(count):
        scope = chooser.choice(
            [
                ["hosts: [web01, web02]"],
                ["groups: [web]"],
                ["hosts: [db01]"],
                [f"profiles: [{kit.PROFILE}]"],
                [
                    "benchmark:",
                    f"  id: {kit.BENCHMARK}",
                    "  version: '1.0'",
                    f"profiles: [{kit.PROFILE}, xccdf_org.example.synthetic_profile_stig]",
                ],
            ]
        )
        created = today - dt.timedelta(days=chooser.randrange(8))
        approved = min(today, created + dt.timedelta(days=chooser.randrange(3)))
        expires = approved + dt.timedelta(days=1 + chooser.randrange(12))
        lines += [
            f"  - id: EXC-{index:03d}",
            f"    rule: {kit.RULE_PREFIX}rule{chooser.randrange(8)}",
            f"    framework: {chooser.choice([m.value for m in model.FrameworkId])}",
            "    scope:",
            *(f"      {line}" for line in scope),
            f"    justification: 'Reason {index}: <b>{chooser.random()}</b> &amp; more'",
            f"    owner: {chooser.choice(list(PEOPLE))}",
            "    approval:",
            f"      approver: {chooser.choice(list(APPROVERS))}",
            f"      date: '{approved.isoformat()}'",
            f"    created: '{created.isoformat()}'",
            f"    expires: '{expires.isoformat()}'",
            f"    risk: {chooser.choice(['low', 'medium', 'high', 'critical'])}",
        ]
    return "\n".join(lines) + "\n"


OUTCOMES = [model.Outcome.FAIL, model.Outcome.PASS, model.Outcome.ERROR]


def random_evaluations(
    chooser: Chooser, kit: Any, write: Callable[..., Path], case: int
) -> list[Path]:
    now = dt.datetime(2026, 10, 25, 0, 0, tzinfo=dt.UTC) + dt.timedelta(
        hours=chooser.randrange(24 * 20)
    )
    text = random_file(chooser, kit, chooser.randrange(1, 12), now.date())
    paths: list[Path] = []
    for host_index, host in enumerate(("web01", "web02", "db01")[: 1 + chooser.randrange(3)]):
        chosen = {f"rule{rule}": chooser.choice(OUTCOMES) for rule in range(chooser.randrange(9))}
        started = now - dt.timedelta(minutes=chooser.randrange(-5, 3000))
        run = kit.evaluation_run(
            chosen,
            host=model.HostIdentity(
                f"{host}.example", "rhel", "9", "x86_64", f"{host_index + 1:032x}"
            ),
            run_id=f"run-{case}-{host}",
            started=started.strftime(model.TIMESTAMP_FORMAT),
        )
        groups = tuple(chooser.sample(["web", "db", "legacy"], chooser.randrange(3)))
        try:
            evaluation = kit.evaluate(run, inventory_host=host, groups=groups, text=text, now=now)
        except exceptions.ExceptionsError:
            continue
        paths.append(write_evaluation(write, f"case{case}-{host}.json", evaluation))
    return paths


def test_random_exceptions_files_always_give_schema_valid_reports(
    kit: Any, write: Callable[..., Path]
) -> None:
    chooser = Chooser(20261026)
    verdicts: set[str] = set()
    reports = 0
    for case in range(40):
        paths = random_evaluations(chooser, kit, write, case)
        if not paths:
            continue
        reports += 1
        document = build(scope=Scope.FLEET, exceptions_evaluation=tuple(paths))
        assert document["sections"]["exceptions"]["status"] == "available"
        listed = entries_of(document)
        assert len(listed) == document["sections"]["exceptions"]["summary"]["total"]
        verdicts.update(entry["status"] for entry in listed.values())
    assert reports >= 20
    assert verdicts == {member.value for member in exceptions.Review}
