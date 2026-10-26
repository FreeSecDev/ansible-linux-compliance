from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
    exceptions,
    model,
)

if TYPE_CHECKING:
    from collections.abc import Callable

HOST = "web01"
RUN_ID = "run-1"
DIRECTORY = f"/var/lib/freesecdev/linux_compliance/evidence/{RUN_ID}"
EXCEPTIONS_PATH = "/srv/compliance/exceptions.yml"
RULE = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
OTHER_RULE = "xccdf_org.ssgproject.content_rule_package_telnet_removed"
UID = 1000
MACHINE = "a" * 32
NOW = datetime.now(timezone.utc).replace(microsecond=0)
TODAY = NOW.date()
XCCDF = b"<?xml version='1.0'?><TestResult/>\n"
ARF = b"<arf>root:$6$planted-hash:19000::</arf>\n"
TAILORING = b"<Tailoring/>\n"
NOTES = b"planted\n"
ENABLED = True
DISABLED = False

Contents = dict[str, bytes]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exceptions_text(host: str = HOST) -> str:
    created = (TODAY - timedelta(days=10)).isoformat()
    approved = (TODAY - timedelta(days=9)).isoformat()
    expires = (TODAY + timedelta(days=30)).isoformat()
    return "\n".join(
        [
            "---",
            "schema_version: '1.0'",
            "exceptions:",
            "  - id: EXC-1",
            f"    rule: {RULE}",
            "    framework: cis",
            "    scope:",
            f"      hosts: [{host}]",
            "    justification: Accepted until the replacement ships.",
            "    owner: platform-team",
            "    approval:",
            "      approver: security-lead",
            f"      date: {approved}",
            f"    created: {created}",
            f"    expires: {expires}",
            "    risk: low",
            "",
        ]
    )


def scan_run(
    machine_id: str | None = None, outcome: model.Outcome = model.Outcome.FAIL
) -> model.ScanRun:
    started = (NOW - timedelta(hours=1)).strftime(model.TIMESTAMP_FORMAT)
    findings = tuple(
        model.Finding(
            rule_id=rule_id,
            outcome=result,
            evaluated_outcome=result,
            severity=model.Severity.HIGH,
            message=None,
            evidence=(),
            exception=model.ExceptionStatus.none(),
            remediation=None,
            disabled_by=None,
            flags=(),
        )
        for rule_id, result in ((RULE, outcome), (OTHER_RULE, model.Outcome.PASS))
    )
    return model.ScanRun(
        run_id=RUN_ID,
        started_at=started,
        finished_at=started,
        host=model.HostIdentity(HOST, "ubuntu", "24.04", "x86_64", machine_id),
        scanner=model.ScannerInfo("openscap", "1.3.9"),
        content=model.Provenance("ssg-ubuntu2404-ds.xml", "0.1.82", "b" * 64),
        benchmark_id="xccdf_org.ssgproject.content_benchmark_UBUNTU2404",
        profile_id="xccdf_org.ssgproject.content_profile_cis_level1_server",
        status=model.ScanStatus.COMPLETED,
        error_message=None,
        findings=findings,
    )


def evaluate(run: model.ScanRun, text: str, host: str = HOST) -> dict[str, object]:
    parsed = exceptions.parse_exceptions(text, NOW)
    return exceptions.evaluate_run(
        run, parsed, exceptions.make_target(host, ["web"]), NOW
    ).to_dict()


def host_files(run: model.ScanRun) -> Contents:
    return {
        "scan-run.json": (model.dumps(run) + "\n").encode("utf-8"),
        "scan/results.xml": XCCDF,
        "scan/results-arf.xml": ARF,
        "tailoring.xml": TAILORING,
        "scan/notes.txt": NOTES,
    }


AUDIT_KINDS = {
    "scan-run.json": "scan_run",
    "tailoring.xml": "tailoring",
}


def audited(
    run: model.ScanRun | None = None,
    *,
    applied: bool = True,
    text: str | None = None,
    files: Contents | None = None,
) -> dict[str, object]:
    run = scan_run() if run is None else run
    files = host_files(run) if files is None else files
    text = exceptions_text() if text is None else text
    listed = [
        {
            "kind": AUDIT_KINDS.get(name, "scanner_output"),
            "path": f"{DIRECTORY}/{name}",
            "sha256": sha(data),
            "size": len(data),
        }
        for name, data in sorted(files.items())
    ]
    waivers: dict[str, object] = {
        "applied": applied,
        "evaluation": evaluate(run, text) if applied else None,
        "file": EXCEPTIONS_PATH,
        "source_sha256": sha(text.encode("utf-8")),
        "status": "applied" if applied else "not_requested",
    }
    if not applied:
        waivers["source_sha256"] = None
    return {
        "evidence": {"directory": DIRECTORY, "files": listed, "skipped": []},
        "evidence_written": True,
        "exceptions": waivers,
        "run_id": RUN_ID,
        "run_status": "completed",
        "scan_run": run.to_dict(),
        "summary": {},
    }


def stat_of(data: bytes, **changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "checksum": sha(data),
        "isreg": True,
        "islnk": False,
        "mode": "0600",
        "size": len(data),
        "uid": UID,
    }
    result.update(changes)
    return result


def fetched(fact: dict[str, object], files: Contents, *, include_arf: bool = False) -> Contents:
    plan = evidence.plan_bundle(fact, HOST, include_arf)
    sources = {f"{DIRECTORY}/{name}": data for name, data in files.items()}
    return {item.path: sources[item.source] for item in plan.files}


def stale(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "audited_hosts": [HOST],
        "complete": True,
        "computed": True,
        "evaluated_hosts": [HOST],
        "not_evaluated_hosts": [],
        "source_sha256": sha(exceptions_text().encode("utf-8")),
        "stale": [],
        "target_hosts": [HOST],
        "unmatched": [],
    }
    result.update(changes)
    return result


def collected(
    received: Contents,
    **changes: object,
) -> evidence.Collected:
    text = exceptions_text()
    values: dict[str, object] = {
        "collection_version": "0.1.0",
        "controller_uid": UID,
        "exceptions_text": text,
        "host": HOST,
        "include_arf": False,
        "machine_id": MACHINE,
        "observed": {path: stat_of(data) for path, data in received.items()},
        "scan_run_text": received[evidence.SCAN_RUN_PATH].decode("utf-8"),
        "stale": stale(),
    }
    values.update(changes)
    return evidence.Collected.from_dict(values)


def build(
    fact: dict[str, object] | None = None, /, **changes: object
) -> tuple[dict[str, object], Contents]:
    fact = audited() if fact is None else fact
    received = fetched(fact, host_files(scan_run()))
    result = evidence.build_documents(fact, collected(received, **changes), NOW)
    return result, received


def bundle(fact: dict[str, object] | None = None, **changes: object) -> Contents:
    result, received = build(fact, **changes)
    contents = dict(received)
    for path, text in cast("dict[str, str]", result["documents"]).items():
        contents[path] = text.encode("utf-8")
    contents[evidence.MANIFEST_NAME] = cast("str", result["manifest"]).encode("utf-8")
    return contents


def manifest_of(contents: Contents) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(contents[evidence.MANIFEST_NAME]))


def reseal(
    contents: Contents, change: Callable[[dict[str, object]], None] | None = None
) -> Contents:
    document = manifest_of(contents)
    if change is not None:
        change(document)
    files = cast("list[dict[str, object]]", document["files"])
    for item in files:
        data = contents[cast("str", item["path"])]
        item["sha256"] = sha(data)
        item["size"] = len(data)
    sums = "".join(f"{item['sha256']}  {item['path']}\n" for item in files).encode("utf-8")
    contents[evidence.CHECKSUMS_NAME] = sums
    document["checksums"] = {
        "path": evidence.CHECKSUMS_NAME,
        "sha256": sha(sums),
        "size": len(sums),
    }
    contents[evidence.MANIFEST_NAME] = evidence.canonical_json(document).encode("utf-8")
    return contents


def test_the_bundle_vocabulary_matches_the_audit_module() -> None:
    names = set(evidence.HOST_SOURCES)
    assert names == {"scan-run.json", "tailoring.xml", "scan/results.xml", "scan/results-arf.xml"}
    assert evidence.bundle_directory_paths() == {"raw", "raw/scan", "exceptions"}
    assert set(evidence.BUNDLE_PATHS) == {
        "raw/scan-run.json",
        "raw/tailoring.xml",
        "raw/scan/results.xml",
        "raw/scan/results-arf.xml",
        "exceptions/evaluation.json",
        "exceptions/exceptions.yml",
        "exceptions/stale.json",
    }


def test_a_plan_collects_the_allow_listed_files_and_excludes_the_rest() -> None:
    plan = evidence.plan_bundle(audited(), HOST, DISABLED).to_dict()
    assert plan["directory"] == f"{HOST}/{RUN_ID}"
    assert plan["directories"] == ["exceptions", "raw", "raw/scan"]
    assert [item["path"] for item in cast("list[dict[str, object]]", plan["fetch"])] == [
        "raw/scan-run.json",
        "raw/scan/results.xml",
        "raw/tailoring.xml",
    ]
    reasons = {
        cast("str", item["source"]).rsplit("/", 2)[-1]: item["reason"]
        for item in cast("list[dict[str, object]]", plan["excluded"])
    }
    assert reasons == {"notes.txt": "not_allow_listed", "results-arf.xml": "arf_not_requested"}
    assert plan["applied"] is True
    assert plan["exceptions_file"] == EXCEPTIONS_PATH
    assert plan["host"] == HOST
    assert plan["run_id"] == RUN_ID


def test_a_plan_collects_the_arf_on_request_and_without_scanner_files_needs_only_raw() -> None:
    plan = evidence.plan_bundle(audited(), HOST, ENABLED)
    assert "raw/scan/results-arf.xml" in [item.path for item in plan.files]
    files = {"scan-run.json": host_files(scan_run())["scan-run.json"]}
    bare = evidence.plan_bundle(audited(applied=False, files=files), HOST, DISABLED)
    assert bare.directories() == ["raw"]
    assert bare.exceptions_status == "not_requested"
    assert bare.evaluation is None


def test_a_plan_without_exceptions_data_means_not_requested() -> None:
    fact = audited()
    del fact["exceptions"]
    plan = evidence.plan_bundle(fact, HOST, DISABLED)
    assert not plan.applied
    assert plan.exceptions_source is None


@pytest.mark.parametrize("status", ["not_run", "not_completed"])
def test_a_plan_records_exceptions_that_were_not_applied(status: str) -> None:
    fact = audited()
    waivers = cast("dict[str, object]", fact["exceptions"])
    waivers.update({"applied": False, "evaluation": None, "status": status})
    plan = evidence.plan_bundle(fact, HOST, DISABLED)
    assert plan.exceptions_status == status
    assert plan.exceptions_source == sha(exceptions_text().encode("utf-8"))
    assert plan.exceptions_file is None


def mutate(
    fact: dict[str, object], path: tuple[str | int, ...], value: object
) -> dict[str, object]:
    target: Any = fact
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value
    return fact


def scan_run_entry(fact: dict[str, object]) -> int:
    files = cast("list[dict[str, object]]", cast("dict[str, object]", fact["evidence"])["files"])
    return next(index for index, item in enumerate(files) if item["kind"] == "scan_run")


PLAN_CASES: list[tuple[Callable[[dict[str, object]], object], str]] = [
    (lambda _fact: "not a mapping", "linux_compliance_audited must be a mapping"),
    (lambda fact: {**fact, "evidence_written": False}, "no evidence was written"),
    (lambda fact: {**fact, "run_id": "../x"}, "run_id"),
    (lambda fact: {**fact, "scan_run": "{"}, "scan_run is invalid"),
    (lambda fact: {**fact, "run_id": "run-2"}, "belongs to another run ID"),
    (lambda fact: {**fact, "run_status": "failed"}, "run_status contradicts"),
    (lambda fact: {**fact, "evidence": None}, "evidence must be a mapping"),
    (
        lambda fact: mutate(fact, ("evidence", "directory"), "/var/lib/x/../run-1"),
        "must be an absolute, normalised path",
    ),
    (lambda fact: mutate(fact, ("evidence", "directory"), "relative/run-1"), "absolute"),
    (lambda fact: mutate(fact, ("evidence", "directory"), "//srv/run-1"), "absolute"),
    (lambda fact: mutate(fact, ("evidence", "directory"), "/srv/other"), "run ID run-1"),
    (lambda fact: mutate(fact, ("evidence", "files"), {}), "files must be a list"),
    (lambda fact: mutate(fact, ("evidence", "files"), [None] * 65), "more than 64 items"),
    (lambda fact: mutate(fact, ("evidence", "files", 0), {"path": "x"}), "missing keys"),
    (
        lambda fact: mutate(
            fact, ("evidence", "files", 0, "path"), "/var/lib/freesecdev/state.json"
        ),
        "is not inside the run directory",
    ),
    (
        lambda fact: mutate(fact, ("evidence", "files", 0, "path"), f"{DIRECTORY}/../state.json"),
        "is not inside the run directory",
    ),
    (lambda fact: mutate(fact, ("evidence", "files", 0, "sha256"), "0"), "sha256"),
    (
        lambda fact: mutate(fact, ("evidence", "files", 0, "size"), ENABLED),
        "size must be an integer",
    ),
    (
        lambda fact: mutate(fact, ("evidence", "files", 0, "size"), -1),
        "size must be an integer",
    ),
    (lambda fact: mutate(fact, ("evidence", "files", 0, "kind"), "Scan"), "kind"),
    (
        lambda fact: mutate(
            fact, ("evidence", "files", scan_run_entry(fact), "kind"), "scanner_output"
        ),
        "must have kind scan_run",
    ),
    (
        lambda fact: mutate(
            fact,
            ("evidence", "files"),
            cast("list[object]", cast("dict[str, object]", fact["evidence"])["files"]) * 2,
        ),
        "lists a file twice",
    ),
    (
        lambda fact: mutate(
            fact,
            ("evidence", "files"),
            [
                item
                for item in cast(
                    "list[dict[str, object]]",
                    cast("dict[str, object]", fact["evidence"])["files"],
                )
                if item["kind"] != "scan_run"
            ],
        ),
        "has no scan-run.json",
    ),
    (lambda fact: mutate(fact, ("exceptions",), "applied"), "exceptions must be a mapping"),
    (lambda fact: mutate(fact, ("exceptions", "status"), "maybe"), "status 'maybe' is unknown"),
    (lambda fact: mutate(fact, ("exceptions", "applied"), "yes"), "applied must be a boolean"),
    (lambda fact: mutate(fact, ("exceptions", "applied"), DISABLED), "contradicts its status"),
    (lambda fact: mutate(fact, ("exceptions", "source_sha256"), None), "source_sha256"),
    (
        lambda fact: mutate(fact, ("exceptions", "file"), "relative.yml"),
        "absolute controller path",
    ),
    (
        lambda fact: mutate(fact, ("exceptions", "evaluation"), None),
        "evaluation must be a mapping",
    ),
    (
        lambda fact: mutate(fact, ("exceptions", "evaluation", "target"), None),
        "target must be a mapping",
    ),
    (
        lambda fact: mutate(fact, ("exceptions", "evaluation", "target", "host"), "db01"),
        "was made for 'db01', not for web01",
    ),
    (
        lambda fact: mutate(fact, ("exceptions", "evaluation", "source_sha256"), "c" * 64),
        "names another exceptions file",
    ),
    (lambda _fact: {1: 2}, "has a key that is not a string"),
    (
        lambda fact: mutate(
            fact,
            ("evidence", "files", 0),
            {"extra": 1, "kind": "x", "path": "x", "sha256": "x", "size": 1},
        ),
        "unknown keys: 'extra'",
    ),
]


@pytest.mark.parametrize(("change", "message"), PLAN_CASES)
def test_a_plan_refuses_malformed_or_tampered_audit_results(
    change: Callable[[dict[str, object]], object], message: str
) -> None:
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.plan_bundle(change(audited()), HOST, DISABLED)


@pytest.mark.parametrize(
    ("host", "include_arf", "message"),
    [("../web01", False, "inventory host name"), (HOST, "yes", "include_arf must be a boolean")],
)
def test_a_plan_refuses_invalid_arguments(host: str, include_arf: object, message: str) -> None:
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.plan_bundle(audited(), host, include_arf)


def test_a_bundle_is_built_and_verifies() -> None:
    contents = bundle()
    document = manifest_of(contents)
    assert document["schema_version"] == "1.0"
    assert document["kind"] == evidence.BUNDLE_KIND
    assert document["collection"] == {"name": evidence.COLLECTION_NAME, "version": "0.1.0"}
    assert document["collected_at"] == NOW.strftime(model.TIMESTAMP_FORMAT)
    assert document["host"] == {
        "inventory_hostname": HOST,
        "machine_id": MACHINE,
        "reported": scan_run().host.to_dict(),
    }
    assert document["exceptions"] == {
        "evaluation": "exceptions/evaluation.json",
        "file": "exceptions/exceptions.yml",
        "source_sha256": sha(exceptions_text().encode("utf-8")),
        "stale": "exceptions/stale.json",
        "status": "applied",
    }
    assert contents["exceptions/exceptions.yml"] == exceptions_text().encode("utf-8")
    sums = contents[evidence.CHECKSUMS_NAME].decode("utf-8")
    assert (
        sums.splitlines()[0]
        == f"{sha(contents['exceptions/evaluation.json'])}  exceptions/evaluation.json"
    )
    verified = evidence.check_bundle(contents)
    assert verified.evaluation is not None
    assert verified.exceptions_text == exceptions_text()
    assert verified.run == scan_run()
    assert verified.manifest.file("raw/scan-run.json") is not None
    assert verified.manifest.file("raw/scan/results-arf.xml") is None
    stale_document = json.loads(contents["exceptions/stale.json"])
    assert stale_document["kind"] == evidence.STALE_KIND
    assert stale_document["result"]["evaluated_hosts"] == [HOST]


def test_a_bundle_without_exceptions_or_stale_result_verifies() -> None:
    fact = audited(applied=False)
    contents = bundle(fact, exceptions_text=None, stale={}, machine_id=None)
    document = manifest_of(contents)
    assert document["exceptions"] == {
        "evaluation": None,
        "file": None,
        "source_sha256": None,
        "stale": None,
        "status": "not_requested",
    }
    assert evidence.check_bundle(contents).evaluation is None
    applied = bundle(stale=None)
    assert cast("dict[str, object]", manifest_of(applied)["exceptions"])["stale"] is None
    assert evidence.check_bundle(applied).evaluation is not None


def test_a_bundle_records_the_incomplete_stale_coverage() -> None:
    contents = bundle(stale=stale(complete=False, stale=None, unmatched=["EXC-1"]))
    result = json.loads(contents["exceptions/stale.json"])["result"]
    assert result["complete"] is False
    assert result["stale"] is None
    assert result["unmatched"] == ["EXC-1"]


def test_the_written_files_are_checked_before_the_manifest() -> None:
    result, received = build()
    contents = dict(received)
    for path, text in cast("dict[str, str]", result["documents"]).items():
        contents[path] = text.encode("utf-8")
    observed = {path: stat_of(data) for path, data in contents.items()}
    expected = result["expected"]
    assert evidence.check_written(expected, observed, UID) == sorted(contents)
    observed["SHA256SUMS"] = stat_of(b"changed")
    with pytest.raises(evidence.EvidenceError, match="differs from what was written"):
        evidence.check_written(expected, observed, UID)
    with pytest.raises(evidence.EvidenceError, match="controller_uid must be"):
        evidence.check_written(expected, observed, ENABLED)
    assert result["manifest_sha256"] == sha(cast("str", result["manifest"]).encode("utf-8"))


def received_with(path: str, **changes: object) -> Callable[[Contents], dict[str, object]]:
    def change(received: Contents) -> dict[str, object]:
        observed: dict[str, object] = {name: stat_of(data) for name, data in received.items()}
        observed[path] = stat_of(received[path], **changes)
        return observed

    return change


OBSERVE_CASES: list[tuple[Callable[[Contents], object], str]] = [
    (
        received_with("raw/scan/results.xml", checksum="0" * 64),
        "checksum mismatch for .*/scan/results.xml",
    ),
    (received_with("raw/scan/results.xml", size=1), "checksum mismatch"),
    (received_with("raw/tailoring.xml", mode="0644"), "has mode '0644', not 0600"),
    (received_with("raw/tailoring.xml", uid=0), "not owned by the controller user"),
    (received_with("raw/tailoring.xml", islnk=True), "is not a regular file"),
    (received_with("raw/tailoring.xml", isreg=False), "is not a regular file"),
    (
        lambda received: {"raw/scan-run.json": stat_of(received["raw/scan-run.json"])},
        "was not found in the bundle",
    ),
    (lambda received: {name: {"checksum": "x"} for name in received}, "is not a regular file"),
    (lambda _received: [], "observed files must be a mapping"),
]


@pytest.mark.parametrize(("observe", "message"), OBSERVE_CASES)
def test_fetched_files_that_do_not_match_the_audit_record_fail_closed(
    observe: Callable[[Contents], object], message: str
) -> None:
    fact = audited()
    received = fetched(fact, host_files(scan_run()))
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.build_documents(fact, collected(received, observed=observe(received)), NOW)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"controller_uid": -1}, "controller_uid must be a non-negative integer"),
        ({"scan_run_text": None}, "the text of scan-run.json is required"),
        ({"scan_run_text": "{}"}, "is not the file whose digest was checked"),
        ({"machine_id": "nope"}, "machine_id"),
        ({"exceptions_text": None}, "the exceptions file text is required"),
        ({"exceptions_text": exceptions_text() + "\n"}, "no longer the file that was applied"),
        ({"stale": "stale"}, "must be a mapping"),
        ({"stale": stale(computed=False)}, "was not computed"),
        ({"stale": stale(complete="yes")}, "stale complete must be a boolean"),
        ({"stale": stale(source_sha256="c" * 64)}, "computed from another exceptions file"),
        ({"stale": stale(evaluated_hosts=["db01"])}, "does not include the evaluation of web01"),
        ({"stale": stale(target_hosts=["../x"])}, "stale target_hosts"),
        ({"stale": stale(unmatched=["bad id"])}, "stale unmatched"),
        ({"stale": stale(stale=None)}, "stale must equal unmatched"),
        ({"collection_version": "one"}, "collection version"),
    ],
)
def test_documents_refuse_inconsistent_controller_data(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(evidence.EvidenceError, match=message):
        build(**changes)


def test_the_collected_record_rejects_unknown_and_missing_keys() -> None:
    with pytest.raises(evidence.EvidenceError, match="missing keys"):
        evidence.Collected.from_dict({"host": HOST})
    with pytest.raises(evidence.EvidenceError, match="must be a mapping"):
        evidence.Collected.from_dict(None)


def test_a_scan_run_file_that_differs_from_the_fact_is_refused() -> None:
    other = replace(
        scan_run(), error_message=None, findings=scan_run(outcome=model.Outcome.PASS).findings
    )
    files = host_files(scan_run())
    files["scan-run.json"] = (model.dumps(other) + "\n").encode("utf-8")
    fact = audited(files=files)
    received = fetched(fact, files)
    with pytest.raises(
        evidence.EvidenceError, match="is not the scan run of linux_compliance_audited"
    ):
        evidence.build_documents(fact, collected(received), NOW)
    files["scan-run.json"] = b"{}\n"
    fact = audited(files=files)
    received = fetched(fact, files)
    with pytest.raises(evidence.EvidenceError, match="is not a valid scan run"):
        evidence.build_documents(fact, collected(received), NOW)


def test_the_machine_id_of_the_facts_must_match_the_scan_run() -> None:
    run = scan_run(machine_id="c" * 32)
    fact = audited(run)
    received = fetched(fact, host_files(run))
    with pytest.raises(evidence.EvidenceError, match="machine ID of the gathered facts differs"):
        evidence.build_documents(fact, collected(received), NOW)
    same = evidence.build_documents(fact, collected(received, machine_id="c" * 32), NOW)
    assert manifest_of({evidence.MANIFEST_NAME: cast("str", same["manifest"]).encode()})["host"]


def test_an_evaluation_that_does_not_verify_or_belongs_to_another_run_is_refused() -> None:
    fact = audited()
    waivers = cast("dict[str, object]", fact["exceptions"])
    evaluation = cast("dict[str, object]", waivers["evaluation"])
    evaluation["summary"] = {"waived": 9}
    received = fetched(fact, host_files(scan_run()))
    with pytest.raises(evidence.EvidenceError, match="the evaluation does not verify"):
        evidence.build_documents(fact, collected(received), NOW)
    other = evaluate(scan_run(outcome=model.Outcome.ERROR), exceptions_text())
    waivers["evaluation"] = other
    with pytest.raises(evidence.EvidenceError, match="was not made from the raw scan run"):
        evidence.build_documents(fact, collected(received), NOW)


def test_load_json_is_strict() -> None:
    assert evidence.load_json(b'{"a": 1}', "x") == {"a": 1}
    for data, message in (
        (b'{"a": 1, "a": 2}', "duplicate key"),
        (b'{"a": NaN}', "non-finite number"),
        (b"\xff", "is not valid JSON"),
        (b"{", "is not valid JSON"),
        (b"[" * 100000, "is not valid JSON"),
    ):
        with pytest.raises(evidence.EvidenceError, match=message):
            evidence.load_json(data, "x")


def test_a_manifest_round_trips() -> None:
    contents = bundle()
    manifest = evidence.parse_manifest(contents[evidence.MANIFEST_NAME])
    assert (
        evidence.canonical_json(manifest.to_dict()).encode("utf-8")
        == contents[evidence.MANIFEST_NAME]
    )


def set_key(*path: str | int, value: object) -> Callable[[dict[str, object]], None]:
    def change(document: dict[str, object]) -> None:
        mutate(document, path, value)

    return change


def delete_key(name: str) -> Callable[[dict[str, object]], None]:
    def change(document: dict[str, object]) -> None:
        del document[name]

    return change


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (set_key("schema_version", value="2.0"), "unsupported schema_version '2.0'"),
        (set_key("kind", value="other"), "manifest kind must be"),
        (set_key("collection", "name", value="other.collection"), "collection name must be"),
        (set_key("checksums", "path", value="SUMS"), "checksums path must be"),
        (set_key("run", "status", value="maybe"), "the manifest is invalid"),
        (set_key("scanner", value={"name": "x"}), "the manifest is invalid"),
        (delete_key("excluded"), "missing keys: excluded"),
        (set_key("extra", value=1), "unknown keys: 'extra'"),
        (set_key("files", 0, "path", value="raw/other.json"), "is not a known bundle path"),
        (set_key("files", 0, "kind", value="xccdf"), "must have kind exceptions_evaluation"),
        (set_key("files", 0, "source", value=""), "source"),
        (set_key("files", value=[]), "has no raw/scan-run.json"),
        (set_key("files", value="x"), "manifest files must be a list"),
        (set_key("excluded", 0, "reason", value="other"), "excluded reason 'other' is unknown"),
        (set_key("excluded", 0, "audit_kind", value="Bad"), "excluded audit_kind"),
        (set_key("exceptions", "status", value="maybe"), "exceptions status 'maybe' is unknown"),
        (set_key("exceptions", "source_sha256", value=None), "set exactly when an exceptions file"),
        (set_key("exceptions", "evaluation", value=None), "exactly when applied"),
        (
            set_key("exceptions", "stale", value="exceptions/evaluation.json"),
            "only in a bundle whose",
        ),
        (set_key("collected_at", value="yesterday"), "collected_at"),
        (set_key("host", "machine_id", value="X"), "host machine_id"),
        (set_key("run", "run_id", value="../x"), "run run_id"),
        (set_key("run", "benchmark_id", value="benchmark"), "run benchmark_id"),
        (set_key("run", "profile_id", value="profile"), "run profile_id"),
        (set_key("checksums", "size", value=-1), "checksums size"),
    ],
)
def test_a_manifest_that_is_not_valid_is_refused(
    change: Callable[[dict[str, object]], None], message: str
) -> None:
    document = manifest_of(bundle())
    change(document)
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.parse_manifest(evidence.canonical_json(document).encode("utf-8"))


def test_manifest_lists_must_be_sorted_and_unique() -> None:
    document = manifest_of(bundle())
    files = cast("list[object]", document["files"])
    document["files"] = list(reversed(files))
    with pytest.raises(evidence.EvidenceError, match="unique and sorted by path"):
        evidence.parse_manifest(evidence.canonical_json(document).encode("utf-8"))
    document = manifest_of(bundle())
    excluded = cast("list[object]", document["excluded"])
    document["excluded"] = list(reversed(excluded))
    with pytest.raises(evidence.EvidenceError, match="unique and sorted by source"):
        evidence.parse_manifest(evidence.canonical_json(document).encode("utf-8"))
    document = manifest_of(bundle())
    entries = cast("list[dict[str, object]]", document["files"])
    document["files"] = [item for item in entries if item["path"] != "exceptions/stale.json"]
    with pytest.raises(evidence.EvidenceError, match="name different documents"):
        evidence.parse_manifest(evidence.canonical_json(document).encode("utf-8"))


def test_an_oversized_manifest_is_refused() -> None:
    with pytest.raises(evidence.EvidenceError, match="larger than"):
        evidence.parse_manifest(b" " * (evidence.MAX_MANIFEST_BYTES + 1))


TAMPER_CASES: list[tuple[Callable[[Contents], object], str]] = [
    (lambda contents: contents.pop(evidence.MANIFEST_NAME), "has no bundle.json"),
    (lambda contents: contents.update({"bundle.sigstore.json": b"{}"}), "carries a signature"),
    (
        lambda contents: contents.update({"raw/extra.txt": b"x"}),
        "does not list: 'raw/extra.txt'",
    ),
    (lambda contents: contents.pop("raw/tailoring.xml"), "is missing raw/tailoring.xml"),
    (
        lambda contents: contents.update({"raw/scan/results.xml": XCCDF + b" "}),
        "checksum mismatch for raw/scan/results.xml",
    ),
    (
        lambda contents: contents.update({"raw/scan/results.xml": b"x" * len(XCCDF)}),
        "checksum mismatch",
    ),
    (
        lambda contents: contents.update({evidence.CHECKSUMS_NAME: b"x"}),
        "SHA256SUMS does not match",
    ),
]


@pytest.mark.parametrize(("tamper", "message"), TAMPER_CASES)
def test_a_bundle_that_changed_after_it_was_written_is_refused(
    tamper: Callable[[Contents], object], message: str
) -> None:
    contents = bundle()
    tamper(contents)
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.check_bundle(contents)


def test_a_consistent_checksums_file_that_the_manifest_does_not_imply_is_refused() -> None:
    contents = bundle()
    sums = contents[evidence.CHECKSUMS_NAME] + b"\n"
    contents[evidence.CHECKSUMS_NAME] = sums
    document = manifest_of(contents)
    document["checksums"] = {
        "path": evidence.CHECKSUMS_NAME,
        "sha256": sha(sums),
        "size": len(sums),
    }
    contents[evidence.MANIFEST_NAME] = evidence.canonical_json(document).encode("utf-8")
    with pytest.raises(evidence.EvidenceError, match="SHA256SUMS does not match"):
        evidence.check_bundle(contents)


def edited(path: str, data: bytes) -> Callable[[Contents], None]:
    def change(contents: Contents) -> None:
        contents[path] = data

    return change


@pytest.mark.parametrize(
    ("edit", "manifest_change", "message"),
    [
        (edited("raw/scan-run.json", b"\xff"), None, "is not a valid scan run"),
        (edited("raw/scan-run.json", b"{}"), None, "is not a valid scan run"),
        (
            None,
            set_key("run", "started_at", value="2020-01-01T00:00:00Z"),
            "does not match the run, host",
        ),
        (
            None,
            set_key("exceptions", "source_sha256", value="c" * 64),
            "is not the exceptions file the manifest names",
        ),
        (edited("exceptions/evaluation.json", b"{}"), None, "evaluation.json does not verify"),
        (edited("exceptions/stale.json", b"{}"), None, "missing keys"),
    ],
)
def test_a_resealed_bundle_with_inconsistent_content_is_refused(
    edit: Callable[[Contents], None] | None,
    manifest_change: Callable[[dict[str, object]], None] | None,
    message: str,
) -> None:
    contents = bundle()
    if edit is not None:
        edit(contents)
    reseal(contents, manifest_change)
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.check_bundle(contents)


def test_an_exceptions_file_that_is_not_utf8_is_refused() -> None:
    contents = bundle()
    raw = b"\xff\xfe"
    contents["exceptions/exceptions.yml"] = raw
    reseal(contents, set_key("exceptions", "source_sha256", value=sha(raw)))
    with pytest.raises(evidence.EvidenceError, match="is not valid UTF-8"):
        evidence.check_bundle(contents)


def test_an_evaluation_for_another_host_or_run_is_refused() -> None:
    contents = bundle()
    other_host = evaluate(scan_run(), exceptions_text("db01"), host="db01")
    text = exceptions_text("db01").encode("utf-8")
    contents["exceptions/evaluation.json"] = evidence.canonical_json(other_host).encode("utf-8")
    contents["exceptions/exceptions.yml"] = text
    reseal(contents, set_key("exceptions", "source_sha256", value=sha(text)))
    with pytest.raises(evidence.EvidenceError, match="was made for another inventory host"):
        evidence.check_bundle(contents)
    contents = bundle()
    other_run = evaluate(scan_run(outcome=model.Outcome.ERROR), exceptions_text())
    contents["exceptions/evaluation.json"] = evidence.canonical_json(other_run).encode("utf-8")
    reseal(contents)
    with pytest.raises(evidence.EvidenceError, match=r"was not made from raw/scan-run\.json"):
        evidence.check_bundle(contents)


def stale_edit(**changes: object) -> Callable[[Contents], None]:
    def change(contents: Contents) -> None:
        document = json.loads(contents["exceptions/stale.json"])
        for key, value in changes.items():
            if key in ("kind", "schema_version"):
                document[key] = value
            else:
                document["result"][key] = value
        contents["exceptions/stale.json"] = evidence.canonical_json(document).encode("utf-8")

    return change


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"kind": "other"}, "unsupported kind or schema_version"),
        ({"schema_version": "9"}, "unsupported kind or schema_version"),
        ({"source_sha256": "c" * 64}, "computed from another exceptions file"),
        ({"evaluated_hosts": ["db01"]}, "does not include the evaluation of web01"),
    ],
)
def test_a_stale_result_that_does_not_belong_to_the_bundle_is_refused(
    changes: dict[str, object], message: str
) -> None:
    contents = bundle()
    stale_edit(**changes)(contents)
    reseal(contents)
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.check_bundle(contents)


def test_the_machine_id_of_the_manifest_must_match_the_scan_run() -> None:
    run = scan_run(machine_id="c" * 32)
    fact = audited(run)
    received = fetched(fact, host_files(run))
    result = evidence.build_documents(fact, collected(received, machine_id="c" * 32), NOW)
    contents = dict(received)
    for path, text in cast("dict[str, str]", result["documents"]).items():
        contents[path] = text.encode("utf-8")
    contents[evidence.MANIFEST_NAME] = cast("str", result["manifest"]).encode("utf-8")
    assert evidence.check_bundle(copy.deepcopy(contents)).run.host.machine_id == "c" * 32
    reseal(contents, set_key("host", "machine_id", value="d" * 32))
    with pytest.raises(evidence.EvidenceError, match="machine ID of the manifest differs"):
        evidence.check_bundle(contents)
