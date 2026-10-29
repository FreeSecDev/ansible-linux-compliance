"""The off-platform opt-in of the audit module (ADR 0019, amendment of FREES-161)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
    model,
    scanner,
)
from tests.unit.plugins.module_utils.compliance.test_audit import (
    ALPHA,
    SHA256,
    START,
    UID,
    Harness,
    host_params,
    params,
)

TARGET = model.HostIdentity("host.example", "ubuntu", "26.04", "x86_64", None)
MARKER = model.OffPlatform(model.Platform("ubuntu", "24.04"), model.Platform("ubuntu", "26.04"))


class MarkingBackend:
    """A stand-in for the SCC backend that returns an off-platform run."""

    def __init__(self, digest: str = SHA256) -> None:
        self.requests: list[scanner.ScanRequest] = []
        self.digest = digest

    def audit(self, request: scanner.ScanRequest) -> model.ScanRun:
        self.requests.append(request)
        findings = tuple(
            model.Finding(
                rule_id=rule_id,
                outcome=model.Outcome.PASS,
                evaluated_outcome=model.Outcome.PASS,
                severity=model.Severity.MEDIUM,
                message=None,
                evidence=(),
                exception=model.ExceptionStatus.none(),
                remediation=None,
                disabled_by=None,
                flags=(),
            )
            for rule_id in request.expected_rule_ids
        )
        return model.ScanRun(
            run_id=request.run_id,
            started_at="2026-10-25T09:00:00Z",
            finished_at="2026-10-25T09:00:01Z",
            host=request.host,
            scanner=model.ScannerInfo("scc", "5.15"),
            content=model.Provenance("synthetic-ds.xml", "1.0", self.digest),
            benchmark_id=request.benchmark_id,
            profile_id=request.profile_id,
            status=model.ScanStatus.COMPLETED,
            error_message=None,
            findings=findings,
            off_platform=MARKER,
        )


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    tmp_path.chmod(0o755)
    release = tmp_path / "os-release"
    release.write_text(
        'PRETTY_NAME="Ubuntu 26.04 LTS"\nNAME="Ubuntu"\nVERSION_ID="26.04"\nID=ubuntu\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(audit, "OS_RELEASE_PATH", str(release))
    monkeypatch.setattr(audit, "OS_RELEASE_FALLBACK_PATH", str(tmp_path / "absent-fallback"))
    return Harness(tmp_path)


def auditor(backend: MarkingBackend) -> audit.Auditor:
    registry = scanner.BackendRegistry()
    registry.register("scc", lambda _settings: backend)
    return audit.Auditor(owner_uid=UID, registry=registry, clock=lambda: START)


def test_the_opt_in_is_off_by_default() -> None:
    job = audit.build_job(params(), START)
    assert job.allow_off_platform_benchmark is False
    without = {key: value for key, value in params().items() if key != "disabled_rules"}
    assert audit.build_job(without, START).allow_off_platform_benchmark is False


def test_the_opt_in_is_accepted_for_the_scc_backend() -> None:
    job = audit.build_job(
        params(
            backend="scc",
            allow_off_platform_benchmark=True,
            host=host_params(distribution_version="26.04"),
        ),
        START,
    )
    assert job.allow_off_platform_benchmark is True


def test_the_openscap_backend_refuses_the_opt_in() -> None:
    with pytest.raises(audit.AuditError, match="applies only to the backend scc") as raised:
        audit.build_job(params(allow_off_platform_benchmark=True), START)
    assert raised.value.error_type == "invalid_argument"


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_the_opt_in_is_strictly_a_boolean(harness: Harness, value: object) -> None:
    with pytest.raises(audit.AuditError, match="must be a boolean") as raised:
        harness.job(backend="scc", allow_off_platform_benchmark=value)
    assert raised.value.error_type == "invalid_argument"


def test_the_opt_in_reaches_the_backend_and_the_run_is_reported_marked(harness: Harness) -> None:
    backend = MarkingBackend()
    job = harness.job(backend="scc", host=TARGET, allow_off_platform_benchmark=True)
    result: dict[str, Any] = auditor(backend).run(job, check_mode=False)
    assert [request.allow_off_platform_benchmark for request in backend.requests] == [True]
    assert result["planned"]["allow_off_platform_benchmark"] is True
    run = result["scan_run"]
    assert run["schema_version"] == "1.1"
    assert run["off_platform"] == MARKER.to_dict()
    assert all(item["off_platform"] == MARKER.to_dict() for item in run["findings"])
    record = Path(harness.run_dir / "scan-run.json").read_text(encoding="utf-8")
    assert model.loads(record).off_platform == MARKER
    assert json.loads(record)["schema_version"] == "1.1"


def test_rules_added_to_a_marked_run_carry_the_marker(harness: Harness) -> None:
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    job = harness.job(
        backend="scc", host=TARGET, allow_off_platform_benchmark=True, disabled_rules=disabled
    )
    result: dict[str, Any] = auditor(MarkingBackend()).run(job, check_mode=False)
    findings = {item["rule_id"]: item for item in result["scan_run"]["findings"]}
    assert findings[ALPHA]["outcome"] == "disabled"
    assert {json.dumps(item["off_platform"]) for item in findings.values()} == {
        json.dumps(MARKER.to_dict())
    }


def test_a_marked_run_with_the_wrong_digest_fails_and_keeps_the_marker(harness: Harness) -> None:
    job = harness.job(backend="scc", host=TARGET, allow_off_platform_benchmark=True)
    result: dict[str, Any] = auditor(MarkingBackend(digest="b" * 64)).run(job, check_mode=False)
    assert result["run_status"] == "failed"
    assert result["scan_run"]["off_platform"] == MARKER.to_dict()
    assert {item["outcome"] for item in result["scan_run"]["findings"]} == {"error"}


def test_without_the_opt_in_the_backend_is_told_so(harness: Harness) -> None:
    backend = MarkingBackend()
    auditor(backend).run(harness.job(backend="scc", host=TARGET), check_mode=False)
    assert [request.allow_off_platform_benchmark for request in backend.requests] == [False]


def test_the_scc_backend_refuses_a_host_that_reports_another_release(harness: Harness) -> None:
    host = model.HostIdentity("host.example", "ubuntu", "24.04", "x86_64", None)
    with pytest.raises(audit.AuditError, match=r"VERSION_ID '26\.04'") as raised:
        audit.plan(harness.job(backend="scc", host=host), owner_uid=UID)
    assert raised.value.error_type == "host_mismatch"
    assert not harness.output_root.exists()


def test_the_scc_backend_refuses_an_unreadable_release_file(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit, "OS_RELEASE_PATH", str(harness.root / "absent"))
    with pytest.raises(audit.AuditError, match="cannot be read") as raised:
        audit.plan(harness.job(backend="scc", host=TARGET), owner_uid=UID)
    assert raised.value.error_type == "host_mismatch"


def test_a_missing_etc_release_falls_back_to_the_usr_lib_file(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    fallback = harness.root / "usr-lib-os-release"
    fallback.write_text('ID=ubuntu\nVERSION_ID="26.04"\n', encoding="utf-8")
    monkeypatch.setattr(audit, "OS_RELEASE_PATH", str(harness.root / "absent"))
    monkeypatch.setattr(audit, "OS_RELEASE_FALLBACK_PATH", str(fallback))
    audit.plan(harness.job(backend="scc", host=TARGET), owner_uid=UID)
    other = model.HostIdentity("host.example", "ubuntu", "24.04", "x86_64", None)
    with pytest.raises(audit.AuditError, match=r"VERSION_ID '26\.04'") as raised:
        audit.plan(harness.job(backend="scc", host=other), owner_uid=UID)
    assert raised.value.error_type == "host_mismatch"


def test_an_existing_etc_release_wins_over_the_usr_lib_file(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    fallback = harness.root / "usr-lib-os-release"
    fallback.write_text('ID=debian\nVERSION_ID="12"\n', encoding="utf-8")
    monkeypatch.setattr(audit, "OS_RELEASE_FALLBACK_PATH", str(fallback))
    audit.plan(harness.job(backend="scc", host=TARGET), owner_uid=UID)


def test_a_dangling_etc_release_symlink_counts_as_missing(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    fallback = harness.root / "usr-lib-os-release"
    fallback.write_text('ID=ubuntu\nVERSION_ID="26.04"\n', encoding="utf-8")
    dangling = harness.root / "etc-os-release"
    dangling.symlink_to(harness.root / "nowhere")
    monkeypatch.setattr(audit, "OS_RELEASE_PATH", str(dangling))
    monkeypatch.setattr(audit, "OS_RELEASE_FALLBACK_PATH", str(fallback))
    assert audit.resolve_os_release(str(dangling), str(fallback)) == str(fallback)
    audit.plan(harness.job(backend="scc", host=TARGET), owner_uid=UID)


def test_an_unreadable_etc_release_does_not_fall_back(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    fallback = harness.root / "usr-lib-os-release"
    fallback.write_text('ID=ubuntu\nVERSION_ID="26.04"\n', encoding="utf-8")
    directory = harness.root / "etc-os-release"
    directory.mkdir()
    monkeypatch.setattr(audit, "OS_RELEASE_PATH", str(directory))
    monkeypatch.setattr(audit, "OS_RELEASE_FALLBACK_PATH", str(fallback))
    with pytest.raises(audit.AuditError, match="cannot be read") as raised:
        audit.plan(harness.job(backend="scc", host=TARGET), owner_uid=UID)
    assert raised.value.error_type == "host_mismatch"


def test_neither_release_file_existing_fails_closed(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit, "OS_RELEASE_PATH", str(harness.root / "absent"))
    assert audit.resolve_os_release(audit.OS_RELEASE_PATH, audit.OS_RELEASE_FALLBACK_PATH) == str(
        harness.root / "absent"
    )
    with pytest.raises(audit.AuditError, match="cannot be read") as raised:
        audit.plan(harness.job(backend="scc", host=TARGET), owner_uid=UID)
    assert raised.value.error_type == "host_mismatch"


def test_an_oversized_release_file_is_refused(harness: Harness) -> None:
    big = harness.root / "big-os-release"
    big.write_bytes(b"#" * (audit.MAX_OS_RELEASE_BYTES + 1))
    with pytest.raises(audit.AuditError, match="exceeds") as raised:
        audit.check_host_release(TARGET, str(big))
    assert raised.value.error_type == "host_mismatch"


def test_the_release_file_is_read_like_os_release(harness: Harness) -> None:
    release = harness.root / "quoted"
    release.write_text(
        '# comment\nID=\'ubuntu\'\nVERSION_ID="26.04"\nlowercase=ignored\nNAME="\nBROKEN\n',
        encoding="utf-8",
    )
    values = audit.read_os_release(str(release))
    assert values == {"ID": "ubuntu", "VERSION_ID": "26.04", "NAME": '"'}
    audit.check_host_release(TARGET, str(release))


def test_the_openscap_backend_does_not_read_the_release_file(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit, "OS_RELEASE_PATH", str(harness.root / "absent"))
    planned = audit.plan(harness.job(), owner_uid=UID)
    assert planned.job.backend == "openscap"
    assert {"scc"} == audit.OS_RELEASE_BACKENDS


def test_the_summary_names_the_off_platform_marker(harness: Harness) -> None:
    job = harness.job(backend="scc", host=TARGET, allow_off_platform_benchmark=True)
    result: dict[str, Any] = auditor(MarkingBackend()).run(job, check_mode=False)
    assert result["summary"]["off_platform"] == MARKER.to_dict()
    assert audit.summarize(None) is None
