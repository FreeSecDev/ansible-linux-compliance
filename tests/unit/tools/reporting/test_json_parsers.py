from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting.common import SectionStatus
from tools.reporting.parsers import (
    codebuild,
    grype,
    lint,
    molecule,
    packer,
    pytest_json,
    sbom,
    scanrun,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def rejected(parse: Callable[..., Any], write: Callable[..., Path], document: object) -> bool:
    text = document if isinstance(document, (str, bytes)) else json.dumps(document)
    return bool(parse(write("doc.json", text)).status is SectionStatus.ERROR)


def test_pytest_json_counts_outcomes(kit: Any) -> None:
    data = pytest_json.parse_pytest_json(kit.REPORTING / "pytest.json").data
    assert data is not None
    assert (data.total, data.passed, data.failed, data.errors, data.skipped) == (8, 3, 2, 1, 2)
    assert [case.kind for case in data.failed_cases] == ["failed", "error", "xpassed"]


BAD_PYTEST_JSON_REJECTS_DOCUMENTS: list[Any] = [
    [],
    {},
    {"summary": []},
    {"summary": {"passed": 1}},
    {"summary": {"passed": 1, "total": 2}},
    {"summary": {"total": 0}},
    {"summary": {"passed": "1", "total": 1}},
    {"summary": {"passed": 1, "total": 1}, "tests": {}},
    {"summary": {"passed": 1, "total": 1}, "tests": [1]},
    {"summary": {"failed": 1, "total": 1}, "tests": [{"outcome": "failed"}]},
    {"summary": {"failed": 1, "total": 1}, "tests": [{"nodeid": "a"}]},
    "{",
]


@pytest.mark.parametrize("document", BAD_PYTEST_JSON_REJECTS_DOCUMENTS)
def test_pytest_json_rejects_bad_documents(write: Callable[..., Path], document: object) -> None:
    assert rejected(pytest_json.parse_pytest_json, write, document)


def test_pytest_json_truncates_failures(write: Callable[..., Path]) -> None:
    tests = [{"nodeid": f"t{i}", "outcome": "failed"} for i in range(1001)]
    document = {"summary": {"failed": 1001, "total": 1001}, "tests": tests}
    data = pytest_json.parse_pytest_json(write("p.json", json.dumps(document))).data
    assert data is not None
    assert data.truncated
    assert len(data.failed_cases) == 1000


def test_pytest_json_without_a_test_list(write: Callable[..., Path]) -> None:
    data = pytest_json.parse_pytest_json(
        write("p.json", json.dumps({"summary": {"passed": 2, "total": 2}}))
    ).data
    assert data is not None
    assert data.failed_cases == ()


def test_lint_sarif(kit: Any) -> None:
    data = lint.parse_lint(kit.REPORTING / "ansible-lint.sarif").data
    assert data is not None
    assert data.format == "sarif"
    assert data.total == 3
    assert data.by_severity["high"] == 1
    assert data.by_severity["medium"] == 1
    assert data.by_severity["low"] == 1
    assert [issue.rule_id for issue in data.issues] == [
        "syntax-check",
        "name[casing]",
        "yaml[line-length]",
    ]
    assert data.issues[0].message == 'Syntax problem <b>bold</b> & "quotes"'
    assert data.issues[2].path is None
    assert data.issues[1].line == 4


def test_lint_json(kit: Any) -> None:
    data = lint.parse_lint(kit.REPORTING / "ansible-lint.json").data
    assert data is not None
    assert data.format == "json"
    assert data.by_severity["critical"] == 1
    assert data.by_severity["high"] == 1
    assert data.by_severity["unknown"] == 1


def test_lint_clean_runs_are_available_with_zero_issues(write: Callable[..., Path]) -> None:
    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}],
    }
    documents: list[object] = [[], sarif]
    for document in documents:
        data = lint.parse_lint(write("l.json", json.dumps(document))).data
        assert data is not None
        assert data.total == 0


def test_lint_truncates_issues(write: Callable[..., Path]) -> None:
    document = [
        {"check_name": f"r{i}", "description": "d", "severity": "info"} for i in range(1001)
    ]
    data = lint.parse_lint(write("l.json", json.dumps(document))).data
    assert data is not None
    assert data.total == 1001
    assert len(data.issues) == 1000
    assert data.truncated


BAD_LINT_REJECTS_DOCUMENTS: list[Any] = [
    {},
    {"version": "2.0.0", "runs": []},
    {"version": "2.1.0"},
    {"version": "2.1.0", "runs": []},
    {"version": "2.1.0", "runs": [{"results": []}]},
    {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}}]},
    {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": [1]}]},
    {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"message": {"text": "m"}}]}],
    },
    {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"ruleId": "r"}]}],
    },
    [1],
    [{"description": "d"}],
    [{"check_name": "c"}],
    "text",
    3,
]


@pytest.mark.parametrize("document", BAD_LINT_REJECTS_DOCUMENTS)
def test_lint_rejects_bad_documents(write: Callable[..., Path], document: object) -> None:
    assert rejected(lint.parse_lint, write, document)


def test_lint_unknown_level_and_defaults(write: Callable[..., Path]) -> None:
    results = [
        {"ruleId": "a", "level": "bogus", "message": {"text": "m"}},
        {"ruleId": "b", "message": {"text": "m"}},
    ]
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "x"}}, "results": results}],
    }
    data = lint.parse_lint(write("l.json", json.dumps(document))).data
    assert data is not None
    assert [issue.severity for issue in data.issues] == ["medium", "unknown"]


def test_grype_normalizes_dedupes_and_sorts(kit: Any) -> None:
    data = grype.parse_grype(kit.REPORTING / "grype.json").data
    assert data is not None
    assert (data.scanner, data.scanner_version, data.database_built) == (
        "grype",
        "0.0.0",
        "2026-10-24T00:00:00Z",
    )
    assert data.total == 4
    assert data.by_severity == {
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 1,
        "unknown": 1,
    }
    assert [item.vulnerability_id for item in data.vulnerabilities] == [
        "CVE-2026-0002",
        "CVE-2026-0001",
        "CVE-2026-0003",
        "CVE-2026-0004",
    ]
    assert data.vulnerabilities[1].fixed_versions == ("1.2.3", "1.2.4")
    assert data.vulnerabilities[1].fix_state == "fixed"


def test_grype_older_database_layout_and_missing_date(write: Callable[..., Path]) -> None:
    base: dict[str, Any] = {
        "matches": [],
        "descriptor": {"name": "grype", "version": "1"},
    }
    older: dict[str, Any] = {
        **base,
        "descriptor": {"name": "grype", "version": "1", "db": {"built": "2026-01-01T00:00:00Z"}},
    }
    assert grype.parse_grype(write("a.json", json.dumps(older))).data is not None
    data = grype.parse_grype(write("b.json", json.dumps(base))).data
    assert data is not None
    assert data.database_built is None
    assert data.total == 0


BAD_GRYPE_REJECTS_DOCUMENTS: list[Any] = [
    [],
    {"matches": []},
    {"descriptor": {"name": "grype", "version": "1"}},
    {"matches": [], "descriptor": {"name": "trivy", "version": "1"}},
    {"matches": [], "descriptor": {"name": "grype"}},
    {"matches": {}, "descriptor": {"name": "grype", "version": "1"}},
    {"matches": [1], "descriptor": {"name": "grype", "version": "1"}},
    {"matches": [{}], "descriptor": {"name": "grype", "version": "1"}},
    {
        "matches": [{"vulnerability": {"id": "x"}}],
        "descriptor": {"name": "grype", "version": "1"},
    },
    {
        "matches": [{"vulnerability": {"id": "x"}, "artifact": {"name": "n"}}],
        "descriptor": {"name": "grype", "version": "1"},
    },
    {
        "matches": [
            {
                "vulnerability": {"id": "x", "fix": {"versions": [1]}},
                "artifact": {"name": "n", "version": "1"},
            }
        ],
        "descriptor": {"name": "grype", "version": "1"},
    },
]


@pytest.mark.parametrize("document", BAD_GRYPE_REJECTS_DOCUMENTS)
def test_grype_rejects_bad_documents(write: Callable[..., Path], document: object) -> None:
    assert rejected(grype.parse_grype, write, document)


def test_grype_truncates(write: Callable[..., Path]) -> None:
    matches = [
        {"vulnerability": {"id": f"CVE-{i}"}, "artifact": {"name": "n", "version": "1"}}
        for i in range(1001)
    ]
    document = {"matches": matches, "descriptor": {"name": "grype", "version": "1"}}
    data = grype.parse_grype(write("g.json", json.dumps(document))).data
    assert data is not None
    assert data.truncated
    assert data.by_severity["unknown"] == 1001


def test_spdx(kit: Any) -> None:
    data = sbom.parse_sbom(kit.REPORTING / "spdx.json").data
    assert data is not None
    assert (data.format, data.spec_version, data.component_count) == ("spdx", "SPDX-2.3", 3)
    assert data.license_counts == {"Apache-2.0": 1, "MIT": 1}
    assert data.unlicensed == 1
    assert [component.name for component in data.components] == ["libdemo", "libnone", "libother"]


def test_cyclonedx(kit: Any) -> None:
    data = sbom.parse_sbom(kit.REPORTING / "cyclonedx.json").data
    assert data is not None
    assert (data.format, data.spec_version, data.component_count) == ("cyclonedx", "1.5", 4)
    assert data.license_counts == {"Custom": 1, "MIT": 1, "MIT OR Apache-2.0": 1}
    assert data.unlicensed == 1


def test_sbom_truncates(write: Callable[..., Path]) -> None:
    components = [{"name": f"c{i}"} for i in range(1001)]
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
    data = sbom.parse_sbom(write("s.json", json.dumps(document))).data
    assert data is not None
    assert data.truncated
    assert data.unlicensed == 1001


BAD_SBOM_REJECTS_DOCUMENTS: list[Any] = [
    [],
    {},
    {"bomFormat": "Other"},
    {"spdxVersion": "SPDX-3.0", "packages": []},
    {"spdxVersion": "SPDX-2.3"},
    {"spdxVersion": "SPDX-2.3", "packages": []},
    {"spdxVersion": "SPDX-2.3", "packages": [1]},
    {"spdxVersion": "SPDX-2.3", "packages": [{}]},
    {"spdxVersion": 2, "packages": [{"name": "a"}]},
    {"bomFormat": "CycloneDX"},
    {"bomFormat": "CycloneDX", "specVersion": "2.0", "components": [{"name": "a"}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5"},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{}]},
]


@pytest.mark.parametrize("document", BAD_SBOM_REJECTS_DOCUMENTS)
def test_sbom_rejects_bad_documents(write: Callable[..., Path], document: object) -> None:
    assert rejected(sbom.parse_sbom, write, document)


def test_packer_manifest(kit: Any) -> None:
    data = packer.parse_packer(kit.REPORTING / "packer-manifest.json").data
    assert data is not None
    assert [build.name for build in data.builds] == ["base", "golden"]
    golden = data.builds[1]
    assert golden.build_time == "2026-10-14T17:46:40Z"
    assert golden.custom_data == {"distro": "rhel-9"}
    assert [(item.name, item.size) for item in golden.files] == [
        ("image-a", 1024),
        ("image-b", None),
    ]
    assert data.builds[0].files == ()
    assert data.builds[0].custom_data == {}
    assert data.last_run_uuid is not None


def test_packer_without_build_time(write: Callable[..., Path]) -> None:
    build = {"name": "n", "builder_type": "b", "artifact_id": "a"}
    data = packer.parse_packer(write("p.json", json.dumps({"builds": [build]}))).data
    assert data is not None
    assert data.builds[0].build_time is None
    assert data.last_run_uuid is None


BAD_PACKER_REJECTS_DOCUMENTS: list[Any] = [
    [],
    {},
    {"builds": []},
    {"builds": [1]},
    {"builds": [{"name": "n", "builder_type": "b"}]},
    {"builds": [{"name": "n", "builder_type": "b", "artifact_id": "a", "files": [1]}]},
    {"builds": [{"name": "n", "builder_type": "b", "artifact_id": "a", "files": [{}]}]},
    {"builds": [{"name": "n", "builder_type": "b", "artifact_id": "a", "custom_data": {"k": 1}}]},
    {"builds": [{"name": "n", "builder_type": "b", "artifact_id": "a", "custom_data": [1]}]},
    {"builds": [{"name": "n", "builder_type": "b", "artifact_id": "a", "files": {}}]},
]


@pytest.mark.parametrize("document", BAD_PACKER_REJECTS_DOCUMENTS)
def test_packer_rejects_bad_documents(write: Callable[..., Path], document: object) -> None:
    assert rejected(packer.parse_packer, write, document)


def test_codebuild(kit: Any) -> None:
    data = codebuild.parse_codebuild(kit.REPORTING / "codebuild.json").data
    assert data is not None
    assert [build.status for build in data.builds] == ["SUCCEEDED", "FAILED"]
    first = data.builds[0]
    assert first.started_at == "2026-10-14T17:46:40Z"
    assert first.ended_at == "2026-10-25T10:05:00Z"
    assert data.builds[1].started_at is None
    assert data.builds[1].project == "demo"


def test_codebuild_boolean_time_is_ignored(write: Callable[..., Path]) -> None:
    build = {"id": "a", "buildStatus": "STOPPED", "startTime": True}
    data = codebuild.parse_codebuild(write("c.json", json.dumps({"builds": [build]}))).data
    assert data is not None
    assert data.builds[0].started_at is None


BAD_CODEBUILD_REJECTS_DOCUMENTS: list[Any] = [
    [],
    {},
    {"builds": []},
    {"builds": [1]},
    {"builds": [{"id": "a"}]},
    {"builds": [{"id": "a", "buildStatus": "PASSED"}]},
    {"builds": [{"buildStatus": "FAILED"}]},
    {"builds": [{"id": "a", "buildStatus": "FAILED", "startTime": 1e300}]},
    {"builds": [{"id": "a", "buildStatus": "FAILED"}], "buildsNotFound": ["demo:x"]},
    {"builds": [{"id": "a", "buildStatus": "FAILED"}], "buildsNotFound": {}},
]


@pytest.mark.parametrize("document", BAD_CODEBUILD_REJECTS_DOCUMENTS)
def test_codebuild_rejects_bad_documents(write: Callable[..., Path], document: object) -> None:
    assert rejected(codebuild.parse_codebuild, write, document)


def test_molecule_summary(kit: Any) -> None:
    data = molecule.parse_molecule(kit.REPORTING / "molecule-summary.json").data
    assert data is not None
    assert (data.total, data.passed, data.failed, data.skipped, data.error) == (4, 1, 1, 1, 1)
    assert (data.scenarios[0].name, data.scenarios[0].platform) == ("audit", "debian-12")


def valid_molecule() -> dict[str, Any]:
    return {
        "format": "freesecdev-molecule-summary",
        "version": 1,
        "scenarios": [{"name": "n", "platform": "p", "result": "passed"}],
    }


SCENARIO = {"name": "n", "platform": "p", "result": "passed"}
MOLECULE_CHANGES: list[tuple[str, Any]] = [
    ("format", "other"),
    ("version", 2),
    ("version", True),
    ("scenarios", None),
    ("scenarios", []),
    ("scenarios", [1]),
    ("scenarios", [{"name": "n", "platform": "p", "result": "ok"}]),
    ("scenarios", [{"name": "n", "platform": "p"}]),
    ("scenarios", [SCENARIO, SCENARIO]),
]


@pytest.mark.parametrize(("key", "value"), MOLECULE_CHANGES)
def test_molecule_rejects_bad_documents(write: Callable[..., Path], key: str, value: Any) -> None:
    document = valid_molecule()
    if key == "scenarios" and value is None:
        del document[key]
    else:
        document[key] = value
    assert rejected(molecule.parse_molecule, write, document)


def test_scan_run_embeds_the_validated_run(kit: Any, write_run: Callable[..., Path]) -> None:
    run = kit.scan_run((kit.finding("a"), kit.finding("b", model.Outcome.FAIL)))
    result = scanrun.parse_scan_run(write_run("run.json", run))
    data = result.data
    assert data is not None
    assert data.scan_run == run
    assert data.host == kit.HOST
    assert data.summary.compliance_percent == 50.0
    assert data.to_dict()["findings"] == []


def test_scan_run_not_completed_keeps_its_status(kit: Any, write_run: Callable[..., Path]) -> None:
    run = kit.scan_run((kit.finding("a", model.Outcome.ERROR),), status=model.ScanStatus.TIMED_OUT)
    data = scanrun.parse_scan_run(write_run("run.json", run)).data
    assert data is not None
    assert data.scan_status == "timed_out"
    assert data.error_message == "scanner did not finish"
    assert data.summary.compliance_percent is None
    assert data.summary.assessment == "run_not_completed"
    assert (data.summary.runs_total, data.summary.runs_not_completed) == (1, 1)


@pytest.mark.parametrize("text", ["{}", "[]", "not json", '{"schema_version": "9.9"}'])
def test_scan_run_rejects_documents_the_model_rejects(
    write: Callable[..., Path], text: str
) -> None:
    result = scanrun.parse_scan_run(write("run.json", text))
    assert result.status is SectionStatus.ERROR


def test_scan_run_rejects_non_utf8(write: Callable[..., Path]) -> None:
    assert scanrun.parse_scan_run(write("run.json", b"\xff")).status is SectionStatus.ERROR
