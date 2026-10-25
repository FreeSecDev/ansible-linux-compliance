from __future__ import annotations

import calendar
import hashlib
import os
import stat
import time
import tracemalloc
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    openscap,
    process,
    scanner,
)

if TYPE_CHECKING:
    from collections.abc import Callable

FIXTURES = Path(__file__).resolve().parents[4] / "fixtures"
XCCDF = FIXTURES / "xccdf"
ADVERSARIAL = FIXTURES / "adversarial"
BENCHMARK = "xccdf_org.example.synthetic_benchmark_demo"
PROFILE = "xccdf_org.example.synthetic_profile_baseline"
RULE_ALPHA = "xccdf_org.example.synthetic_rule_alpha"
RULE_BETA = "xccdf_org.example.synthetic_rule_beta"
HOST = model.HostIdentity("host.example", "rhel", "9", "x86_64", None)
VERSION_OUTPUT = b"OpenSCAP command line tool (oscap) 1.3.10\nCopyright 2010--2022 Red Hat Inc.\n"
DATASTREAM = b"synthetic datastream bytes\n"


NON_UTF8 = bytes.fromhex((ADVERSARIAL / "non-utf8.xml.hex").read_text(encoding="ascii").strip())


def non_utf8_file(directory: Path) -> Path:
    path = directory / "non-utf8.xml"
    path.write_bytes(NON_UTF8)
    return path


def skip_declaration_scan(_previous: bytes, _chunk: bytes) -> bytes:
    return b""


def text(name: str, folder: Path = XCCDF) -> str:
    return (folder / name).read_text(encoding="utf-8")


def parse(name: str, folder: Path = XCCDF, **limits: Any) -> openscap.ParsedResults:
    return openscap.parse_results(
        text(name, folder), openscap.XmlLimits(**limits) if limits else None
    )


def command_result(
    returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"", *, timed_out: bool = False
) -> process.CommandResult:
    return process.CommandResult(
        argv=("/usr/bin/oscap",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.1,
        timed_out=timed_out,
    )


class FakeRunner:
    """Stands in for process.run; never starts a process."""

    def __init__(self, results: str | None = None) -> None:
        self.results = results
        self.version = command_result(0, VERSION_OUTPUT)
        self.evaluation = command_result(0)
        self.version_error: Exception | None = None
        self.evaluation_error: Exception | None = None
        self.on_evaluate: Callable[[Path], None] | None = None
        self.specs: list[process.CommandSpec] = []

    def __call__(self, spec: process.CommandSpec) -> process.CommandResult:
        self.specs.append(spec)
        if spec.args == ("--version",):
            if self.version_error is not None:
                raise self.version_error
            return self.version
        results = Path(spec.args[spec.args.index("--results") + 1])
        if self.results is not None:
            results.write_text(self.results, encoding="utf-8")
        if self.on_evaluate is not None:
            self.on_evaluate(results)
        if self.evaluation_error is not None:
            raise self.evaluation_error
        return self.evaluation


class Harness:
    """A temporary content root, output root and fake runner."""

    def __init__(self, root: Path, runner: FakeRunner) -> None:
        self.content_root = root / "content"
        self.output_root = root / "output"
        self.content_root.mkdir()
        self.output_root.mkdir()
        self.datastream = self.content_root / "ds.xml"
        self.datastream.write_bytes(DATASTREAM)
        self.runner = runner
        self.settings = scanner.ScanSettings(str(self.content_root), str(self.output_root), 60.0)
        self.moments = iter(
            datetime.fromisoformat("2026-10-25T09:00:00+00:00") + timedelta(seconds=n)
            for n in range(100)
        )

    def backend(self, **keywords: Any) -> openscap.OpenScapBackend:
        return openscap.OpenScapBackend(
            self.settings, runner=self.runner, clock=lambda: next(self.moments), **keywords
        )

    def request(self, **fields: Any) -> scanner.ScanRequest:
        values: dict[str, Any] = {
            "run_id": "run-1",
            "host": HOST,
            "benchmark_id": BENCHMARK,
            "profile_id": PROFILE,
            "content_path": "ds.xml",
            "output_dir": "scan-1",
            "expected_rule_ids": (RULE_ALPHA, RULE_BETA),
        }
        values.update(fields)
        return scanner.ScanRequest(**values)

    def audit(self, **fields: Any) -> model.ScanRun:
        return self.backend().audit(self.request(**fields))


def harness(tmp_path: Path, results: str | None = None) -> Harness:
    return Harness(tmp_path, FakeRunner(text("all-pass.xml") if results is None else results))


def assert_failure(run: model.ScanRun, status: model.ScanStatus, message: str) -> None:
    assert run.status is status
    assert run.error_message is not None
    assert message in run.error_message
    assert [f.rule_id for f in run.findings] == [RULE_ALPHA, RULE_BETA]
    assert {f.outcome for f in run.findings} == {model.Outcome.ERROR}
    assert {f.evaluated_outcome for f in run.findings} == {model.Outcome.ERROR}
    assert not any(f.outcome in {model.Outcome.PASS, model.Outcome.FAIL} for f in run.findings)
    assert run.content.content_version == "unknown"
    assert run.content.content_sha256 == hashlib.sha256(DATASTREAM).hexdigest()


class TestParseResults:
    """Mapping and extraction of XCCDF results."""

    def test_all_pass_document(self) -> None:
        parsed = parse("all-pass.xml")
        assert parsed.benchmark_id == BENCHMARK
        assert parsed.benchmark_version == "1.0"
        assert parsed.profile_id == PROFILE
        assert parsed.started_at == "2026-10-25T10:00:00Z"
        assert parsed.finished_at == "2026-10-25T10:00:09Z"
        assert [(f.rule_id, f.outcome, f.severity) for f in parsed.findings] == [
            (RULE_ALPHA, model.Outcome.PASS, model.Severity.HIGH),
            (RULE_BETA, model.Outcome.PASS, model.Severity.LOW),
        ]
        assert all(f.message is None and f.flags == () for f in parsed.findings)

    def test_every_xccdf_result_value_goes_through_the_mapping(self) -> None:
        parsed = parse("mixed-results.xml")
        mapped = {f.rule_id.rsplit("_rule_", 1)[1]: f for f in parsed.findings}
        assert {name: f.outcome for name, f in mapped.items()} == {
            "r_pass": model.Outcome.PASS,
            "r_fail": model.Outcome.FAIL,
            "r_na": model.Outcome.NOTAPPLICABLE,
            "r_nc": model.Outcome.NOTCHECKED,
            "r_err": model.Outcome.ERROR,
            "r_fixed": model.Outcome.PASS,
            "r_info": model.Outcome.NOTCHECKED,
            "r_nsel": model.Outcome.NOTCHECKED,
            "r_unk": model.Outcome.ERROR,
        }
        assert mapped["r_fixed"].flags == (model.ResultFlag.FIXED,)
        assert mapped["r_info"].flags == (model.ResultFlag.INFORMATIONAL,)
        assert mapped["r_nsel"].flags == (model.ResultFlag.NOTSELECTED,)
        assert mapped["r_pass"].flags == ()
        assert mapped["r_err"].message is None
        assert mapped["r_unk"].message == "scanner result 'unknown' was mapped to error"
        assert mapped["r_nsel"].severity is model.Severity.UNKNOWN
        assert mapped["r_unk"].severity is model.Severity.UNKNOWN
        assert mapped["r_na"].severity is model.Severity.LOW
        assert mapped["r_nc"].severity is model.Severity.INFO
        assert mapped["r_fail"].severity is model.Severity.MEDIUM

    def test_unknown_result_values_map_to_error_not_pass(self) -> None:
        parsed = parse("unknown-result-value.xml", ADVERSARIAL)
        outcomes = {f.rule_id.rsplit("_rule_", 1)[1]: f.outcome for f in parsed.findings}
        assert outcomes == {
            "alpha": model.Outcome.PASS,
            "beta": model.Outcome.ERROR,
            "gamma": model.Outcome.ERROR,
            "delta": model.Outcome.ERROR,
        }
        messages = {f.rule_id.rsplit("_rule_", 1)[1]: f.message for f in parsed.findings}
        assert messages["beta"] == "scanner result 'compliant' was mapped to error"
        assert messages["delta"] == "scanner result 'waived' was mapped to error"

    def test_missing_and_repeated_result_elements_are_errors(self) -> None:
        missing = parse("missing-result-element.xml", ADVERSARIAL)
        assert [f.outcome for f in missing.findings] == [model.Outcome.ERROR]
        assert missing.findings[0].message == "scanner result 'None' was mapped to error"
        repeated = text("all-pass.xml").replace(
            "<result>pass</result>", "<result>pass</result><result>fail</result>", 1
        )
        parsed = openscap.parse_results(repeated)
        assert parsed.findings[0].outcome is model.Outcome.ERROR

    def test_test_result_may_be_the_root(self) -> None:
        parsed = parse("test-result-root.xml")
        assert parsed.benchmark_version == "1.0"
        assert parsed.benchmark_id == BENCHMARK
        assert [f.outcome for f in parsed.findings] == [model.Outcome.PASS]

    def test_timestamps_are_normalised_to_utc(self) -> None:
        zulu = parse("utc-z-timestamps.xml")
        assert (zulu.started_at, zulu.finished_at) == (
            "2026-10-25T12:00:00Z",
            "2026-10-25T12:00:05Z",
        )
        offset = parse("offset-timestamps.xml")
        assert (offset.started_at, offset.finished_at) == (
            "2026-10-25T10:00:00Z",
            "2026-10-25T10:00:05Z",
        )

    def test_benchmark_identity_falls_back_to_the_root_element(self) -> None:
        document = text("all-pass.xml").replace(
            f'<benchmark href="#synthetic-datastream" id="{BENCHMARK}"/>', ""
        )
        assert openscap.parse_results(document).benchmark_id == BENCHMARK

    def test_version_falls_back_to_the_test_result_attribute(self) -> None:
        document = text("all-pass.xml").replace("<version>1.0</version>", "")
        assert openscap.parse_results(document).benchmark_version == "1.0"

    def test_elements_outside_the_test_result_do_not_affect_the_result(self) -> None:
        document = text("all-pass.xml").replace(
            "<status>draft</status>",
            "<status>draft</status><Group id='g'><Rule id='r'><title>x</title></Rule></Group>",
        )
        assert openscap.parse_results(document) == parse("all-pass.xml")

    def test_missing_version_everywhere_is_rejected(self) -> None:
        document = (
            text("all-pass.xml")
            .replace("<version>1.0</version>", "")
            .replace('" version="1.0">', '">')
        )
        with pytest.raises(openscap.XccdfParseError, match="benchmark version"):
            openscap.parse_results(document)

    def test_test_result_root_without_a_benchmark_reference_is_rejected(self) -> None:
        document = text("test-result-root.xml").replace(f'<benchmark id="{BENCHMARK}"/>', "")
        with pytest.raises(openscap.XccdfParseError, match="identify the benchmark"):
            openscap.parse_results(document)

    @pytest.mark.parametrize(
        ("old", "new", "message"),
        [
            (f'<profile idref="{PROFILE}"/>', "", "identify the profile"),
            (f'<profile idref="{PROFILE}"/>', "<profile/>", "identify the profile"),
            (f'<benchmark href="#synthetic-datastream" id="{BENCHMARK}"/>', "", "benchmark"),
            ('start-time="2026-10-25T10:00:00+00:00"', "", "start-time is missing"),
            ('end-time="2026-10-25T10:00:09+00:00"', "", "end-time is missing"),
            ('end-time="2026-10-25T10:00:09+00:00"', 'end-time="  "', "end-time is missing"),
            ('end-time="2026-10-25T10:00:09+00:00"', 'end-time="soon"', "not an ISO 8601"),
            (
                'end-time="2026-10-25T10:00:09+00:00"',
                'end-time="2026-10-25T10:00:09"',
                "no time zone",
            ),
            (
                'start-time="2026-10-25T10:00:00+00:00"',
                'start-time="0001-01-01T00:00:00+05:00"',
                "not an ISO 8601",
            ),
        ],
    )
    def test_incomplete_results_are_rejected(self, old: str, new: str, message: str) -> None:
        document = text("all-pass.xml").replace(old, new)
        if "benchmark href" in old:
            document = document.replace(f'id="{BENCHMARK}">', ">", 1)
        with pytest.raises(openscap.XccdfParseError, match=message):
            openscap.parse_results(document)

    @pytest.mark.parametrize(
        ("name", "message"),
        [
            ("missing-namespace.xml", "not an XCCDF 1.2"),
            ("wrong-namespace.xml", "not an XCCDF 1.2"),
            ("wrong-root.xml", "not an XCCDF 1.2"),
            ("no-test-result.xml", "exactly one TestResult, found 0"),
            ("two-test-results.xml", "exactly one TestResult, found 2"),
            ("truncated.xml", "not well-formed XML"),
            ("duplicate-rule.xml", "more than once"),
            ("bad-rule-id.xml", "invalid rule-result"),
            ("rule-result-without-idref.xml", "no idref"),
            ("bad-timestamp.xml", "not an ISO 8601"),
            ("naive-timestamp.xml", "no time zone"),
        ],
    )
    def test_adversarial_documents_are_rejected(self, name: str, message: str) -> None:
        with pytest.raises(openscap.XccdfParseError, match=message):
            parse(name, ADVERSARIAL)

    def test_reversed_times_parse_but_are_rejected_by_the_model(self) -> None:
        parsed = parse("end-before-start.xml", ADVERSARIAL)
        assert parsed.finished_at < parsed.started_at
        with pytest.raises(model.ModelError, match="precedes"):
            model.ScanRun(
                "run-1",
                parsed.started_at,
                parsed.finished_at,
                HOST,
                model.ScannerInfo("openscap", "1"),
                model.Provenance("a", "1", "0" * 64),
                BENCHMARK,
                PROFILE,
                model.ScanStatus.COMPLETED,
                None,
                parsed.findings,
            )

    def test_empty_text_is_rejected(self) -> None:
        with pytest.raises(openscap.XccdfParseError, match="empty"):
            openscap.parse_results("")

    def test_markup_free_of_elements_is_not_a_pass(self) -> None:
        with pytest.raises(openscap.XccdfParseError):
            openscap.parse_results("<?xml version='1.0'?>")


class TestHardening:
    """Rejection of hostile XML."""

    @pytest.mark.parametrize(
        "name",
        ["billion-laughs.xml", "external-entity.xml", "doctype.xml", "parameter-entity.xml"],
    )
    def test_declarations_are_rejected_before_parsing(self, name: str) -> None:
        with pytest.raises(openscap.XccdfParseError, match="DOCTYPE and ENTITY"):
            parse(name, ADVERSARIAL)

    @pytest.mark.parametrize(
        "name",
        ["billion-laughs.xml", "external-entity.xml", "doctype.xml", "parameter-entity.xml"],
    )
    def test_parser_rejects_declarations_even_if_the_text_check_is_bypassed(
        self, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(openscap, "_scan_for_declarations", skip_declaration_scan)
        with pytest.raises(openscap.XccdfParseError, match="not allowed"):
            parse(name, ADVERSARIAL)

    def test_external_entity_is_never_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = tmp_path / "secret.txt"
        secret.write_text("TOP-SECRET-VALUE", encoding="utf-8")
        document = (
            f'<?xml version="1.0"?>\n<!DOCTYPE b [<!ENTITY xxe SYSTEM "file://{secret}">]>\n'
            f'<Benchmark xmlns="{openscap.XCCDF_NAMESPACE}"><title>&xxe;</title></Benchmark>\n'
        )
        with pytest.raises(openscap.XccdfParseError) as caught:
            openscap.parse_results(document)
        assert "TOP-SECRET-VALUE" not in str(caught.value)
        monkeypatch.setattr(openscap, "_scan_for_declarations", skip_declaration_scan)
        with pytest.raises(openscap.XccdfParseError) as bypassed:
            openscap.parse_results(document)
        assert "TOP-SECRET-VALUE" not in str(bypassed.value)

    def test_deep_nesting_is_rejected(self) -> None:
        with pytest.raises(openscap.XccdfParseError, match="nested deeper than 64"):
            parse("deep-nesting.xml", ADVERSARIAL)

    def test_depth_bound_is_exact(self) -> None:
        document = text("deep-nesting.xml", ADVERSARIAL)
        with pytest.raises(openscap.XccdfParseError, match="exactly one TestResult"):
            openscap.parse_results(document, openscap.XmlLimits(max_depth=201))
        with pytest.raises(openscap.XccdfParseError, match="nested deeper than 200"):
            openscap.parse_results(document, openscap.XmlLimits(max_depth=200))

    def test_element_count_is_bounded(self) -> None:
        with pytest.raises(openscap.XccdfParseError, match="more than 5 elements"):
            parse("all-pass.xml", max_elements=5)
        assert parse("all-pass.xml", max_elements=1000).findings

    def test_wide_documents_are_bounded_too(self) -> None:
        wide = f'<Benchmark xmlns="{openscap.XCCDF_NAMESPACE}">' + "<Group/>" * 50 + "</Benchmark>"
        with pytest.raises(openscap.XccdfParseError, match="more than 10 elements"):
            openscap.parse_results(wide, openscap.XmlLimits(max_elements=10))

    def test_defaults_are_documented_values(self) -> None:
        limits = openscap.XmlLimits()
        assert (limits.max_elements, limits.max_depth) == (2_000_000, 64)
        assert scanner.DEFAULT_MAX_RESULT_BYTES == 128 * 1024 * 1024

    def test_error_messages_are_bounded(self) -> None:
        document = text("all-pass.xml").replace("rule_alpha", "rule_" + "Z" * 500 + " bad", 1)
        with pytest.raises(openscap.XccdfParseError) as caught:
            openscap.parse_results(document)
        assert len(str(caught.value)) < 400


class TestReadResults:
    """Bounded reading of results files."""

    def read(self, path: Path, limit: int = 1_000_000) -> openscap.ParsedResults:
        return openscap.read_results(str(path), limit)

    def test_reads_a_valid_file(self) -> None:
        assert self.read(XCCDF / "all-pass.xml").benchmark_id == BENCHMARK

    def test_accepts_a_byte_order_mark(self, tmp_path: Path) -> None:
        path = tmp_path / "bom.xml"
        path.write_bytes(b"\xef\xbb\xbf" + (XCCDF / "all-pass.xml").read_bytes())
        assert self.read(path).profile_id == PROFILE

    def test_oversized_file_is_rejected_before_reading(self) -> None:
        size = (ADVERSARIAL / "oversized.xml").stat().st_size
        with pytest.raises(openscap.XccdfParseError, match="larger than 1024 bytes"):
            self.read(ADVERSARIAL / "oversized.xml", 1024)
        assert size > 1024

    def test_file_exactly_at_the_limit_is_read(self) -> None:
        size = (XCCDF / "all-pass.xml").stat().st_size
        assert self.read(XCCDF / "all-pass.xml", size).findings
        with pytest.raises(openscap.XccdfParseError, match="larger than"):
            self.read(XCCDF / "all-pass.xml", size - 1)

    def test_size_is_enforced_while_reading_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "grows.xml"
        path.write_bytes(b"<a>" + b"x" * 5000 + b"</a>")
        real = Path.lstat

        def understated(self: Path, **keywords: Any) -> Any:
            info = real(self, **keywords)
            if self != path:
                return info
            return type("Info", (), {"st_mode": info.st_mode, "st_size": 10})()

        monkeypatch.setattr(Path, "lstat", understated)
        with pytest.raises(openscap.XccdfParseError, match="larger than 100 bytes"):
            self.read(path, 100)

    def test_symlinked_results_path_is_rejected(self, tmp_path: Path) -> None:
        link = tmp_path / "link.xml"
        link.symlink_to(XCCDF / "all-pass.xml")
        with pytest.raises(openscap.XccdfParseError, match="not a regular file"):
            self.read(link)

    def test_non_regular_files_are_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(openscap.XccdfParseError, match="not a regular file"):
            self.read(tmp_path)

    def test_missing_file_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(openscap.XccdfParseError, match="cannot be read"):
            self.read(tmp_path / "missing.xml")

    def test_unreadable_file_is_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "locked.xml"
        path.write_text("<a/>", encoding="utf-8")

        def refuse(*_arguments: Any, **_keywords: Any) -> Any:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(Path, "open", refuse)
        with pytest.raises(openscap.XccdfParseError, match="Permission denied"):
            self.read(path)

    def test_empty_file_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.xml"
        path.write_bytes(b"")
        with pytest.raises(openscap.XccdfParseError, match="empty"):
            self.read(path)

    def test_non_utf8_file_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(openscap.XccdfParseError, match="not well-formed"):
            self.read(non_utf8_file(tmp_path))

    def test_utf16_file_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "utf16.xml"
        path.write_bytes((XCCDF / "all-pass.xml").read_text(encoding="utf-8").encode("utf-16"))
        with pytest.raises(openscap.XccdfParseError, match="UTF-16 or UTF-32"):
            self.read(path)

    @pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32"])
    def test_other_encodings_are_never_parsed(self, tmp_path: Path, encoding: str) -> None:
        document = text("all-pass.xml", XCCDF).replace("<status>", "<!DOCTYPE x><status>")
        path = tmp_path / "wide.xml"
        path.write_bytes(document.encode(encoding))
        with pytest.raises(openscap.XccdfParseError):
            self.read(path)

    def test_truncated_file_is_not_a_pass(self) -> None:
        with pytest.raises(openscap.XccdfParseError, match="not well-formed"):
            self.read(ADVERSARIAL / "truncated.xml")

    def test_entity_file_is_rejected(self) -> None:
        with pytest.raises(openscap.XccdfParseError, match="DOCTYPE"):
            self.read(ADVERSARIAL / "billion-laughs.xml")

    def test_limits_are_passed_through(self) -> None:
        with pytest.raises(openscap.XccdfParseError, match="more than 3 elements"):
            openscap.read_results(
                str(XCCDF / "all-pass.xml"), 1_000_000, openscap.XmlLimits(max_elements=3)
            )


class TestCompletedScans:
    """Scans that finish and are normalized."""

    def test_all_pass(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        run = setup.audit()
        assert run.status is model.ScanStatus.COMPLETED
        assert run.error_message is None
        assert [f.outcome for f in run.findings] == [model.Outcome.PASS, model.Outcome.PASS]
        assert run.started_at == "2026-10-25T10:00:00Z"
        assert run.finished_at == "2026-10-25T10:00:09Z"
        assert run.benchmark_id == BENCHMARK
        assert run.profile_id == PROFILE
        assert run.scanner == model.ScannerInfo("openscap", "1.3.10")
        assert run.content == model.Provenance(
            "ds.xml", "1.0", hashlib.sha256(DATASTREAM).hexdigest()
        )
        assert run.host == HOST
        assert run.run_id == "run-1"

    def test_rules_failed_is_a_normal_result(self, tmp_path: Path) -> None:
        setup = harness(tmp_path, text("one-fail.xml"))
        setup.runner.evaluation = command_result(2)
        run = setup.audit()
        assert run.status is model.ScanStatus.COMPLETED
        assert {f.rule_id: f.outcome for f in run.findings} == {
            RULE_ALPHA: model.Outcome.PASS,
            RULE_BETA: model.Outcome.FAIL,
        }

    def test_unknown_result_values_become_error_findings(self, tmp_path: Path) -> None:
        setup = harness(tmp_path, text("unknown-result-value.xml", ADVERSARIAL))
        setup.runner.evaluation = command_result(2)
        run = setup.audit(
            expected_rule_ids=(
                "xccdf_org.example.synthetic_rule_alpha",
                "xccdf_org.example.synthetic_rule_beta",
                "xccdf_org.example.synthetic_rule_gamma",
                "xccdf_org.example.synthetic_rule_delta",
            )
        )
        assert run.status is model.ScanStatus.COMPLETED
        assert [f.outcome for f in run.findings].count(model.Outcome.ERROR) == 3

    def test_command_line_goes_through_the_process_policy(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.audit()
        version, evaluation = setup.runner.specs
        assert version.args == ("--version",)
        out = setup.output_root / "scan-1"
        assert evaluation.executable == "oscap"
        assert evaluation.args == (
            "xccdf",
            "eval",
            "--profile",
            PROFILE,
            "--results-arf",
            str(out / "results-arf.xml"),
            "--results",
            str(out / "results.xml"),
            str(setup.datastream),
        )
        assert evaluation.timeout_seconds == 60.0
        for spec in setup.runner.specs:
            process.check_policy(spec, process.ALLOWED_EXECUTABLES)
        joined = " ".join(evaluation.args)
        assert "remediate" not in joined
        assert "--fetch-remote-resources" not in joined

    def test_tailoring_file_is_passed(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        tailoring = setup.content_root / "tailoring.xml"
        tailoring.write_text("<tailoring/>", encoding="utf-8")
        setup.audit(tailoring_path="tailoring.xml")
        arguments = setup.runner.specs[1].args
        position = arguments.index("--tailoring-file")
        assert arguments[position + 1] == str(tailoring)
        assert position == arguments.index(PROFILE) + 1
        process.check_policy(setup.runner.specs[1], process.ALLOWED_EXECUTABLES)

    def test_output_directory_is_created_private_and_fresh(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.audit()
        out = setup.output_root / "scan-1"
        assert stat.S_IMODE(out.stat().st_mode) == 0o700
        assert sorted(item.name for item in out.iterdir()) == ["results.xml"]

    def test_private_mode_survives_a_permissive_umask(self, tmp_path: Path) -> None:
        previous = os.umask(0)
        try:
            harness(tmp_path).audit()
        finally:
            os.umask(previous)
        assert stat.S_IMODE((tmp_path / "output" / "scan-1").stat().st_mode) == 0o700

    def test_absolute_paths_inside_the_roots_are_accepted(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        run = setup.audit(
            content_path=str(setup.datastream), output_dir=str(setup.output_root / "abs")
        )
        assert run.status is model.ScanStatus.COMPLETED

    def test_content_provenance_is_the_digest_of_the_datastream(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.datastream.write_bytes(b"other bytes")
        assert setup.audit().content.content_sha256 == hashlib.sha256(b"other bytes").hexdigest()

    def test_unparseable_version_output_is_unknown(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.version = command_result(0, b"something else entirely\n")
        run = setup.audit()
        assert run.status is model.ScanStatus.COMPLETED
        assert run.scanner.version == "unknown"

    def test_clock_that_goes_backwards_does_not_break_the_run(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.evaluation = command_result(1)
        moments = iter(
            [
                datetime.fromisoformat("2026-01-01T00:00:05+00:00"),
                datetime.fromisoformat("2026-01-01T00:00:00+00:00"),
            ]
        )
        backend = openscap.OpenScapBackend(
            setup.settings, runner=setup.runner, clock=lambda: next(moments)
        )
        run = backend.audit(setup.request())
        assert run.started_at == run.finished_at == "2026-01-01T00:00:05Z"

    def test_reversed_result_times_are_a_failure(self, tmp_path: Path) -> None:
        setup = harness(tmp_path, text("end-before-start.xml", ADVERSARIAL))
        run = setup.audit(expected_rule_ids=(RULE_ALPHA,))
        assert run.status is model.ScanStatus.FAILED
        assert run.error_message is not None
        assert "precedes" in run.error_message

    def test_model_rejection_of_the_results_is_a_failure(self, tmp_path: Path) -> None:
        long_version = text("all-pass.xml").replace(
            "<version>1.0</version>", "<version>" + "9" * 70 + "</version>"
        )
        run = harness(tmp_path, long_version).audit()
        assert run.status is model.ScanStatus.FAILED
        assert run.error_message is not None
        assert "rejected by the model" in run.error_message
        assert {f.outcome for f in run.findings} == {model.Outcome.ERROR}


class TestExecutionFailures:
    """Scanner execution failures never become pass or fail."""

    @pytest.mark.parametrize("code", [1, 3, 255, -9, -11])
    def test_unexpected_exit_status_is_an_execution_error(self, tmp_path: Path, code: int) -> None:
        setup = harness(tmp_path)
        setup.runner.evaluation = command_result(code, stderr=b"E: boom\nsecond line\x00\xff")
        run = setup.audit()
        assert_failure(run, model.ScanStatus.FAILED, f"oscap exited with status {code}")
        assert run.error_message is not None
        assert "E: boom?second line??" in run.error_message
        assert "\x00" not in run.error_message
        assert run.scanner.version == "1.3.10"

    def test_exit_status_without_stderr(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.evaluation = command_result(1)
        run = setup.audit()
        assert run.error_message == "oscap exited with status 1"

    def test_a_failed_exit_status_ignores_results_that_look_like_a_pass(
        self, tmp_path: Path
    ) -> None:
        setup = harness(tmp_path)
        setup.runner.evaluation = command_result(1)
        run = setup.audit()
        assert_failure(run, model.ScanStatus.FAILED, "status 1")

    def test_timeout_is_recorded_as_timed_out(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.evaluation = command_result(-9, timed_out=True)
        run = setup.audit()
        assert_failure(run, model.ScanStatus.TIMED_OUT, "exceeded the timeout of 60.0")

    def test_missing_binary_is_a_scanner_failure(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.version_error = process.ProcessExecutionError(
            "executable not found in the trusted directories: 'oscap'"
        )
        run = setup.audit()
        assert_failure(run, model.ScanStatus.FAILED, "oscap is not available")
        assert run.scanner.version == "unknown"
        assert len(setup.runner.specs) == 1

    def test_binary_that_cannot_be_started_for_the_scan(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.evaluation_error = process.ProcessExecutionError("cannot start 'oscap'")
        run = setup.audit()
        assert_failure(run, model.ScanStatus.FAILED, "oscap could not run")

    def test_version_probe_timeout(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.version = command_result(-9, timed_out=True)
        assert_failure(setup.audit(), model.ScanStatus.TIMED_OUT, "oscap --version timed out")
        assert len(setup.runner.specs) == 1

    def test_version_probe_failure(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.version = command_result(127)
        assert_failure(setup.audit(), model.ScanStatus.FAILED, "--version exited with status 127")

    def test_policy_violations_propagate_and_are_never_swallowed(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.evaluation_error = process.ProcessPolicyError("option is forbidden")
        with pytest.raises(process.ProcessPolicyError):
            setup.audit()


class TestResultFailures:
    """Results that cannot be trusted are scanner failures."""

    def test_missing_results_file_is_a_failure(self, tmp_path: Path) -> None:
        setup = Harness(tmp_path, FakeRunner(None))
        run = setup.audit()
        assert_failure(run, model.ScanStatus.FAILED, "results rejected")

    @pytest.mark.parametrize(
        "name",
        [
            "truncated.xml",
            "billion-laughs.xml",
            "external-entity.xml",
            "doctype.xml",
            "missing-namespace.xml",
            "deep-nesting.xml",
            "bad-timestamp.xml",
        ],
    )
    def test_hostile_results_are_failures_not_passes(self, tmp_path: Path, name: str) -> None:
        run = Harness(tmp_path, FakeRunner(text(name, ADVERSARIAL))).audit()
        assert_failure(run, model.ScanStatus.FAILED, "results rejected")

    def test_empty_results_are_a_failure(self, tmp_path: Path) -> None:
        setup = Harness(tmp_path, FakeRunner(""))
        assert_failure(setup.audit(), model.ScanStatus.FAILED, "empty")

    def test_non_utf8_results_are_a_failure(self, tmp_path: Path) -> None:
        setup = Harness(tmp_path, FakeRunner(None))

        def write(path: Path) -> None:
            path.write_bytes(NON_UTF8)

        setup.runner.on_evaluate = write
        assert_failure(setup.audit(), model.ScanStatus.FAILED, "not well-formed")

    def test_symlinked_results_path_is_a_failure(self, tmp_path: Path) -> None:
        setup = Harness(tmp_path, FakeRunner(None))
        target = tmp_path / "elsewhere.xml"
        target.write_text(text("all-pass.xml"), encoding="utf-8")
        setup.runner.on_evaluate = lambda path: path.symlink_to(target)
        assert_failure(setup.audit(), model.ScanStatus.FAILED, "not a regular file")

    def test_oversized_results_are_a_failure(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.settings = scanner.ScanSettings(
            str(setup.content_root), str(setup.output_root), 60.0, 100
        )
        assert_failure(setup.audit(), model.ScanStatus.FAILED, "larger than 100 bytes")

    def test_limits_apply_to_the_backend(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        run = setup.backend(limits=openscap.XmlLimits(max_elements=4)).audit(setup.request())
        assert_failure(run, model.ScanStatus.FAILED, "more than 4 elements")

    def test_exit_zero_with_a_failed_rule_is_inconsistent(self, tmp_path: Path) -> None:
        setup = harness(tmp_path, text("one-fail.xml"))
        assert_failure(
            setup.audit(),
            model.ScanStatus.FAILED,
            "reported success but the results contain failed",
        )

    def test_exit_zero_with_an_errored_rule_is_inconsistent(self, tmp_path: Path) -> None:
        setup = harness(tmp_path, text("unknown-result-value.xml", ADVERSARIAL))
        run = setup.audit(
            expected_rule_ids=(
                "xccdf_org.example.synthetic_rule_alpha",
                "xccdf_org.example.synthetic_rule_beta",
                "xccdf_org.example.synthetic_rule_gamma",
                "xccdf_org.example.synthetic_rule_delta",
            )
        )
        assert run.status is model.ScanStatus.FAILED
        assert run.error_message is not None
        assert "reported success" in run.error_message

    def test_exit_two_without_a_failed_rule_is_inconsistent(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.evaluation = command_result(2)
        assert_failure(
            setup.audit(),
            model.ScanStatus.FAILED,
            "reported failed rules but the results contain none",
        )

    def test_results_for_another_profile_are_rejected(self, tmp_path: Path) -> None:
        other = "xccdf_org.example.synthetic_profile_other"
        setup = harness(tmp_path)
        run = setup.audit(profile_id=other)
        assert_failure(run, model.ScanStatus.FAILED, "different profile")

    def test_results_for_another_benchmark_are_rejected(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        run = setup.audit(benchmark_id="xccdf_org.example.synthetic_benchmark_other")
        assert_failure(run, model.ScanStatus.FAILED, "different benchmark")

    def test_content_that_changes_during_the_scan_is_rejected(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)

        def tamper(_path: Path) -> None:
            setup.datastream.write_bytes(b"tampered")

        setup.runner.on_evaluate = tamper
        run = setup.audit()
        assert_failure(
            run, model.ScanStatus.FAILED, "content or tailoring file changed during the scan"
        )
        assert run.content.content_sha256 == hashlib.sha256(DATASTREAM).hexdigest()


class TestRequestSafety:
    """Unsafe requests are refused before anything runs."""

    def test_content_outside_the_root_is_rejected(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        for path in ("../output/x", "/etc/passwd", "sub/../../ds.xml"):
            with pytest.raises(scanner.ScanRequestError, match="escapes"):
                setup.audit(content_path=path)
        assert setup.runner.specs == []
        assert list(setup.output_root.iterdir()) == []

    def test_symlinked_content_is_rejected(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        (setup.content_root / "link.xml").symlink_to(setup.datastream)
        with pytest.raises(scanner.ScanRequestError, match="symlink"):
            setup.audit(content_path="link.xml")

    def test_content_below_a_symlinked_directory_is_rejected(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        (setup.content_root / "dir").symlink_to(tmp_path)
        with pytest.raises(scanner.ScanRequestError, match="symlink"):
            setup.audit(content_path="dir/ds.xml")

    @pytest.mark.parametrize("path", ["missing.xml", "."])
    def test_content_must_be_an_existing_regular_file(self, tmp_path: Path, path: str) -> None:
        with pytest.raises(scanner.ScanRequestError, match="existing regular file"):
            harness(tmp_path).audit(content_path=path)

    def test_missing_tailoring_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(scanner.ScanRequestError, match="tailoring"):
            harness(tmp_path).audit(tailoring_path="missing.xml")

    def test_tailoring_outside_the_root_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(scanner.ScanRequestError, match="escapes"):
            harness(tmp_path).audit(tailoring_path="../../etc/passwd")

    def test_existing_output_directory_is_never_reused(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        existing = setup.output_root / "scan-1"
        existing.mkdir()
        keep = existing / "results.xml"
        keep.write_text("precious", encoding="utf-8")
        with pytest.raises(scanner.ScanRequestError, match="already exists"):
            setup.audit()
        assert keep.read_text(encoding="utf-8") == "precious"
        assert setup.runner.specs == []

    def test_existing_output_file_is_never_overwritten(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        (setup.output_root / "scan-1").write_text("a file", encoding="utf-8")
        with pytest.raises(scanner.ScanRequestError, match="already exists"):
            setup.audit()
        assert (setup.output_root / "scan-1").read_text(encoding="utf-8") == "a file"

    def test_output_directory_cannot_be_a_symlink(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        (setup.output_root / "scan-1").symlink_to(tmp_path)
        with pytest.raises(scanner.ScanRequestError, match="symlink"):
            setup.audit()

    def test_output_directory_cannot_be_the_root(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        with pytest.raises(scanner.ScanRequestError, match="already exists"):
            setup.audit(output_dir=".")

    def test_output_outside_the_root_is_rejected(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        with pytest.raises(scanner.ScanRequestError, match="escapes"):
            setup.audit(output_dir="../escaped")
        assert not (tmp_path / "escaped").exists()

    def test_missing_parent_directory_is_rejected(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        with pytest.raises(scanner.ScanRequestError, match="cannot be created"):
            setup.audit(output_dir="no/such/parent")

    def test_missing_roots_are_rejected(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.settings = scanner.ScanSettings(str(tmp_path / "nowhere"), str(setup.output_root))
        with pytest.raises(scanner.ScanRequestError, match="existing directory"):
            setup.audit()

    def test_unreadable_content_is_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        setup = harness(tmp_path)
        real: Any = Path.open

        def refuse(self: Path, *arguments: Any, **keywords: Any) -> Any:
            if self == setup.datastream:
                raise PermissionError(13, "Permission denied")
            return real(self, *arguments, **keywords)

        monkeypatch.setattr(Path, "open", refuse)
        with pytest.raises(scanner.ScanRequestError, match="content cannot be read"):
            setup.audit()
        assert list(setup.output_root.iterdir()) == []

    def test_unreadable_content_without_a_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        setup = harness(tmp_path)

        def refuse(*_arguments: Any, **_keywords: Any) -> Any:
            raise OSError

        monkeypatch.setattr(Path, "open", refuse)
        with pytest.raises(scanner.ScanRequestError, match="OSError"):
            setup.audit()

    def test_failed_directory_creation_without_a_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        setup = harness(tmp_path)

        def refuse(*_arguments: Any, **_keywords: Any) -> Any:
            raise OSError

        monkeypatch.setattr(Path, "mkdir", refuse)
        with pytest.raises(scanner.ScanRequestError, match="cannot be created: error"):
            setup.audit()


class TestSeams:
    """Test seams stay out of production paths."""

    def test_production_defaults_use_the_real_process_layer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        setup = harness(tmp_path)
        monkeypatch.setattr(process, "run", setup.runner)
        backend = openscap.create_backend(setup.settings)
        run = backend.audit(setup.request())
        assert run.status is model.ScanStatus.COMPLETED
        assert len(setup.runner.specs) == 2

    def test_default_clock_times_a_failed_run_in_utc(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        setup.runner.evaluation = command_result(1)
        backend = openscap.OpenScapBackend(setup.settings, runner=setup.runner)
        before = time.time()
        run = backend.audit(setup.request())
        after = time.time()
        started = calendar.timegm(time.strptime(run.started_at, model.TIMESTAMP_FORMAT))
        assert before - 1 <= started <= after + 1

    def test_registration(self) -> None:
        registry = scanner.BackendRegistry()
        openscap.register(registry)
        assert registry.names() == (openscap.BACKEND_NAME,)
        created = openscap.create_backend(scanner.ScanSettings("/a", "/b"))
        assert isinstance(created, openscap.OpenScapBackend)

    def test_the_real_process_layer_reports_a_missing_binary_as_a_failure(
        self, tmp_path: Path
    ) -> None:
        setup = harness(tmp_path)
        backend = openscap.OpenScapBackend(
            setup.settings,
            runner=lambda spec: process.run(
                spec, trusted_dirs=[str(tmp_path)], owner_uid=os.getuid()
            ),
        )
        run = backend.audit(setup.request())
        assert run.status is model.ScanStatus.FAILED
        assert {f.outcome for f in run.findings} == {model.Outcome.ERROR}


def strip_rule(document: str, name: str) -> str:
    start = document.index(f'    <rule-result idref="xccdf_org.example.synthetic_rule_{name}"')
    end = document.index("    </rule-result>\n", start) + len("    </rule-result>\n")
    return document[:start] + document[end:]


class TestResultIntegrity:
    """Results are reconciled with the rules that the profile selects."""

    def test_zero_results_report_every_rule_as_error(self, tmp_path: Path) -> None:
        document = strip_rule(strip_rule(text("all-pass.xml"), "alpha"), "beta")
        setup = harness(tmp_path, document)
        setup.runner.evaluation = command_result(2)
        run = setup.audit()
        assert run.status is model.ScanStatus.COMPLETED
        assert [(f.rule_id, f.outcome) for f in run.findings] == [
            (RULE_ALPHA, model.Outcome.ERROR),
            (RULE_BETA, model.Outcome.ERROR),
        ]
        assert all(f.message and "no rule-result" in f.message for f in run.findings)

    def test_zero_results_with_exit_zero_fail_the_run(self, tmp_path: Path) -> None:
        document = strip_rule(strip_rule(text("all-pass.xml"), "alpha"), "beta")
        run = harness(tmp_path, document).audit()
        assert_failure(run, model.ScanStatus.FAILED, "failed, errored or missing")

    def test_partial_results_report_the_missing_rule_as_error(self, tmp_path: Path) -> None:
        setup = harness(tmp_path, strip_rule(text("all-pass.xml"), "beta"))
        setup.runner.evaluation = command_result(2)
        run = setup.audit()
        assert run.status is model.ScanStatus.COMPLETED
        assert {f.rule_id: f.outcome for f in run.findings} == {
            RULE_ALPHA: model.Outcome.PASS,
            RULE_BETA: model.Outcome.ERROR,
        }

    def test_partial_results_with_exit_zero_fail_the_run(self, tmp_path: Path) -> None:
        run = harness(tmp_path, strip_rule(text("all-pass.xml"), "beta")).audit()
        assert_failure(run, model.ScanStatus.FAILED, "failed, errored or missing")

    def test_unexpected_rule_fails_the_run(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        run = setup.audit(expected_rule_ids=(RULE_ALPHA,))
        assert run.status is model.ScanStatus.FAILED
        assert run.error_message == "the results contain 1 rule(s) that the profile does not select"
        assert [f.rule_id for f in run.findings] == [RULE_ALPHA]
        assert run.findings[0].outcome is model.Outcome.ERROR

    def test_duplicate_rule_results_fail_the_run(self, tmp_path: Path) -> None:
        setup = harness(tmp_path, text("duplicate-rule.xml", ADVERSARIAL))
        setup.runner.evaluation = command_result(2)
        assert_failure(setup.audit(), model.ScanStatus.FAILED, "more than once")

    @pytest.mark.parametrize(
        "name",
        [
            "foreign-namespace-rule-result.xml",
            "no-namespace-rule-result.xml",
            "foreign-namespace-result.xml",
        ],
    )
    def test_foreign_namespace_results_fail_the_run(self, tmp_path: Path, name: str) -> None:
        setup = harness(tmp_path, text(name, ADVERSARIAL))
        setup.runner.evaluation = command_result(2)
        assert_failure(setup.audit(), model.ScanStatus.FAILED, "outside the XCCDF 1.2 namespace")

    @pytest.mark.parametrize(
        ("name", "message"),
        [
            ("foreign-namespace-rule-result.xml", "rule-result element outside"),
            ("no-namespace-rule-result.xml", "rule-result element outside"),
            ("foreign-namespace-result.xml", "result element outside"),
        ],
    )
    def test_parser_rejects_foreign_namespace_results(self, name: str, message: str) -> None:
        with pytest.raises(openscap.XccdfParseError, match=message):
            parse(name, ADVERSARIAL)

    def test_foreign_elements_with_other_names_are_ignored(self) -> None:
        document = text("all-pass.xml").replace(
            "<title>Synthetic scan</title>", '<note xmlns="urn:example:other">x</note>'
        )
        assert len(openscap.parse_results(document).findings) == 2

    def test_a_repeated_benchmark_or_profile_reference_keeps_the_first(self) -> None:
        document = text("all-pass.xml").replace(
            "<title>Synthetic scan</title>",
            '<benchmark id="xccdf_org.example.synthetic_benchmark_other"/>'
            '<profile idref="xccdf_org.example.synthetic_profile_other"/>',
        )
        parsed = openscap.parse_results(document)
        assert (parsed.benchmark_id, parsed.profile_id) == (BENCHMARK, PROFILE)


class TestMixedContent:
    """Text and elements are never merged."""

    @pytest.mark.parametrize("name", ["mixed-content-result.xml", "mixed-content-ident.xml"])
    def test_leaf_elements_with_children_are_malformed(self, name: str) -> None:
        with pytest.raises(openscap.XccdfParseError, match="may not contain child elements"):
            parse(name, ADVERSARIAL)

    def test_a_mixed_content_result_fails_the_run(self, tmp_path: Path) -> None:
        setup = harness(tmp_path, text("mixed-content-result.xml", ADVERSARIAL))
        assert_failure(setup.audit(), model.ScanStatus.FAILED, "child elements")

    def test_text_after_a_child_is_not_merged_into_the_parent(self) -> None:
        document = text("all-pass.xml").replace(
            "<version>1.0</version>", "<version>1.0<x/>9.9</version>"
        )
        assert openscap.parse_results(document).benchmark_version == "1.0"

    def test_text_before_a_child_is_not_lost(self) -> None:
        document = text("all-pass.xml").replace(
            "<version>1.0</version>", "<version>1.0<x>fail</x></version>"
        )
        assert openscap.parse_results(document).benchmark_version == "1.0"


class TestStreaming:
    """The file is parsed in chunks and memory does not follow its size."""

    def test_small_chunks_give_the_same_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        expected = openscap.read_results(str(XCCDF / "all-pass.xml"), 10**6)
        monkeypatch.setattr(openscap, "READ_CHUNK_BYTES", 7)
        assert openscap.read_results(str(XCCDF / "all-pass.xml"), 10**6) == expected

    @pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 9, 13])
    @pytest.mark.parametrize("name", ["doctype.xml", "billion-laughs.xml", "external-entity.xml"])
    def test_declarations_split_across_chunks_are_rejected_by_the_scan(
        self, monkeypatch: pytest.MonkeyPatch, name: str, size: int
    ) -> None:
        monkeypatch.setattr(openscap, "READ_CHUNK_BYTES", size)
        with pytest.raises(openscap.XccdfParseError, match="DOCTYPE and ENTITY"):
            openscap.read_results(str(ADVERSARIAL / name), 10**6)

    def test_size_is_enforced_across_chunks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(openscap, "READ_CHUNK_BYTES", 16)
        path = str(XCCDF / "all-pass.xml")
        size = (XCCDF / "all-pass.xml").stat().st_size
        assert openscap.read_results(path, size)
        with pytest.raises(openscap.XccdfParseError, match="larger than"):
            openscap.read_results(path, size - 1)

    def test_elements_are_not_retained(self, tmp_path: Path) -> None:
        rule = (
            '<rule-result idref="xccdf_org.example.synthetic_rule_r{n}" severity="low">'
            "<result>pass</result><message severity='info'>" + "x" * 4000 + "</message>"
            "</rule-result>\n"
        )
        head = text("all-pass.xml").split("    <rule-result")[0]
        body = "".join(rule.format(n=n) for n in range(3000))
        path = tmp_path / "big.xml"
        path.write_text(head + body + "  </TestResult>\n</Benchmark>\n", encoding="utf-8")
        tracemalloc.start()
        parsed = openscap.read_results(str(path), 10**8)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert len(parsed.findings) == 3000
        assert peak < path.stat().st_size // 2


class TestTailoringProvenance:
    """The tailoring file is hashed next to the datastream."""

    def tailoring(self, setup: Harness) -> Path:
        path = setup.content_root / "tailoring.xml"
        path.write_text("<tailoring/>", encoding="utf-8")
        return path

    def test_digest_is_recorded_in_the_provenance(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        self.tailoring(setup)
        run = setup.audit(tailoring_path="tailoring.xml")
        digest = hashlib.sha256(b"<tailoring/>").hexdigest()
        assert run.content.source == f"ds.xml tailoring=tailoring.xml tailoring_sha256={digest}"
        assert run.content.content_sha256 == hashlib.sha256(DATASTREAM).hexdigest()

    def test_failed_runs_record_it_too(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        self.tailoring(setup)
        setup.runner.evaluation = command_result(1)
        run = setup.audit(tailoring_path="tailoring.xml")
        assert "tailoring_sha256=" in run.content.source

    def test_without_tailoring_the_source_is_the_file_name(self, tmp_path: Path) -> None:
        assert harness(tmp_path).audit().content.source == "ds.xml"

    def test_tailoring_that_changes_during_the_scan_is_rejected(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        path = self.tailoring(setup)

        def tamper(_path: Path) -> None:
            path.write_text("<other/>", encoding="utf-8")

        setup.runner.on_evaluate = tamper
        run = setup.audit(tailoring_path="tailoring.xml")
        assert_failure(run, model.ScanStatus.FAILED, "changed during the scan")

    def test_unreadable_tailoring_is_a_request_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        setup = harness(tmp_path)
        path = self.tailoring(setup)
        real: Any = Path.open

        def refuse(self: Path, *arguments: Any, **keywords: Any) -> Any:
            if self == path:
                raise PermissionError(13, "Permission denied")
            return real(self, *arguments, **keywords)

        monkeypatch.setattr(Path, "open", refuse)
        with pytest.raises(scanner.ScanRequestError, match="cannot be read"):
            setup.audit(tailoring_path="tailoring.xml")

    def test_awkward_file_names_are_cleaned_and_bounded(self, tmp_path: Path) -> None:
        setup = harness(tmp_path)
        long_name = "t" * 200 + ".xml"
        (setup.content_root / long_name).write_text("<tailoring/>", encoding="utf-8")
        run = setup.audit(tailoring_path=long_name)
        assert f"tailoring={'t' * 64} " in run.content.source
        assert len(run.content.source) <= 256
        odd = setup.content_root / "caf\u00e9.xml"
        odd.write_bytes(DATASTREAM)
        other = setup.audit(content_path=odd.name, output_dir="odd")
        assert other.content.source == "caf?.xml"
