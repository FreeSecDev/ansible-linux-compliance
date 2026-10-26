"""Unit tests of the SCC backend with synthetic installations and outputs (FREES-145).

Real SCC output is never committed (ADR 0019, decision 4). These tests build a
fake installation (``install_root``), a fake runner that writes the files SCC
writes, in the observed shape, and synthetic XCCDF results.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    openscap,
    process,
    scanner,
    scc,
    xmlsafe,
)

BENCHMARK = "xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG"
PROFILE = "xccdf_mil.disa.stig_profile_MAC-1_Classified"
RULE = "xccdf_mil.disa.stig_rule_SV-27064{}r1_rule"
RULES = tuple(RULE.format(index) for index in range(6))
STREAM_NAME = "U_CAN_Ubuntu_24-04_STIG_SCAP_1-4_Benchmark-signed.xml"
STREAM = b"<synthetic stream/>\n"
EXECUTABLE = b"#!/bin/sh\n"
HOST = model.HostIdentity("target.example", "ubuntu", "24.04", "x86_64", None)
NOW = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)
SESSION = "2026-10-26_120001"
LOG_NAME = "TARGET_SCC-5.15_2026-10-26_120001_Debug_Log_001.txt"
XCCDF_NAME = "TARGET_SCC-5.15_2026-10-26_120001_XCCDF-Results_CAN_Ubuntu_24-04_STIG-001.005.007.xml"
ARF_NAME = "TARGET_SCC-5.15_2026-10-26_120001_ARF_CAN_Ubuntu_24-04_STIG-001.005.007.xml"
NS = "http://checklists.nist.gov/xccdf/1.2"
CHECKSUM = "a" * 64
RECORD = f"""
    <content>
      <stream>scap_mil.disa.stig_datastream_U_CAN_Ubuntu_24-04</stream>
      <family>Linux</family>
      <benchmarkID>CAN_Ubuntu_24-04_STIG</benchmarkID>
      <scapVersion>1.4</scapVersion>
      <filepath>Resources/Content/SCAP12_Content/{STREAM_NAME}</filepath>
      <selectedProfile>xccdf_mil.disa.stig_profile_MAC-3_Public</selectedProfile>
      <profiles><profile>no_profile_selected</profile></profiles>
      <checksumSCAP12>{CHECKSUM}</checksumSCAP12>
      <version>001.005.007</version>
      <xccdf>scap_mil.disa.stig_comp_U_CAN_Ubuntu_24-04-xccdf.xml</xccdf>
      <oval_components>
        <oval version="5.11">scap_mil.disa.stig_comp_U_CAN_Ubuntu_24-04-oval.xml</oval>
      </oval_components>
      <enabled>1</enabled>
    </content>"""
OTHER_RECORD = RECORD.replace(STREAM_NAME, "U_Other_STIG.xml").replace(
    "24-04</stream>", "x</stream>"
)
OPTIONS = f"""<?xml version="1.0" encoding="UTF-8"?>
<options>
  <downloadExternalFiles>1</downloadExternalFiles>
  <contents>{OTHER_RECORD}{RECORD}
  </contents>
</options>
"""
OUTCOMES = ("pass", "fail", "notapplicable", "notchecked", "unknown")
OVAL_LINE = '<oval version="5.11">scap_mil.disa.stig_comp_U_CAN_Ubuntu_24-04-oval.xml</oval>\n'


def log_line(package: str, message: str, level: str = "DEBUG") -> str:
    return f"12:00:01\t {level:>6}\t{package:>32}\t {1:4d}\t{message}"


def confirmation(options: str, **overrides: str) -> str:
    values = dict.fromkeys(scc.CONFIRMED_ZERO, "0")
    values["selectedConfigProfile"] = ""
    values.update(overrides)
    lines = [
        "SCC - 5.15 on host TARGET running Debian Variant Unknown (x86_64)",
        "",
        log_line(
            "SCC_Config", f"SCC_Config::_setOptionFileName line: 730 --- options file = {options}"
        ),
        log_line("Utilities", f"checking to see if a config profile is enabled {options}"),
        log_line("Utilities", "selectedConfigProfile: "),
        log_line("SCC_Config", f"Loading options from: {options}", "SCREEN"),
        log_line("Output", "     Using configuration profile: default", "SCREEN"),
        log_line("SoftwareExpiration", "Software expires in 30 days."),
        log_line("Output", f"*  Contents of {options}:"),
        log_line("Output", "*        <sccConfigProfile>default</sccConfigProfile>"),
    ]
    for name, value in values.items():
        element = f"<{name}/>" if value == "" else f"<{name}>{value}</{name}>"
        lines.append(log_line("Output", f"*        {element}"))
    return "\n".join(lines) + "\n"


def results_document(
    *,
    outcomes: tuple[str, ...] = OUTCOMES,
    profile: str = PROFILE,
    benchmark: str = BENCHMARK,
    start: str = "2026-10-26T12:00:05",
    end: str = "2026-10-26T12:00:30",
) -> str:
    rules = "".join(
        f'<cdf:rule-result idref="{RULES[index]}" severity="medium" version="UBTU-24-{index}">'
        f"<cdf:result>{outcome}</cdf:result></cdf:rule-result>"
        for index, outcome in enumerate(outcomes)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<!-- SessionID:x -->\n'
        f'<cdf:Benchmark xmlns:cdf="{NS}" id="{benchmark}"><cdf:version>001.005.007</cdf:version>'
        f'<cdf:TestResult start-time="{start}" end-time="{end}" version="001.005.007">'
        f'<cdf:benchmark href="#x" id="{benchmark}"/><cdf:profile idref="{profile}"/>'
        f"{rules}</cdf:TestResult></cdf:Benchmark>\n"
    )


@dataclass
class FakeScc:
    """Runner that answers like ``cscc`` and writes what it writes."""

    log: str | None = None
    results: str | None = None
    version: bytes = b"scc version: 5.15 date: 2026-08-27 build: 8478-21156\n"
    version_status: int = 0
    version_timeout: bool = False
    version_error: process.ProcessError | None = None
    scan_status: int = 0
    scan_timeout: bool = False
    scan_error: process.ProcessError | None = None
    sessions: tuple[str, ...] = (SESSION,)
    logs: tuple[str, ...] = (LOG_NAME,)
    xccdf: tuple[str, ...] = (XCCDF_NAME,)
    arf: tuple[str, ...] = (ARF_NAME,)
    during: Any = None
    calls: list[tuple[str, ...]] = field(default_factory=list[tuple[str, ...]])

    def __call__(self, spec: process.CommandSpec) -> process.CommandResult:
        self.calls.append(spec.args)
        if spec.args == ("--version",):
            if self.version_error is not None:
                raise self.version_error
            return result(self.version, self.version_status, timed_out=self.version_timeout)
        if self.scan_error is not None:
            raise self.scan_error
        options, user = spec.args[1], Path(spec.args[3])
        self.write(user, options)
        if self.during is not None:
            self.during()
        return result(b"", self.scan_status, timed_out=self.scan_timeout)

    def write(self, user: Path, options: str) -> None:
        logs = user / "ApplicationLogs"
        logs.mkdir()
        for name in self.logs:
            (logs / name).write_text(
                confirmation(options) if self.log is None else self.log, encoding="utf-8"
            )
        sessions = user / "Sessions"
        sessions.mkdir()
        (sessions / "scanSessions.db").write_bytes(b"")
        for session in self.sessions:
            xml = sessions / session / "Results" / "SCAP" / "XML"
            xml.mkdir(parents=True)
            for name in self.xccdf:
                document = results_document() if self.results is None else self.results
                (xml / name).write_text(document, encoding="utf-8")
            for name in self.arf:
                (xml / name).write_text("<arf/>", encoding="utf-8")


def result(stdout: bytes, status: int, *, timed_out: bool = False) -> process.CommandResult:
    return process.CommandResult(
        argv=("/opt/scc/cscc",),
        returncode=status,
        stdout=stdout,
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.1,
        timed_out=timed_out,
    )


@dataclass
class Setup:
    """A fake SCC installation and the paths of one scan."""

    root: Path
    content: Path
    output: Path
    install: Path
    installed: Path

    def backend(self, runner: FakeScc, clock: Any = None) -> scc.SccBackend:
        settings = scanner.ScanSettings(str(self.content), str(self.output), 60.0)
        return scc.SccBackend(
            settings, runner=runner, clock=clock or (lambda: NOW), install_root=str(self.install)
        )

    def request(self, **fields: Any) -> scanner.ScanRequest:
        values: dict[str, Any] = {
            "run_id": "run-1",
            "host": HOST,
            "benchmark_id": BENCHMARK,
            "profile_id": PROFILE,
            "content_path": STREAM_NAME,
            "output_dir": "scan",
            "expected_rule_ids": RULES[:5],
        }
        values.update(fields)
        return scanner.ScanRequest(**values)

    def audit(self, runner: FakeScc | None = None, **fields: Any) -> model.ScanRun:
        return self.backend(runner or FakeScc()).audit(self.request(**fields))


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Setup:
    root = tmp_path / "root"
    content = root / "run"
    install = root / "opt-scc"
    stream_directory = install / "Resources" / "Content" / "SCAP12_Content"
    for directory in (content, stream_directory):
        directory.mkdir(parents=True)
    (content / STREAM_NAME).write_bytes(STREAM)
    (stream_directory / STREAM_NAME).write_bytes(STREAM)
    (install / "options.xml").write_text(OPTIONS, encoding="utf-8")
    (install / "cscc").write_bytes(EXECUTABLE)
    for path in (root, content, install, install / "Resources", install / "Resources" / "Content"):
        path.chmod(0o755)
    stream_directory.chmod(0o755)
    digest = hashlib.sha256(EXECUTABLE).hexdigest()
    release = scc.Release("5.15", digest, date(2099, 1, 1))
    monkeypatch.setattr(scc, "SUPPORTED_RELEASES", {digest: release})
    return Setup(root, content, content, install, stream_directory / STREAM_NAME)


def outcomes(run: model.ScanRun) -> dict[str, str]:
    return {finding.rule_id: finding.outcome.value for finding in run.findings}


def assert_failed(run: model.ScanRun, fragment: str, status: str = "failed") -> None:
    assert run.status.value == status
    assert run.error_message is not None
    assert fragment in run.error_message
    assert {finding.outcome for finding in run.findings} == {model.Outcome.ERROR}
    assert {finding.rule_id for finding in run.findings} == set(RULES[:5])


class TestCompletedRun:
    """A run whose every completion condition holds."""

    def test_maps_outcomes_honestly_and_records_scc_provenance(self, setup: Setup) -> None:
        runner = FakeScc()
        run = setup.audit(runner)
        assert run.status is model.ScanStatus.COMPLETED
        assert run.error_message is None
        assert run.scanner == model.ScannerInfo("scc", "5.15")
        assert run.content == model.Provenance(
            STREAM_NAME, "001.005.007", hashlib.sha256(STREAM).hexdigest()
        )
        assert outcomes(run) == {
            RULES[0]: "pass",
            RULES[1]: "fail",
            RULES[2]: "notapplicable",
            RULES[3]: "notchecked",
            RULES[4]: "error",
        }
        assert run.started_at == "2026-10-26T12:00:05Z"
        assert run.finished_at == "2026-10-26T12:00:30Z"
        options = setup.output / "scan" / "scc" / "options.xml"
        assert runner.calls == [
            ("--version",),
            ("-o", str(options), "-u", str(setup.output / "scan" / "scc" / "user"), "-q", "-d"),
        ]
        assert (
            (setup.output / "scan" / "results.xml").read_text(encoding="utf-8").startswith("<?xml")
        )
        assert (setup.output / "scan" / "results-arf.xml").read_text(encoding="utf-8") == "<arf/>"
        document = options.read_text(encoding="utf-8")
        assert "<downloadExternalFiles>0</downloadExternalFiles>" in document
        assert f"<selectedProfile>{PROFILE}</selectedProfile>" in document
        assert options.stat().st_mode & 0o777 == scc.FILE_MODE
        assert (setup.output / "scan").stat().st_mode & 0o777 == scc.DIRECTORY_MODE

    def test_a_missing_expected_rule_is_an_error_and_notselected_extras_are_skipped(
        self, setup: Setup
    ) -> None:
        document = results_document(outcomes=("pass", "fail", "notapplicable", "notchecked"))
        document = document.replace(
            "</cdf:TestResult>",
            f'<cdf:rule-result idref="{RULES[5]}"><cdf:result>notselected</cdf:result>'
            "</cdf:rule-result></cdf:TestResult>",
        )
        run = setup.audit(FakeScc(results=document))
        assert run.status is model.ScanStatus.COMPLETED
        assert outcomes(run)[RULES[4]] == "error"
        assert RULES[5] not in outcomes(run)

    def test_the_backend_registers_under_scc(self) -> None:
        registry = scanner.BackendRegistry()
        scc.register(registry)
        assert registry.names() == ("scc",)
        backend = registry.create("scc", scanner.ScanSettings("/a", "/b"))
        assert isinstance(backend, scc.SccBackend)


class TestRequestErrors:
    """What the backend refuses before anything runs."""

    def test_refuses_tailoring(self, setup: Setup) -> None:
        with pytest.raises(scanner.ScanRequestError, match="FREES-146"):
            setup.audit(tailoring_path="tailoring.xml")

    def test_refuses_a_benchmark_without_an_scc_pin(self, setup: Setup) -> None:
        with pytest.raises(scanner.ScanRequestError, match="no SCC benchmark is pinned"):
            setup.audit(benchmark_id="xccdf_org.example_benchmark_other")

    @pytest.mark.parametrize(("distribution", "version"), [("ubuntu", "26.04"), ("rhel", "24.04")])
    def test_never_scans_a_release_with_the_content_of_another(
        self, setup: Setup, distribution: str, version: str
    ) -> None:
        host = model.HostIdentity("target.example", distribution, version, "x86_64", None)
        with pytest.raises(scanner.ScanRequestError, match="never scanned with the content"):
            setup.audit(host=host)

    def test_refuses_missing_content(self, setup: Setup) -> None:
        with pytest.raises(scanner.ScanRequestError, match="not a readable regular file"):
            setup.audit(content_path="missing.xml")

    def test_refuses_content_outside_the_content_root(self, setup: Setup) -> None:
        with pytest.raises(scanner.ScanRequestError, match="escapes"):
            setup.audit(content_path="../other.xml")

    def test_refuses_an_existing_output_directory(self, setup: Setup) -> None:
        (setup.output / "scan").mkdir()
        with pytest.raises(scanner.ScanRequestError, match="already exists"):
            setup.audit()

    def test_reports_an_output_directory_that_cannot_be_created(self, setup: Setup) -> None:
        with pytest.raises(scanner.ScanRequestError, match="cannot be created"):
            setup.audit(output_dir="missing/scan")


class TestInstallation:
    """The installation and SCC's record of the stream."""

    def test_an_unpinned_executable_is_refused(self, setup: Setup) -> None:
        (setup.install / "cscc").write_bytes(b"other")
        assert_failed(setup.audit(), "not a pinned SCC release")

    def test_a_different_installed_stream_is_refused(self, setup: Setup) -> None:
        setup.installed.write_bytes(b"other stream")
        assert_failed(setup.audit(), "not the pinned")

    def test_an_expired_release_is_refused(self, setup: Setup) -> None:
        later = datetime(2099, 1, 1, tzinfo=timezone.utc)
        assert_failed(
            setup.backend(FakeScc(), clock=lambda: later).audit(setup.request()), "expired"
        )

    def test_a_missing_installed_stream_is_refused(self, setup: Setup) -> None:
        setup.installed.unlink()
        assert_failed(setup.audit(), "SCC installation is unusable")

    def test_a_writable_installed_stream_is_refused(self, setup: Setup) -> None:
        setup.installed.chmod(0o666)
        assert_failed(setup.audit(), "SCC installation is unusable")

    @pytest.mark.parametrize(
        ("options", "fragment"),
        [
            (OPTIONS.replace(RECORD, ""), "hold 0 records"),
            (OPTIONS.replace(RECORD, RECORD + RECORD), "hold 2 records"),
            (
                OPTIONS.replace("<family>Linux</family>", "<family>Li nux</family>"),
                "invalid family",
            ),
            (OPTIONS.replace(f"<checksumSCAP12>{CHECKSUM}", "<checksumSCAP12>x"), "checksumSCAP12"),
            (
                OPTIONS.replace(
                    "<family>Linux</family>", "<family>Linux</family><family>A</family>"
                ),
                "repeats",
            ),
            (OPTIONS.replace("      <version>001.005.007</version>\n", ""), "lacks"),
            (OPTIONS.replace('version="5.11"', 'version="x"'), "invalid OVAL"),
            (
                OPTIONS.replace('<oval version="5.11">scap_', '<oval version="5.11">bad'),
                "invalid OVAL",
            ),
            (
                OPTIONS.replace(
                    OVAL_LINE,
                    "",
                ),
                "no or too many OVAL",
            ),
            ("<!DOCTYPE x [<!ENTITY a 'b'>]><options/>", "cannot be read"),
        ],
    )
    def test_an_unusable_record_is_refused(self, setup: Setup, options: str, fragment: str) -> None:
        (setup.install / "options.xml").write_text(options, encoding="utf-8")
        run = setup.audit()
        assert_failed(run, fragment)


class TestVersionProbe:
    """``cscc --version`` must report the pinned release."""

    @pytest.mark.parametrize(
        ("runner", "fragment", "status"),
        [
            (FakeScc(version=b"scc version: 5.14 date: x\n"), "does not report SCC 5.15", "failed"),
            (FakeScc(version=b"garbage\n"), "does not report SCC 5.15", "failed"),
            (FakeScc(version_status=1), "does not report SCC 5.15", "failed"),
            (FakeScc(version_timeout=True), "--version timed out", "timed_out"),
            (
                FakeScc(version_error=process.ProcessExecutionError("missing")),
                "cscc is not available",
                "failed",
            ),
            (
                FakeScc(version_error=process.ProcessPolicyError("unsafe")),
                "cscc is not available",
                "failed",
            ),
        ],
    )
    def test_a_failed_probe_fails_the_run(
        self, setup: Setup, runner: FakeScc, fragment: str, status: str
    ) -> None:
        assert_failed(setup.audit(runner), fragment, status)
        assert runner.calls == [("--version",)]


class TestScanProcess:
    """The exit status never proves completion, but a failure fails the run."""

    def test_a_timeout_is_timed_out(self, setup: Setup) -> None:
        assert_failed(setup.audit(FakeScc(scan_timeout=True)), "timeout", "timed_out")

    def test_a_non_zero_exit_fails_the_run(self, setup: Setup) -> None:
        assert_failed(setup.audit(FakeScc(scan_status=3)), "exited with status 3")

    def test_a_start_failure_fails_the_run(self, setup: Setup) -> None:
        runner = FakeScc(scan_error=process.ProcessExecutionError("cannot start"))
        assert_failed(setup.audit(runner), "cscc could not run")

    def test_content_that_changes_during_the_scan_fails_the_run(self, setup: Setup) -> None:
        runner = FakeScc(during=lambda: setup.installed.write_bytes(b"changed"))
        assert_failed(setup.audit(runner), "content changed during the scan")

    def test_exit_zero_without_results_is_not_completion(self, setup: Setup) -> None:
        assert_failed(setup.audit(FakeScc(xccdf=())), "0 XCCDF results files")


class TestCompletion:
    """Every completion condition of ADR 0019, decision 4."""

    @pytest.mark.parametrize(
        ("runner", "fragment"),
        [
            (FakeScc(logs=()), "no single application debug log"),
            (FakeScc(logs=(LOG_NAME, LOG_NAME.replace("001", "002"))), "no single application"),
            (FakeScc(sessions=()), "0 scan sessions"),
            (FakeScc(sessions=(SESSION, "2026-10-26_120002")), "2 scan sessions"),
            (FakeScc(xccdf=(XCCDF_NAME, XCCDF_NAME.replace("STIG-", "STIG-x"))), "2 XCCDF"),
            (FakeScc(arf=()), "0 ARF results files"),
            (FakeScc(results="<cdf:Benchmark"), "results rejected"),
            (FakeScc(results=results_document(profile=PROFILE + "x")), "different profile"),
            (FakeScc(results=results_document(benchmark=BENCHMARK + "x")), "different benchmark"),
            (
                FakeScc(results=results_document(outcomes=(*OUTCOMES, "pass"))),
                "1 rule(s) that the profile does not select",
            ),
            (
                FakeScc(results=results_document(start="2026-10-26T11:59:59")),
                "started before this run",
            ),
            (FakeScc(results=results_document(end="2026-10-26T12:00:04")), "end before they start"),
            (FakeScc(results=results_document(start="")), "results rejected"),
            (FakeScc(log=confirmation("/elsewhere/options.xml")), "not confirmed"),
            (
                FakeScc(log=confirmation("{options}").replace("30 days", "0 days")),
                "not confirmed",
            ),
        ],
    )
    def test_anything_else_fails_the_run(
        self, setup: Setup, runner: FakeScc, fragment: str
    ) -> None:
        assert_failed(setup.audit(runner), fragment)

    def test_an_expired_scc_log_fails_the_run(self, setup: Setup) -> None:
        options = str(setup.output / "scan" / "scc" / "options.xml")
        runner = FakeScc(log=confirmation(options).replace("in 30 days", "in -2 days"))
        assert_failed(setup.audit(runner), "has expired")

    def test_an_unreadable_log_fails_the_run(
        self, setup: Setup, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(scc, "MAX_LOG_BYTES", 10)
        assert_failed(setup.audit(), "not confirmed")

    def test_a_results_directory_that_is_a_file_is_not_completion(self, setup: Setup) -> None:
        class FileSessions(FakeScc):
            """Writes the results directory as a file."""

            def write(self, user: Path, options: str) -> None:
                super().write(user, options)
                xml = user / "Sessions" / SESSION / "Results" / "SCAP" / "XML"
                for entry in xml.iterdir():
                    entry.unlink()
                xml.rmdir()
                xml.write_text("not a directory", encoding="utf-8")

        assert_failed(setup.audit(FileSessions()), "0 XCCDF results files")

    def test_a_symlinked_results_file_is_not_completion(self, setup: Setup, tmp_path: Path) -> None:
        class LinkedResults(FakeScc):
            """Replaces the results file with a symlink."""

            def write(self, user: Path, options: str) -> None:
                super().write(user, options)
                xml = user / "Sessions" / SESSION / "Results" / "SCAP" / "XML"
                target = tmp_path / "elsewhere.xml"
                target.write_text(results_document(), encoding="utf-8")
                (xml / XCCDF_NAME).unlink()
                (xml / XCCDF_NAME).symlink_to(target)

        assert_failed(setup.audit(LinkedResults()), "0 XCCDF results files")

    def test_a_model_rejection_fails_the_run(
        self, setup: Setup, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = model.ScanRun

        def strict(**fields: Any) -> model.ScanRun:
            if fields["status"] is model.ScanStatus.COMPLETED:
                message = "synthetic rejection"
                raise model.ModelError(message)
            return real(**fields)

        monkeypatch.setattr(model, "ScanRun", strict)
        assert_failed(setup.audit(), "rejected by the model")


class TestConfirmation:
    """``confirm_options`` and the acceptance criteria of FREES-145."""

    OPTIONS_PATH = "/var/lib/run/scan/scc/options.xml"

    def test_accepts_the_record_of_a_confirmed_run(self) -> None:
        scc.confirm_options(confirmation(self.OPTIONS_PATH), self.OPTIONS_PATH)

    def test_a_missing_confirmation_is_refused(self) -> None:
        with pytest.raises(scc.OptionsConfirmationError, match="does not record the options file"):
            scc.confirm_options("SCC - 5.15\nno debug lines\n", self.OPTIONS_PATH)

    def test_a_confirmation_that_names_another_options_file_is_refused(self) -> None:
        with pytest.raises(scc.OptionsConfirmationError, match="not the run's"):
            scc.confirm_options(confirmation("/opt/scc/options.xml"), self.OPTIONS_PATH)

    @pytest.mark.parametrize("name", scc.CONFIRMED_ZERO)
    def test_a_confirmation_that_shows_a_value_as_1_is_refused(self, name: str) -> None:
        log = confirmation(self.OPTIONS_PATH, **{name: "1"})
        with pytest.raises(scc.OptionsConfirmationError, match=f"shows {name} as '1'"):
            scc.confirm_options(log, self.OPTIONS_PATH)

    def test_an_enabled_configuration_profile_is_refused(self) -> None:
        log = confirmation(self.OPTIONS_PATH).replace(
            "selectedConfigProfile: ", "selectedConfigProfile: hardened"
        )
        with pytest.raises(
            scc.OptionsConfirmationError, match="configuration profile as 'hardened'"
        ):
            scc.confirm_options(log, self.OPTIONS_PATH)

    def test_an_enabled_configuration_profile_in_the_dump_is_refused(self) -> None:
        log = confirmation(self.OPTIONS_PATH, selectedConfigProfile="hardened")
        with pytest.raises(scc.OptionsConfirmationError, match="selectedConfigProfile as"):
            scc.confirm_options(log, self.OPTIONS_PATH)

    def test_another_configuration_profile_name_is_refused(self) -> None:
        log = confirmation(self.OPTIONS_PATH).replace(
            "Using configuration profile: default", "Using configuration profile: site"
        )
        with pytest.raises(scc.OptionsConfirmationError, match="'site'"):
            scc.confirm_options(log, self.OPTIONS_PATH)

    @pytest.mark.parametrize(
        ("old", "new", "fragment"),
        [
            (
                "Loading options from: {path}",
                "Loading options from: /opt/scc/options.xml",
                "loaded",
            ),
            ("Loading options from: {path}", "Loaded", "the options file that was loaded"),
            ("Contents of {path}:", "Contents of /opt/scc/options.xml:", "dumped options"),
            ("Contents of {path}:", "nothing", "0 dumps"),
        ],
    )
    def test_every_record_must_name_the_run_file(self, old: str, new: str, fragment: str) -> None:
        log = confirmation(self.OPTIONS_PATH).replace(old.format(path=self.OPTIONS_PATH), new)
        with pytest.raises(scc.OptionsConfirmationError, match=fragment):
            scc.confirm_options(log, self.OPTIONS_PATH)

    def test_two_dumps_are_refused(self) -> None:
        log = confirmation(self.OPTIONS_PATH)
        with pytest.raises(scc.OptionsConfirmationError, match="2 dumps"):
            scc.confirm_options(log + log, self.OPTIONS_PATH)

    def test_a_value_that_appears_twice_is_refused(self) -> None:
        log = confirmation(self.OPTIONS_PATH)
        extra = log_line("Output", "*        <appCheckForUpdates>0</appCheckForUpdates>")
        with pytest.raises(scc.OptionsConfirmationError, match="2 times"):
            scc.confirm_options(log + extra + "\n", self.OPTIONS_PATH)

    def test_a_value_missing_from_the_dump_is_refused(self) -> None:
        log = "\n".join(
            line
            for line in confirmation(self.OPTIONS_PATH).splitlines()
            if "contentCheckForUpdates" not in line
        )
        with pytest.raises(scc.OptionsConfirmationError, match="0 times"):
            scc.confirm_options(log, self.OPTIONS_PATH)

    def test_the_expiry_is_read_from_the_log(self) -> None:
        assert scc.expiry_days(confirmation(self.OPTIONS_PATH)) == 30
        assert scc.expiry_days("nothing\n") is None


class TestOptionsDocument:
    """The per-run options file."""

    def record(self) -> scc.InstalledContent:
        return scc.InstalledContent(
            {
                "stream": "scap_a",
                "family": "Linux",
                "benchmarkID": "B",
                "scapVersion": "1.3",
                "filepath": "Resources/Content/SCAP12_Content/a.xml",
                "checksumSCAP12": CHECKSUM,
                "version": "1.0",
                "xccdf": "scap_x",
            },
            (("5.11", "scap_o"),),
        )

    def test_the_document_holds_every_setting_in_order_and_one_enabled_stream(self) -> None:
        document = self.record_document()
        positions = [document.index(f"<{name}>") for name, _value in scc.OPTIONS_TEMPLATE]
        assert positions == sorted(positions)
        assert document.count("<content>") == 1
        assert document.count("<enabled>1</enabled>") == 1
        for name in scc.CONFIRMED_ZERO:
            assert f"<{name}>0</{name}>" in document
        for name in ("sshEnabled", "saveDISACKL", "saveDISACKLB", "deviationsEnabled"):
            assert f"<{name}>0</{name}>" in document
        for name in ("keepXCCDFXML", "keepARFXML", "validateDigitalSignature", "failOnXMLDSig"):
            assert f"<{name}>1</{name}>" in document
        assert '<oval version="5.11">scap_o</oval>' in document
        xmlsafe.parse_text(document, Collector(), xmlsafe.XmlBounds())

    def record_document(self) -> str:
        return scc.options_document(self.record(), PROFILE)

    def test_the_template_names_each_setting_once(self) -> None:
        names = [name for name, _value in scc.OPTIONS_TEMPLATE]
        assert len(names) == len(set(names))
        values = dict(scc.OPTIONS_TEMPLATE)
        assert values["appUpdateURL"] == values["contentRepository"] == ""
        assert values["selectedConfigProfile"] == ""

    def test_the_profile_must_be_an_xccdf_profile(self) -> None:
        with pytest.raises(scanner.ScanRequestError):
            scc.options_document(self.record(), "<injected/>")

    def test_values_are_escaped(self) -> None:
        assert scc.xml_escape("<a href=\"x\">'&'</a>") == (
            "&lt;a href=&quot;x&quot;&gt;&apos;&amp;&apos;&lt;/a&gt;"
        )

    def test_the_record_rejects_markup(self) -> None:
        fields = dict(self.record().fields)
        fields["stream"] = "scap_<x>"
        with pytest.raises(scc.InstallationError, match="invalid stream"):
            scc.InstalledContent(fields, (("5.11", "scap_o"),))

    def test_the_record_is_read_only(self) -> None:
        record = self.record()
        with pytest.raises(TypeError):
            cast("dict[str, str]", record.fields)["stream"] = "scap_b"


class Collector:
    """Minimal :mod:`xmlsafe` receiver that checks the document is well formed."""

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        del name, attributes

    def end(self, name: str, /) -> None:
        del name

    def text(self, data: str, /) -> None:
        del data


def test_zone_less_times_are_utc_only_when_the_caller_fixed_the_zone() -> None:
    document = results_document()
    with pytest.raises(openscap.XccdfParseError, match="no time zone"):
        openscap.parse_results(document)
    parsed = openscap.parse_results(document, assume_utc=True)
    assert parsed.started_at == "2026-10-26T12:00:05Z"
    offset = results_document(start="2026-10-26T14:00:05+02:00")
    assert openscap.parse_results(offset, assume_utc=True).started_at == "2026-10-26T12:00:05Z"


class SilentScc(FakeScc):
    """Runner that exits 0 and writes nothing, like the observed failure modes."""

    def write(self, user: Path, options: str) -> None:
        del user, options


def test_exit_zero_with_no_output_at_all_is_a_failed_run(setup: Setup) -> None:
    assert_failed(setup.audit(SilentScc()), "no single application debug log")


def test_the_default_clock_is_the_system_clock(setup: Setup) -> None:
    settings = scanner.ScanSettings(str(setup.content), str(setup.output), 60.0)
    backend = scc.SccBackend(settings, runner=FakeScc(), install_root=str(setup.install))
    run = backend.audit(setup.request())
    assert run.status is model.ScanStatus.FAILED
    assert run.finished_at >= "2026-10-26T00:00:00Z"
