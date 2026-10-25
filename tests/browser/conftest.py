from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, Playwright, Route, sync_playwright

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting.common import dumps
from tools.reporting.dashboard import render_dashboard
from tools.reporting.report import ReportInputs, RunMetadata, Scope, build_report

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
REPORTING = FIXTURES / "reporting"
BROWSER_DIR = Path(os.environ.get("FREESECDEV_BROWSER_TEST_DIR", ROOT / "build" / "browser-test"))
SHELL = BROWSER_DIR / "chrome-headless-shell-linux64" / "chrome-headless-shell"
AXE = BROWSER_DIR / "axe.min.js"
BROWSER_VERSION = "156.0.8078.4"
AXE_SHA256 = "20c09fe157a8a34a30e241aaa1fcdade657734f08ab379ecfbeb7d45cc46e878"
BENCHMARK = "xccdf_org.example.synthetic_benchmark_demo"
PROFILE = "xccdf_org.example.synthetic_profile_baseline"
RULE_PREFIX = "xccdf_org.example.synthetic_rule_"
MACHINE_ID = "0123456789abcdef0123456789abcdef"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
STARTED = "2026-10-25T10:00:00Z"
FINISHED = "2026-10-25T10:00:09Z"
MONITOR = """
window.__cspViolations = [];
document.addEventListener("securitypolicyviolation", function (event) {
  window.__cspViolations.push(event.violatedDirective + " " + event.blockedURI);
});
"""


def xccdf_text(target: str | None, results: list[tuple[str, str]]) -> str:
    host = "" if target is None else f"<target>{target}</target>"
    rules = "".join(
        f'<rule-result idref="{RULE_PREFIX}{name}" severity="medium"><result>{state}</result>'
        "</rule-result>"
        for name, state in results
    )
    stamps = 'start-time="2026-10-25T10:00:00+00:00" end-time="2026-10-25T10:00:09+00:00"'
    return (
        f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="{BENCHMARK}">'
        "<version>1.0</version>"
        f'<TestResult id="x" {stamps} version="1.0">'
        f'<benchmark id="{BENCHMARK}"/><profile idref="{PROFILE}"/>{host}{rules}'
        "</TestResult></Benchmark>"
    )


def finding(name: str, outcome: model.Outcome, **changes: Any) -> model.Finding:
    fields: dict[str, Any] = {
        "rule_id": RULE_PREFIX + name,
        "outcome": outcome,
        "evaluated_outcome": outcome,
        "severity": model.Severity.MEDIUM,
        "message": None,
        "evidence": (model.Evidence("file", "/etc/demo.conf", "PermitRootLogin yes"),),
        "exception": model.ExceptionStatus.none(),
        "remediation": None,
        "disabled_by": None,
        "flags": (),
    }
    fields.update(changes)
    return model.Finding(**fields)


def scan_run(
    hostname: str,
    machine_id: str | None,
    findings: tuple[model.Finding, ...],
    status: model.ScanStatus = model.ScanStatus.COMPLETED,
) -> str:
    run = model.ScanRun(
        run_id=f"run-{hostname}",
        started_at=STARTED,
        finished_at=FINISHED,
        host=model.HostIdentity(hostname, "rhel", "9", "x86_64", machine_id),
        scanner=model.ScannerInfo("oscap", "1.3.10"),
        content=model.Provenance("synthetic-ds.xml", "1.0", "a" * 64),
        benchmark_id=BENCHMARK,
        profile_id=PROFILE,
        status=status,
        error_message=None if status is model.ScanStatus.COMPLETED else "scanner did not finish",
        findings=findings,
    )
    return model.dumps(run)


def detailed_findings() -> tuple[model.Finding, ...]:
    active = model.ExceptionStatus(
        model.ExceptionState.ACTIVE, "EXC-1", "accepted risk", "2026-12-31T00:00:00Z"
    )
    expired = model.ExceptionStatus(
        model.ExceptionState.EXPIRED, "EXC-2", "old risk", "2026-10-01T00:00:00Z"
    )
    return (
        finding("alpha", model.Outcome.PASS, severity=model.Severity.HIGH),
        finding("beta", model.Outcome.FAIL, message="sshd allows root login"),
        finding(
            "gamma", model.Outcome.WAIVED, exception=active, evaluated_outcome=model.Outcome.FAIL
        ),
        finding("delta", model.Outcome.FAIL, exception=expired),
        finding("epsilon", model.Outcome.DISABLED, disabled_by="linux_compliance_ssh_root_login"),
        finding(
            "zeta",
            model.Outcome.NOTCHECKED,
            flags=(model.ResultFlag.NOTSELECTED,),
            severity=model.Severity.LOW,
        ),
    )


def as_json(document: dict[str, Any]) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(dumps(document))
    return loaded


def write(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


def typical_report(directory: Path) -> dict[str, Any]:
    """Every section available; a machine-identified and a self-asserted ``host.example``."""
    machine = write(
        directory, "machine.json", scan_run("host.example", MACHINE_ID, detailed_findings())
    )
    claimed = write(directory, "claimed.xml", xccdf_text("host.example", [("alpha", "fail")]))
    inputs = ReportInputs(
        scope=Scope.FLEET,
        metadata=RunMetadata(commit=COMMIT, pull_request="77", generated_at="2026-10-25T10:11:00Z"),
        xccdf=(FIXTURES / "xccdf" / "mixed-results.xml", claimed),
        arf=(REPORTING / "arf.xml",),
        scan_run=(machine,),
        junit=(REPORTING / "junit.xml",),
        pytest_json=(REPORTING / "pytest.json",),
        cobertura=(REPORTING / "cobertura.xml",),
        lint=(REPORTING / "ansible-lint.sarif", REPORTING / "ansible-lint.json"),
        grype=(REPORTING / "grype.json",),
        sbom=(REPORTING / "spdx.json", REPORTING / "cyclonedx.json"),
        packer=(REPORTING / "packer-manifest.json",),
        codebuild=(REPORTING / "codebuild.json",),
        molecule=(REPORTING / "molecule-summary.json",),
    )
    return as_json(build_report(inputs))


def degraded_report(directory: Path) -> dict[str, Any]:
    """A failed scan run, a partial tests section and a lint section in error."""
    failed = write(
        directory,
        "failed.json",
        scan_run(
            "host.example",
            None,
            (finding("alpha", model.Outcome.ERROR),),
            model.ScanStatus.FAILED,
        ),
    )
    broken = write(directory, "broken.sarif", "{not json")
    inputs = ReportInputs(
        scope=Scope.SINGLE_HOST,
        scan_run=(failed,),
        junit=(REPORTING / "junit.xml", directory / "absent.xml"),
        lint=(broken,),
    )
    return as_json(build_report(inputs))


def many_rules_report(directory: Path, hosts: int, rules: int) -> dict[str, Any]:
    states = ("pass", "fail", "notchecked", "error", "notapplicable", "pass", "informational")
    paths: list[Path] = []
    for host in range(hosts):
        results = [
            (f"r{index:06d}", states[(index + host) % len(states)]) for index in range(rules)
        ]
        target = f"host-{host % max(1, hosts - 1):04d}"
        paths.append(write(directory, f"host-{host:04d}.xml", xccdf_text(target, results)))
    inputs = ReportInputs(scope=Scope.FLEET, xccdf=tuple(paths))
    return as_json(build_report(inputs))


MAX_INPUTS = 1000
DETAIL_ENTRIES = 1200
OUTCOMES = ("pass", "fail", "notchecked", "error", "notapplicable", "pass", "informational")


def copies(
    directory: Path, source: Path, count: int, first: tuple[str, str] | None
) -> tuple[Path, ...]:
    paths: list[Path] = []
    content = source.read_text(encoding="utf-8")
    for index in range(count):
        name = f"{source.stem}-{index:04d}{source.suffix}"
        text = first[1] if first is not None and index == 0 else content
        paths.append(write(directory, name, text))
    return tuple(paths)


def big_details() -> dict[str, tuple[str, str]]:
    many = range(DETAIL_ENTRIES)
    junit = "".join(
        f'<testcase classname="suite.c{i}" name="test_{i}">'
        f'<failure message="m{i}">t</failure></testcase>'
        for i in many
    )
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ansible-lint"}},
                "results": [
                    {"ruleId": f"rule[{i}]", "level": "warning", "message": {"text": f"issue {i}"}}
                    for i in many
                ],
            }
        ],
    }
    grype = {
        "matches": [
            {
                "vulnerability": {"id": f"CVE-2026-{i:05d}", "severity": "High"},
                "artifact": {"name": f"pkg{i}", "version": "1", "type": "rpm"},
            }
            for i in many
        ],
        "descriptor": {"name": "grype", "version": "0.0.0"},
    }
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": f"lib{i}",
                "version": "1",
                "licenses": [{"license": {"id": f"L-{i}"}}],
            }
            for i in many
        ],
    }
    packages = "".join(
        f'<package name="p{i}" line-rate="0.5" branch-rate="0.5"><classes/></package>' for i in many
    )
    coverage = f'<coverage line-rate="0.5" branch-rate="0.5"><packages>{packages}</packages>'
    return {
        "junit": ("big.xml", f'<testsuite name="big">{junit}</testsuite>'),
        "lint": ("big.sarif", json.dumps(sarif)),
        "grype": ("big.json", json.dumps(grype)),
        "sbom": ("big.json", json.dumps(sbom)),
        "cobertura": ("big.xml", f"{coverage}</coverage>"),
    }


def compliance_inputs(
    directory: Path, rules_per_input: int
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Write 950 XCCDF files and 50 ScanRuns with ``rules_per_input`` results each.

    Every 50th XCCDF file repeats a host name (a merge note), and every ScanRun has a
    machine ID and the name of an XCCDF host, so groups share labels.
    """
    compliance = directory / "compliance"
    compliance.mkdir()
    xccdf: list[Path] = []
    runs: list[Path] = []
    for index in range(MAX_INPUTS):
        results = [
            (f"r{rule:06d}", OUTCOMES[(rule + index) % len(OUTCOMES)])
            for rule in range(rules_per_input)
        ]
        if index % 20 == 19:
            findings = tuple(
                finding(name, model.Outcome.ERROR if state == "error" else model.Outcome.PASS)
                for name, state in results
            )
            document = scan_run(f"host-{index - 19:04d}", f"{index:032x}", findings)
            runs.append(write(compliance, f"run-{index:04d}.json", document))
            continue
        host = f"host-{index - index % 50:04d}" if index % 50 == 1 else f"host-{index:04d}"
        xccdf.append(write(compliance, f"xccdf-{index:04d}.xml", xccdf_text(host, results)))
    return tuple(xccdf), tuple(runs)


def other_inputs(directory: Path) -> dict[str, tuple[Path, ...]]:
    """Write 1000 inputs for every other section; the first of five has an oversized list."""
    details = big_details()
    others: dict[str, tuple[Path, ...]] = {}
    for name, source in (
        ("junit", REPORTING / "junit.xml"),
        ("cobertura", REPORTING / "cobertura.xml"),
        ("lint", REPORTING / "ansible-lint.sarif"),
        ("grype", REPORTING / "grype.json"),
        ("sbom", REPORTING / "cyclonedx.json"),
        ("packer", REPORTING / "packer-manifest.json"),
        ("codebuild", REPORTING / "codebuild.json"),
        ("molecule", REPORTING / "molecule-summary.json"),
    ):
        folder = directory / name
        folder.mkdir()
        others[name] = copies(folder, source, MAX_INPUTS, details.get(name))
    return others


def maximum_report(directory: Path, rules_per_input: int) -> dict[str, Any]:
    """1000 inputs in every section, detail lists past their cap, and many compliance rules.

    Inputs are named relative to ``directory``, so the size of the report does not depend on
    where the temporary directory is.
    """
    with contextlib.chdir(directory):
        xccdf, runs = compliance_inputs(Path(), rules_per_input)
        others = other_inputs(Path())
        inputs = ReportInputs(
            scope=Scope.FLEET,
            metadata=RunMetadata(commit=COMMIT, generated_at="2026-10-25T10:11:00Z"),
            xccdf=xccdf,
            scan_run=runs,
            junit=others["junit"],
            cobertura=others["cobertura"],
            lint=others["lint"],
            grype=others["grype"],
            sbom=others["sbom"],
            packer=others["packer"],
            codebuild=others["codebuild"],
            molecule=others["molecule"],
        )
        return as_json(build_report(inputs))


@dataclass
class Dashboard:
    """A dashboard page opened offline, with every request, error and CSP violation recorded."""

    page: Page
    url: str
    requests: list[str] = field(default_factory=list[str])
    blocked: list[str] = field(default_factory=list[str])
    console: list[str] = field(default_factory=list[str])
    errors: list[str] = field(default_factory=list[str])
    dialogs: list[str] = field(default_factory=list[str])

    def violations(self) -> list[str]:
        recorded: list[str] = self.page.evaluate("() => window.__cspViolations.slice()")
        logged = [line for line in self.console if "Content Security Policy" in line]
        return recorded + logged

    def assert_clean(self) -> None:
        assert self.violations() == []
        assert self.errors == []
        assert self.dialogs == []
        assert self.blocked == []
        assert [url for url in self.requests if url != self.url] == []
        assert self.page.evaluate("() => window.__pwned") is None

    def tab(self, name: str) -> None:
        self.page.locator(f"#tab-{name}").click()
        self.page.locator(f"#panel-{name}").wait_for(state="visible")

    def tab_names(self) -> list[str]:
        ids: list[str] = self.page.eval_on_selector_all(
            "[role=tab]", "nodes => nodes.map(node => node.id.slice(4))"
        )
        return ids

    def run_axe(self) -> list[dict[str, Any]]:
        self.page.evaluate(axe_source())
        result: list[dict[str, Any]] = self.page.evaluate(
            """async () => {
                const outcome = await window.axe.run(document, {
                    resultTypes: ["violations"],
                    runOnly: {
                        type: "tag",
                        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"]
                    }
                });
                return outcome.violations.map(v => ({
                    id: v.id,
                    impact: v.impact,
                    nodes: v.nodes.slice(0, 3).map(n => n.target.join(" "))
                }));
            }"""
        )
        return result


def axe_source() -> str:
    data = AXE.read_bytes()
    assert hashlib.sha256(data).hexdigest() == AXE_SHA256
    return data.decode("utf-8")


@pytest.fixture(scope="session")
def playwright_instance() -> Iterator[Playwright]:
    if not SHELL.is_file() or not AXE.is_file():
        message = (
            f"{BROWSER_DIR} is missing the pinned browser or axe-core: run 'make test-browser'"
        )
        raise pytest.UsageError(message)
    with sync_playwright() as instance:
        yield instance


@pytest.fixture(scope="session")
def browser(playwright_instance: Playwright) -> Iterator[Browser]:
    launched = playwright_instance.chromium.launch(executable_path=str(SHELL))
    assert launched.version == BROWSER_VERSION
    yield launched
    launched.close()


@pytest.fixture
def render(tmp_path: Path) -> Callable[[dict[str, Any], str], Path]:
    def _render(document: dict[str, Any], name: str) -> Path:
        path = tmp_path / f"{name}.html"
        path.write_text(render_dashboard(document), encoding="utf-8")
        return path

    return _render


@pytest.fixture
def reports(tmp_path: Path) -> Path:
    directory = tmp_path / "inputs"
    directory.mkdir()
    return directory


@pytest.fixture
def open_dashboard(browser: Browser) -> Iterator[Callable[..., Dashboard]]:
    contexts: list[BrowserContext] = []

    def _open(path: Path, **options: Any) -> Dashboard:
        timeout = float(options.get("timeout", 30000))
        context = browser.new_context(
            color_scheme="dark" if options.get("color_scheme") == "dark" else "light",
            viewport={"width": int(options.get("width", 1280)), "height": 900},
            offline=True,
            service_workers="block",
            bypass_csp=bool(options.get("bypass_csp", False)),
        )
        contexts.append(context)
        context.add_init_script(script=MONITOR)
        page = context.new_page()
        page.set_default_timeout(timeout)
        dashboard = Dashboard(page, path.resolve().as_uri())

        def guard(route: Route) -> None:
            if route.request.url == dashboard.url:
                route.continue_()
                return
            dashboard.blocked.append(route.request.url)
            route.abort()

        context.route("**/*", guard)
        page.on("request", lambda request: dashboard.requests.append(request.url))
        page.on("console", lambda message: dashboard.console.append(message.text))
        page.on("pageerror", lambda error: dashboard.errors.append(str(error)))

        def dismiss(dialog: Any) -> None:
            dashboard.dialogs.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", dismiss)
        page.goto(dashboard.url)
        if options.get("wait", True):
            page.locator("[role=tablist]").wait_for(state="visible", timeout=timeout)
        return dashboard

    yield _open
    for context in contexts:
        context.close()


@pytest.fixture
def typical(reports: Path) -> dict[str, Any]:
    return typical_report(reports)


@pytest.fixture
def degraded(reports: Path) -> dict[str, Any]:
    return degraded_report(reports)


@pytest.fixture
def across_benchmarks(reports: Path) -> dict[str, Any]:
    """Two self-asserted ``web01`` files for different benchmarks: one failing, one passing."""
    failing = write(reports, "a.xml", xccdf_text("web01", [("alpha", "pass"), ("beta", "fail")]))
    other = xccdf_text("WEB01", [("alpha", "pass")]).replace(
        BENCHMARK, "xccdf_org.example.synthetic_benchmark_other"
    )
    passing = write(reports, "b.xml", other)
    unrelated = write(reports, "c.xml", xccdf_text("db01", [("alpha", "pass")]))
    inputs = ReportInputs(scope=Scope.FLEET, xccdf=(failing, passing, unrelated))
    return as_json(build_report(inputs))


@pytest.fixture
def all_passed() -> dict[str, Any]:
    inputs = ReportInputs(scope=Scope.FLEET, xccdf=(FIXTURES / "xccdf" / "all-pass.xml",))
    return as_json(build_report(inputs))


@pytest.fixture
def many_rules(reports: Path) -> dict[str, Any]:
    return many_rules_report(reports, 3, 120)


@pytest.fixture(scope="session")
def build_maximum() -> Callable[[Path, int], dict[str, Any]]:
    return maximum_report


@pytest.fixture
def copy_of() -> Callable[[dict[str, Any]], dict[str, Any]]:
    def _copy(document: dict[str, Any]) -> dict[str, Any]:
        copied: dict[str, Any] = copy.deepcopy(document)
        return copied

    return _copy
