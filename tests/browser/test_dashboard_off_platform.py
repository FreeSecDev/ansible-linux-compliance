"""Off-platform scan runs on the dashboard (ADR 0017 amendment of FREES-161)."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tests.browser.conftest import (
    MACHINE_ID,
    as_json,
    detailed_findings,
    finding,
    scan_run,
    write,
)
from tests.browser.test_dashboard_accessibility import blocking
from tools.reporting.report import ReportInputs, Scope, build_report

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from tests.browser.conftest import Dashboard

MARKER = model.OffPlatform(model.Platform("ubuntu", "24.04"), model.Platform("ubuntu", "26.04"))
HOSTILE = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>'


def off_platform_report(directory: Path) -> dict[str, Any]:
    on_platform = write(
        directory, "machine.json", scan_run("host.example", MACHINE_ID, detailed_findings())
    )
    run = model.loads(
        scan_run(
            "lab2604",
            "f" * 32,
            (finding("alpha", model.Outcome.PASS), finding("beta", model.Outcome.FAIL)),
        )
    )
    marked = dataclasses.replace(
        run,
        host=dataclasses.replace(run.host, distribution_id="ubuntu", distribution_version="26.04"),
        off_platform=MARKER,
    )
    off = write(directory, "off-platform.json", model.dumps(marked))
    inputs = ReportInputs(scope=Scope.MULTI_HOST, scan_run=(on_platform, off))
    return as_json(build_report(inputs))


@pytest.fixture
def off_platform(reports: Path) -> dict[str, Any]:
    return off_platform_report(reports)


def test_off_platform_results_are_labelled_and_never_a_figure(
    off_platform: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(off_platform, "off-platform"))
    overview = view.page.locator("#panel-overview").inner_text()
    assert "Off-platform results: never compliance with the host's own release." in overview
    assert "1 input was scanned with a benchmark made for another platform" in overview
    assert "ubuntu 24.04 benchmark" in overview
    assert "ubuntu 26.04 host" in overview
    assert "excluded from every figure" in overview
    view.tab("compliance")
    panel = view.page.locator("#panel-compliance").inner_text()
    assert "Off-platform results (never in a figure)" in panel
    assert "off-platform: not a figure" in panel
    assert "off-platform: no figure" in panel
    pooled = panel.split("Pooled figures")[1].split("Host groups")[0]
    assert "lab2604" not in pooled
    groups = panel.split("Host groups")[1].split("Rules")[0]
    assert "lab2604" not in groups
    view.assert_clean()


def test_without_off_platform_results_there_is_no_callout(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, "on-platform"))
    assert "Off-platform results" not in view.page.locator("#panel-overview").inner_text()
    view.tab("compliance")
    assert "Off-platform results" not in view.page.locator("#panel-compliance").inner_text()
    view.assert_clean()


def test_hostile_off_platform_values_are_rendered_as_text(
    off_platform: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
    copy_of: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    document = copy_of(off_platform)
    entry = document["sections"]["compliance"]["off_platform"][0]
    entry["host"]["hostname"] = HOSTILE
    entry["benchmark_platform"]["distribution_id"] = HOSTILE
    entry["benchmark_id"] = HOSTILE
    view = open_dashboard(render(document, "off-platform-hostile"))
    assert HOSTILE in view.page.locator("#panel-overview").inner_text()
    view.tab("compliance")
    assert HOSTILE in view.page.locator("#panel-compliance").inner_text()
    assert view.page.locator("#panel-compliance img").count() == 0
    assert view.page.locator("#panel-overview script, #panel-compliance script").count() == 0
    view.assert_clean()


def test_axe_finds_no_serious_violation_with_off_platform_results(
    off_platform: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    for scheme in ("light", "dark"):
        view = open_dashboard(render(off_platform, f"off-platform-{scheme}"), color_scheme=scheme)
        for name in ("overview", "compliance"):
            view.tab(name)
            assert blocking(view.run_axe()) == [], name
        view.assert_clean()
