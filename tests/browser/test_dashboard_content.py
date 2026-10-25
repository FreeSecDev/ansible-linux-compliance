from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, cast

from tools.reporting.dashboard import dashboard_views

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from tests.browser.conftest import Dashboard

PERCENT = re.compile(r"(\d+(?:\.\d+)?) %")


def visit_all(view: Dashboard) -> str:
    for name in view.tab_names():
        view.tab(name)
    return view.page.locator("main").text_content() or ""


def report_percentages(document: dict[str, Any]) -> set[str]:
    found: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            mapping = cast("dict[str, object]", value)
            percent = mapping.get("compliance_percent")
            if isinstance(percent, float):
                found.add(f"{percent:.1f}" if percent.is_integer() else repr(percent))
            for item in mapping.values():
                walk(item)
        elif isinstance(value, list):
            entries = cast("list[object]", value)
            for item in entries:
                walk(item)

    walk(document)
    return found


def test_every_percentage_shown_is_one_the_report_gives(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, "figures"))
    text = visit_all(view)
    shown = set(PERCENT.findall(text))
    assert shown
    assert shown <= report_percentages(typical)
    summary = typical["sections"]["compliance"]["summary"]
    assert (
        f"Pass percentage: {summary['compliance_percent']} % ({summary['counts']['pass']} pass of "
        f"{summary['evaluated']} evaluated, scope fleet)"
    ) in text
    assert "all evaluated rules passed" not in text
    view.assert_clean()


def test_host_groups_show_identity_sources_merge_notes_and_variants(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    groups = typical["sections"]["compliance"]["groups"]
    views: Any = dashboard_views(typical)
    view = open_dashboard(render(typical, "groups"))
    view.tab("compliance")
    table = view.page.locator(".data-table").filter(
        has=view.page.locator("caption", has_text="Host groups")
    )
    rows = table.locator("tbody > tr")
    assert rows.count() == len(groups)
    texts = [rows.nth(index).inner_text() for index in range(rows.count())]
    for group, extra in zip(groups, views["groups"], strict=True):
        host = group["host"]
        row = next(
            text
            for text in texts
            if (host["hostname"] or host["input_sha256"]) in text
            and (host["machine_id"] or "self-asserted") in text
        )
        assert extra["sources"]
        for source in extra["sources"]:
            assert source["sha256"] in row
            assert source["format"] in row
        if extra["notes"]:
            assert "Merged inputs" in row
    labelled = [text for text in texts if "host.example" in text]
    assert len(labelled) == 2
    assert any("variant 1 of 2" in text for text in labelled)
    assert any("variant 2 of 2" in text for text in labelled)
    assert any("machine ID" in text for text in labelled)
    assert any("self-asserted (no machine ID)" in text for text in labelled)
    assert any("Merged inputs" in text for text in labelled)
    view.assert_clean()


def test_special_outcomes_are_labelled(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, "outcomes"))
    view.tab("compliance")
    findings = view.page.locator(".data-table").filter(
        has=view.page.locator("caption", has_text="Findings")
    )
    select = findings.locator("select").nth(0)
    value = select.evaluate(
        "s => Array.from(s.options).find(o => o.text.endsWith('machine.json')).value"
    )
    select.select_option(value=value)
    text = findings.inner_text()
    for label in ("waived", "waiver active", "disabled", "notselected", "waiver expired", "fail"):
        assert label in text
    assert "linux_compliance_ssh_root_login" in text
    panel = view.page.locator("#panel-compliance").inner_text()
    assert "Not selected by the profile" in panel
    assert "never in the figures" in panel
    view.assert_clean()


def test_degraded_states_are_labelled_and_never_shown_as_passed(
    degraded: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(degraded, "degraded"))
    assert view.tab_names() == ["overview", "compliance", "tests", "lint", "raw"]
    tabs = view.page.locator("[role=tablist]").inner_text()
    assert "Tests (partial)" in tabs
    assert "Ansible lint (error)" in tabs
    overview = view.page.locator("#panel-overview").inner_text()
    assert "run failed" in overview
    assert "No pass percentage" in overview
    assert "partial: some inputs are missing" in overview
    assert "error: an input is invalid" in overview
    assert "Report types not supplied" in overview
    assert "Coverage" in overview
    text = visit_all(view)
    assert PERCENT.search(text) is None
    assert "all evaluated rules passed" not in text
    assert "run not completed: no figure is given" in text
    assert "absent.xml" in view.page.locator("#panel-tests").inner_text()
    assert "This section has no summary" in view.page.locator("#panel-lint").inner_text()
    view.assert_clean()


def test_all_passed_appears_only_when_the_report_says_so(
    all_passed: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
    copy_of: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    assert all_passed["sections"]["compliance"]["summary"]["assessment"] == "all_evaluated_passed"
    view = open_dashboard(render(all_passed, "all-pass"))
    text = visit_all(view)
    assert "all evaluated rules passed" in text
    assert "Pass percentage: 100.0 %" in text
    altered = copy_of(all_passed)
    altered["sections"]["compliance"]["summary"]["assessment"] = "findings_open"
    view = open_dashboard(render(altered, "altered"))
    assert "all evaluated rules passed" not in view.page.locator("#panel-overview").inner_text()
    view.assert_clean()
