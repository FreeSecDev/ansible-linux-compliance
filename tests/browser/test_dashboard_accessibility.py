from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from playwright.sync_api import Locator
    from tests.browser.conftest import Dashboard

BLOCKING = frozenset({"serious", "critical"})
ALWAYS_BLOCKING = frozenset({"landmark-unique"})
LIGHT_BACKGROUND = "rgb(255, 255, 255)"
DARK_BACKGROUND = "rgb(17, 20, 24)"


def blocking(violations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        violation
        for violation in violations
        if violation["impact"] in BLOCKING or violation["id"] in ALWAYS_BLOCKING
    ]


def background(view: Dashboard) -> str:
    color: str = view.page.evaluate("() => getComputedStyle(document.body).backgroundColor")
    return color


def active_tab(view: Dashboard) -> str:
    selected: str = view.page.evaluate(
        "() => document.querySelector('[role=tab][aria-selected=true]').id"
    )
    return selected


def focused(view: Dashboard) -> str:
    identifier: str = view.page.evaluate("() => document.activeElement.id")
    return identifier


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_axe_finds_no_serious_violation_on_any_tab(
    scheme: str,
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, f"axe-{scheme}"), color_scheme=scheme)
    expected = DARK_BACKGROUND if scheme == "dark" else LIGHT_BACKGROUND
    assert background(view) == expected
    failures: dict[str, list[dict[str, Any]]] = {}
    for name in view.tab_names():
        view.tab(name)
        toggles = view.page.locator(f"#panel-{name} .details-toggle")
        for index in range(min(3, toggles.count())):
            toggles.nth(index).click()
        found = blocking(view.run_axe())
        if found:
            failures[name] = found
    assert failures == {}
    view.assert_clean()


def test_axe_finds_no_serious_violation_in_degraded_states(
    degraded: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    for scheme in ("light", "dark"):
        view = open_dashboard(render(degraded, f"degraded-{scheme}"), color_scheme=scheme)
        for name in view.tab_names():
            view.tab(name)
            assert blocking(view.run_axe()) == [], name
        view.assert_clean()


def test_the_theme_toggle_switches_both_ways_and_stays_accessible(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, "toggle"), color_scheme="dark")
    toggle = view.page.locator("#theme-toggle")
    assert toggle.inner_text() == "Use light theme"
    toggle.focus()
    view.page.keyboard.press("Enter")
    assert background(view) == LIGHT_BACKGROUND
    assert toggle.inner_text() == "Use dark theme"
    assert toggle.get_attribute("aria-label") == "Theme is light. Use dark theme"
    assert blocking(view.run_axe()) == []
    view.page.keyboard.press("Space")
    assert background(view) == DARK_BACKGROUND
    view.tab("compliance")
    assert blocking(view.run_axe()) == []
    view.assert_clean()


def test_tabs_follow_the_aria_tabs_pattern_with_the_keyboard(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, "tabs"))
    page = view.page
    names = view.tab_names()
    assert names[0] == "overview"
    assert names[-1] == "raw"
    assert page.locator("[role=tablist]").get_attribute("aria-label") == "Report sections"
    page.locator("#theme-toggle").focus()
    page.keyboard.press("Tab")
    assert focused(view) == "tab-overview"
    page.keyboard.press("ArrowRight")
    assert focused(view) == f"tab-{names[1]}"
    assert active_tab(view) == f"tab-{names[1]}"
    assert page.locator(f"#panel-{names[1]}").is_visible()
    assert page.locator("#panel-overview").is_hidden()
    page.keyboard.press("End")
    assert focused(view) == "tab-raw"
    page.keyboard.press("ArrowRight")
    assert focused(view) == "tab-overview"
    page.keyboard.press("ArrowLeft")
    assert active_tab(view) == "tab-raw"
    page.keyboard.press("Home")
    assert active_tab(view) == "tab-overview"
    stops = page.eval_on_selector_all(
        "[role=tab]", "tabs => tabs.filter(t => t.getAttribute('tabindex') === '0').length"
    )
    assert stops == 1
    for name in names:
        tab = page.locator(f"#tab-{name}")
        assert tab.get_attribute("aria-controls") == f"panel-{name}"
        assert page.locator(f"#panel-{name}").get_attribute("aria-labelledby") == f"tab-{name}"
    page.keyboard.press("Tab")
    assert focused(view) == "panel-overview"
    view.assert_clean()


def test_the_focus_indicator_is_visible(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, "focus"))
    view.page.locator("#theme-toggle").focus()
    view.page.keyboard.press("Tab")
    outline = view.page.evaluate(
        "() => { const s = getComputedStyle(document.activeElement);"
        " return [s.outlineStyle, s.outlineWidth]; }"
    )
    assert outline == ["solid", "3px"]


def test_tables_sort_page_and_expand_with_the_keyboard(
    many_rules: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(many_rules, "table"))
    page = view.page
    view.tab("compliance")
    table = (
        page.locator("#panel-compliance .data-table")
        .filter(has=page.locator("caption", has_text="Rules"))
        .first
    )
    header = table.locator("th", has=page.locator("button", has_text="Rule ID"))
    first_cell = table.locator("tbody tr").first.locator("td").nth(1)
    assert header.get_attribute("aria-sort") == "none"
    header.locator("button").focus()
    page.keyboard.press("Enter")
    assert header.get_attribute("aria-sort") == "ascending"
    ascending = first_cell.inner_text()
    page.keyboard.press("Enter")
    assert header.get_attribute("aria-sort") == "descending"
    assert first_cell.inner_text() != ascending
    page.keyboard.press("Space")
    assert header.get_attribute("aria-sort") == "ascending"
    assert first_cell.inner_text() == ascending
    others = table.locator("th[aria-sort=ascending], th[aria-sort=descending]")
    assert others.count() == 1
    assert table.locator("tbody > tr").count() == 25
    pager = table.locator(".pager")
    assert "Page 1 of" in pager.inner_text()
    pager.locator("button", has_text="Next page").focus()
    page.keyboard.press("Enter")
    assert "Page 2 of" in pager.inner_text()
    assert table.locator("tbody > tr").first.locator("td").nth(1).inner_text() != ascending
    pager.locator("button", has_text="First page").focus()
    page.keyboard.press("Enter")
    toggle = table.locator(".details-toggle").first
    toggle.focus()
    page.keyboard.press("Enter")
    toggle = table.locator(".details-toggle").first
    assert toggle.get_attribute("aria-expanded") == "true"
    assert page.evaluate("() => document.activeElement.getAttribute('aria-expanded')") == "true"
    detail = page.locator(f"#{toggle.get_attribute('aria-controls')}")
    assert detail.is_visible()
    assert "Sources of" in detail.inner_text()
    page.keyboard.press("Enter")
    assert table.locator(".details-toggle").first.get_attribute("aria-expanded") == "false"
    search = table.locator("input[type=search]")
    search.focus()
    page.keyboard.type("r000007")
    page.wait_for_timeout(400)
    assert "of 2 matching rows" in table.locator(".table-status").inner_text()
    view.assert_clean()


def test_status_is_never_conveyed_by_colour_alone(
    degraded: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(degraded, "words"))
    for name in view.tab_names():
        view.tab(name)
    empty = view.page.evaluate(
        "() => Array.from(document.querySelectorAll('.badge'))"
        ".filter(b => b.textContent.trim() === '').length"
    )
    assert empty == 0
    styles = view.page.evaluate(
        "() => Array.from(new Set(Array.from(document.querySelectorAll('.badge'))"
        ".map(b => b.className + ' ' + getComputedStyle(b).borderStyle))).sort()"
    )
    assert any("tone-bad" in style and "solid" in style for style in styles)
    assert any("tone-warn" in style and "dashed" in style for style in styles)
    view.assert_clean()


@pytest.mark.parametrize(("scheme", "toggle"), [("dark", False), ("light", True), ("dark", True)])
def test_print_uses_the_light_palette_whatever_the_theme(
    scheme: str,
    toggle: bool,
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, f"print-{scheme}-{toggle}"), color_scheme=scheme)
    if toggle:
        view.page.locator("#theme-toggle").click()
    view.page.emulate_media(media="print")
    colours = view.page.evaluate(
        """() => {
            const body = getComputedStyle(document.body);
            const badge = getComputedStyle(document.querySelector('.badge'));
            return [body.color, body.backgroundColor, badge.color];
        }"""
    )
    assert colours == ["rgb(0, 0, 0)", LIGHT_BACKGROUND, "rgb(0, 0, 0)"]
    view.assert_clean()


def test_print_view_shows_every_panel_without_controls(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, "print"))
    view.page.evaluate("() => window.dispatchEvent(new Event('beforeprint'))")
    view.page.emulate_media(media="print")
    state = view.page.evaluate(
        """() => ({
            panels: Array.from(document.querySelectorAll('[role=tabpanel]')).map(
                p => [getComputedStyle(p).display, p.textContent.length > 0]),
            tabs: getComputedStyle(document.querySelector('[role=tablist]')).display,
            toggle: getComputedStyle(document.querySelector('#theme-toggle')).display,
            controls: Array.from(document.querySelectorAll('.controls, .pager')).every(
                c => getComputedStyle(c).display === 'none')
        })"""
    )
    assert all(panel == ["block", True] for panel in state["panels"])
    assert state["tabs"] == "none"
    assert state["toggle"] == "none"
    assert state["controls"]
    view.assert_clean()


def own_table(view: Dashboard, caption: str) -> Locator:
    exact = re.compile(f"^{re.escape(caption)}$")
    caption_of = view.page.locator(":scope > .table-wrap > table > caption", has_text=exact)
    return view.page.locator("#panel-compliance .data-table").filter(has=caption_of).first


def region_labels(view: Dashboard) -> list[str]:
    labels: list[str] = view.page.eval_on_selector_all(
        "[role=region]", "nodes => nodes.map(node => node.getAttribute('aria-label'))"
    )
    return labels


def test_region_labels_are_unique_meaningful_and_stable_across_redraws(
    many_rules: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(many_rules, "labels"))
    for name in view.tab_names():
        view.tab(name)
    view.tab("compliance")
    for caption in ("Host groups", "Rules"):
        own_table(view, caption).locator(".details-toggle").first.click()
    before = region_labels(view)
    assert len(before) == len(set(before))
    assert not [label for label in before if re.search(r"\(\d+\)$", label)]
    assert "Compliance: Rules" in before
    assert "Compliance: Host groups, row 1: rules per outcome" in before
    assert "Compliance: Rules, row 1: sources" in before
    rules = own_table(view, "Rules")
    size = rules.locator("select").last
    size.select_option(value="100")
    size.select_option(value="25")
    rules.locator(".details-toggle").nth(1).click()
    rules.locator(".details-toggle").nth(1).click()
    assert region_labels(view) == before
    assert blocking(view.run_axe()) == []
    view.assert_clean()
