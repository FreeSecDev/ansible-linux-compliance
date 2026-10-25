from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator

from tools.reporting import dashboard
from tools.reporting.dashboard import MAX_EMBEDDED_BYTES, dashboard_views, embed_json

if TYPE_CHECKING:
    from collections.abc import Callable

    from playwright.sync_api import Locator
    from tests.browser.conftest import Dashboard

RULES_PER_INPUT = 152
LOAD_SECONDS = 60.0
ACTION_SECONDS = 10.0
SCHEMA = json.loads(
    (Path(dashboard.__file__).parent / "schema" / "report-v1.json").read_text(encoding="utf-8")
)


@pytest.fixture(scope="module")
def maximum(
    tmp_path_factory: pytest.TempPathFactory, build_maximum: Callable[[Path, int], dict[str, Any]]
) -> tuple[dict[str, Any], Path]:
    directory = tmp_path_factory.mktemp("maximum")
    document = build_maximum(directory, RULES_PER_INPUT)
    path = directory / "maximum.html"
    path.write_text(dashboard.render_dashboard(document), encoding="utf-8")
    return document, path


def timed(action: Callable[[], object]) -> float:
    began = time.monotonic()
    action()
    return time.monotonic() - began


def table(view: Dashboard, panel: str, caption: str) -> Locator:
    return (
        view.page.locator(f"#panel-{panel} .data-table")
        .filter(has=view.page.locator("caption", has_text=caption))
        .first
    )


def test_the_generator_writes_schema_valid_reports(
    tmp_path: Path, build_maximum: Callable[[Path, int], dict[str, Any]]
) -> None:
    document = build_maximum(tmp_path, 2)
    validator: Any = Draft202012Validator(SCHEMA)
    assert [error.message[:200] for error in validator.iter_errors(document)] == []


def test_the_maximum_fixture_fills_the_list_limits_and_the_size_cap(
    maximum: tuple[dict[str, Any], Path],
) -> None:
    document, path = maximum
    sections = document["sections"]
    assert {name: len(section["items"]) for name, section in sections.items()} == dict.fromkeys(
        sections, 1000
    )
    assert len(document["raw_artifacts"]) == 9000
    compliance = sections["compliance"]
    assert len(compliance["rules"]) > 140_000
    assert compliance["notes"]
    truncated = [
        name
        for name, section in sections.items()
        if any(item["data"].get("truncated") for item in section["items"])
    ]
    assert sorted(truncated) == ["coverage", "lint", "sbom", "tests", "vulnerabilities"]
    embedded = len(embed_json({"report": document, "views": dashboard_views(document)}))
    assert 0.9 * MAX_EMBEDDED_BYTES < embedded <= MAX_EMBEDDED_BYTES
    assert path.stat().st_size > embedded


def test_the_maximum_fixture_stays_responsive(
    maximum: tuple[dict[str, Any], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    _, path = maximum
    began = time.monotonic()
    view = open_dashboard(path, timeout=LOAD_SECONDS * 1000)
    loaded = time.monotonic() - began
    assert loaded < LOAD_SECONDS
    view.page.set_default_timeout(ACTION_SECONDS * 1000)
    timings = {"compliance tab": timed(lambda: view.tab("compliance"))}
    timings.update(exercise_rules(view))
    for name in ("tests", "lint", "sbom", "raw"):
        began = time.monotonic()
        view.tab(name)
        timings[f"{name} tab"] = time.monotonic() - began
    slow = {
        name: round(seconds, 2) for name, seconds in timings.items() if seconds > ACTION_SECONDS
    }
    assert slow == {}
    nodes = view.page.evaluate("() => document.getElementsByTagName('*').length")
    assert nodes < 60_000
    view.assert_clean()


def exercise_rules(view: Dashboard) -> dict[str, float]:
    page = view.page
    timings: dict[str, float] = {}
    rules = table(view, "compliance", "Rules")
    status = rules.locator(".table-status")
    assert rules.locator("tbody > tr").count() == 25
    assert "of 1" in status.inner_text()
    outcome = rules.locator("th", has=page.locator("button", has_text="Outcome")).locator("button")
    timings["sort"] = timed(outcome.click)
    assert rules.locator("tbody > tr").first.locator(".badge").nth(-1).count() == 1
    timings["sort again"] = timed(outcome.click)
    size = rules.locator("select").last
    timings["500 rows"] = timed(lambda: size.select_option(value="500"))
    assert rules.locator("tbody > tr").count() == 500
    timings["last page"] = timed(rules.locator("button", has_text="Last page").click)
    host = rules.locator("select").first
    second = host.evaluate("s => s.options[2].value")
    timings["filter"] = timed(lambda: host.select_option(value=second))
    before = status.inner_text()
    search = rules.locator("input[type=search]")

    def find() -> None:
        search.fill("r000042")
        page.wait_for_function(
            "([node, previous]) => node.textContent !== previous",
            arg=[status.element_handle(), before],
        )

    timings["search"] = timed(find)
    assert "of 1 matching rows" in status.inner_text()
    return timings
