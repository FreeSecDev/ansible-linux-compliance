from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
)
from tools.reporting import dashboard

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.browser.conftest import Dashboard

SCHEMA = json.loads(
    (Path(dashboard.__file__).parent / "schema" / "report-v2.json").read_text(encoding="utf-8")
)
VALIDATOR: Any = Draft202012Validator(SCHEMA)
LONG = "J" * 4000
PAYLOADS = (
    "</script><script>window.__pwned = 1</script>",
    '<img src=x onerror="window.__pwned = 2">',
    "<!--<script>window.__pwned = 3</script>-->",
    "line\u2028separator\u2029paragraph </SCRIPT >",
    "&lt;b&gt;entity&lt;/b&gt; &amp; &#x3C;script&#x3E; &quot;",
    "\u202eesrever\u202c \u2066isolated\u2069 \u200fmark",
    '" onmouseover="window.__pwned = 5" x="',
    "${window.__pwned = 6}{{constructor.constructor('window.__pwned = 7')()}}",
    "all controls compliant (100%)\nApproved by the auditor.",
)

REVIEW_LABELS = {
    "expired": "expired: a failure it covered is no longer waived",
    "in_effect": "in effect: waives a failure",
    "not_yet_effective": "not yet in effect",
    "superseded": "superseded: another exception was chosen",
    "not_failing": "not failing: the rule did not fail where the scope matched",
    "stale": "stale: the rule or scope matched nothing",
}


def exceptions_table(view: Dashboard) -> Any:
    view.tab("exceptions")
    return (
        view.page.locator(".data-table")
        .filter(has=view.page.locator("caption", has_text="Exceptions"))
        .first
    )


def expand_all(table: Any) -> None:
    while True:
        closed = table.locator(".details-toggle[aria-expanded=false]")
        if closed.count() == 0:
            return
        closed.first.click()


def test_every_exception_is_listed_with_its_review_and_details(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    section = typical["sections"]["exceptions"]
    view = open_dashboard(render(typical, "exceptions"))
    assert "exceptions" in view.tab_names()
    table = exceptions_table(view)
    text = table.inner_text()
    for entry in section["exceptions"]:
        assert entry["id"] in text
        assert REVIEW_LABELS[entry["status"]] in text
    assert text.count("removal candidate") >= section["summary"]["removal_candidates"]
    assert "expiry passed" in text
    expand_all(table)
    details = table.inner_text()
    for entry in section["exceptions"]:
        assert entry["justification"] in details
        assert entry["owner"] in details
        assert entry["approver"] in details
    assert section["source_sha256"] in details
    assert "superseded" in details
    panel = view.page.locator("#panel-exceptions").inner_text()
    assert "Nothing on this tab changes a compliance figure" in panel
    assert "every evaluation verified against this file" in panel
    assert section["exceptions_file"]["path"] in panel
    assert section["exceptions_file"]["sha256"] in panel
    assert "inventory names" in panel
    assert "web01.example" not in table.inner_text()
    view.assert_clean()


def test_the_overview_shows_stale_and_expired_counts_without_a_figure(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    summary = typical["overview"]["exceptions"]
    view = open_dashboard(render(typical, "overview-exceptions"))
    overview = view.page.locator("#panel-overview").inner_text()
    assert f"Stale (matched nothing)\n{summary['by_status']['stale']}" in overview
    assert (
        f"Expired (a covered failure is no longer waived)\n{summary['by_status']['expired']}"
        in (overview)
    )
    assert f"Removal candidates\n{summary['removal_candidates']}" in overview
    assert "These counts do not change any figure" in overview
    view.assert_clean()


def test_without_an_evaluation_the_overview_says_nothing_about_exceptions(
    degraded: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(degraded, "no-exceptions"))
    assert "exceptions" not in view.tab_names()
    overview = view.page.locator("#panel-overview").inner_text()
    assert "No exceptions evaluation was supplied" in overview
    view.assert_clean()


def hostile_justifications(document: dict[str, Any], copy_of: Callable[..., Any]) -> Any:
    changed = copy_of(document)
    for index, entry in enumerate(changed["sections"]["exceptions"]["exceptions"]):
        entry["justification"] = f"{PAYLOADS[index % len(PAYLOADS)]}#{index}"
    changed["sections"]["exceptions"]["exceptions"][-1]["justification"] = LONG
    return changed


def test_hostile_justification_text_never_executes_and_is_shown_as_text(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
    copy_of: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    document = hostile_justifications(typical, copy_of)
    assert list(VALIDATOR.iter_errors(document)) == []
    path = render(document, "hostile-justification")
    html = path.read_text(encoding="utf-8")
    assert html.count("<script") == 2
    assert html.count("</script>") == 2
    for width in (1280, 375):
        view = open_dashboard(path, width=width)
        table = exceptions_table(view)
        expand_all(table)
        text = table.text_content() or ""
        for entry in document["sections"]["exceptions"]["exceptions"]:
            assert entry["justification"] in text
        counts = view.page.evaluate(
            """() => ({
                scripts: document.scripts.length,
                images: document.querySelectorAll("img, svg, iframe, object, embed").length,
                links: document.querySelectorAll("a, [href], [src]").length,
                handlers: Array.from(document.querySelectorAll("*")).filter(
                    node => Array.from(node.attributes).some(a => a.name.startsWith("on"))).length,
                styles: document.querySelectorAll("style").length
            })"""
        )
        assert counts == {"scripts": 2, "images": 0, "links": 0, "handlers": 0, "styles": 1}
        overflow = view.page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        assert overflow <= 0
        view.assert_clean()


def test_an_exceptions_file_at_its_limit_stays_responsive(
    exceptions_limit: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    document = exceptions_limit
    assert list(VALIDATOR.iter_errors(document)) == []
    section = document["sections"]["exceptions"]
    assert len(section["exceptions"]) == exceptions.MAX_EXCEPTIONS
    assert section["summary"]["removal_candidates"] > 0
    view = open_dashboard(render(document, "exceptions-limit"))
    began = time.monotonic()
    table = exceptions_table(view)
    assert table.locator("tbody > tr").count() == 25
    review = table.locator("th", has=view.page.locator("button", has_text="Review")).locator(
        "button"
    )
    review.click()
    size = table.locator("select").last
    size.select_option(value="500")
    assert table.locator("tbody > tr").count() == 500
    assert time.monotonic() - began < 10.0
    view.assert_clean()


def test_the_exceptions_tab_passes_axe_with_details_open(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    for scheme in ("light", "dark"):
        view = open_dashboard(render(typical, f"axe-exceptions-{scheme}"), color_scheme=scheme)
        table = exceptions_table(view)
        expand_all(table)
        violations = [
            violation
            for violation in view.run_axe()
            if violation["impact"] in {"serious", "critical"}
            or violation["id"] == "landmark-unique"
        ]
        assert violations == []
        view.assert_clean()
