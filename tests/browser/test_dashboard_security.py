from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from jsonschema import Draft202012Validator

from tools.reporting import dashboard

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.browser.conftest import Dashboard

SCHEMA = json.loads(
    (Path(dashboard.__file__).parent / "schema" / "report-v1.json").read_text(encoding="utf-8")
)
VALIDATOR: Any = Draft202012Validator(SCHEMA)
LONG = "W" * 4000
PAYLOADS = (
    "</script><script>window.__pwned = 1</script>",
    '<img src=x onerror="window.__pwned = 2">',
    "<!--<script>window.__pwned = 3</script>-->",
    "line\u2028separator\u2029paragraph </SCRIPT >",
    "&lt;b&gt;entity&lt;/b&gt; &amp; &#x3C;script&#x3E; &quot;",
    "\u202eesrever\u202c \u2066isolated\u2069 \u200fmark",
    "javascript:window.__pwned = 4",
    '" onmouseover="window.__pwned = 5" x="',
    "${window.__pwned = 6}{{constructor.constructor('window.__pwned = 7')()}}",
    "<svg/onload=window.__pwned=8><style>body{display:none}</style>",
    LONG,
)
FREE_TEXT = frozenset(
    {
        "path",
        "artifact",
        "message",
        "name",
        "classname",
        "rule_id",
        "benchmark_id",
        "profile_id",
        "content_version",
        "package",
        "version",
        "license",
        "platform",
        "build_id",
        "project",
        "artifact_id",
        "builder_type",
        "reason",
        "content",
        "source",
        "error_message",
        "vulnerability_id",
        "phase",
        "scanner_version",
        "spec_version",
    }
)
RENAMED_KEYS = frozenset({"license_counts", "custom_data"})


class Hostile:
    """Replace free-text values consistently, so joins between report parts still hold."""

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}

    def text(self, value: str) -> str:
        if value not in self.mapping:
            self.mapping[value] = (
                f"{PAYLOADS[len(self.mapping) % len(PAYLOADS)]}#{len(self.mapping)}"
            )
        return self.mapping[value]

    def walk(self, value: object, key: str = "") -> Any:
        if isinstance(value, dict):
            items = cast("dict[str, object]", value)
            if key in RENAMED_KEYS:
                return {self.text(name): self.walk(item, name) for name, item in items.items()}
            return {name: self.walk(item, name) for name, item in items.items()}
        if isinstance(value, list):
            entries = cast("list[object]", value)
            return [self.walk(item, key) for item in entries]
        if isinstance(value, str) and key in FREE_TEXT:
            return self.text(value)
        if isinstance(value, str) and key == "custom_data":
            return self.text(value)
        return value


def hostile_report(document: dict[str, Any]) -> dict[str, Any]:
    changed: dict[str, Any] = Hostile().walk(document)
    custom = changed["sections"]["packer"]["items"][0]["data"]["builds"][0]["custom_data"]
    custom.update({payload[:500]: payload[:500] for payload in PAYLOADS})
    return changed


def test_the_hostile_report_is_schema_valid(typical: dict[str, Any]) -> None:
    document = hostile_report(typical)
    assert [error.message[:200] for error in VALIDATOR.iter_errors(document)] == []
    text = json.dumps(document)
    assert "</script>" in text
    assert "\\u2028" in text


def test_hostile_report_data_never_executes_and_is_shown_as_text(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    path = render(hostile_report(typical), "hostile")
    html = path.read_text(encoding="utf-8")
    assert html.count("<script") == 2
    assert html.count("</script>") == 2
    view = open_dashboard(path)
    for name in view.tab_names():
        view.tab(name)
        for toggle in view.page.locator(f"#panel-{name} .details-toggle").all()[:3]:
            toggle.click()
    body = view.page.locator("body").text_content() or ""
    for payload in PAYLOADS[:-1]:
        assert payload in body
    assert LONG in body
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
    view.assert_clean()


def test_hostile_strings_do_not_break_the_layout(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    path = render(hostile_report(typical), "layout")
    for width in (1280, 375):
        view = open_dashboard(path, width=width)
        for name in view.tab_names():
            view.tab(name)
            overflow = view.page.evaluate(
                "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
            )
            assert overflow <= 0, f"{name} overflows by {overflow}px at {width}px"
            hidden = view.page.evaluate("() => getComputedStyle(document.body).display")
            assert hidden != "none"
        isolated = view.page.evaluate(
            "() => Array.from(document.querySelectorAll('bdi.v')).every("
            "node => getComputedStyle(node).unicodeBidi === 'isolate')"
        )
        assert isolated
        view.assert_clean()


def test_the_page_works_offline_from_a_file_url_without_requests(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    path = render(typical, "offline")
    view = open_dashboard(path)
    assert view.url.startswith("file://")
    for name in view.tab_names():
        view.tab(name)
    view.page.locator("#theme-toggle").click()
    view.page.evaluate("() => window.dispatchEvent(new Event('beforeprint'))")
    assert view.requests == [view.url]
    view.assert_clean()


def test_the_static_page_has_no_external_reference(
    typical: dict[str, Any], render: Callable[[dict[str, Any], str], Path]
) -> None:
    html = render(typical, "static").read_text(encoding="utf-8")
    shell = re.sub(r'(<script id="report-data" type="application/json">)[^<]*', r"\1", html)
    assert (
        re.search(r"(?i)(\b(?:https?|ftp|wss?|file|javascript):|//[a-z0-9]|@import|url\()", shell)
        is None
    )
    assert re.search(r"(?i)\s(on[a-z]+|href|src|style)=", shell) is None


def test_the_network_monitor_catches_a_request(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, "monitor"), bypass_csp=True)
    view.page.evaluate("() => fetch('https://example.invalid/beacon').catch(() => null)")
    view.page.wait_for_timeout(200)
    assert "https://example.invalid/beacon" in view.blocked


def test_the_csp_monitor_catches_a_violation(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    view = open_dashboard(render(typical, "csp"))
    assert view.violations() == []
    view.page.evaluate(
        "() => { const s = document.createElement('style'); s.textContent = 'body{color:red}';"
        " document.head.appendChild(s); }"
    )
    view.page.evaluate("() => { try { document.body.innerHTML = '<b>x</b>'; } catch (e) {} }")
    view.page.wait_for_timeout(200)
    directives = " ".join(view.violations())
    assert "style-src" in directives
    assert "require-trusted-types-for" in directives


def test_the_policy_blocks_inline_code_that_is_not_hashed(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
) -> None:
    path = render(typical, "inline")
    html = path.read_text(encoding="utf-8")
    tampered = html.replace("<footer", '<p id="probe" onclick="window.__pwned = 9">x</p><footer', 1)
    tampered = tampered.replace("<script>", "<script>window.__pwned = 10;", 1)
    path.write_text(tampered, encoding="utf-8")
    view = open_dashboard(path, wait=False)
    view.page.locator("#probe").click()
    view.page.wait_for_timeout(200)
    assert view.page.evaluate("() => window.__pwned") is None
    assert view.page.locator("[role=tablist]").count() == 0
    assert len([line for line in view.violations() if "script-src" in line]) >= 2
