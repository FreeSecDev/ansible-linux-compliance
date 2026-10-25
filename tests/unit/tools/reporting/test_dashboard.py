from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import cli, compliance, dashboard
from tools.reporting.common import dumps
from tools.reporting.dashboard import DashboardError
from tools.reporting.parsers.scanrun import parse_scan_run
from tools.reporting.parsers.xccdf import parse_xccdf
from tools.reporting.report import ReportInputs, Scope, build_report

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

HOSTILE = (
    "</script><script>alert(1)</script>",
    "<!--",
    "]]>",
    "a & b > c < d",
    "\u2028\u2029",
    "\u202e\u2066bidi\u2069",
    "&lt;&amp;&#60;",
    '"quoted" \\ backslash',
    "\u00e9 \u2713 \U0001f9ea",
)
MACHINE_ID = "0123456789abcdef0123456789abcdef"
DATA_BLOCK = re.compile(r'<script id="report-data" type="application/json">([^<]*)</script>')


def build(**inputs: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(dumps(build_report(ReportInputs(**inputs))))
    return document


def embedded(html: str) -> dict[str, Any]:
    match = DATA_BLOCK.search(html)
    assert match is not None
    loaded: dict[str, Any] = json.loads(match.group(1))
    return loaded


def inline(html: str, tag: str) -> str:
    match = re.search(rf"<{tag}>(.*?)</{tag}>", html, re.DOTALL)
    assert match is not None
    return match.group(1)


@pytest.mark.parametrize("text", HOSTILE)
def test_embed_json_escapes_markup_and_line_separators(text: str) -> None:
    document: Any = {"value": text, text: [text, {"nested": text}]}
    result = dashboard.embed_json(document)
    for character in ("<", ">", "&", "\u2028", "\u2029"):
        assert character not in result
    assert result.isascii()
    assert json.loads(result) == document


def test_embed_json_is_compact_sorted_and_strict() -> None:
    assert dashboard.embed_json({"b": 1, "a": [True, None, 1.5]}) == '{"a":[true,null,1.5],"b":1}'
    assert dashboard.embed_json("<&>") == '"\\u003c\\u0026\\u003e"'
    with pytest.raises(ValueError, match="Out of range"):
        dashboard.embed_json(float("nan"))


def test_csp_hash_is_the_base64_sha256_of_the_utf8_text() -> None:
    assert dashboard.csp_hash("") == "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"
    text = 'body { content: "\u00e9"; }'
    digest = base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")
    assert dashboard.csp_hash(text) == f"'sha256-{digest}'"


def test_the_policy_allows_only_the_hashed_script_and_style() -> None:
    policy = dashboard.content_security_policy("s", "t")
    assert policy == (
        f"default-src 'none'; script-src {dashboard.csp_hash('s')}; "
        f"style-src {dashboard.csp_hash('t')}; base-uri 'none'; form-action 'none'; "
        "require-trusted-types-for 'script'; trusted-types 'none'"
    )
    assert "unsafe" not in policy


@pytest.mark.parametrize(
    "content", ["a</script>b", "a</STYLE>", "<!-- x", "x<Script src=y>", "</script >"]
)
def test_assets_that_could_close_their_element_are_rejected(content: str) -> None:
    with pytest.raises(DashboardError, match=r"asset demo\.js contains"):
        dashboard.check_asset("demo.js", content)


def test_the_shipped_assets_pass_the_check_and_hold_no_external_reference() -> None:
    for name in (dashboard.SCRIPT_ASSET, dashboard.STYLE_ASSET):
        content = dashboard.load_asset(name)
        assert re.search(r"(?i)\b(?:https?|ftp|wss?|javascript):|@import|url\(", content) is None
    script = dashboard.load_asset(dashboard.SCRIPT_ASSET)
    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "Function(",
    ):
        assert sink not in script
    assert ".href" not in script
    assert 'setAttribute("style' not in script


def test_the_rendered_policy_matches_the_inline_script_and_style(kit: Any) -> None:
    html = dashboard.render_dashboard(
        build(scope=Scope.FLEET, junit=(kit.REPORTING / "junit.xml",))
    )
    script = inline(html, "script")
    style = inline(html, "style")
    policy = dashboard.content_security_policy(script, style)
    assert f'<meta http-equiv="Content-Security-Policy" content="{policy}">' in html
    assert html.index("Content-Security-Policy") < html.index("<style>")
    assert html.count("<script") == 2
    assert script == dashboard.load_asset(dashboard.SCRIPT_ASSET)


def test_rendering_is_deterministic(kit: Any) -> None:
    sboms = (kit.REPORTING / "spdx.json", kit.REPORTING / "cyclonedx.json")
    document = build(scope=Scope.FLEET, sbom=sboms, junit=(kit.REPORTING / "junit.xml",))
    again = build(scope=Scope.FLEET, sbom=sboms, junit=(kit.REPORTING / "junit.xml",))
    html = dashboard.render_dashboard(document)
    assert html == dashboard.render_dashboard(again)
    assert html == dashboard.render_dashboard(json.loads(json.dumps(document)))
    shuffled = dict(reversed(list(document.items())))
    assert html == dashboard.render_dashboard(shuffled)


def test_hostile_report_text_cannot_escape_the_data_block(kit: Any) -> None:
    document = build(scope=Scope.FLEET, junit=(kit.REPORTING / "junit.xml",))
    document["sections"]["tests"]["items"][0]["artifact"]["path"] = "".join(HOSTILE)
    document["raw_artifacts"][0]["path"] = "</script><script>alert(1)</script>"
    html = dashboard.render_dashboard(document)
    assert html.count("</script>") == 2
    assert embedded(html)["report"] == document


def test_unsupported_schema_versions_are_refused() -> None:
    with pytest.raises(DashboardError, match="schema version"):
        dashboard.render_dashboard({"schema_version": "2.0"})
    with pytest.raises(DashboardError, match="schema version"):
        dashboard.render_dashboard({"schema_version": 1})
    with pytest.raises(DashboardError, match="schema version"):
        dashboard.render_dashboard({})


def test_a_report_above_the_size_cap_is_refused(kit: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    document = build(scope=Scope.FLEET, junit=(kit.REPORTING / "junit.xml",))
    monkeypatch.setattr(dashboard, "MAX_EMBEDDED_BYTES", 100)
    with pytest.raises(DashboardError, match="too large"):
        dashboard.render_dashboard(document)


def test_a_report_without_sections_renders_with_an_empty_view() -> None:
    document: dict[str, Any] = {"schema_version": "1.0"}
    assert dashboard.dashboard_views(document) == {"groups": [], "hosts": []}
    assert embedded(dashboard.render_dashboard(document))["views"] == {"groups": [], "hosts": []}


def shared_label_report(
    kit: Any, write: Callable[[str, str | bytes], Path], write_run: Callable[..., Path]
) -> dict[str, Any]:
    identified = model.HostIdentity("web01", "rhel", "9", "x86_64", MACHINE_ID)
    run = write_run("run.json", kit.scan_run((kit.finding("a"),), host=identified))
    first = write("first.xml", kit.xccdf_text("WEB01", "fail"))
    second = write("second.xml", kit.xccdf_text("web01", "pass", results=[("b", "pass")]))
    unnamed = write("unnamed.xml", kit.xccdf_text(None, "pass"))
    missing = write("missing.xml", "<broken")
    document = build(scope=Scope.FLEET, xccdf=(first, second, unnamed), scan_run=(run,))
    document["sections"]["compliance"]["items"].append(
        {
            "artifact": {"path": str(missing), "sha256": None, "size": None},
            "data": None,
            "format": "xccdf",
            "reason": "x",
            "status": "error",
        }
    )
    return document


def test_views_join_each_group_to_its_inputs_notes_and_identity(
    kit: Any, write: Callable[[str, str | bytes], Path], write_run: Callable[..., Path]
) -> None:
    document = shared_label_report(kit, write, write_run)
    section = document["sections"]["compliance"]
    views: Any = dashboard.dashboard_views(document)
    by_sha = {item["artifact"]["sha256"]: item for item in section["items"] if item["data"]}
    assert len(views["groups"]) == len(section["groups"]) == 3
    for group, view in zip(section["groups"], views["groups"], strict=True):
        assert view["sources"]
        for source in view["sources"]:
            item = by_sha[source["sha256"]]
            assert source == {
                "format": item["format"],
                "path": item["artifact"]["path"],
                "sha256": item["artifact"]["sha256"],
            }
            assert dashboard.item_host(item["data"]) == dashboard.key_of(group["host"])
        merged = group["host"]["hostname"] == "web01" and group["host"]["machine_id"] is None
        assert (view["notes"] == [0]) is merged
        assert len(view["sources"]) == (2 if merged else 1)
    assert section["notes"][0]["host"] == "web01"
    hosts = {(host["hostname"], host["machine_id"]): host for host in views["hosts"]}
    assert hosts["web01", MACHINE_ID]["identity"] == "machine_id"
    assert hosts["web01", None]["identity"] == "self_asserted"
    assert {hosts["web01", MACHINE_ID]["variant"], hosts["web01", None]["variant"]} == {1, 2}
    assert hosts["web01", None]["variants"] == 2
    unnamed = hosts[None, None]
    assert unnamed["identity"] == "unnamed"
    assert unnamed["input_sha256"] is not None
    assert (unnamed["variant"], unnamed["variants"]) == (1, 1)


def test_item_host_matches_the_report_host_key(
    kit: Any, write: Callable[[str, str | bytes], Path], write_run: Callable[..., Path]
) -> None:
    identified = model.HostIdentity("Web02", "rhel", "9", "x86_64", MACHINE_ID)
    paths = {
        "scan_run": (write_run("r.json", kit.scan_run((kit.finding("a"),), host=identified)),),
        "xccdf": (write("n.xml", kit.xccdf_text("Named")), write("u.xml", kit.xccdf_text(None))),
    }
    document = build(scope=Scope.FLEET, **paths)
    parsed = [parse_scan_run(paths["scan_run"][0], 10**6)] + [
        parse_xccdf(path, 10**6) for path in paths["xccdf"]
    ]
    expected: set[tuple[str, str, str]] = set()
    for result in parsed:
        assert result.data is not None
        key = compliance.host_key(result.data)
        expected.add((key.hostname, key.machine_id, key.input_sha256))
    items = document["sections"]["compliance"]["items"]
    assert {dashboard.item_host(item["data"]) for item in items} == expected
    groups = document["sections"]["compliance"]["groups"]
    assert {dashboard.key_of(group["host"]) for group in groups} == expected


def test_cli_writes_the_dashboard_next_to_the_report(
    kit: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "report.json"
    html = tmp_path / "html" / "report.html"
    argv = ["--scope", "fleet", "--output", str(output), "--html", str(html)]
    status = cli.main([*argv, "--junit", str(kit.REPORTING / "junit.xml")])
    assert status == 0
    out = capsys.readouterr().out
    assert f"report written to {output}" in out
    assert f"dashboard written to {html}" in out
    document = json.loads(output.read_text(encoding="utf-8"))
    assert html.read_text(encoding="utf-8") == dashboard.render_dashboard(document)


def test_cli_writes_nothing_when_the_dashboard_cannot_be_rendered(
    kit: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(dashboard, "MAX_EMBEDDED_BYTES", 10)
    output = tmp_path / "report.json"
    html = tmp_path / "report.html"
    argv = ["--scope", "fleet", "--output", str(output), "--html", str(html)]
    assert cli.main([*argv, "--junit", str(kit.REPORTING / "junit.xml")]) == 2
    assert "too large for the dashboard" in capsys.readouterr().err
    assert not output.exists()
    assert not html.exists()


def test_cli_reports_an_unwritable_dashboard(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    argv = ["--scope", "fleet", "--output", str(tmp_path / "r.json"), "--html", str(blocker / "x")]
    assert cli.main(argv) == 2
    assert "cannot write the dashboard" in capsys.readouterr().err
