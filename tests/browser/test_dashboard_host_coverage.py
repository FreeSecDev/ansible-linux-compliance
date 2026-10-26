from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tests.browser.test_dashboard_accessibility import blocking

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from tests.browser.conftest import Dashboard

HOSTILE_PATH = "/srv/<script>alert(1)</script>/collection-20261026T080001.234567Z.json"


def missing_hosts(document: dict[str, Any]) -> dict[str, Any]:
    compliance = document["sections"]["compliance"]
    compliance.update({"aggregates": [], "groups": [], "notes": [], "rules": [], "summary": None})
    compliance["status"] = "partial"
    compliance["reason"] = "2 of 3 input(s) are missing and 0 are invalid"
    hosts = [
        {
            "host": "lost01",
            "in_report": False,
            "manifest_sha256": None,
            "run_id": None,
            "status": "unreachable",
        },
        {
            "host": "web01",
            "in_report": True,
            "manifest_sha256": "a" * 64,
            "run_id": "run-web01",
            "status": "collected",
        },
        {
            "host": "db01",
            "in_report": False,
            "manifest_sha256": "b" * 64,
            "run_id": "run-db01",
            "status": "collected",
        },
    ]
    compliance["host_coverage"] = {
        "collection": {
            "collected_at": "2026-10-26T08:00:01Z",
            "collection_id": "20261026T080001.234567Z",
            "path": HOSTILE_PATH,
            "sha256": "c" * 64,
            "size": 958,
        },
        "hosts": hosts,
        "reason": "2 of 3 target host(s) have no evidence bundle in this report",
        "status": "incomplete",
        "summary": {
            "by_status": {
                "collected": 2,
                "collection_failed": 0,
                "limited_out": 0,
                "no_audit_result": 0,
                "no_evidence_written": 0,
                "unreachable": 1,
            },
            "in_report": 1,
            "missing": 2,
            "target_hosts": 3,
        },
    }
    document["overview"]["available"].remove("compliance")
    document["overview"]["partial"].append("compliance")
    return document


def test_missing_hosts_are_named_on_the_overview_and_the_compliance_tab(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
    copy_of: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    view = open_dashboard(render(missing_hosts(copy_of(typical)), "missing-hosts"))
    overview = view.page.locator("#panel-overview").inner_text()
    assert "Target hosts are missing from this report." in overview
    assert "lost01: unreachable: did not complete fact gathering" in overview
    assert "db01: collected as run run-db01, but that bundle is not in this report" in overview
    assert (
        "web01"
        not in overview.split("Target hosts are missing from this report.")[1].split(
            "Compliance result"
        )[0]
    )
    view.tab("compliance")
    panel = view.page.locator("#panel-compliance").inner_text()
    assert "2 of 3 target hosts of the evidence collection have no evidence bundle" in panel
    assert "no: missing" in panel
    assert HOSTILE_PATH in panel
    assert view.page.locator("#panel-compliance script").count() == 0
    view.assert_clean()


def test_an_unknown_coverage_is_labelled(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
    copy_of: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    older = copy_of(typical)
    older["schema_version"] = "2.0"
    del older["sections"]["compliance"]["host_coverage"]
    for document, name in ((typical, "unknown"), (older, "schema-2-0")):
        view = open_dashboard(render(document, name))
        overview = view.page.locator("#panel-overview").inner_text()
        assert "Host coverage unknown." in overview
        assert "Build the report with --evidence-collection" in overview
        view.assert_clean()
    assert "does not record which target hosts have no input" in overview


def test_axe_finds_no_serious_violation_with_missing_hosts(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
    copy_of: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    document = missing_hosts(copy_of(typical))
    for scheme in ("light", "dark"):
        view = open_dashboard(render(document, f"missing-{scheme}"), color_scheme=scheme)
        for name in ("overview", "compliance"):
            view.tab(name)
            assert blocking(view.run_axe()) == [], name
        view.assert_clean()


def off_platform_only_host(document: dict[str, Any]) -> dict[str, Any]:
    compliance = document["sections"]["compliance"]
    compliance.update({"aggregates": [], "groups": [], "notes": [], "rules": [], "summary": None})
    compliance["status"] = "partial"
    compliance["reason"] = "1 of 3 input(s) are missing and 0 are invalid"
    hosts = [
        {
            "host": "db01",
            "in_report": True,
            "manifest_sha256": "b" * 64,
            "off_platform": True,
            "run_id": "run-db01",
            "status": "collected",
        },
        {
            "host": "web01",
            "in_report": True,
            "manifest_sha256": "a" * 64,
            "off_platform": False,
            "run_id": "run-web01",
            "status": "collected",
        },
    ]
    compliance["host_coverage"] = {
        "collection": {
            "collected_at": "2026-10-26T08:00:01Z",
            "collection_id": "20261026T080001.234567Z",
            "path": "/srv/evidence/collection-20261026T080001.234567Z.json",
            "sha256": "c" * 64,
            "size": 958,
        },
        "hosts": hosts,
        "reason": "1 of 2 target host(s) have only an off-platform scan (db01), which never "
        "counts as their compliance evidence",
        "status": "incomplete",
        "summary": {
            "by_status": {
                "collected": 2,
                "collection_failed": 0,
                "limited_out": 0,
                "no_audit_result": 0,
                "no_evidence_written": 0,
                "unreachable": 0,
            },
            "in_report": 2,
            "missing": 0,
            "off_platform": 1,
            "target_hosts": 2,
        },
    }
    document["overview"]["available"].remove("compliance")
    document["overview"]["partial"].append("compliance")
    return document


def test_an_off_platform_only_host_is_named_as_not_covered(
    typical: dict[str, Any],
    render: Callable[[dict[str, Any], str], Path],
    open_dashboard: Callable[..., Dashboard],
    copy_of: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    document = off_platform_only_host(copy_of(typical))
    view = open_dashboard(render(document, "off-platform-only-host"))
    overview = view.page.locator("#panel-overview").inner_text()
    assert "Target hosts are missing from this report." in overview
    assert "1 of 2 target hosts have only an off-platform scan in this report." in overview
    assert "db01: only an off-platform scan" in overview
    assert "have no evidence bundle in this report" not in overview
    view.tab("compliance")
    panel = view.page.locator("#panel-compliance").inner_text()
    assert "only an off-platform scan: not covered" in panel
    assert "Only an off-platform scan (not covered)" in panel
    view.assert_clean()
    for scheme in ("light", "dark"):
        themed = open_dashboard(
            render(document, f"off-platform-only-{scheme}"), color_scheme=scheme
        )
        for name in ("overview", "compliance"):
            themed.tab(name)
            assert blocking(themed.run_axe()) == [], name
        themed.assert_clean()
