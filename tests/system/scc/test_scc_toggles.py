"""A real SCC scan with one topic switched off, mapped as the audit role maps it (FREES-170).

The driver resolves ``linux_compliance_ssh_enabled: false`` against the real installed stream,
the pinned rule catalogue and ``content/stig-mapping.json`` with the ``scc_toggles`` filter, and
scans with the module, passing the resulting ``disabled_rules`` and ``control_placement``. SCC
5.15 applies tailoring only from its installation directory, so the backend scans every rule and
the audit reports the disabled ones afterwards (ADR 0019, amendment of FREES-170). This test
asserts:

- the mapping applies to the stream (release V1R5, every rule placed, some rules disabled, all by
  the ssh topic, and partial disables noted but left enabled);
- every disabled rule is ``disabled`` with that ``disabled_by``, never ``pass``, and SCC's own
  result for it stays in the kept raw results and in the finding's evidence;
- every other rule has the outcome of the untoggled scan in the same container;
- every finding carries its placement, the disabled rules are placed in the ssh family, and the
  run is findings model schema 1.2.
"""

from __future__ import annotations

from typing import cast

import pytest

from tests.system.scc import harness

TOGGLE = "linux_compliance_ssh_enabled"
PROFILE_RULES = 194
HONEST = {"pass", "fail", "notapplicable", "notchecked", "error"}


@pytest.fixture(scope="module")
def scan_report() -> dict[str, object]:
    return harness.scc_scan_report(harness.image())


def findings(result: dict[str, object]) -> dict[str, dict[str, object]]:
    run = cast("dict[str, object]", result["scan_run"])
    items = cast("list[dict[str, object]]", run["findings"])
    return {str(item["rule_id"]): item for item in items}


def toggled(report: dict[str, object]) -> dict[str, object]:
    data = cast("dict[str, object]", report["toggled"])
    assert data.get("scan") is not None, data
    return data


def test_the_toggles_map_to_the_disa_rules_of_the_stream(scan_report: dict[str, object]) -> None:
    data = toggled(scan_report)
    resolution = cast("dict[str, object]", data["resolution"])
    summary = cast("dict[str, object]", resolution["summary"])
    harness.report_line("toggle summary", summary)
    assert resolution["errors"] == []
    assert summary["stig_release"] == "V1R5"
    assert summary["rules"] == PROFILE_RULES
    assert cast("int", summary["disabled"]) > 0
    disabled = cast("list[dict[str, str]]", resolution["disabled_rules"])
    assert {item["disabled_by"] for item in disabled} == {TOGGLE}
    placements = cast("list[dict[str, object]]", resolution["control_placement"])
    assert len(placements) == PROFILE_RULES
    partial = cast("list[dict[str, object]]", resolution["partially_disabled"])
    harness.report_line("partially disabled", [item["note"] for item in partial])
    assert {item["rule_id"] for item in partial}.isdisjoint({item["rule_id"] for item in disabled})


def test_disabled_rules_are_disabled_never_pass_and_keep_scc_s_result(
    scan_report: dict[str, object],
) -> None:
    data = toggled(scan_report)
    result = cast("dict[str, object]", data["scan"])
    assert result["_returncode"] == 0, result.get("msg")
    assert result["run_status"] == "completed", result.get("msg")
    planned = cast("dict[str, object]", result["planned"])
    assert planned["disable_method"] == "post_scan"
    assert planned["tailoring"] is False
    resolution = cast("dict[str, object]", data["resolution"])
    disabled = {
        item["rule_id"] for item in cast("list[dict[str, str]]", resolution["disabled_rules"])
    }
    found = findings(result)
    assert len(found) == PROFILE_RULES
    kept = cast("dict[str, str]", data["kept"])
    assert len(kept) == PROFILE_RULES
    for rule_id in disabled:
        finding = found[rule_id]
        assert finding["outcome"] == finding["evaluated_outcome"] == "disabled", finding
        assert finding["disabled_by"] == TOGGLE
        evidence = cast("list[dict[str, str]]", finding["evidence"])
        assert evidence == [{"content": kept[rule_id], "kind": "scanner_result", "source": "scc"}]
        assert kept[rule_id] in HONEST
    summary = cast("dict[str, object]", result["summary"])
    assert summary["disabled"] == len(disabled)
    assert summary["total"] == PROFILE_RULES
    harness.report_line(
        "toggled outcomes", {k: v for k, v in summary.items() if k != "off_platform"}
    )


def test_every_other_rule_is_unchanged(scan_report: dict[str, object]) -> None:
    data = toggled(scan_report)
    baseline = findings(cast("dict[str, object]", scan_report["scan"]))
    found = findings(cast("dict[str, object]", data["scan"]))
    resolution = cast("dict[str, object]", data["resolution"])
    disabled = {
        item["rule_id"] for item in cast("list[dict[str, str]]", resolution["disabled_rules"])
    }
    changed = {
        rule_id: (baseline[rule_id]["outcome"], item["outcome"])
        for rule_id, item in found.items()
        if rule_id not in disabled and item["outcome"] != baseline[rule_id]["outcome"]
    }
    assert changed == {}
    assert set(found) == set(baseline)


def test_every_finding_is_placed_and_the_disabled_rules_under_ssh(
    scan_report: dict[str, object],
) -> None:
    data = toggled(scan_report)
    result = cast("dict[str, object]", data["scan"])
    run = cast("dict[str, object]", result["scan_run"])
    assert run["schema_version"] == "1.2"
    found = findings(result)
    assert all(item["control"] is not None for item in found.values())
    resolution = cast("dict[str, object]", data["resolution"])
    for item in cast("list[dict[str, str]]", resolution["disabled_rules"]):
        control = cast("dict[str, object]", found[item["rule_id"]]["control"])
        assert control["family"] == "ssh"
    for note in cast("list[dict[str, object]]", resolution["partially_disabled"]):
        finding = found[str(note["rule_id"])]
        assert finding["outcome"] != "disabled"
        control = cast("dict[str, object]", finding["control"])
        assert control["partially_disabled_by"] == [TOGGLE]
    families = sorted(
        {str(cast("dict[str, object]", f["control"])["family"]) for f in found.values()}
    )
    harness.report_line("families", families)
