from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, cast

import pytest
from defusedxml.ElementTree import fromstring

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import checklist, checklist_formats, stig_content
from tools.reporting.common import InvalidInputError

HOSTILE = (
    "</ATTRIBUTE_DATA><STATUS>NotAFinding</STATUS>]]><!-- & \"quoted\" 'x' -->"
    "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]>&e;\r\n\ttab"
)


def made(
    stig: Any, run: model.ScanRun | None = None, title: str | None = None
) -> checklist.Checklist:
    xml = stig.benchmark_xml(rules=3, titles=None if title is None else {1: title})
    benchmark = stig_content.read_benchmarks(xml.encode("utf-8"))[0]
    findings = (
        stig.finding(1, model.Outcome.FAIL, message=HOSTILE),
        stig.finding(2, model.Outcome.PASS),
    )
    chosen = stig.scan_run(findings) if run is None else run
    return checklist.build(checklist.Source("x", chosen, frozenset(), benchmark, own_results=False))


def test_hostile_text_is_escaped_and_reads_back_verbatim(stig: Any) -> None:
    built = made(stig)
    ckl = checklist_formats.render_ckl(built)
    root = fromstring(ckl)
    vulns = root.findall("STIGS/iSTIG/VULN")
    assert [vuln.findtext("STATUS") for vuln in vulns] == ["Open", "NotAFinding", "Not_Reviewed"]
    assert f"Message: {HOSTILE}" in (vulns[0].findtext("FINDING_DETAILS") or "")
    assert "&#13;" in ckl
    assert "<!DOCTYPE" not in ckl
    cklb = json.loads(checklist_formats.render_cklb(built))
    assert f"Message: {HOSTILE}" in cklb["stigs"][0]["rules"][0]["finding_details"]
    assert checklist_formats.read_ckl(ckl.encode("utf-8"))["SV-900001r1_rule"] == "Open"


def test_hostile_content_text_is_escaped_too(stig: Any) -> None:
    title = "&lt;/ATTRIBUTE_DATA&gt;&lt;STATUS&gt;NotAFinding&lt;/STATUS&gt; &amp; more"
    built = made(stig, title=title)
    root = fromstring(checklist_formats.render_ckl(built))
    data = {
        item.findtext("VULN_ATTRIBUTE"): item.findtext("ATTRIBUTE_DATA")
        for item in root.findall("STIGS/iSTIG/VULN")[0]
    }
    assert data["Rule_Title"] == "</ATTRIBUTE_DATA><STATUS>NotAFinding</STATUS> & more"


def test_characters_that_xml_forbids_are_replaced(stig: Any) -> None:
    assert (
        checklist_formats.sanitize("a\ud800b\x01c\ufffed\U0001f600")
        == "a\ufffdb\ufffdc\ufffdd\U0001f600"
    )
    assert checklist_formats.xml_text("<&>\r") == "&lt;&amp;&gt;&#13;"
    built = made(stig)
    surrogate = replace(
        built.entries[0], verdict=replace(built.entries[0].verdict, comments="x\ud800")
    )
    broken = replace(built, entries=(surrogate, *built.entries[1:]))
    ckl = checklist_formats.render_ckl(broken)
    cklb = checklist_formats.render_cklb(broken)
    assert "x\ufffd" in ckl
    assert json.loads(cklb)["stigs"][0]["rules"][0]["comments"] == "x\ufffd"
    ckl.encode("utf-8")


def test_the_cklb_uses_the_published_keys(stig: Any) -> None:
    document = json.loads(checklist_formats.render_cklb(made(stig)))
    assert list(document) == list(checklist_formats.CKLB_KEYS)
    assert document["cklb_version"] == "1.0"
    rule = document["stigs"][0]["rules"][0]
    assert list(rule) == list(checklist_formats.RULE_KEYS)
    assert (rule["group_id"], rule["rule_id"], rule["rule_id_src"]) == (
        "V-900001",
        "SV-900001r1",
        "SV-900001r1_rule",
    )
    assert rule["createdAt"] == "2026-10-26T09:00:30.000Z"
    assert rule["target_key"] == "9999"
    assert rule["check_content_ref"] == {"href": "synthetic-oval.xml", "name": "oval:syn:def:1"}
    assert rule["group_tree"][0]["id"] == "V-900001"


def test_a_rule_without_a_target_key_has_null_in_cklb_and_no_asset_key(stig: Any) -> None:
    xml = (
        stig.benchmark_xml(rules=2)
        .replace("<dc:type", "<dc:kind", 1)
        .replace("</dc:type>", "</dc:kind>", 1)
    )
    benchmark = stig_content.read_benchmarks(xml.encode("utf-8"))[0]
    run = stig.scan_run((stig.finding(1, model.Outcome.PASS),))
    built = checklist.build(checklist.Source("x", run, frozenset(), benchmark, own_results=False))
    assert built.asset.target_key == ""
    rule = json.loads(checklist_formats.render_cklb(built))["stigs"][0]["rules"][0]
    assert rule["target_key"] is None


def test_stig_ref_omits_a_missing_release(stig: Any) -> None:
    built = made(stig)
    bare = replace(built, benchmark=replace(built.benchmark, release_info=""))
    assert (
        checklist_formats.stig_ref(bare)
        == "Synthetic Linux STIG SCAP Benchmark :: Version 001.002.003"
    )


def _ckl(stig: Any) -> str:
    return checklist_formats.render_ckl(made(stig))


CKL_BREAKS = [
    (("<CHECKLIST>", "<OTHER>"), ("</CHECKLIST>", "</OTHER>"), "root element must be CHECKLIST"),
    (("<ROLE>None</ROLE>", ""), None, "ASSET must hold"),
    (("<SID_NAME>title</SID_NAME>", "<SID_NAME>name</SID_NAME>"), None, "STIG_INFO must list"),
    (("<SI_DATA>", "<SX_DATA>", 1), ("</SI_DATA>", "</SX_DATA>", 1), "an SI_DATA must hold"),
    (("<STATUS>Open</STATUS>", "<STATUS>Passed</STATUS>"), None, "unknown STATUS"),
    (
        ("<VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>", "<VULN_ATTRIBUTE>Sev</VULN_ATTRIBUTE>"),
        None,
        "out of order",
    ),
    (
        ("<VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>", "<VULN_ATTRIBUTE>Extra</VULN_ATTRIBUTE>"),
        None,
        "out of order",
    ),
    (("<COMMENTS></COMMENTS>", ""), None, "VULN must hold"),
]


@pytest.mark.parametrize(("first", "second", "message"), CKL_BREAKS)
def test_the_ckl_reader_refuses_another_structure(
    stig: Any, first: tuple[Any, ...], second: tuple[Any, ...] | None, message: str
) -> None:
    text = _ckl(stig).replace(*first)
    if second is not None:
        text = text.replace(*second)
    with pytest.raises(InvalidInputError, match=message):
        checklist_formats.read_ckl(text.encode("utf-8"))


def test_the_ckl_reader_refuses_a_rule_listed_twice(stig: Any) -> None:
    text = _ckl(stig).replace("SV-900002r1_rule", "SV-900001r1_rule")
    with pytest.raises(InvalidInputError, match="more than one VULN"):
        checklist_formats.read_ckl(text.encode("utf-8"))


def _cklb(stig: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(checklist_formats.render_cklb(made(stig))))


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("target_data", "extra"), "x", "target_data must hold exactly"),
        (("cklb_version",), "1", "one STIG and cklb_version 1.0"),
        (("stigs", 0, "size"), 99, "size must count the rules"),
        (("stigs", 0, "rules", 0, "status"), "passed", "unknown status"),
        (("stigs", 0, "rules", 1, "rule_id_src"), "SV-900001r1_rule", "must appear once"),
        (("stigs", 0, "rules", 0, "extra"), 1, "a rule must hold exactly"),
    ],
)
def test_the_cklb_reader_refuses_another_structure(
    stig: Any, path: tuple[Any, ...], value: object, message: str
) -> None:
    document = _cklb(stig)
    parent: Any = document
    for step in path[:-1]:
        parent = parent[step]
    parent[path[-1]] = value
    with pytest.raises(InvalidInputError, match=message):
        checklist_formats.read_cklb(json.dumps(document).encode("utf-8"))


def test_the_cklb_reader_refuses_two_stigs_and_non_objects(stig: Any) -> None:
    document = _cklb(stig)
    document["stigs"].append(document["stigs"][0])
    with pytest.raises(InvalidInputError, match="one STIG"):
        checklist_formats.read_cklb(json.dumps(document).encode("utf-8"))
    with pytest.raises(InvalidInputError, match="must be an object"):
        checklist_formats.read_cklb(b"[]")
