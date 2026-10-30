from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
)
from tools.content import script_checks as sc

SCE = catalog.SCE_CHECK_SYSTEM
OVAL = catalog.OVAL_CHECK_SYSTEM
OCIL = catalog.OCIL_CHECK_SYSTEM
NAMESPACES = (
    'xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2" '
    'xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2" '
    'xmlns:cat="urn:oasis:names:tc:entity:xmlns:xml:catalog" '
    'xmlns:sce="http://open-scap.org/page/SCE_xccdf_stream" '
    'xmlns:xlink="http://www.w3.org/1999/xlink"'
)
OVAL_CHECK = (
    f'            <xccdf-1.2:check system="{OVAL}">\n'
    '              <xccdf-1.2:check-content-ref href="oval.xml" name="oval:x:def:1"/>\n'
    "            </xccdf-1.2:check>\n"
)
OCIL_CHECK = (
    f'            <xccdf-1.2:check system="{OCIL}">\n'
    '              <xccdf-1.2:check-content-ref href="ocil.xml" name="ocil:x:questionnaire:1"/>\n'
    "            </xccdf-1.2:check>\n"
)


def sce_check(name: str) -> str:
    return (
        f'            <xccdf-1.2:check system="{SCE}">\n'
        '              <xccdf-1.2:check-import import-name="stdout"/>\n'
        f'              <xccdf-1.2:check-content-ref href="sce/{name}.sh"/>\n'
        "            </xccdf-1.2:check>\n"
    )


def uri(name: str) -> str:
    return f'          <cat:uri name="sce/{name}.sh" uri="#cref_{name}"/>\n'


def reference(name: str) -> str:
    return f'      <ds:component-ref id="cref_{name}" xlink:href="#ecomp_{name}"/>\n'


def component(name: str, content: str = "") -> str:
    script = f"    <sce:script>#!/bin/bash\necho '{name}' &gt; /dev/null\n</sce:script>\n"
    return (
        f'  <ds:extended-component id="ecomp_{name}" timestamp="t">\n'
        f"{content or script}  </ds:extended-component>\n"
    )


def document(names: tuple[str, ...] = ("a", "b"), **parts: str) -> bytes:
    rules = parts.get("rules")
    uris = parts.get("uris")
    references = parts.get("references")
    components = parts.get("components")
    extra_checks = parts.get("extra_checks", "")
    rule_text = (
        "".join(
            f'          <xccdf-1.2:Rule id="xccdf_x_rule_{name}" selected="false">\n'
            f"{sce_check(name)}{OVAL_CHECK if name == 'a' else OCIL_CHECK}"
            "          </xccdf-1.2:Rule>\n"
            for name in names
        )
        if rules is None
        else rules
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<ds:data-stream-collection {NAMESPACES} id="c" schematron-version="1.3">\n'
        '  <ds:data-stream id="d" scap-version="1.3">\n'
        "    <ds:checklists>\n"
        '      <ds:component-ref id="cref_xccdf" xlink:href="#comp_xccdf">\n'
        "        <cat:catalog>\n"
        '          <cat:uri name="oval.xml" uri="#cref_oval"/>\n'
        f"{''.join(uri(name) for name in names) if uris is None else uris}"
        "        </cat:catalog>\n"
        "      </ds:component-ref>\n"
        "    </ds:checklists>\n"
        "    <ds:checks>\n"
        '      <ds:component-ref id="cref_oval" xlink:href="#comp_oval"/>\n'
        f"{''.join(reference(name) for name in names) if references is None else references}"
        "    </ds:checks>\n"
        "  </ds:data-stream>\n"
        '  <ds:component id="comp_xccdf" timestamp="t">\n'
        '    <xccdf-1.2:Benchmark id="xccdf_x_benchmark_b" resolved="1">\n'
        f"{rule_text}{extra_checks}"
        "    </xccdf-1.2:Benchmark>\n"
        "  </ds:component>\n"
        f"{''.join(component(name) for name in names) if components is None else components}"
        "</ds:data-stream-collection>\n"
    ).encode()


def without_scripts(names: tuple[str, ...] = ("a", "b")) -> bytes:
    rules = "".join(
        f'          <xccdf-1.2:Rule id="xccdf_x_rule_{name}" selected="false">\n'
        f"{OVAL_CHECK if name == 'a' else OCIL_CHECK}"
        "          </xccdf-1.2:Rule>\n"
        for name in names
    )
    return document(names=names, rules=rules, uris="", references="", components="")


def test_every_sce_check_script_and_reference_is_removed_and_nothing_else() -> None:
    stripped = sc.strip_script_checks(document())
    assert stripped.data == without_scripts()
    assert (stripped.checks, stripped.scripts) == (2, 2)
    assert (stripped.component_refs, stripped.catalog_uris) == (2, 2)


def test_stripping_is_idempotent_and_leaves_clean_content_byte_identical() -> None:
    clean = without_scripts()
    again = sc.strip_script_checks(clean)
    assert again.data == clean
    assert (again.checks, again.scripts, again.component_refs, again.catalog_uris) == (0, 0, 0, 0)


def test_a_quoted_closing_bracket_in_a_removed_tag_is_honoured() -> None:
    data = document().replace(b'href="sce/a.sh"/>', b'href="sce/a.sh" note="a > b"/>')
    data = data.replace(b'name="sce/a.sh" uri', b"name='sce/a.sh' title='x > y' uri")
    data = data.replace(b'uri name="sce/a.sh"', b'uri name="sce/a.sh"')
    stripped = sc.strip_script_checks(data)
    assert b"sce/a.sh" not in stripped.data
    assert stripped.checks == 2


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (
            document(extra_checks='<xccdf-1.2:check system="urn:example:shell"/>\n'),
            "the system 'urn:example:shell', which is not removed safely",
        ),
        (
            document(extra_checks=f'<xccdf-1.2:check system="{SCE}"/>\n'),
            "an SCE check is not a direct child of a rule",
        ),
        (
            document(components=component("a") + component("b", "    <ds:other/>\n")),
            "the extended component 'ecomp_b' is not exactly one SCE script",
        ),
        (
            document(
                components=component("a")
                + component("b", "    <sce:script>x</sce:script>\n    <sce:script>y</sce:script>\n")
            ),
            "is not exactly one SCE script",
        ),
        (
            document(extra_checks="<sce:script>echo</sce:script>\n"),
            "is not the content of an extended component",
        ),
        (
            document(references=reference("a")),
            "is not referenced by exactly one component-ref",
        ),
        (
            document(references=reference("a") + reference("b") + reference("b")),
            "is not referenced by exactly one component-ref",
        ),
        (document(uris=uri("a")), "do not match"),
        (
            document(uris=uri("a") + uri("b").replace("sce/b.sh", "sce/other.sh")),
            "do not match",
        ),
        (
            document(
                names=("a",),
                rules=(
                    '<xccdf-1.2:Rule id="xccdf_x_rule_a" selected="false">\n'
                    f"{sce_check('a')}</xccdf-1.2:Rule>\n"
                ),
            ),
            "would leave {http://checklists.nist.gov/xccdf/1.2}Rule without children",
        ),
        (b'<!DOCTYPE x [<!ENTITY a "b">]><x/>', "not allowed"),
        (b"<x>", "not well-formed"),
    ],
    ids=[
        "other-script-system",
        "sce-check-outside-a-rule",
        "component-without-a-script",
        "component-with-two-scripts",
        "sce-element-outside-a-component",
        "unreferenced-component",
        "component-referenced-twice",
        "missing-catalog-entry",
        "catalog-entry-for-another-script",
        "rule-left-empty",
        "doctype",
        "not-well-formed",
    ],
)
def test_a_script_construct_that_is_not_removed_safely_fails_closed(
    data: bytes, message: str
) -> None:
    with pytest.raises(sc.ScriptCheckError, match=message.replace("(", r"\(").replace(")", r"\)")):
        sc.strip_script_checks(data)


def test_an_unclosed_start_tag_fails_closed() -> None:
    with pytest.raises(sc.ScriptCheckError, match="a start tag is not closed"):
        sc.tag_end(b'<x a="1"', 0)


def test_an_end_tag_where_the_parser_did_not_report_it_fails_closed() -> None:
    collector = sc.Collector(b"<a><b>x</b></a>")
    collector.offset = 6
    with pytest.raises(sc.ScriptCheckError, match="the end tag of b is not where"):
        collector.element_end(sc.Frame("b", 3))


def test_overlapping_removals_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def overlapping(_collector: sc.Collector) -> tuple[list[sc.Frame], int, int, int]:
        frame = sc.Frame("x", 10, end=40)
        return [frame, sc.Frame("y", 20, end=30)], 0, 0, 0

    monkeypatch.setattr(sc, "removed_elements", overlapping)
    with pytest.raises(sc.ScriptCheckError, match="two removed elements overlap"):
        sc.strip_script_checks(document())


def test_a_result_that_still_holds_a_script_check_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def nothing(_collector: sc.Collector) -> tuple[list[sc.Frame], int, int, int]:
        return [], 0, 0, 0

    monkeypatch.setattr(sc, "removed_elements", nothing)
    with pytest.raises(sc.ScriptCheckError, match="without its scripts is not acceptable"):
        sc.strip_script_checks(document())


def test_a_root_element_that_could_be_removed_is_kept_without_scripts() -> None:
    data = b'<ds:component-ref xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2" id="x"/>\n'
    assert sc.strip_script_checks(data).data == data
