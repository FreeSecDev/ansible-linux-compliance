"""OpenSCAP XCCDF 1.2 results and ARF reports.

The XCCDF mapping reuses the hardened controller-side parser of the findings model
(``openscap.parse_results``), so result values go through ``map_xccdf_result`` and
any unknown value becomes ``error``. ARF is bounded and read with defusedxml first;
its single embedded ``TestResult`` is then handed to the same parser.

``oscap`` lists every rule of the benchmark and marks the ones the profile did not
select as ``notselected``. Those results never enter the compliance maths (ADR 0013);
they are only counted. The host name in the file (XCCDF ``target`` or fqdn fact, ARF
asset) is self-asserted and is only used to group files of the same host.
"""

from pathlib import Path
from typing import Final

from defusedxml.ElementTree import fromstring, tostring

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    openscap,
)
from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    InvalidInputError,
    ParseResult,
    bounded,
    clean_text,
    decode_text,
    run_parser,
)
from tools.reporting.compliance import COMPLETED, ComplianceData, summarize, tally_findings
from tools.reporting.xmlsafe import XmlNode, parse_xml

ARF_ROOT_TAG: Final[str] = (
    "{http://scap.nist.gov/schema/asset-reporting-format/1.1}asset-report-collection"
)
TEST_RESULT_TAG: Final[str] = "{http://checklists.nist.gov/xccdf/1.2}TestResult"
FQDN_FACT: Final[str] = "urn:xccdf:fact:asset:identifier:fqdn"
MAX_HOST_LENGTH: Final[int] = 255


def _name(text: str) -> str | None:
    return clean_text(text.strip(), MAX_HOST_LENGTH).strip().lower() or None


def _host_names(tree: XmlNode) -> list[str]:
    nodes = tree.descendants()
    facts = [n.text for n in nodes if n.local == "fact" and n.attributes.get("name") == FQDN_FACT]
    targets = [n.text for n in nodes if n.local == "target"]
    names = (_name(text) for text in [*facts, *targets])
    return [name for name in names if name is not None]


def _first(names: list[str]) -> str | None:
    return names[0] if names else None


def _asset_names(tree: XmlNode) -> set[str]:
    names: set[str] = set()
    for device in (n for n in tree.descendants() if n.local == "computing-device"):
        for child in device.children:
            name = _name(child.text)
            if child.local in {"fqdn", "hostname"} and name is not None:
                names.add(name)
    return names


def _convert(document: str, kind: str, reported_host: str | None) -> ComplianceData:
    try:
        parsed = openscap.parse_results(document)
    except openscap.XccdfParseError as error:
        message = f"XCCDF results rejected: {clean_text(str(error), 200)}"
        raise InvalidInputError(message) from None
    selected = tuple(
        finding for finding in parsed.findings if model.ResultFlag.NOTSELECTED not in finding.flags
    )
    bounded(list(selected), model.MAX_FINDINGS, "rule results")
    not_selected = len(parsed.findings) - len(selected)
    summary = summarize(tally_findings(selected), COMPLETED, 1, 0, not_selected)
    return ComplianceData(
        kind=kind,
        scan_status=COMPLETED,
        error_message=None,
        benchmark_id=parsed.benchmark_id,
        benchmark_version=parsed.benchmark_version,
        profile_id=parsed.profile_id,
        started_at=parsed.started_at,
        finished_at=parsed.finished_at,
        host=None,
        reported_host=reported_host,
        content_version=parsed.benchmark_version,
        findings=selected,
        not_selected=not_selected,
        scan_run=None,
        summary=summary,
    )


def _build_xccdf(data: bytes) -> ComplianceData:
    return _convert(decode_text(data), "xccdf", _first(_host_names(parse_xml(data))))


def _build_arf(data: bytes) -> ComplianceData:
    tree = parse_xml(data)
    root = fromstring(data, forbid_dtd=True)
    if root.tag != ARF_ROOT_TAG:
        message = "the root element is not an ARF 1.1 asset-report-collection"
        raise InvalidInputError(message)
    results = [element for element in root.iter() if element.tag == TEST_RESULT_TAG]
    if len(results) != 1:
        message = f"expected exactly one XCCDF TestResult in the ARF, found {len(results)}"
        raise InvalidInputError(message)
    names = _host_names(tree)
    assets = _asset_names(tree)
    if assets and any(name not in assets for name in names):
        message = "the ARF asset names a different host than the XCCDF TestResult target"
        raise InvalidInputError(message)
    return _convert(tostring(results[0], encoding="unicode"), "arf", _first(names))


def parse_xccdf(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[ComplianceData]:
    """Parse an XCCDF 1.2 results file (Benchmark or TestResult root)."""
    return run_parser(path, "xccdf", max_bytes, _build_xccdf)


def parse_arf(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[ComplianceData]:
    """Parse an ARF 1.1 asset report collection that embeds one XCCDF TestResult."""
    return run_parser(path, "arf", max_bytes, _build_arf)
