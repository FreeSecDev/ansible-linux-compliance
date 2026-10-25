"""OpenSCAP XCCDF 1.2 results and ARF reports.

The XCCDF mapping reuses the hardened controller-side parser of the findings model
(``openscap.parse_results``), so result values go through ``map_xccdf_result`` and
any unknown value becomes ``error``. ARF is bounded and read with defusedxml first;
its single embedded ``TestResult`` is then handed to the same parser.
"""

from pathlib import Path
from typing import Final

from defusedxml.ElementTree import fromstring, tostring

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    openscap,
)
from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    InvalidInputError,
    ParseResult,
    clean_text,
    decode_text,
    run_parser,
)
from tools.reporting.compliance import COMPLETED, ComplianceData, summarize, tally_findings
from tools.reporting.xmlsafe import parse_xml

ARF_ROOT_TAG: Final[str] = (
    "{http://scap.nist.gov/schema/asset-reporting-format/1.1}asset-report-collection"
)
TEST_RESULT_TAG: Final[str] = "{http://checklists.nist.gov/xccdf/1.2}TestResult"


def _convert(document: str, kind: str) -> ComplianceData:
    try:
        parsed = openscap.parse_results(document)
    except openscap.XccdfParseError as error:
        message = f"XCCDF results rejected: {clean_text(str(error), 200)}"
        raise InvalidInputError(message) from None
    summary = summarize(tally_findings(parsed.findings), COMPLETED, 1, 0)
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
        content_version=parsed.benchmark_version,
        findings=parsed.findings,
        scan_run=None,
        summary=summary,
    )


def _build_xccdf(data: bytes) -> ComplianceData:
    return _convert(decode_text(data), "xccdf")


def _build_arf(data: bytes) -> ComplianceData:
    parse_xml(data)
    root = fromstring(data, forbid_dtd=True)
    if root.tag != ARF_ROOT_TAG:
        message = "the root element is not an ARF 1.1 asset-report-collection"
        raise InvalidInputError(message)
    results = [element for element in root.iter() if element.tag == TEST_RESULT_TAG]
    if len(results) != 1:
        message = f"expected exactly one XCCDF TestResult in the ARF, found {len(results)}"
        raise InvalidInputError(message)
    return _convert(tostring(results[0], encoding="unicode"), "arf")


def parse_xccdf(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[ComplianceData]:
    """Parse an XCCDF 1.2 results file (Benchmark or TestResult root)."""
    return run_parser(path, "xccdf", max_bytes, _build_xccdf)


def parse_arf(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[ComplianceData]:
    """Parse an ARF 1.1 asset report collection that embeds one XCCDF TestResult."""
    return run_parser(path, "arf", max_bytes, _build_arf)
