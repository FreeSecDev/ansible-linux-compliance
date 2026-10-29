"""OpenSCAP XCCDF 1.2 results and ARF reports.

The XCCDF mapping reuses the hardened controller-side parser of the findings model
(``openscap.parse_results``), so result values go through ``map_xccdf_result`` and
any unknown value becomes ``error``. ARF is bounded and read with defusedxml first;
its single embedded ``TestResult`` is then handed to the same parser.

``oscap`` lists every rule of the benchmark and marks the ones the profile did not
select as ``notselected``. Those results never enter the compliance maths (ADR 0013);
they are only counted. The host name in the file (XCCDF ``target`` or fqdn fact, ARF
asset) is self-asserted and is only used to group files of the same host. Every
``target`` and fqdn fact must name the same host (compared lower-cased); a file whose
names disagree is an input error, because no name could be preferred safely.

XCCDF and ARF files carry no off-platform marker (FREES-161). A file named
``*.off-platform.xml``, which is how the SCC backend names the raw copies of an
off-platform run, is refused, and so is a file whose own directory or the directory
above it holds a ``scan-run.json`` that carries the marker, or one that cannot be read.
Such a run is reported through its ``scan-run.json``, which carries the marker.

A copy taken out of its bundle is also refused by its content (FREES-164). A TestResult
that SCC wrote (``test-system`` ``cpe:/a:niwc:scc``) lists, as ``platform`` children,
the platforms that SCC matched to the target. When the benchmark declares operating system
platforms (``cpe:/o:``) and none of them is listed in the TestResult, SCC ignored the
platform test, so the results belong to another release than the benchmark and are
refused. SCC 5.15 observed on 2026-10-29 lists the benchmark's ``cpe:/o:canonical:ubuntu_linux``
platform on an Ubuntu 24.04 host and omits it on an Ubuntu 26.04 host with the platform
test ignored. Its ``os_name`` and ``os_version`` target facts are no evidence: they read
``Debian Variant`` and ``Unknown`` on both.
"""

import re
from collections.abc import Callable
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
    MissingInputError,
    ParseResult,
    bounded,
    clean_text,
    decode_text,
    read_input,
    run_parser,
    sha256_hex,
)
from tools.reporting.compliance import COMPLETED, ComplianceData, summarize, tally_findings
from tools.reporting.xmlsafe import XmlNode, parse_xml

ARF_ROOT_TAG: Final[str] = (
    "{http://scap.nist.gov/schema/asset-reporting-format/1.1}asset-report-collection"
)
TEST_RESULT_TAG: Final[str] = "{http://checklists.nist.gov/xccdf/1.2}TestResult"
FQDN_FACT: Final[str] = "urn:xccdf:fact:asset:identifier:fqdn"
OFF_PLATFORM_SUFFIX: Final[str] = ".off-platform.xml"
SCAN_RUN_NAME: Final[str] = "scan-run.json"
NIWC_TEST_SYSTEM_PREFIXES: Final[tuple[str, ...]] = ("cpe:/a:niwc:scc", "cpe:2.3:a:niwc:scc")
NIWC_NAME: Final[re.Pattern[str]] = re.compile(r"(?<![a-z])(?:niwc|scc)(?![a-z])")
OS_PLATFORM_PREFIXES: Final[tuple[str, ...]] = ("cpe:/o:", "cpe:2.3:o:")
PLATFORM_REFUSAL: Final[str] = (
    "the SCC results do not list any operating system platform of their benchmark, so the "
    "scanned host was not matched to the benchmark platform; these are the results of an "
    "off-platform scan, which carry no off-platform marker and are never figured"
)
OFF_PLATFORM_REFUSAL: Final[str] = (
    "these are the raw results of an off-platform scan run, which carry no off-platform "
    "marker and are never figured; report the run's scan-run.json instead"
)


def _name(text: str) -> str | None:
    stripped = text.strip()
    if not stripped:
        return None
    name = stripped.lower()
    try:
        model.HostIdentity(name, "unknown", "0", "unknown", None)
    except model.ModelError:
        message = "the host name in the results is not a valid host name"
        raise InvalidInputError(message) from None
    return name


def _host_names(tree: XmlNode) -> list[str]:
    nodes = tree.descendants()
    facts = [n.text for n in nodes if n.local == "fact" and n.attributes.get("name") == FQDN_FACT]
    targets = [n.text for n in nodes if n.local == "target"]
    names = (_name(text) for text in [*facts, *targets])
    present = [name for name in names if name is not None]
    if len(set(present)) > 1:
        message = "the target and fqdn fact of the results name different hosts"
        raise InvalidInputError(message)
    return present


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


def _os_platforms(nodes: list[XmlNode]) -> set[str]:
    listed = (
        node.attributes.get("idref", "").strip().lower()
        for node in nodes
        if node.local == "platform"
    )
    return {idref for idref in listed if idref.startswith(OS_PLATFORM_PREFIXES)}


def _outside_results(tree: XmlNode) -> list[XmlNode]:
    kept: list[XmlNode] = []
    pending: list[XmlNode] = [tree]
    while pending:
        node = pending.pop()
        if node.local != "TestResult":
            kept.append(node)
            pending.extend(node.children)
    return kept


def _is_niwc_result(result: XmlNode) -> bool:
    system = result.attributes.get("test-system", "").strip().lower()
    if system.startswith(NIWC_TEST_SYSTEM_PREFIXES):
        return True
    if NIWC_NAME.search(system):
        message = "the test-system names SCC in a form this report does not recognise"
        raise InvalidInputError(message)
    return False


def _declared_platforms(tree: XmlNode, result: XmlNode) -> set[str]:
    references = [node for node in result.children if node.local == "benchmark"]
    wanted = references[0].attributes.get("id", "") if references else ""
    benchmarks = [
        node
        for node in tree.descendants()
        if node.local == "Benchmark" and wanted and node.attributes.get("id") == wanted
    ]
    scope = benchmarks or [tree]
    return set().union(*(_os_platforms(_outside_results(node)) for node in scope))


def refuse_platform_mismatch(tree: XmlNode) -> None:
    """Refuse SCC results whose TestResult does not list a platform of their benchmark.

    The platforms are those of the Benchmark that the TestResult names in its own
    ``benchmark`` element; when no Benchmark of the document has that ID, those of the
    whole document. CPE 2.2 URIs and CPE 2.3 formatted strings are both recognised.

    Raises:
        InvalidInputError: If a TestResult written by SCC lists none of the operating
            system platforms that the benchmark declares, or if its ``test-system``
            names SCC in a form that is not recognised.
    """
    results = [
        node for node in tree.descendants() if node.local == "TestResult" and _is_niwc_result(node)
    ]
    for result in results:
        declared = _declared_platforms(tree, result)
        if declared and not declared & _os_platforms(result.descendants()):
            raise InvalidInputError(PLATFORM_REFUSAL)


def _convert(document: str, kind: str, reported_host: str | None, digest: str) -> ComplianceData:
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
        input_sha256=digest,
        content_version=parsed.benchmark_version,
        findings=selected,
        not_selected=not_selected,
        scan_run=None,
        summary=summary,
    )


def _build_xccdf(data: bytes) -> ComplianceData:
    tree = parse_xml(data)
    refuse_platform_mismatch(tree)
    return _convert(decode_text(data), "xccdf", _first(_host_names(tree)), sha256_hex(data))


def _build_arf(data: bytes) -> ComplianceData:
    tree = parse_xml(data)
    refuse_platform_mismatch(tree)
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
    return _convert(
        tostring(results[0], encoding="unicode"), "arf", _first(names), sha256_hex(data)
    )


def _neighbour_is_off_platform(candidate: Path, max_bytes: int) -> bool:
    try:
        data = read_input(candidate, max_bytes)
    except MissingInputError:
        return False
    except InvalidInputError:
        message = (
            f"{SCAN_RUN_NAME} next to these results cannot be read, so the report cannot tell "
            "whether they are off-platform"
        )
        raise InvalidInputError(message) from None
    try:
        return model.loads(decode_text(data)).off_platform is not None
    except (model.ModelError, InvalidInputError):
        message = (
            f"{SCAN_RUN_NAME} next to these results is not a valid scan run, so the report "
            "cannot tell whether they are off-platform"
        )
        raise InvalidInputError(message) from None


def refuse_off_platform(path: Path, max_bytes: int) -> None:
    """Refuse raw results of an off-platform run.

    Raises:
        InvalidInputError: If the file name ends with ``.off-platform.xml``, or a
            ``scan-run.json`` in its directory or the one above carries the
            off-platform marker or cannot be read as a scan run.
    """
    if path.name.endswith(OFF_PLATFORM_SUFFIX):
        raise InvalidInputError(OFF_PLATFORM_REFUSAL)
    for directory in (path.parent, path.parent.parent):
        if _neighbour_is_off_platform(directory / SCAN_RUN_NAME, max_bytes):
            raise InvalidInputError(OFF_PLATFORM_REFUSAL)


def _guarded(
    path: Path, max_bytes: int, build: Callable[[bytes], ComplianceData]
) -> Callable[[bytes], ComplianceData]:
    def run(data: bytes) -> ComplianceData:
        refuse_off_platform(path, max_bytes)
        return build(data)

    return run


def parse_xccdf(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[ComplianceData]:
    """Parse an XCCDF 1.2 results file (Benchmark or TestResult root)."""
    return run_parser(path, "xccdf", max_bytes, _guarded(path, max_bytes, _build_xccdf))


def parse_arf(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[ComplianceData]:
    """Parse an ARF 1.1 asset report collection that embeds one XCCDF TestResult."""
    return run_parser(path, "arf", max_bytes, _guarded(path, max_bytes, _build_arf))
