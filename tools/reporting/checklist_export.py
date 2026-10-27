"""Select the scan runs and DISA content of a checklist export and render the files (FREES-147).

The export reads the same parsed, validated and verified scan inputs as the report:
ScanRun JSON (``--scan-run``), exceptions evaluations verified against
``--exceptions-file`` and evidence bundles. Every input that parsed is exported; an
input that did not parse is reported by the report and has no checklist. Nothing is
written, and the command exits with status 2, when an input that parsed cannot be
exported honestly:

- it is an XCCDF or ARF file, which carries neither waivers nor the off-platform marker;
- its findings are not DISA STIG rules, and the STIG mapping (FREES-146) has no entry for
  its benchmark and profile;
- no DISA content of its benchmark (and version) is available, or more than one is;
- the content does not describe the run: another benchmark, profile or version, or a
  finding whose rule is not in it;
- two inputs give the checklist of the same host and benchmark.

A bundle's own XCCDF results are its content. Without them (a scan that did not complete
writes none), and for ScanRun JSON and evaluations, ``--checklist-content`` supplies it.

A ComplianceAsCode run whose benchmark and profile the mapping lists (FREES-146) is exported
through the mapping, and refused when:

- its content SHA-256 is not the one the mapping was generated from (another
  ComplianceAsCode version);
- the ``--checklist-content`` files do not hold exactly one DISA benchmark with a rule of
  one of the mapped STIG IDs;
- that benchmark states another DISA release than the one the profile implements, or none.

Its content is always the supplied DISA content, never the bundle's own ComplianceAsCode
results, so its asset IP and FQDN stay empty. ``--compare-stig FILE`` writes the comparison of
:mod:`tools.reporting.stig_compare` from the same sources.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting.checklist import (
    Checklist,
    ChecklistError,
    Source,
    build,
    build_all,
    refuse_unmapped,
)
from tools.reporting.checklist_formats import read_ckl, read_cklb, render_ckl, render_cklb
from tools.reporting.common import InvalidInputError, ParseResult, clean_text, dumps, read_input
from tools.reporting.compliance import ComplianceData
from tools.reporting.report import ScanInputs
from tools.reporting.stig_compare import compare
from tools.reporting.stig_content import StigBenchmark, read_benchmarks
from tools.reporting.stig_mapping import (
    DEFAULT_PATH,
    ProfileMapping,
    StigMapping,
    load_mapping,
    release_of,
)

if TYPE_CHECKING:
    from tools.reporting.bundle import BundleInput

CKL_SUFFIX: Final[str] = ".ckl"
CKLB_SUFFIX: Final[str] = ".cklb"
CKL_NAME: Final[str] = "CKL checklist"
CKLB_NAME: Final[str] = "CKLB checklist"
COMPARISON_NAME: Final[str] = "STIG comparison"
PRIVATE_OUTPUTS: Final[frozenset[str]] = frozenset({CKL_NAME, CKLB_NAME, COMPARISON_NAME})
EXPORTED_KINDS: Final[frozenset[str]] = frozenset({"scan_run", "exceptions_evaluation"})


@dataclass(frozen=True)
class ExportRequest:
    """Where to write checklists and which DISA content files to read.

    Attributes:
        ckl_directory: The directory of the CKL files, or ``None``.
        cklb_directory: The directory of the CKLB files, or ``None``.
        content: The ``--checklist-content`` files.
        max_bytes: The size bound of every content file.
        mapping: The STIG mapping file.
        comparison: The file of the SCC and OpenSCAP comparison, or ``None``.
    """

    ckl_directory: Path | None
    cklb_directory: Path | None
    content: tuple[Path, ...]
    max_bytes: int
    mapping: Path = DEFAULT_PATH
    comparison: Path | None = None


Content = dict[str, list[tuple[str, StigBenchmark]]]


def load_content(paths: tuple[Path, ...], max_bytes: int) -> Content:
    """Read every ``--checklist-content`` file and index its benchmarks by benchmark ID.

    Raises:
        ChecklistError: If a file cannot be read or holds no XCCDF 1.2 benchmark.
    """
    content: Content = {}
    for path in paths:
        display = clean_text(str(path), 256)
        try:
            benchmarks = read_benchmarks(read_input(path, max_bytes))
        except InvalidInputError as error:
            message = f"--checklist-content {display}: {error}"
            raise ChecklistError(message) from None
        for benchmark in benchmarks:
            content.setdefault(benchmark.benchmark_id, []).append((display, benchmark))
    return content


def _own_content(run: model.ScanRun, display: str, results: bytes) -> StigBenchmark:
    try:
        benchmarks = read_benchmarks(results)
    except InvalidInputError as error:
        message = f"{display}: the bundle's XCCDF results cannot be read: {error}"
        raise ChecklistError(message) from None
    matching = [item for item in benchmarks if item.benchmark_id == run.benchmark_id]
    target = matching[0].target if len(matching) == 1 else None
    foreign = target is not None and (
        target.benchmark_id not in (None, run.benchmark_id)
        or target.profile_id not in (None, run.profile_id)
    )
    if len(matching) != 1 or foreign:
        message = (
            f"{display}: the bundle's XCCDF results do not hold exactly one benchmark "
            f"{run.benchmark_id} with a TestResult of profile {run.profile_id}"
        )
        raise ChecklistError(message)
    return matching[0]


def _supplied_content(run: model.ScanRun, display: str, content: Content) -> StigBenchmark:
    candidates = content.get(run.benchmark_id, [])
    versioned = [item for item in candidates if item[1].version == run.content.content_version]
    if versioned or run.status is model.ScanStatus.COMPLETED:
        candidates = versioned
    if len(candidates) != 1:
        found = ", ".join(sorted({name for name, _ in candidates})) or "none"
        message = (
            f"{display}: checklists need exactly one DISA content of benchmark {run.benchmark_id} "
            f"version {run.content.content_version} (found: {found}); supply the content that "
            "the scan evaluated with --checklist-content"
        )
        raise ChecklistError(message)
    return candidates[0][1]


def _checked_version(run: model.ScanRun, display: str, benchmark: StigBenchmark) -> None:
    if (
        run.status is model.ScanStatus.COMPLETED
        and benchmark.version != run.content.content_version
    ):
        message = (
            f"{display}: the content is version {benchmark.version} of {run.benchmark_id}, but "
            f"the scan run evaluated version {run.content.content_version}"
        )
        raise ChecklistError(message)


def _checked_mapping(run: model.ScanRun, display: str, mapping: ProfileMapping) -> None:
    if run.content.content_sha256 != mapping.content_sha256:
        message = (
            f"{display}: version mismatch: scan run {run.run_id} evaluated ComplianceAsCode "
            f"content {run.content.source} {run.content.content_version} (sha256 "
            f"{run.content.content_sha256}), but the STIG mapping of {run.profile_id} was "
            f"generated from {mapping.file_name} {mapping.benchmark_version} (sha256 "
            f"{mapping.content_sha256}); scan with the pinned content, or regenerate the mapping "
            "for this content with make stig-mapping"
        )
        raise ChecklistError(message)


def _mapped_content(
    display: str, content: Content, mapping: ProfileMapping
) -> tuple[str, StigBenchmark]:
    candidates = [
        (name, benchmark)
        for items in content.values()
        for name, benchmark in items
        if any(rule.version in mapping.checks for rule in benchmark.rules)
    ]
    if len(candidates) != 1:
        found = ", ".join(sorted({name for name, _ in candidates})) or "none"
        message = (
            f"{display}: the export of profile {mapping.profile_id} through the STIG mapping needs "
            f"exactly one DISA benchmark with its STIG IDs (found: {found}); supply the DISA STIG "
            f"content of release {mapping.stig_release} with --checklist-content"
        )
        raise ChecklistError(message)
    name, benchmark = candidates[0]
    release = release_of(benchmark.version, benchmark.release_info)
    if release != mapping.stig_release:
        message = (
            f"{display}: version mismatch: {name} is DISA release {release or 'unknown'} "
            f"(version {benchmark.version}) of {benchmark.benchmark_id}, but profile "
            f"{mapping.profile_id} of {mapping.file_name} implements release {mapping.stig_release}"
        )
        raise ChecklistError(message)
    return Path(name).name, benchmark


def _source(
    result: ParseResult[ComplianceData],
    results: bytes | None,
    content: Content,
    mappings: StigMapping,
) -> Source | None:
    data = result.data
    if data is None:
        return None
    display = result.artifact.path
    if data.kind not in EXPORTED_KINDS or data.scan_run is None:
        message = (
            f"{display}: checklists are exported from scan runs and evidence bundles only; "
            "XCCDF and ARF results carry neither waivers nor the off-platform marker"
        )
        raise ChecklistError(message)
    run = data.scan_run
    lapsed = frozenset(data.lapsed_waivers)
    mapping = mappings.find(run.benchmark_id, run.profile_id)
    if mapping is not None:
        _checked_mapping(run, display, mapping)
        name, benchmark = _mapped_content(display, content, mapping)
        return Source(
            display, run, lapsed, benchmark, own_results=False, mapping=mapping, content_name=name
        )
    refuse_unmapped(run, display, mappings.path)
    if results is not None:
        benchmark = _own_content(run, display, results)
    else:
        benchmark = _supplied_content(run, display, content)
    _checked_version(run, display, benchmark)
    return Source(display, run, lapsed, benchmark, results is not None)


def _key(result: ParseResult[ComplianceData]) -> tuple[str, str | None]:
    return result.artifact.path, result.artifact.sha256


def select(scan: ScanInputs, content: Content, mappings: StigMapping) -> list[Source]:
    """Return the exportable scan runs of ``scan``, with their DISA content.

    Raises:
        ChecklistError: If an input that parsed cannot be exported (see the module
            docstring), or no input can be exported at all.
    """
    bundled: dict[tuple[str, str | None], BundleInput] = {
        _key(item.compliance): item for item in scan.bundles
    }
    sources: list[Source] = []
    for result in scan.compliance:
        own = bundled.get(_key(result))
        results = None if own is None else own.scanner_results
        source = _source(result, results, content, mappings)
        if source is not None:
            sources.append(source)
    if not sources:
        message = "no checklist to export: no scan run or evidence bundle was read"
        raise ChecklistError(message)
    return sources


def verify_read_back(checklist: Checklist, ckl: str, cklb: str) -> None:
    """Read both documents back and require the statuses of the checklist's entries.

    Raises:
        ChecklistError: If a document does not read back or reads back with other statuses.
    """
    expected_ckl = {entry.rule.rule_ref: entry.verdict.status.ckl for entry in checklist.entries}
    expected_cklb = {entry.rule.rule_ref: entry.verdict.status.cklb for entry in checklist.entries}
    try:
        same = read_ckl(ckl.encode("utf-8")) == expected_ckl
        same = same and read_cklb(cklb.encode("utf-8")) == expected_cklb
    except InvalidInputError as error:
        message = f"the checklist {checklist.file_stem} does not read back: {error}"
        raise ChecklistError(message) from None
    if not same:
        message = f"the checklist {checklist.file_stem} reads back with other statuses"
        raise ChecklistError(message)


def _mappings(path: Path) -> StigMapping:
    try:
        return load_mapping(path)
    except InvalidInputError as error:
        raise ChecklistError(str(error)) from None


def _checklist_files(request: ExportRequest, sources: list[Source]) -> list[tuple[Path, str, str]]:
    files: list[tuple[Path, str, str]] = []
    for checklist in build_all(sources):
        ckl = render_ckl(checklist)
        cklb = render_cklb(checklist)
        verify_read_back(checklist, ckl, cklb)
        if request.ckl_directory is not None:
            path = request.ckl_directory / f"{checklist.file_stem}{CKL_SUFFIX}"
            files.append((path, ckl, CKL_NAME))
        if request.cklb_directory is not None:
            path = request.cklb_directory / f"{checklist.file_stem}{CKLB_SUFFIX}"
            files.append((path, cklb, CKLB_NAME))
    return files


def outputs(request: ExportRequest, scan: ScanInputs) -> list[tuple[Path, str, str]]:
    """Return the checklist and comparison files to write, as ``(path, text, name)``.

    Raises:
        ChecklistError: If any checklist cannot be produced.
    """
    content = load_content(request.content, request.max_bytes)
    sources = select(scan, content, _mappings(request.mapping))
    files: list[tuple[Path, str, str]] = []
    if request.ckl_directory is not None or request.cklb_directory is not None:
        files.extend(_checklist_files(request, sources))
    if request.comparison is not None:
        document = compare([(source, build(source)) for source in sources])
        files.append((request.comparison, dumps(document), COMPARISON_NAME))
    return files
