"""ScanRun JSON documents produced by the audit module (findings model serialization)."""

from pathlib import Path

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    InvalidInputError,
    ParseResult,
    clean_text,
    decode_text,
    run_parser,
    sha256_hex,
)
from tools.reporting.compliance import ComplianceData, scan_run_summary, summarize, tally_findings


def scan_run_data(data: bytes) -> ComplianceData:
    """Build the compliance input of the ScanRun JSON ``data``."""
    try:
        run = model.loads(decode_text(data))
    except model.ModelError as error:
        message = f"scan run rejected: {clean_text(str(error), 200)}"
        raise InvalidInputError(message) from None
    status = run.status.value
    unfinished = 0 if status == "completed" else 1
    return ComplianceData(
        kind="scan_run",
        scan_status=status,
        error_message=run.error_message,
        benchmark_id=run.benchmark_id,
        benchmark_version=None,
        profile_id=run.profile_id,
        started_at=run.started_at,
        finished_at=run.finished_at,
        host=run.host,
        reported_host=None,
        input_sha256=sha256_hex(data),
        content_version=run.content.content_version,
        findings=run.findings,
        not_selected=0,
        scan_run=run,
        summary=scan_run_summary(
            summarize(tally_findings(run.findings), status, 1, unfinished), run.off_platform
        ),
        off_platform=run.off_platform,
    )


def parse_scan_run(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[ComplianceData]:
    """Parse a ScanRun JSON file with the validating findings model loader."""
    return run_parser(path, "scan_run", max_bytes, scan_run_data)
