"""AWS CodeBuild metadata as printed by ``aws codebuild batch-get-builds``."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    InvalidInputError,
    ParseResult,
    as_list,
    as_object,
    as_text,
    load_json,
    maybe_text,
    optional_list,
    require,
    run_parser,
)

BUILD_STATUSES: Final[frozenset[str]] = frozenset(
    {"SUCCEEDED", "FAILED", "FAULT", "TIMED_OUT", "IN_PROGRESS", "STOPPED"}
)


@dataclass(frozen=True)
class CodeBuildRecord:
    """One build: identity, status and source version. Times are UTC, from the input."""

    build_id: str
    project: str | None
    status: str
    phase: str | None
    source_version: str | None
    resolved_source_version: str | None
    started_at: str | None
    ended_at: str | None


@dataclass(frozen=True)
class CodeBuildData:
    """Builds in the file; builds that AWS reported as not found make the file an error."""

    builds: tuple[CodeBuildRecord, ...]


def _time(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            message = "a build time is outside the supported range"
            raise InvalidInputError(message) from None
    return maybe_text(value)


def _record(raw: object) -> CodeBuildRecord:
    build = as_object(raw, "build")
    status = as_text(require(build, "buildStatus", "build"), "buildStatus")
    if status not in BUILD_STATUSES:
        message = "buildStatus is not a known CodeBuild status"
        raise InvalidInputError(message)
    return CodeBuildRecord(
        build_id=as_text(require(build, "id", "build"), "build.id"),
        project=maybe_text(build.get("projectName")),
        status=status,
        phase=maybe_text(build.get("currentPhase")),
        source_version=maybe_text(build.get("sourceVersion")),
        resolved_source_version=maybe_text(build.get("resolvedSourceVersion")),
        started_at=_time(build.get("startTime")),
        ended_at=_time(build.get("endTime")),
    )


def _build(data: bytes) -> CodeBuildData:
    document = as_object(load_json(data), "codebuild document")
    missing = optional_list(document, "buildsNotFound", "document")
    if missing:
        message = f"CodeBuild reported {len(missing)} requested build(s) as not found"
        raise InvalidInputError(message)
    builds = [_record(raw) for raw in as_list(require(document, "builds", "document"), "builds")]
    if not builds:
        message = "the document lists no builds"
        raise InvalidInputError(message)
    return CodeBuildData(tuple(sorted(builds, key=lambda build: build.build_id)))


def parse_codebuild(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[CodeBuildData]:
    """Parse ``batch-get-builds`` JSON. Unknown statuses and missing builds are errors."""
    return run_parser(path, "codebuild", max_bytes, _build)
