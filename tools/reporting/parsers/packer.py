"""Packer ``manifest.json`` (post-processor manifest)."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    MAX_EPOCH_SECONDS,
    InvalidInputError,
    ParseResult,
    as_list,
    as_object,
    as_text,
    load_json,
    maybe_count,
    maybe_text,
    optional_list,
    optional_object,
    require,
    run_parser,
)


@dataclass(frozen=True)
class PackerFile:
    """A file that a build produced."""

    name: str
    size: int | None


@dataclass(frozen=True)
class PackerBuild:
    """One built image. ``build_time`` is the value from the manifest, in UTC."""

    name: str
    builder_type: str
    artifact_id: str
    build_time: str | None
    run_uuid: str | None
    files: tuple[PackerFile, ...]
    custom_data: dict[str, str]


@dataclass(frozen=True)
class PackerData:
    """All builds of a manifest and the UUID of the last run."""

    builds: tuple[PackerBuild, ...]
    last_run_uuid: str | None


def _timestamp(value: object) -> str | None:
    seconds = maybe_count(value, MAX_EPOCH_SECONDS)
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _custom_data(entry: dict[str, object]) -> dict[str, str]:
    mapping = optional_object(entry, "custom_data", "build")
    return {key: as_text(item, f"custom_data.{key}") for key, item in sorted(mapping.items())}


def _build_entry(raw: object) -> PackerBuild:
    entry = as_object(raw, "build")
    files = [as_object(item, "file") for item in optional_list(entry, "files", "build")]
    return PackerBuild(
        name=as_text(require(entry, "name", "build"), "build.name"),
        builder_type=as_text(require(entry, "builder_type", "build"), "build.builder_type"),
        artifact_id=as_text(require(entry, "artifact_id", "build"), "build.artifact_id"),
        build_time=_timestamp(entry.get("build_time")),
        run_uuid=maybe_text(entry.get("packer_run_uuid")),
        files=tuple(
            PackerFile(
                as_text(require(item, "name", "file"), "file.name"), maybe_count(item.get("size"))
            )
            for item in files
        ),
        custom_data=_custom_data(entry),
    )


def _build(data: bytes) -> PackerData:
    document = as_object(load_json(data), "packer manifest")
    builds = [
        _build_entry(raw) for raw in as_list(require(document, "builds", "manifest"), "builds")
    ]
    if not builds:
        message = "the manifest lists no builds"
        raise InvalidInputError(message)
    ordered = sorted(
        builds, key=lambda build: (build.name, build.artifact_id, build.run_uuid or "")
    )
    return PackerData(tuple(ordered), maybe_text(document.get("last_run_uuid")))


def parse_packer(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[PackerData]:
    """Parse a Packer manifest. An empty build list is an error, not an empty success."""
    return run_parser(path, "packer_manifest", max_bytes, _build)
