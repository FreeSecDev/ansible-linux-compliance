"""Fetch the pinned SCAP content listed in ``content/manifest.yml`` (ADR 0015).

The controller-side tool downloads the pinned release archive over HTTPS only
(or reads a pre-downloaded archive with ``--from-file``), verifies its SHA-512
against the manifest, and extracts only the datastreams that the manifest lists.
Every other member of the archive, including the Ansible playbooks and Bash
fixes that ComplianceAsCode ships, is never read (ADR 0003).

No script written by ComplianceAsCode may run on a managed host, not even while it
is audited (FREES-191, ADR 0026). A member is therefore checked against
``source_sha256`` and ``source_size_bytes``, the published bytes, and then
:func:`script_checks.strip_script_checks` removes every Script Check Engine check,
embedded script and XCCDF ``fix`` element. The numbers removed must equal
``removed_sce_checks``, ``removed_sce_scripts`` and ``removed_fix_elements``, and the
result must have ``sha256`` and ``size_bytes``,
the digest and size of the processed datastream that every other consumer pins
(the discover and audit roles, Molecule, the catalogue). Only the processed
datastream is written.

Extraction never uses a member name to build a path. A member is found by its
exact manifest path, must be unique, a regular file (no directory, symlink or
other special file), unencrypted, and exactly the size the manifest records. The
bytes are streamed into a temporary file, checked against the manifest SHA-256
and only then renamed to ``<output-dir>/<file name>``. Nothing the tool fetches
is committed or redistributed by this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import re
import ssl
import stat
import sys
import tempfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final, Protocol, cast
from urllib.parse import urljoin, urlsplit

import yaml

from tools.content import script_checks

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST: Final[Path] = REPO_ROOT / "content" / "manifest.yml"
DEFAULT_OUTPUT: Final[Path] = REPO_ROOT / "build" / "content"
SCHEMA_VERSION: Final[int] = 1
MAX_ARCHIVE_BYTES: Final[int] = 1024 * 1024 * 1024
MAX_MEMBER_BYTES: Final[int] = 256 * 1024 * 1024
CHUNK_BYTES: Final[int] = 1024 * 1024
MAX_REDIRECTS: Final[int] = 5
TIMEOUT_SECONDS: Final[float] = 60.0
FILE_MODE: Final[int] = 0o644
ENCRYPTED_FLAG: Final[int] = 0x1
REDIRECT_STATUSES: Final[frozenset[int]] = frozenset({301, 302, 303, 307, 308})
HTTP_OK: Final[int] = 200
MIN_PORT: Final[int] = 1
MAX_PORT: Final[int] = 65535
MAX_REMOVED: Final[int] = 100_000

SHA256: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
SHA512: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{128}")
ARCHIVE_NAME: Final[re.Pattern[str]] = re.compile(r"scap-security-guide-[0-9]+(?:\.[0-9]+)*\.zip")
DATASTREAM_NAME: Final[re.Pattern[str]] = re.compile(r"[a-z0-9]+")
DATASTREAM_FILE: Final[re.Pattern[str]] = re.compile(r"ssg-[a-z0-9]+-ds\.xml")
MEMBER_PATH: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+-]*-ds\.xml")


class ContentError(Exception):
    """Raised when the manifest, the download or the archive is not acceptable."""


class Readable(Protocol):
    """What the downloader needs from an HTTP response."""

    def read(self, size: int, /) -> bytes:
        """Read up to ``size`` bytes."""
        ...

    def close(self) -> None:
        """Release the connection."""
        ...


@dataclass(frozen=True)
class ProfileEntry:
    """A profile that a datastream contains, as recorded in the manifest."""

    profile_id: str
    title: str


@dataclass(frozen=True)
class Datastream:
    """One datastream pinned by the manifest."""

    name: str
    path: str
    sha256: str
    size_bytes: int
    benchmark_id: str
    profiles: tuple[ProfileEntry, ...]
    source_sha256: str
    source_size_bytes: int
    removed_sce_checks: int
    removed_sce_scripts: int
    removed_fix_elements: int

    @property
    def file_name(self) -> str:
        """Return the name that the extracted file gets."""
        return PurePosixPath(self.path).name


@dataclass(frozen=True)
class Archive:
    """The release archive pinned by the manifest."""

    url: str
    sha512: str
    size_bytes: int


@dataclass(frozen=True)
class Manifest:
    """The validated content manifest."""

    version: str
    archive: Archive
    datastreams: tuple[Datastream, ...]


def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        message = f"{where} must be a mapping"
        raise ContentError(message)
    table = cast("dict[object, object]", value)
    return {str(key): item for key, item in table.items()}


def _text(table: Mapping[str, object], key: str, where: str, pattern: re.Pattern[str]) -> str:
    value = table.get(key)
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        message = f"{where}.{key} is missing or malformed"
        raise ContentError(message)
    return value


def _size(table: Mapping[str, object], key: str, where: str, limit: int) -> int:
    value = table.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= limit:
        message = f"{where}.{key} must be an integer from 1 to {limit}"
        raise ContentError(message)
    return value


def check_https_url(url: str) -> str:
    """Return ``url`` if it is an HTTPS URL without credentials, else raise."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as error:
        message = f"not a valid URL: {url!r}"
        raise ContentError(message) from error
    if parts.scheme != "https" or not parts.hostname:
        message = f"only HTTPS URLs are allowed: {url!r}"
        raise ContentError(message)
    if parts.username is not None or parts.password is not None:
        message = f"URLs with credentials are not allowed: {url!r}"
        raise ContentError(message)
    if port is not None and not MIN_PORT <= port <= MAX_PORT:
        message = f"invalid port in URL: {url!r}"
        raise ContentError(message)
    return url


def _count(table: Mapping[str, object], key: str, where: str) -> int:
    value = table.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_REMOVED:
        message = f"{where}.{key} must be an integer from 0 to {MAX_REMOVED}"
        raise ContentError(message)
    return value


def _profile(value: object, where: str) -> ProfileEntry:
    table = _mapping(value, where)
    profile_id, title = table.get("id"), table.get("title")
    if not isinstance(profile_id, str) or not profile_id or not isinstance(title, str):
        message = f"{where} needs a string id and title"
        raise ContentError(message)
    return ProfileEntry(profile_id, title)


def _datastream(value: object, index: int) -> Datastream:
    where = f"datastreams[{index}]"
    table = _mapping(value, where)
    path = _text(table, "path", where, MEMBER_PATH)
    parts = PurePosixPath(path).parts
    if (
        PurePosixPath(path).as_posix() != path
        or ".." in parts
        or DATASTREAM_FILE.fullmatch(parts[-1]) is None
    ):
        message = f"{where}.path must be a relative archive path to an ssg-*-ds.xml file"
        raise ContentError(message)
    raw_profiles = table.get("profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        message = f"{where}.profiles must be a non-empty list"
        raise ContentError(message)
    profiles = tuple(
        _profile(item, f"{where}.profiles[{number}]")
        for number, item in enumerate(cast("list[object]", raw_profiles))
    )
    if len({profile.profile_id for profile in profiles}) != len(profiles):
        message = f"{where}.profiles lists a profile twice"
        raise ContentError(message)
    return Datastream(
        name=_text(table, "name", where, DATASTREAM_NAME),
        path=path,
        sha256=_text(table, "sha256", where, SHA256),
        size_bytes=_size(table, "size_bytes", where, MAX_MEMBER_BYTES),
        benchmark_id=_text(table, "benchmark_id", where, re.compile(r"\S+")),
        profiles=profiles,
        source_sha256=_text(table, "source_sha256", where, SHA256),
        source_size_bytes=_size(table, "source_size_bytes", where, MAX_MEMBER_BYTES),
        removed_sce_checks=_count(table, "removed_sce_checks", where),
        removed_sce_scripts=_count(table, "removed_sce_scripts", where),
        removed_fix_elements=_count(table, "removed_fix_elements", where),
    )


def parse_manifest(document: object) -> Manifest:
    """Validate a loaded manifest document.

    Raises:
        ContentError: If any field is missing, malformed, unsafe or duplicated.
    """
    root = _mapping(document, "manifest")
    schema = root.get("schema_version")
    if isinstance(schema, bool) or schema != SCHEMA_VERSION:
        message = f"manifest schema_version must be {SCHEMA_VERSION}"
        raise ContentError(message)
    source = _mapping(root.get("source"), "source")
    archive = _mapping(root.get("archive"), "archive")
    base = check_https_url(_text(archive, "download_base_url", "archive", re.compile(r"\S+")))
    file_name = _text(archive, "file_name", "archive", ARCHIVE_NAME)
    raw = root.get("datastreams")
    if not isinstance(raw, list) or not raw:
        message = "datastreams must be a non-empty list"
        raise ContentError(message)
    streams = tuple(
        _datastream(item, number) for number, item in enumerate(cast("list[object]", raw))
    )
    for key in ("name", "file_name", "path"):
        values = [getattr(stream, key) for stream in streams]
        if len(set(values)) != len(values):
            message = f"datastream {key} values must be unique"
            raise ContentError(message)
    return Manifest(
        version=_text(source, "version", "source", re.compile(r"v[0-9]+(?:\.[0-9]+)*")),
        archive=Archive(
            url=check_https_url(f"{base.rstrip('/')}/{file_name}"),
            sha512=_text(archive, "sha512", "archive", SHA512),
            size_bytes=_size(archive, "size_bytes", "archive", MAX_ARCHIVE_BYTES),
        ),
        datastreams=streams,
    )


def load_manifest(path: Path) -> Manifest:
    """Read and validate the manifest file at ``path``."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        message = f"cannot read manifest {path}: {error}"
        raise ContentError(message) from error
    return parse_manifest(document)


class _Download:
    def __init__(
        self, connection: http.client.HTTPSConnection, response: http.client.HTTPResponse
    ) -> None:
        self.connection = connection
        self.response = response

    def read(self, size: int, /) -> bytes:
        return self.response.read(size)

    def close(self) -> None:
        self.response.close()
        self.connection.close()


def https_open(url: str) -> Readable:
    """Open ``url`` over HTTPS, following at most five redirects that stay on HTTPS.

    Certificates are verified with the default trust store. Any other scheme,
    including a redirect to plain HTTP, is refused.
    """
    current = check_https_url(url)
    context = ssl.create_default_context()
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        connection = http.client.HTTPSConnection(
            parts.hostname or "", parts.port, timeout=TIMEOUT_SECONDS, context=context
        )
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        try:
            connection.request("GET", target, headers={"Accept-Encoding": "identity"})
            response = connection.getresponse()
        except (OSError, http.client.HTTPException) as error:
            connection.close()
            message = f"download failed: {type(error).__name__}"
            raise ContentError(message) from error
        if response.status == HTTP_OK:
            return _Download(connection, response)
        location = response.getheader("Location")
        status = response.status
        response.close()
        connection.close()
        if status not in REDIRECT_STATUSES or not location:
            message = f"download failed: HTTP status {status}"
            raise ContentError(message)
        current = check_https_url(urljoin(current, location))
    message = "download failed: too many redirects"
    raise ContentError(message)


def _read(source: Readable) -> bytes:
    try:
        return source.read(CHUNK_BYTES)
    except (OSError, http.client.HTTPException) as error:
        message = f"download failed: {type(error).__name__}"
        raise ContentError(message) from error


def _within(received: int, limit: int, label: str) -> None:
    if received > limit:
        message = f"{label} is larger than the manifest allows"
        raise ContentError(message)


def _matches(label: str, *, ok: bool) -> None:
    if not ok:
        message = f"{label} does not match the manifest SHA-256 or size"
        raise ContentError(message)


def _new_file(directory: Path, prefix: str) -> tuple[int, str]:
    return tempfile.mkstemp(prefix=prefix, suffix=".part", dir=directory)


def download_archive(
    archive: Archive, directory: Path, opener: Callable[[str], Readable] = https_open
) -> Path:
    """Download the pinned archive into ``directory`` and verify its SHA-512.

    The download is capped at the size that the manifest records and is deleted
    if its size or SHA-512 differs.

    Returns:
        The path of the verified archive.
    """
    source = opener(check_https_url(archive.url))
    descriptor, name = _new_file(directory, ".archive-")
    digest = hashlib.sha512()
    received = 0
    try:
        with os.fdopen(descriptor, "wb") as handle:
            while chunk := _read(source):
                received += len(chunk)
                _within(received, archive.size_bytes, "the download")
                digest.update(chunk)
                handle.write(chunk)
        _check_archive(received, digest.hexdigest(), archive)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    finally:
        source.close()
    return Path(name)


def _check_archive(size: int, sha512: str, archive: Archive) -> None:
    if size != archive.size_bytes:
        message = f"archive size {size} differs from the manifest ({archive.size_bytes})"
        raise ContentError(message)
    if sha512 != archive.sha512:
        message = "archive SHA-512 does not match the manifest"
        raise ContentError(message)


def verify_archive_file(path: Path, archive: Archive) -> None:
    """Verify the size and SHA-512 of a pre-downloaded archive.

    Raises:
        ContentError: If the file is not a regular file, cannot be read or differs.
    """
    digest = hashlib.sha512()
    size = 0
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            message = f"{path} is not a regular file"
            raise ContentError(message)
        with path.open("rb") as handle:
            while chunk := handle.read(CHUNK_BYTES):
                size += len(chunk)
                digest.update(chunk)
    except OSError as error:
        message = f"cannot read {path}: {error.strerror or type(error).__name__}"
        raise ContentError(message) from error
    _check_archive(size, digest.hexdigest(), archive)


def _find_member(bundle: zipfile.ZipFile, stream: Datastream) -> zipfile.ZipInfo:
    matches = [info for info in bundle.infolist() if info.filename == stream.path]
    if len(matches) != 1:
        message = f"{stream.path} must appear exactly once in the archive, found {len(matches)}"
        raise ContentError(message)
    info = matches[0]
    file_type = stat.S_IFMT(info.external_attr >> 16)
    if file_type not in {0, stat.S_IFREG}:
        message = f"{stream.path} is not a regular file (no directories, symlinks or special files)"
        raise ContentError(message)
    if info.flag_bits & ENCRYPTED_FLAG:
        message = f"{stream.path} is encrypted"
        raise ContentError(message)
    if info.file_size != stream.source_size_bytes:
        message = (
            f"{stream.path} has size {info.file_size}, "
            f"the manifest records {stream.source_size_bytes}"
        )
        raise ContentError(message)
    return info


def processed(stream: Datastream, data: bytes) -> bytes:
    """Return the published bytes of ``stream`` without their script checks, as pinned.

    Raises:
        ContentError: If ``data`` is not the published member, a script construct cannot be
            removed safely, the numbers removed differ from the manifest, or the result does
            not have the pinned digest and size.
    """
    _matches(
        stream.path,
        ok=len(data) == stream.source_size_bytes
        and hashlib.sha256(data).hexdigest() == stream.source_sha256,
    )
    try:
        stripped = script_checks.strip_script_checks(data)
    except script_checks.ScriptCheckError as error:
        message = f"{stream.path}: {error}"
        raise ContentError(message) from error
    removed = (stripped.checks, stripped.scripts, stripped.fixes)
    pinned = (stream.removed_sce_checks, stream.removed_sce_scripts, stream.removed_fix_elements)
    if removed != pinned:
        message = (
            f"{stream.path}: removed {stripped.checks} SCE checks, {stripped.scripts} scripts and "
            f"{stripped.fixes} fix elements, the manifest records {pinned[0]}, {pinned[1]} and "
            f"{pinned[2]}"
        )
        raise ContentError(message)
    _matches(
        f"{stream.path} without its script checks",
        ok=len(stripped.data) == stream.size_bytes
        and hashlib.sha256(stripped.data).hexdigest() == stream.sha256,
    )
    return stripped.data


def _extract_member(
    bundle: zipfile.ZipFile, info: zipfile.ZipInfo, stream: Datastream, directory: Path
) -> Path:
    descriptor, name = _new_file(directory, ".datastream-")
    pieces: list[bytes] = []
    received = 0
    try:
        with bundle.open(info) as source, os.fdopen(descriptor, "wb") as handle:
            while chunk := _read(source):
                received += len(chunk)
                _within(received, stream.source_size_bytes, stream.path)
                pieces.append(chunk)
            handle.write(processed(stream, b"".join(pieces)))
        Path(name).chmod(FILE_MODE)
        destination = directory / stream.file_name
        Path(name).replace(destination)
    except (
        zipfile.BadZipFile,
        OSError,
        EOFError,
        zlib.error,
        NotImplementedError,
        RuntimeError,
    ) as error:
        Path(name).unlink(missing_ok=True)
        message = f"cannot extract {stream.path}: {type(error).__name__}"
        raise ContentError(message) from error
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return destination


def extract_datastreams(
    archive_path: Path, streams: Sequence[Datastream], directory: Path
) -> list[Path]:
    """Extract only ``streams`` from the archive, verified and without their script checks.

    No other member is read. Each member must have its ``source_sha256``, and the file
    written is the processed datastream with its pinned ``sha256`` (:func:`processed`).
    Returns the written files in the order given.
    """
    try:
        with zipfile.ZipFile(archive_path) as bundle:
            infos = [_find_member(bundle, stream) for stream in streams]
            return [
                _extract_member(bundle, info, stream, directory)
                for info, stream in zip(infos, streams, strict=True)
            ]
    except (zipfile.BadZipFile, OSError) as error:
        message = f"cannot read the archive: {type(error).__name__}"
        raise ContentError(message) from error


def _prepare_directory(directory: Path) -> None:
    if directory.is_symlink():
        message = f"{directory} is a symlink"
        raise ContentError(message)
    directory.mkdir(parents=True, exist_ok=True)


def select(manifest: Manifest, names: Sequence[str]) -> tuple[Datastream, ...]:
    """Return the manifest datastreams called ``names``, or all of them when empty."""
    if not names:
        return manifest.datastreams
    known = {stream.name: stream for stream in manifest.datastreams}
    unknown = sorted(set(names) - set(known))
    if unknown:
        message = f"not in the manifest: {', '.join(unknown)}"
        raise ContentError(message)
    return tuple(known[name] for name in dict.fromkeys(names))


def fetch(
    manifest: Manifest,
    directory: Path,
    from_file: Path | None = None,
    names: Sequence[str] = (),
    opener: Callable[[str], Readable] = https_open,
) -> list[Path]:
    """Obtain the archive, verify it, and extract the selected datastreams.

    Args:
        manifest: The validated manifest.
        directory: Where the datastreams are written.
        from_file: A pre-downloaded archive; no network access is used when set.
        names: Datastream names to extract; all when empty.
        opener: Opens a URL; replaced in tests.

    Returns:
        The extracted, verified files.
    """
    streams = select(manifest, names)
    _prepare_directory(directory)
    if from_file is not None:
        verify_archive_file(from_file, manifest.archive)
        return extract_datastreams(from_file, streams, directory)
    downloaded = download_archive(manifest.archive, directory, opener)
    try:
        return extract_datastreams(downloaded, streams, directory)
    finally:
        downloaded.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--from-file", type=Path, help="Use this archive; never touch the network.")
    parser.add_argument("--datastream", action="append", default=[], help="Datastream name.")
    arguments = parser.parse_args(argv)
    try:
        manifest = load_manifest(arguments.manifest)
        written = fetch(manifest, arguments.output_dir, arguments.from_file, arguments.datastream)
    except ContentError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    for path in written:
        print(f"verified {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
