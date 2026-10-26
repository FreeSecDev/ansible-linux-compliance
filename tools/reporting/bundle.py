"""Evidence bundles written by the ``evidence`` role as report inputs (FREES-51).

``--evidence-bundle DIR`` names one bundle directory. The directory is read without
following any symbolic link: every component of the path is opened with
``O_NOFOLLOW``, every entry is inspected with ``lstat`` semantics, only the
directories and files that the bundle format defines are accepted, and each file is
read through a descriptor with a size bound. The bytes are then verified with
:func:`evidence_check.check_bundle`: the manifest, every SHA-256 and size, ``SHA256SUMS``,
the scan run against the manifest, and, when exceptions were applied, the evaluation
against the exceptions file in the bundle and against the raw scan run.

A bundle contributes one compliance input: the evaluation when exceptions were
applied (its scan run carries the waivers, and it also feeds the ``exceptions``
section), otherwise the raw scan run. The XCCDF, ARF and tailoring files are
verified but not parsed again, because they describe the same scan as the scan run.

A bundle that does not verify is an input ``error``; nothing from it is used. Unless its
manifest is readable and records that no exceptions were applied, the error is an
``exceptions_evaluation`` input, so it is also an error in the ``exceptions`` section
and cannot make an exception look stale there. The
bundle is not signed (ADR 0018 is proposed), so a verified bundle is consistent, not
authentic, and the report labels nothing as verified.
"""

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
    evidence_check,
)
from tools.reporting.common import (
    MAX_PATH_LENGTH,
    ArtifactRef,
    InvalidInputError,
    ParseResult,
    SectionStatus,
    clean_text,
    decode_text,
    parse_bytes,
    read_descriptor,
    sha256_hex,
)
from tools.reporting.compliance import ComplianceData
from tools.reporting.parsers.evaluation import (
    EXCEPTIONS_FILE_FORMAT,
    EvaluationData,
    compliance_result,
    evaluation_data,
)
from tools.reporting.parsers.evaluation import FORMAT as EVALUATION_FORMAT
from tools.reporting.parsers.scanrun import scan_run_data

SCAN_RUN_FORMAT: Final[str] = "scan_run"
MAX_ENTRIES: Final[int] = 64
DIRECTORIES: Final[frozenset[str]] = evidence_check.bundle_directory_paths()
_DIRECTORY_FLAGS: Final[int] = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
_FILE_FLAGS: Final[int] = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(frozen=True)
class BundleInput:
    """The report inputs of one evidence bundle.

    Attributes:
        compliance: The compliance input: the evaluation's scan run or the raw scan run.
        evaluation: The evaluation input of the ``exceptions`` section, or ``None``.
        exceptions_file: The exceptions file of the bundle, or ``None``.
    """

    compliance: ParseResult[ComplianceData]
    evaluation: ParseResult[EvaluationData] | None
    exceptions_file: ParseResult[str] | None


def _open_directory(path: Path) -> int:
    parts = path.parts[1:] if path.is_absolute() else path.parts
    directory = os.open("/" if path.is_absolute() else ".", _DIRECTORY_FLAGS)
    try:
        for name in parts:
            child = os.open(name, _DIRECTORY_FLAGS | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
    except BaseException:
        os.close(directory)
        raise
    return directory


class _Reader:
    """Reads the files of one bundle directory tree with bounded size and count."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self.entries = 0
        self.contents: dict[str, bytes] = {}

    def read(self, directory: int, prefix: str) -> None:
        with os.scandir(directory) as listing:
            names = sorted(entry.name for entry in listing)
        for name in names:
            self.entries += 1
            if self.entries > MAX_ENTRIES:
                message = f"the bundle has more than {MAX_ENTRIES} entries"
                raise InvalidInputError(message)
            self._entry(directory, prefix, name)

    def _entry(self, directory: int, prefix: str, name: str) -> None:
        relative = f"{prefix}{name}"
        shown = clean_text(relative, 128)
        mode = os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode
        if stat.S_ISDIR(mode):
            if relative not in DIRECTORIES:
                message = f"the bundle has an unexpected directory {shown!r}"
                raise InvalidInputError(message)
            child = os.open(name, _DIRECTORY_FLAGS | os.O_NOFOLLOW, dir_fd=directory)
            try:
                self.read(child, f"{relative}/")
            finally:
                os.close(child)
            return
        if not stat.S_ISREG(mode):
            message = f"{shown!r} in the bundle is not a regular file or a directory"
            raise InvalidInputError(message)
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory)
        try:
            self.contents[relative] = read_descriptor(descriptor, self.max_bytes)
        except InvalidInputError as error:
            message = f"{shown!r} in the bundle: {error}"
            raise InvalidInputError(message) from None
        finally:
            os.close(descriptor)


def read_bundle(path: Path, max_bytes: int) -> dict[str, bytes]:
    """Read every file of a bundle directory, by path relative to the bundle.

    Raises:
        FileNotFoundError: If the directory does not exist.
        InvalidInputError: If the tree has a symbolic link, a special file, an
            unexpected directory, too many entries or a file that cannot be read.
    """
    try:
        directory = _open_directory(path)
    except FileNotFoundError:
        raise
    except OSError:
        message = "the evidence bundle cannot be opened (not a directory, or a symbolic link)"
        raise InvalidInputError(message) from None
    reader = _Reader(max_bytes)
    try:
        reader.read(directory, "")
    except OSError:
        message = "the evidence bundle cannot be read"
        raise InvalidInputError(message) from None
    finally:
        os.close(directory)
    return reader.contents


def _peek_manifest(path: Path, max_bytes: int) -> dict[str, bytes]:
    """Read only ``bundle.json`` of a bundle whose tree could not be read, or nothing."""
    try:
        directory = _open_directory(path)
    except OSError:
        return {}
    try:
        descriptor = os.open(evidence.MANIFEST_NAME, _FILE_FLAGS, dir_fd=directory)
    except OSError:
        return {}
    finally:
        os.close(directory)
    try:
        return {evidence.MANIFEST_NAME: read_descriptor(descriptor, max_bytes)}
    except InvalidInputError:
        return {}
    finally:
        os.close(descriptor)


def may_hold_exceptions(contents: dict[str, bytes]) -> bool:
    """Return whether a rejected bundle may have carried an exceptions evaluation.

    Only a readable manifest that records that no exceptions were applied, in a bundle
    without exception documents, says no. Anything else counts as yes, so a broken
    bundle is also an error in the ``exceptions`` section and cannot make an exception
    look stale or unused there.
    """
    if evidence.EVALUATION_PATH in contents or evidence.EXCEPTIONS_FILE_PATH in contents:
        return True
    manifest = contents.get(evidence.MANIFEST_NAME)
    if manifest is None:
        return True
    try:
        status = evidence.parse_manifest(manifest).waivers.status
    except evidence.EvidenceError:
        return True
    return status == evidence.EXCEPTIONS_APPLIED


def _rejected(
    display: str, contents: dict[str, bytes], status: SectionStatus, reason: str
) -> BundleInput:
    manifest = contents.get(evidence.MANIFEST_NAME)
    artifact = ArtifactRef(
        f"{display}/{evidence.MANIFEST_NAME}",
        None if manifest is None else sha256_hex(manifest),
        None if manifest is None else len(manifest),
    )
    if not may_hold_exceptions(contents):
        rejected: ParseResult[ComplianceData] = ParseResult(
            SCAN_RUN_FORMAT, status, reason, artifact, None
        )
        return BundleInput(rejected, None, None)
    evaluation: ParseResult[EvaluationData] = ParseResult(
        EVALUATION_FORMAT, status, reason, artifact, None
    )
    return BundleInput(compliance_result(evaluation), evaluation, None)


def parse_bundle(path: Path, max_bytes: int) -> BundleInput:
    """Read and verify one evidence bundle and return its report inputs.

    A missing directory is ``unavailable``; every other problem is ``error``.
    """
    display = clean_text(str(path), MAX_PATH_LENGTH - 64)
    try:
        contents = read_bundle(path, max_bytes)
    except FileNotFoundError:
        return _rejected(display, {}, SectionStatus.UNAVAILABLE, "evidence bundle does not exist")
    except InvalidInputError as error:
        reason = f"evidence bundle rejected: {error}"
        return _rejected(display, _peek_manifest(path, max_bytes), SectionStatus.ERROR, reason)
    try:
        verified = evidence_check.check_bundle(contents)
    except evidence.EvidenceError as error:
        reason = f"evidence bundle rejected: {clean_text(str(error), 300)}"
        return _rejected(display, contents, SectionStatus.ERROR, reason)
    checked = verified.evaluation
    if checked is None:
        compliance = parse_bytes(
            f"{display}/{evidence.SCAN_RUN_PATH}",
            SCAN_RUN_FORMAT,
            contents[evidence.SCAN_RUN_PATH],
            scan_run_data,
        )
        return BundleInput(compliance, None, None)
    evaluation = parse_bytes(
        f"{display}/{evidence.EVALUATION_PATH}",
        EVALUATION_FORMAT,
        contents[evidence.EVALUATION_PATH],
        lambda data: evaluation_data(data, checked),
    )
    exceptions_file = parse_bytes(
        f"{display}/{evidence.EXCEPTIONS_FILE_PATH}",
        EXCEPTIONS_FILE_FORMAT,
        contents[evidence.EXCEPTIONS_FILE_PATH],
        decode_text,
    )
    return BundleInput(compliance_result(evaluation), evaluation, exceptions_file)
