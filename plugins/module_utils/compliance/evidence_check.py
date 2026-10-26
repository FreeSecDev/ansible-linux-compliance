"""Verification of an evidence bundle read from disk (FREES-51).

The reporting package calls :func:`check_bundle` with the bytes of every regular file of
a bundle directory before it uses anything from it. The bundle format and the manifest
are defined in :mod:`evidence`; this module only checks a bundle that already exists.
The checks give integrity, not authenticity: the bundle is not signed (ADR 0018 is
proposed), so whoever can write it can rewrite it consistently.

The module uses only the Python standard library and runs on Python 3.9.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final, NoReturn, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
    exceptions,
    model,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

MAX_SHOWN: Final[int] = 64


def _refuse(message: str) -> NoReturn:
    raise evidence.EvidenceError(message)


def _shown(value: object) -> str:
    return repr(str(value)[:MAX_SHOWN])


def _object(value: object, where: str, keys: tuple[str, ...]) -> dict[str, object]:
    if not isinstance(value, dict):
        _refuse(f"{where} must be a mapping")
    data = cast("dict[object, object]", value)
    result = {str(key): item for key, item in data.items()}
    if len(result) != len(data) or sorted(result) != sorted(keys):
        _refuse(f"{where} must have exactly the keys {', '.join(sorted(keys))}")
    return result


def _items(value: object, where: str, max_items: int) -> list[object]:
    if not isinstance(value, list) or len(cast("list[object]", value)) > max_items:
        _refuse(f"{where} must be a list of at most {max_items} items")
    return cast("list[object]", value)


@dataclass(frozen=True)
class VerifiedBundle:
    """A bundle whose manifest, files and documents verified.

    Attributes:
        manifest: The parsed manifest.
        run: The raw scan run of ``raw/scan-run.json``.
        evaluation: The verified evaluation, or ``None`` without exceptions.
        exceptions_text: The text of the exceptions file, or ``None``.
    """

    manifest: evidence.Manifest
    run: model.ScanRun
    evaluation: exceptions.Evaluation | None
    exceptions_text: str | None


def _unlisted_message(names: list[str]) -> str:
    signed = [name for name in names if name.endswith(evidence.SIGNATURE_SUFFIXES)]
    if signed:
        return (
            f"the bundle carries a signature ({_shown(signed[0])}) that this version cannot "
            "verify (ADR 0018 is proposed); it is refused rather than treated as unsigned"
        )
    listed = ", ".join(_shown(name) for name in names[:5])
    return f"the bundle has files that its manifest does not list: {listed}"


def _check_files(manifest: evidence.Manifest, contents: Mapping[str, bytes]) -> None:
    expected = {item.path for item in manifest.files} | {
        evidence.MANIFEST_NAME,
        evidence.CHECKSUMS_NAME,
    }
    unlisted = sorted(set(contents) - expected)
    if unlisted:
        _refuse(_unlisted_message(unlisted))
    missing = sorted(expected - set(contents))
    if missing:
        _refuse(f"the bundle is missing {', '.join(missing)}")
    for item in manifest.files:
        data = contents[item.path]
        if len(data) != item.size or evidence.sha256_hex(data) != item.sha256:
            _refuse(f"checksum mismatch for {item.path}: it changed after the bundle was written")
    sums = contents[evidence.CHECKSUMS_NAME]
    if (
        evidence.sha256_hex(sums) != manifest.checksums_sha256
        or len(sums) != manifest.checksums_size
        or sums != evidence.checksums_text(manifest.files).encode("utf-8")
    ):
        _refuse(f"{evidence.CHECKSUMS_NAME} does not match the manifest")


def _check_run(manifest: evidence.Manifest, data: bytes) -> model.ScanRun:
    try:
        run = model.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, model.ModelError) as error:
        message = f"{evidence.SCAN_RUN_PATH} is not a valid scan run: {error}"
        raise evidence.EvidenceError(message) from None
    identity = (
        run.run_id,
        run.status,
        run.started_at,
        run.finished_at,
        run.benchmark_id,
        run.profile_id,
        run.host,
        run.scanner,
        run.content,
    )
    recorded = (
        manifest.run_id,
        manifest.run_status,
        manifest.started_at,
        manifest.finished_at,
        manifest.benchmark_id,
        manifest.profile_id,
        manifest.reported_host,
        manifest.scanner,
        manifest.content,
    )
    if identity != recorded:
        _refuse(
            f"{evidence.SCAN_RUN_PATH} does not match the run, host, scanner or content "
            "of the manifest"
        )
    machine = manifest.machine_id
    if machine is not None and run.host.machine_id not in (None, machine):
        _refuse("the machine ID of the manifest differs from the one in the scan run")
    return run


def _check_stale(manifest: evidence.Manifest, data: bytes) -> None:
    document = _object(
        evidence.load_json(data, evidence.STALE_PATH),
        evidence.STALE_PATH,
        evidence.STALE_DOCUMENT_KEYS,
    )
    if (
        document["schema_version"] != evidence.STALE_SCHEMA_VERSION
        or document["kind"] != evidence.STALE_KIND
    ):
        _refuse(f"{evidence.STALE_PATH} has an unsupported kind or schema_version")
    result = _object(document["result"], f"{evidence.STALE_PATH} result", evidence.STALE_KEYS)
    if result["source_sha256"] != manifest.waivers.source_sha256:
        _refuse(f"{evidence.STALE_PATH} was computed from another exceptions file")
    evaluated = _items(
        result["evaluated_hosts"], f"{evidence.STALE_PATH} evaluated_hosts", evidence.MAX_HOSTS
    )
    if manifest.inventory_host not in evaluated:
        _refuse(
            f"{evidence.STALE_PATH} does not include the evaluation of {manifest.inventory_host}"
        )


def _check_exceptions(
    manifest: evidence.Manifest, contents: Mapping[str, bytes], run: model.ScanRun
) -> tuple[exceptions.Evaluation | None, str | None]:
    if manifest.waivers.status != evidence.EXCEPTIONS_APPLIED:
        return None, None
    raw = contents[evidence.EXCEPTIONS_FILE_PATH]
    if evidence.sha256_hex(raw) != manifest.waivers.source_sha256:
        _refuse(f"{evidence.EXCEPTIONS_FILE_PATH} is not the exceptions file the manifest names")
    try:
        text = raw.decode("utf-8")
        evaluation = exceptions.verify_evaluation(
            evidence.load_json(contents[evidence.EVALUATION_PATH], evidence.EVALUATION_PATH), text
        )
    except UnicodeDecodeError:
        _refuse(f"{evidence.EXCEPTIONS_FILE_PATH} is not valid UTF-8")
    except exceptions.ExceptionsError as error:
        message = f"{evidence.EVALUATION_PATH} does not verify: {error}"
        raise evidence.EvidenceError(message) from None
    if evaluation.target.host != manifest.inventory_host:
        _refuse(f"{evidence.EVALUATION_PATH} was made for another inventory host")
    if model.dumps(exceptions.unmarked(evaluation.run)) != model.dumps(run):
        _refuse(f"{evidence.EVALUATION_PATH} was not made from {evidence.SCAN_RUN_PATH}")
    if manifest.waivers.stale is not None:
        _check_stale(manifest, contents[evidence.STALE_PATH])
    return evaluation, text


def check_bundle(contents: Mapping[str, bytes]) -> VerifiedBundle:
    """Verify a bundle read from disk and return its verified content.

    ``contents`` maps every regular file of the bundle directory, by its path relative
    to the bundle, to its bytes. The manifest must be valid; the files must be exactly
    the listed ones plus ``bundle.json`` and ``SHA256SUMS``; every size and SHA-256
    must match; ``SHA256SUMS`` must be the one the manifest implies; the scan run must
    match the manifest; and when exceptions were applied, the exceptions file must have
    the recorded SHA-256, the evaluation must verify against it
    (:func:`exceptions.verify_evaluation`), must name the bundle's inventory host and
    must have been made from the bundle's raw scan run.

    The result is integrity, not authenticity: the bundle is not signed, so whoever can
    write it can rewrite it consistently.

    Raises:
        evidence.EvidenceError: If any check fails.
    """
    if evidence.MANIFEST_NAME not in contents:
        _refuse(
            f"the directory has no {evidence.MANIFEST_NAME}; it is not a complete evidence bundle"
        )
    manifest = evidence.parse_manifest(contents[evidence.MANIFEST_NAME])
    _check_files(manifest, contents)
    run = _check_run(manifest, contents[evidence.SCAN_RUN_PATH])
    evaluation, text = _check_exceptions(manifest, contents, run)
    return VerifiedBundle(manifest, run, evaluation, text)


def bundle_directory_paths() -> frozenset[str]:
    """Return every directory that a bundle may contain, relative to the bundle."""
    names: set[str] = set()
    for path in evidence.BUNDLE_PATHS:
        names.update(str(parent) for parent in PurePosixPath(path).parents if str(parent) != ".")
    return frozenset(names)
