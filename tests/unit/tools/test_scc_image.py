"""Repository guarantees of the CI-only SCC image (ADR 0019, FREES-144).

The SCAP Compliance Checker is downloaded from DISA when the image is built and is
never redistributed:

- No SCC bundle, package or binary is tracked in Git, whether plain, compressed or
  encoded.
- The image carries a ``localhost/`` tag.
- The SCC identifiers (the image name, the SCC paths, the ``SCC_*`` variables, the
  SCC make targets and ``cscc``) appear only in an allow-list of places: the
  ``scc-smoke`` job, the SCC variables and targets of the Makefile, ``tools/scc``,
  ``extensions/ci/scc``, documentation and tests. None of those places pushes,
  saves or exports an image.

Any tracked file that names an SCC identifier may not contain a push, login, save
or export command. Only Markdown and this module are exempt, because their mutation
strings and examples are data. The Makefile may include only ``$(SCC_PINS)``
unchecked; every other included file is checked as Makefile text.

The guard is an allow-list on purpose. The release workflow of ADR 0012 may publish
the collection, but it can never name the SCC image. The SCC expiry is enforced on
the SCC path (``make scc-expiry-check``, a prerequisite of ``scc-image``), not in
every pull request. ``ci-gate`` accepts a skipped ``scc-smoke`` only for a pull
request or a merge group whose path filter found no SCC change, never for a push
or a scheduled run.

A detector hit names the file and the offset. A reviewed false positive is accepted
only through ``ACCEPTED_BINARY_FINDINGS`` (path and SHA-256 of the exact content).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PINS_PATH = REPOSITORY_ROOT / "extensions" / "ci" / "scc" / "scc.pins"
CONTAINERFILE = REPOSITORY_ROOT / "extensions" / "ci" / "scc" / "Containerfile"
WORKFLOW_DIRECTORY = REPOSITORY_ROOT / ".github" / "workflows"
CI_WORKFLOW = WORKFLOW_DIRECTORY / "ci.yml"
MAKEFILE = REPOSITORY_ROOT / "Makefile"
FETCH_SCRIPT = REPOSITORY_ROOT / "tools" / "scc" / "fetch-scc.sh"
SMOKE_SCRIPT = REPOSITORY_ROOT / "tools" / "scc" / "smoke-test.sh"
DISA_ZIP = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
DISA_TXT = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/txt/"
SHA256 = re.compile(r"[0-9a-f]{64}")
PIN_LINE = re.compile(r"(SCC_[A-Z0-9_]+) := (\S+)")
MINIMUM_PIN_AGE = timedelta(days=7)
EXPIRY_MARGIN = timedelta(days=7)
EXPECTED_PINS = (
    "SCC_VERSION",
    "SCC_PUBLISHED",
    "SCC_EXPIRES",
    "SCC_BUNDLE",
    "SCC_BUNDLE_URL",
    "SCC_BUNDLE_SIZE",
    "SCC_BUNDLE_SHA256",
    "SCC_CHECKSUMS_URL",
    "SCC_DEB_MEMBER",
    "SCC_DEB_SHA256",
    "SCC_CSCC_SHA256",
)
PACKAGE_SUFFIXES = (".deb", ".rpm", ".zip", ".tar.gz", ".tgz", ".pkg", ".exe", ".msi", ".scc")
SCC_NAMES = re.compile(
    r"(?i)^(cscc|cscc-remote|scc|scc\.sig|options\.xml)$|^scc[-_][0-9]|_scc-[0-9]|\.cklb?$"
)
BINARY_MAGIC = (
    b"\x7fELF",
    b"PK\x03\x04",
    b"!<arch>\n",
    b"\xed\xab\xee\xdb",
    b"\x1f\x8b",
    b"\xfd7zXZ\x00",
    b"(\xb5/\xfd",
    b"7z\xbc\xaf\x27\x1c",
)
BZIP2_MAGIC = re.compile(rb"BZh[1-9]1AY&SY")
GZIP_ANYWHERE = re.compile(rb"\x1f\x8b\x08[\x00-\x1f]")
EMBEDDED_MAGIC = tuple(magic for magic in BINARY_MAGIC if len(magic) >= 4)
BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]{24,}")
HEX_RUN = re.compile(rb"[0-9a-fA-F]{128,}")
BASE64_ALIGNMENTS = 4
MAX_DECODED_CHARACTERS = 1024 * 1024
SCC_IDENTIFIER = re.compile(
    r"freesecdev-scc|build/scc|extensions/ci/scc|tools/scc|scc\.pins|\bcscc\b"
    r"|\bSCC_[A-Z][A-Z0-9_]*\b|\bscc-(?:expiry-check|fetch|image-clean|image|smoke)\b"
)
SCC_WORKFLOW = "ci.yml"
SCC_JOBS = frozenset({"scc-changes", "scc-smoke", "ci-gate"})
SCC_JOB_PERMISSIONS: tuple[dict[str, str], ...] = ({}, {"contents": "read"})
SCC_TARGETS = frozenset(
    {"scc-expiry-check", "scc-fetch", "scc-image", "scc-smoke", "scc-image-clean"}
)
GUARD_MODULE = "tests/unit/tools/test_scc_image.py"
ACCEPTED_BINARY_FINDINGS: dict[str, str] = {}
INCLUDE = re.compile(r"(?:-include|sinclude|include)\s+(.+)")
PINS_INCLUDE = "include $(SCC_PINS)"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
EXPIRY_SCRIPT = REPOSITORY_ROOT / "tools" / "scc" / "check-expiry.sh"
FILTER_SCRIPT = REPOSITORY_ROOT / "tools" / "scc" / "needs-smoke.sh"
SCC_RECIPE_TARGETS = SCC_TARGETS | {"lint-containerfile"}
ALLOWED_PREFIXES = ("docs/", "tests/", "changelogs/", "tools/scc/", "extensions/ci/scc/")
SHELL_SCRIPT_LIST = "SHELL_SCRIPTS"
HELP_DEFINE = "define HELP_TEXT"
ASSIGNMENT = re.compile(r"([A-Za-z0-9_.-]+)\s*(?::=|::=|\?=|\+=|=)")
RULE = re.compile(r"([A-Za-z0-9_./%-]+(?:\s+[A-Za-z0-9_./%-]+)*)\s*:(?!=)")
PUSH_PATTERNS = re.compile(
    r"(?i)\b(docker|podman|buildah|nerdctl)\b[^\n]*?\b(push|login|save|export)\b"
    r"|\bskopeo\b|\bcrane\b|\boras\b|--push\b|\bregctl\b"
)
PUBLISHING_ACTIONS = (
    "docker/login-action",
    "docker/build-push-action",
    "redhat-actions/push-to-registry",
    "actions/upload-artifact",
)
TIMEOUT_SECONDS = 60
DIGEST_PINS = ("SCC_BUNDLE_SHA256", "SCC_DEB_SHA256", "SCC_CSCC_SHA256")
CONTAINERFILE_FORBIDDEN = re.compile(
    r"(?i)\b(curl|wget|apt-get|apt|ADD)\b|https?://(?!github\.com/FreeSecDev/)"
)
REGISTRY_TAGS = ("ghcr.io/freesecdev/scc:latest", "freesecdev-scc:ci", "localhost/x")
PLAIN_HTTP_CHECKSUMS = "http://dl.dod.cyber.mil/wp-content/uploads/stigs/txt/x"
PYTEST_EXPORT = (
    "import subprocess\n\n\ndef test_export() -> None:\n"
    '    subprocess.run(["docker", "save", "localhost/freesecdev-scc:ci", "-o", "x.tar"])\n'
)
INDIRECT_SAVE = "IMAGE = 'localhost/freesecdev-scc:ci'\nCOMMAND = 'docker image save ' + IMAGE\n"
CHANGELOG_PUSH = "---\ntrivial:\n  - podman push localhost/freesecdev-scc:ci\n"


def pins() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in PINS_PATH.read_text(encoding="utf-8").splitlines():
        match = PIN_LINE.fullmatch(line)
        assert match is not None, f"unexpected line in {PINS_PATH.name}: {line!r}"
        assert match.group(1) not in values
        values[match.group(1)] = match.group(2)
    return values


def magic_offset(data: bytes) -> int | None:
    offsets = [data.find(magic) for magic in EMBEDDED_MAGIC]
    offsets += [
        match.start() for match in (BZIP2_MAGIC.search(data), GZIP_ANYWHERE.search(data)) if match
    ]
    found = [offset for offset in offsets if offset >= 0]
    return min(found) if found else None


def starts_with_binary_magic(data: bytes) -> bool:
    return data.startswith(BINARY_MAGIC) or BZIP2_MAGIC.match(data) is not None


def decoded_base64(run: bytes) -> list[tuple[int, bytes]]:
    decoded: list[tuple[int, bytes]] = []
    for offset in range(BASE64_ALIGNMENTS):
        chunk = run[offset : offset + MAX_DECODED_CHARACTERS]
        try:
            decoded.append((offset, base64.b64decode(chunk[: len(chunk) // 4 * 4], validate=True)))
        except binascii.Error:
            continue
    return decoded


def decoded_hex(run: bytes) -> list[tuple[int, bytes]]:
    decoded: list[tuple[int, bytes]] = []
    for offset in range(2):
        chunk = run[offset : offset + MAX_DECODED_CHARACTERS]
        decoded.append((offset, bytes.fromhex(chunk[: len(chunk) // 2 * 2].decode("ascii"))))
    return decoded


def binary_evidence(data: bytes) -> str | None:
    if starts_with_binary_magic(data):
        return "binary magic at offset 0"
    encodings = (("base64", BASE64_RUN, decoded_base64), ("hex", HEX_RUN, decoded_hex))
    for encoding, pattern, decode in encodings:
        for run in pattern.finditer(data):
            for alignment, decoded in decode(run.group(0)):
                offset = magic_offset(decoded)
                if offset is not None:
                    start = run.start() + alignment
                    return (
                        f"{encoding} run at offset {start}: binary magic at decoded offset {offset}"
                    )
    return None


def looks_like_binary(data: bytes) -> bool:
    return binary_evidence(data) is not None


@dataclass
class _MakeState:
    in_help: bool = False
    recipe_target: str | None = None
    violations: list[str] = field(default_factory=list[str])


def logical_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        if line.endswith("\\"):
            pending.append(line[:-1])
            continue
        pending.append(line)
        lines.append((start, " ".join(pending)))
        pending = []
    if pending:
        lines.append((start, " ".join(pending)))
    return lines


def _makefile_line_allowed(line: str, state: _MakeState) -> bool:
    if state.in_help or line.startswith(".PHONY:") or line == "include $(SCC_PINS)":
        return True
    if line.startswith("\t"):
        return state.recipe_target in SCC_RECIPE_TARGETS
    assignment = ASSIGNMENT.match(line)
    if assignment is not None:
        name = assignment.group(1)
        if name == SHELL_SCRIPT_LIST:
            return {match.group(0) for match in SCC_IDENTIFIER.finditer(line)} == {"tools/scc"}
        return name.startswith("SCC_")
    rule = RULE.match(line)
    return rule is not None and set(rule.group(1).split()) <= SCC_TARGETS


def _include_violations(
    name: str, number: int, line: str, files: dict[str, str], seen: frozenset[str]
) -> list[str]:
    match = INCLUDE.fullmatch(line)
    if match is None or line == PINS_INCLUDE:
        return []
    found: list[str] = []
    for included in match.group(1).split():
        if "$" in included or "%" in included or "*" in included:
            found.append(f"{name}:{number}: include of a computed path {included!r}")
        elif included not in files:
            found.append(f"{name}:{number}: include of an untracked file {included!r}")
        elif included in seen:
            found.append(f"{name}:{number}: recursive include of {included!r}")
        else:
            found += makefile_violations(
                files[included], files, name=included, seen=seen | {included}
            )
    return found


def makefile_violations(
    text: str,
    files: dict[str, str] | None = None,
    *,
    name: str = "Makefile",
    seen: frozenset[str] = frozenset(),
) -> list[str]:
    known = files if files is not None else {}
    state = _MakeState()
    for number, line in logical_lines(text):
        state.violations += _include_violations(name, number, line, known, seen)
        if line.startswith(HELP_DEFINE):
            state.in_help = True
        elif state.in_help and line == "endef":
            state.in_help = False
        elif not line.startswith("\t") and not state.in_help:
            rule = RULE.match(line)
            assignment = ASSIGNMENT.match(line)
            if rule is not None and assignment is None:
                state.recipe_target = rule.group(1)
            elif line.strip():
                state.recipe_target = None
        if not SCC_IDENTIFIER.search(line):
            continue
        if not _makefile_line_allowed(line, state):
            state.violations.append(f"{name}:{number}: SCC identifier outside the SCC targets")
        elif not state.in_help and PUSH_PATTERNS.search(line):
            state.violations.append(f"{name}:{number}: publishing command in an SCC context")
    return state.violations


def _job_violations(name: str, job_name: str, job: dict[str, object]) -> list[str]:
    if name == SCC_WORKFLOW and job_name in SCC_JOBS:
        violations = [
            f"{name}:{job_name}: publishing step"
            for step in cast("list[dict[str, object]]", job.get("steps", []))
            if str(step.get("uses", "")).startswith(PUBLISHING_ACTIONS)
            or PUSH_PATTERNS.search(str(step.get("run", "")))
        ]
        permissions = cast("dict[str, str]", job.get("permissions", {}))
        if permissions not in SCC_JOB_PERMISSIONS:
            violations.append(f"{name}:{job_name}: permissions other than contents: read")
        return violations
    rest = {key: value for key, value in job.items() if key != "needs"}
    needs = job.get("needs", [])
    listed = [needs] if isinstance(needs, str) else cast("list[str]", needs)
    found: list[str] = []
    if SCC_IDENTIFIER.search(yaml.safe_dump(rest)):
        found.append(f"{name}:{job_name}: SCC identifier outside the SCC jobs")
    if any(SCC_IDENTIFIER.search(item) and item not in SCC_JOBS for item in listed):
        found.append(f"{name}:{job_name}: needs an unknown SCC job")
    return found


def workflow_violations(name: str, text: str) -> list[str]:
    workflow = cast("dict[str, object]", yaml.safe_load(text))
    top_level = {key: value for key, value in workflow.items() if key != "jobs"}
    violations: list[str] = []
    if SCC_IDENTIFIER.search(yaml.safe_dump(top_level)):
        violations.append(f"{name}: SCC identifier at workflow level")
    for job_name, job in cast("dict[str, dict[str, object]]", workflow.get("jobs", {})).items():
        violations += _job_violations(name, job_name, job)
    return violations


def file_violations(relative: str, text: str, files: dict[str, str] | None = None) -> list[str]:
    if relative.startswith(".github/workflows/"):
        return workflow_violations(Path(relative).name, text)
    if relative == "Makefile":
        return makefile_violations(text, files)
    names_scc = SCC_IDENTIFIER.search(text) is not None
    in_scc_tree = relative.startswith(("tools/scc/", "extensions/ci/scc/"))
    exempt = relative == GUARD_MODULE or relative.endswith(".md")
    found: list[str] = []
    if (names_scc or in_scc_tree) and not exempt:
        if PUSH_PATTERNS.search(text):
            found.append(f"{relative}: publishing command next to an SCC identifier")
        elif names_scc and not relative.startswith(ALLOWED_PREFIXES):
            found.append(f"{relative}: SCC identifier outside the allow-list")
    return found


def repository_violations(files: dict[str, str]) -> list[str]:
    return [
        violation
        for relative, text in files.items()
        for violation in file_violations(relative, text, files)
    ]


def run_script(
    arguments: list[str], environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        cwd=REPOSITORY_ROOT,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **(environment or {})},
    )


def gate_script() -> str:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    gate = cast("dict[str, dict[str, object]]", workflow["jobs"])["ci-gate"]
    steps = cast("list[dict[str, str]]", gate["steps"])
    assert len(steps) == 1
    return steps[0]["run"]


def git() -> str:
    path = shutil.which("git")
    assert path is not None, "git is required to list the tracked files"
    return path


def tracked_files() -> list[Path]:
    listing = subprocess.run(
        [git(), "-C", str(REPOSITORY_ROOT), "ls-files", "-z", "--cached"],
        check=True,
        capture_output=True,
        timeout=TIMEOUT_SECONDS,
    ).stdout
    names = [name for name in listing.decode("utf-8").split("\0") if name]
    assert names, "git ls-files listed nothing"
    return [REPOSITORY_ROOT / name for name in names]


def tracked_text() -> dict[str, str]:
    texts: dict[str, str] = {}
    for path in tracked_files():
        if path.is_symlink() or not path.is_file():
            continue
        try:
            texts[path.relative_to(REPOSITORY_ROOT).as_posix()] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    return texts


def is_cache_step(step: dict[str, object]) -> bool:
    return str(step.get("uses", "")).startswith("actions/cache@")


def run_fetch(environment: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(FETCH_SCRIPT), str(tmp_path / "download"), str(tmp_path / "context")],
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **environment},
    )


def test_the_pins_are_complete_and_well_formed() -> None:
    values = pins()
    assert tuple(values) == EXPECTED_PINS
    assert re.fullmatch(r"[0-9]+(\.[0-9]+)+", values["SCC_VERSION"])
    version = values["SCC_VERSION"]
    assert values["SCC_BUNDLE"] == f"scc-{version}_linux_x86_64_bundle.zip"
    assert values["SCC_BUNDLE_URL"] == DISA_ZIP + values["SCC_BUNDLE"]
    assert values["SCC_CHECKSUMS_URL"] == f"{DISA_TXT}SCC_{version}_Checksums.txt"
    assert values["SCC_DEB_MEMBER"] == f"scc-{version}_linux_x86_64/scc-{version}.linux_amd64.deb"
    assert int(values["SCC_BUNDLE_SIZE"]) > 0
    for name in DIGEST_PINS:
        assert SHA256.fullmatch(values[name]), name
    assert len({values[name] for name in DIGEST_PINS}) == len(DIGEST_PINS)
    assert date.fromisoformat(values["SCC_PUBLISHED"]) < date.fromisoformat(values["SCC_EXPIRES"])


def test_the_pinned_release_is_old_enough() -> None:
    published = date.fromisoformat(pins()["SCC_PUBLISHED"])
    assert published <= datetime.now(tz=UTC).date() - MINIMUM_PIN_AGE


@pytest.mark.parametrize(
    ("days_before_deadline", "status"),
    [(30, 0), (1, 0), (0, 1), (-7, 1), (-365, 1)],
)
def test_the_expiry_check_fails_from_a_week_before_expiry(
    days_before_deadline: int, status: int
) -> None:
    expires = date.fromisoformat(pins()["SCC_EXPIRES"])
    today = expires - EXPIRY_MARGIN - timedelta(days=days_before_deadline)
    result = run_script([str(EXPIRY_SCRIPT), expires.isoformat(), today.isoformat()])
    assert result.returncode == status, result.stderr
    if status:
        assert "Bump the SCC pin" in result.stderr


@pytest.mark.parametrize("value", ["2026-13-01", "tomorrow", "2026-11-25; true", ""])
def test_the_expiry_check_refuses_a_malformed_date(value: str) -> None:
    result = run_script([str(EXPIRY_SCRIPT), "2026-11-25", value or "x"])
    assert result.returncode == 2
    assert run_script([str(EXPIRY_SCRIPT), value or "x"]).returncode == 2


def test_the_expiry_check_guards_every_scc_build() -> None:
    lines = MAKEFILE.read_text(encoding="utf-8").splitlines()
    assert "scc-image: scc-expiry-check lint-containerfile scc-fetch" in lines
    recipe = lines[lines.index("scc-expiry-check:") + 1]
    assert recipe == "\ttools/scc/check-expiry.sh '$(SCC_EXPIRES)'"
    assert "scc-smoke: scc-image" in lines


def test_no_scc_bundle_package_or_binary_is_tracked() -> None:
    values = pins()
    pinned_digests = {values[name] for name in DIGEST_PINS}
    offenders: list[str] = []
    for path in tracked_files():
        if path.is_symlink() or not path.is_file():
            continue
        name = path.name
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        data = path.read_bytes()
        if (
            name.lower().endswith(PACKAGE_SUFFIXES)
            or SCC_NAMES.search(name)
            or hashlib.sha256(data).hexdigest() in pinned_digests
        ):
            offenders.append(f"{relative}: SCC name, package suffix or pinned digest")
            continue
        evidence = binary_evidence(data)
        if evidence and ACCEPTED_BINARY_FINDINGS.get(relative) != hashlib.sha256(data).hexdigest():
            offenders.append(f"{relative}: {evidence}")
    assert offenders == []


def test_downloads_stay_ignored_by_git() -> None:
    ignored = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for pattern in ("build/", "*.zip", "*.deb", "*.rpm", "*.ckl", "*.cklb"):
        assert pattern in ignored, pattern
    makefile = MAKEFILE.read_text(encoding="utf-8")
    assert "SCC_DOWNLOAD_DIR := build/scc/download" in makefile
    assert "SCC_CONTEXT_DIR := build/scc/context" in makefile


def test_the_image_definition_is_not_shipped_in_the_collection() -> None:
    galaxy = cast("dict[str, object]", yaml.safe_load((REPOSITORY_ROOT / "galaxy.yml").read_text()))
    assert "extensions/ci" in cast("list[str]", galaxy["build_ignore"])


def test_the_containerfile_is_pinned_and_downloads_nothing() -> None:
    text = CONTAINERFILE.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert re.fullmatch(r"FROM docker\.io/library/ubuntu:24\.04@sha256:[0-9a-f]{64}", lines[0])
    assert sum(line.startswith("FROM ") for line in lines) == 1
    assert not any(line.lstrip().startswith("#") for line in lines)
    assert not CONTAINERFILE_FORBIDDEN.search(text)
    assert "sha256sum --check --strict" in text
    assert "COPY --chmod=0644 scc.deb /tmp/scc.deb" in text


@pytest.mark.parametrize(
    "payload",
    [
        b"\x7fELF\x02\x01\x01" + bytes(32),
        b"\xfd7zXZ\x00\x00\x04" + bytes(32),
        b"(\xb5/\xfd\x04\x58" + bytes(32),
        b"BZh91AY&SY" + bytes(32),
        b"7z\xbc\xaf\x27\x1c\x00\x04" + bytes(32),
        b"\x1f\x8b\x08\x00" + bytes(32),
    ],
)
def test_the_binary_detector_finds_plain_compressed_and_encoded_payloads(payload: bytes) -> None:
    assert looks_like_binary(payload)
    encoded = base64.b64encode(payload)
    assert looks_like_binary(encoded)
    assert looks_like_binary(b"data = '" + encoded + b"'\n")
    assert looks_like_binary(base64.encodebytes(payload * 4))
    for shift in range(1, 4):
        assert looks_like_binary(b"A" * shift + encoded)
    assert looks_like_binary(base64.b64encode(b"some header " + payload))
    assert looks_like_binary(base64.b64encode(b"xy" + payload))
    assert looks_like_binary((b"0" + (payload * 3).hex().encode())[1:])
    assert looks_like_binary(b"7" + (b"header" + payload * 3).hex().encode())


def test_a_detector_hit_names_the_offset() -> None:
    encoded = base64.b64encode(b"head" + b"\x7fELF\x02\x01\x01" + bytes(32))
    evidence = binary_evidence(b"prefix: " + encoded)
    assert evidence is not None
    assert "base64 run at offset 8" in evidence
    assert "decoded offset 4" in evidence
    assert binary_evidence(b"\x7fELF" + bytes(8)) == "binary magic at offset 0"


def test_the_binary_detector_accepts_text_and_digests() -> None:
    digest = pins()["SCC_BUNDLE_SHA256"].encode()
    assert not looks_like_binary(b"plain text with a digest " + digest + b"\n")
    assert not looks_like_binary(b"two digests " + digest + digest + b"\n")
    assert not looks_like_binary(base64.b64encode(b"a short note that is only text, no binary"))


def test_only_the_allowed_places_name_the_scc_image() -> None:
    assert repository_violations(tracked_text()) == []


def _mutated_workflow() -> str:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    workflow["env"] = {"IMG": "localhost/freesecdev-scc:ci"}
    lint = cast("dict[str, dict[str, object]]", workflow["jobs"])["lint"]
    cast("list[dict[str, object]]", lint["steps"]).append({"run": 'docker push "$IMG"'})
    return yaml.safe_dump(workflow)


@pytest.mark.parametrize(
    ("relative", "mutation"),
    [
        (".github/workflows/ci.yml", "workflow-env"),
        ("Makefile", "\nrelease-scc:\n\tdocker push localhost/freesecdev-scc:local\n"),
        (
            "Makefile",
            "\nIMG := localhost/freesecdev-scc:local\npublish:\n\t$(DOCKER) push $(IMG)\n",
        ),
        ("Makefile", "\nIMG := $(SCC_IMAGE)\npublish:\n\t$(DOCKER) push $(IMG)\n"),
        ("Makefile", "\nrelease: scc-image\n\t@true\n"),
        ("Makefile", "\nSCC_PUBLISH := docker push localhost/freesecdev-scc:local\n"),
        ("Makefile", "\nscc-image-push:\n\t$(DOCKER) push '$(SCC_IMAGE)'\n"),
        ("tools/release/publish.sh", "#!/bin/sh\ndocker push localhost/freesecdev-scc:local\n"),
        ("tools/scc/publish.sh", '#!/bin/sh\ndocker push "$SCC_IMAGE"\n'),
        ("extensions/ci/scc/push.sh", "#!/bin/sh\nskopeo copy docker-daemon:x docker://y\n"),
        ("README.example", "build/scc/download\n"),
    ],
)
def test_the_allow_list_refuses_scc_references_elsewhere(relative: str, mutation: str) -> None:
    files = tracked_text()
    if mutation == "workflow-env":
        files[relative] = _mutated_workflow()
    elif relative in files:
        files[relative] += mutation
    else:
        files[relative] = mutation
    assert file_violations(relative, files[relative], files)


@pytest.mark.parametrize(
    "additions",
    [
        {
            "tests/ci/publish.sh": "#!/bin/sh\ndocker push localhost/freesecdev-scc:ci\n",
            ".github/workflows/ci.yml": "publish-job",
        },
        {
            "Makefile": "\ninclude tests/ci/extra.mk\n",
            "tests/ci/extra.mk": "release-image:\n\tdocker push localhost/freesecdev-scc:local\n",
        },
        {"Makefile": "\nEXTRA := tests/ci/extra.mk\ninclude $(EXTRA)\n"},
        {"Makefile": "\n-include tests/ci/missing.mk\n"},
        {"tests/unit/tools/test_zz_export.py": PYTEST_EXPORT},
        {"tests/ci/load.py": INDIRECT_SAVE},
        {"docs/planning/notes.yml": "---\nstep: docker push localhost/freesecdev-scc:ci\n"},
        {"changelogs/fragments/x.yml": CHANGELOG_PUSH},
    ],
)
def test_executable_code_in_allowed_trees_may_not_publish_the_image(
    additions: dict[str, str],
) -> None:
    files = tracked_text()
    for relative, addition in additions.items():
        if addition == "publish-job":
            workflow = cast("dict[str, object]", yaml.safe_load(files[relative]))
            jobs = cast("dict[str, dict[str, object]]", workflow["jobs"])
            jobs["publish"] = {"steps": [{"run": "sh tests/ci/publish.sh"}]}
            files[relative] = yaml.safe_dump(workflow)
        else:
            files[relative] = files.get(relative, "") + addition
    assert repository_violations(files)


def test_markdown_and_the_guard_itself_may_quote_publishing_commands() -> None:
    files = tracked_text()
    files["docs/example.md"] = "Never run `docker push localhost/freesecdev-scc:ci`.\n"
    assert repository_violations(files) == []


def test_the_scc_job_may_not_publish_or_widen_its_permissions() -> None:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    job = cast("dict[str, dict[str, object]]", workflow["jobs"])["scc-smoke"]
    cast("list[dict[str, object]]", job["steps"]).append({"run": "docker save x -o y.tar"})
    assert workflow_violations("ci.yml", yaml.safe_dump(workflow))
    cast("list[dict[str, object]]", job["steps"]).pop()
    job["permissions"] = {"contents": "read", "packages": "write"}
    assert workflow_violations("ci.yml", yaml.safe_dump(workflow))


def test_other_workflows_may_publish_unrelated_things() -> None:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    jobs = cast("dict[str, dict[str, object]]", workflow["jobs"])
    jobs["release"] = {
        "permissions": {"contents": "read", "packages": "write"},
        "steps": [
            {
                "uses": "actions/upload-artifact@0000000000000000000000000000000000000000",
                "with": {"path": "dist/"},
            },
            {"run": "oras push ghcr.io/freesecdev/collection:1 dist/collection.tar.gz"},
        ],
    }
    assert workflow_violations("ci.yml", yaml.safe_dump(workflow)) == []


@pytest.mark.parametrize(
    "recipe",
    [
        "\t$(DOCKER) push '$(SCC_IMAGE)'",
        "\tdocker image save localhost/freesecdev-scc:local -o scc.tar",
        "\tskopeo copy docker-daemon:localhost/freesecdev-scc:local docker://ghcr.io/x/scc",
        "\t$(DOCKER) buildx build --push .",
    ],
)
def test_the_push_patterns_catch_publishing_commands(recipe: str) -> None:
    assert PUSH_PATTERNS.search(recipe)


def test_the_smoke_job_builds_locally_with_read_only_permissions() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    triggers = workflow[True]
    assert {"pull_request", "push", "merge_group", "schedule"} <= set(triggers)
    job = workflow["jobs"]["scc-smoke"]
    assert job["needs"] == ["scc-changes"]
    assert job["if"] == "needs.scc-changes.outputs.scc != 'false'"
    assert workflow["jobs"]["scc-changes"]["permissions"] == {"contents": "read"}
    assert {"scc-changes", "scc-smoke"} <= set(workflow["jobs"]["ci-gate"]["needs"])
    assert job["permissions"] == {"contents": "read"}
    assert "secrets" not in yaml.safe_dump(job)
    assert job["env"]["SCC_IMAGE"].startswith("localhost/")
    assert [step.get("run") for step in job["steps"] if "run" in step] == ["make scc-smoke"]
    cache = [step for step in job["steps"] if is_cache_step(step)]
    assert len(cache) == 1
    assert cache[0]["with"]["path"] == "build/scc/download"
    assert "scc-smoke" in workflow["jobs"]["ci-gate"]["needs"]


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"SCC_BUNDLE_URL": "https://example.org/scc.zip"}, "official DISA download host"),
        ({"SCC_CHECKSUMS_URL": PLAIN_HTTP_CHECKSUMS}, "official"),
        ({"SCC_BUNDLE_SHA256": "0" * 63}, "64 lower-case hex digits"),
        ({"SCC_DEB_SHA256": "A" * 64}, "64 lower-case hex digits"),
        ({"SCC_CSCC_SHA256": ""}, "SCC_CSCC_SHA256 is not set"),
    ],
)
def test_the_fetch_script_refuses_unsafe_pins_before_any_download(
    tmp_path: Path, override: dict[str, str], message: str
) -> None:
    result = run_fetch({**pins(), **override}, tmp_path)
    assert result.returncode == 2
    assert message in result.stderr
    assert not (tmp_path / "download").exists()
    assert not (tmp_path / "context").exists()


def gate_needs(changes: str, scc: str, smoke: str, other: str = "success") -> str:
    return json.dumps(
        {
            "lint": {"result": other, "outputs": {}},
            "scc-changes": {"result": changes, "outputs": {"scc": scc}},
            "scc-smoke": {"result": smoke, "outputs": {}},
        }
    )


@pytest.mark.parametrize(
    ("event", "needs", "passes"),
    [
        ("pull_request", ("success", "false", "skipped", "success"), True),
        ("pull_request", ("success", "true", "success", "success"), True),
        ("pull_request", ("success", "false", "success", "success"), True),
        ("pull_request", ("success", "true", "skipped", "success"), False),
        ("pull_request", ("success", "", "skipped", "success"), False),
        ("pull_request", ("failure", "false", "skipped", "success"), False),
        ("pull_request", ("success", "false", "skipped", "failure"), False),
        ("pull_request", ("success", "true", "failure", "success"), False),
        ("pull_request", ("success", "true", "cancelled", "success"), False),
        ("merge_group", ("success", "false", "skipped", "success"), True),
        ("merge_group", ("success", "true", "skipped", "success"), False),
        ("merge_group", ("success", "", "skipped", "success"), False),
        ("merge_group", ("failure", "false", "skipped", "success"), False),
        ("push", ("success", "false", "skipped", "success"), False),
        ("workflow_dispatch", ("success", "false", "skipped", "success"), False),
        ("schedule", ("success", "false", "skipped", "success"), False),
        ("merge_group", ("success", "true", "success", "success"), True),
        ("push", ("success", "true", "success", "success"), True),
    ],
)
def test_ci_gate_accepts_a_skipped_smoke_only_without_scc_changes_in_a_pr_or_the_queue(
    event: str, needs: tuple[str, str, str, str], passes: bool
) -> None:
    bash = shutil.which("bash")
    assert bash is not None
    assert shutil.which("jq") is not None, "jq is required to run the ci-gate script"
    result = run_script(
        [bash, "-euo", "pipefail", "-c", gate_script()],
        {"NEEDS": gate_needs(*needs), "EVENT_NAME": event},
    )
    assert (result.returncode == 0) is passes, result.stdout + result.stderr


def test_the_path_filter_runs_the_smoke_test_unless_a_pull_request_changes_nothing_scc() -> None:
    head = subprocess.run(
        [git(), "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
    ).stdout.strip()
    cases = [
        (["push", head, head], "true"),
        (["schedule", head, head], "true"),
        (["workflow_dispatch", head, head], "true"),
        (["pull_request", ""], "true"),
        (["pull_request", "not-a-sha"], "true"),
        (["pull_request", "0" * 40], "true"),
        (["pull_request", EMPTY_TREE], "true"),
        (["pull_request", head, "not-a-sha"], "true"),
        (["pull_request", head], "false"),
        (["pull_request", head, head], "false"),
        (["merge_group", head, head], "false"),
        (["merge_group", EMPTY_TREE, head], "true"),
        (["merge_group", head, ""], "true"),
        (["merge_group", head, "not-a-sha"], "true"),
        (["merge_group", "not-a-sha", head], "true"),
        (["merge_group", "", head], "true"),
        (["merge_group", "0" * 40, head], "true"),
        (["merge_group", head, "0" * 40], "true"),
    ]
    for arguments, expected in cases:
        result = run_script([str(FILTER_SCRIPT), *arguments])
        assert result.stdout.strip() == expected, (arguments, result.stdout, result.stderr)


@pytest.mark.parametrize("image", REGISTRY_TAGS)
def test_the_smoke_test_refuses_a_tag_that_names_a_registry(image: str) -> None:
    result = subprocess.run(
        [str(SMOKE_SCRIPT), image, "5.15"],
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
    )
    assert result.returncode == 2
    assert "localhost/ tag" in result.stderr
