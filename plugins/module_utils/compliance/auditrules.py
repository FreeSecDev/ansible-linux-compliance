"""Read audit rule files and the output of ``auditctl`` without side effects (FREES-110).

This helper uses only the Python standard library and syntax that runs on Python 3.9, the oldest
managed-node interpreter supported by ansible-core 2.20. It never runs a process and never writes:
the module ``audit_control`` runs ``auditctl`` and ``augenrules`` through the audited process
helper (ADR 0004) and uses these functions to read what they print and what
``/etc/audit/rules.d`` holds.

``augenrules`` concatenates every file of ``/etc/audit/rules.d`` whose name ends in ``.rules``
(``ls`` without ``-a``, so names that start with a dot are left out), drops empty lines and
comment lines, and moves the control lines ``-D``, ``-b``, ``-f`` and ``-e`` to fixed places. Two
equal rules make ``auditctl -R`` stop at the second with ``Rule exists`` and leave every later
rule unloaded, so :func:`duplicates` finds rule lines that two places of the set hold, after
:func:`normalise` has put each line into one spelling.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    fileio,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

RULES_DIRECTORY: Final[str] = "/etc/audit/rules.d"
RULES_SUFFIX: Final[str] = ".rules"
MAX_FILES: Final[int] = 512
MAX_FILE_BYTES: Final[int] = 1024 * 1024
MAX_LINE_LENGTH: Final[int] = 4096
CONTROL_LINE: Final[str] = r"\s*-[efb].*|\s*-D\s*"
COMMENT_LINE: Final[str] = r"\s*#.*"
STATUS_LINE: Final[str] = r"([a-z_]+) (-?[0-9]+)(?: .*)?"
UNSET_FORMS: Final[frozenset[str]] = frozenset({"auid!=-1", "auid!=4294967295"})
NO_RULES: Final[str] = "No rules"
UNSET: Final[str] = "auid!=unset"
KEY_FIELD: Final[str] = "key="
SYSCALL_OPTION: Final[str] = "-S"


class RulesFileError(ValueError):
    """A rule file that the helper refuses to read, with the path in the message."""


def normalise(line: str) -> str:
    """Return ``line`` in one spelling: single spaces, ``-k`` for keys and ``auid!=unset``.

    ``auditctl`` treats ``-F key=x`` as ``-k x`` and ``auid!=-1`` and ``auid!=4294967295`` as
    ``auid!=unset``, so two lines that differ only in these spellings are the same rule.
    """
    words = line.split()
    result: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        following = words[index + 1] if index + 1 < len(words) else ""
        if word == "-F" and following.startswith(KEY_FIELD):
            result.extend(("-k", following[len(KEY_FIELD) :]))
            index += 2
            continue
        result.append(UNSET if word in UNSET_FORMS else word)
        index += 1
    return " ".join(result)


def rule_lines(text: str) -> list[str]:
    """Return the rule lines of a rule file as ``augenrules`` keeps them, normalised.

    Empty lines, comment lines and the control lines ``-D``, ``-b``, ``-f`` and ``-e`` are left
    out; a carriage return at the end of a line is ignored, as ``augenrules`` does.
    """
    found: list[str] = []
    for raw in text.split("\n"):
        line = raw.removesuffix("\r")
        if not line.strip():
            continue
        if re.fullmatch(COMMENT_LINE, line) or re.fullmatch(CONTROL_LINE, line):
            continue
        found.append(normalise(line))
    return found


def rule_file_names(names: Iterable[str]) -> list[str]:
    """Return the names that ``augenrules`` reads, sorted: ``*.rules`` without a leading dot."""
    return sorted(
        name for name in names if name.endswith(RULES_SUFFIX) and not name.startswith(".")
    )


def _read_bounded(path: Path) -> str:
    with path.open("rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        message = f"{path} is larger than {MAX_FILE_BYTES} bytes"
        raise RulesFileError(message)
    return data.decode("utf-8", "replace")


def read_rule_files(directory: str = RULES_DIRECTORY) -> list[dict[str, object]]:
    """Return every file that ``augenrules`` reads below ``directory`` with its rule lines.

    A missing directory gives no files. A name that is not a regular file and does not lead to
    one through a symbolic link, such as a directory named ``x.rules``, is listed without lines,
    as ``cat`` would fail on it. More than :data:`MAX_FILES` names or a file above
    :data:`MAX_FILE_BYTES` raises :class:`RulesFileError`.
    """
    base = Path(directory)
    try:
        info = base.lstat()
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(info.st_mode):
        message = f"{directory} is not a directory"
        raise RulesFileError(message)
    names = rule_file_names(entry.name for entry in base.iterdir())
    if len(names) > MAX_FILES:
        message = f"{directory} holds more than {MAX_FILES} rule files"
        raise RulesFileError(message)
    files: list[dict[str, object]] = []
    for name in names:
        path = base / name
        try:
            regular = stat.S_ISREG(path.stat().st_mode)
        except OSError:
            regular = False
        lines = rule_lines(_read_bounded(path)) if regular else []
        files.append({"path": str(path), "regular": regular, "lines": lines})
    return files


def duplicates(files: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    """Return every rule line that the files hold more than once, with the files that hold it."""
    places: dict[str, list[str]] = {}
    for item in files:
        path = str(item["path"])
        lines = item["lines"]
        if not isinstance(lines, list):
            continue
        for line in cast("list[object]", lines):
            places.setdefault(str(line), []).append(path)
    return [
        {"line": line, "paths": paths} for line, paths in sorted(places.items()) if len(paths) > 1
    ]


def parse_status(text: str) -> dict[str, int]:
    """Return the numeric fields of ``auditctl -s``, such as ``enabled`` and ``pid``."""
    fields: dict[str, int] = {}
    for line in text.splitlines():
        found = re.fullmatch(STATUS_LINE, line.strip())
        if found is not None:
            fields[found.group(1)] = int(found.group(2))
    return fields


def _without_syscalls(line: str) -> str:
    words = line.split()
    kept: list[str] = []
    index = 0
    while index < len(words):
        if words[index] == SYSCALL_OPTION:
            index += 2
            continue
        kept.append(words[index])
        index += 1
    return " ".join(kept)


def missing_rules(expect: Sequence[str], listed: Sequence[str]) -> list[str]:
    """Return the lines of ``expect`` that no rule of ``listed`` (``auditctl -l``) loads.

    Both sides are compared in the spelling of :func:`normalise`. ``auditctl -l`` lists a rule
    without ``-S`` with the system calls that the kernel derives from its fields (``-S all``, or
    every call of a ``perm=`` class), which depends on the kernel, so for an expected line without
    ``-S`` the system calls of the listed rule are left out of the comparison.
    """
    normal = [normalise(line) for line in listed]
    bare = [_without_syscalls(line) for line in normal]
    missing: list[str] = []
    for line in expect:
        wanted = normalise(line)
        pool = normal if SYSCALL_OPTION in wanted.split() else bare
        if wanted not in pool:
            missing.append(line)
    return missing


def log_megabytes(directory: str) -> int | None:
    """Return the size of the file system of the audit log directory in MiB, or ``None``.

    A directory that does not exist yet is measured at its nearest existing parent, where auditd
    would create it. A relative path or one with ``..`` gives ``None``.
    """
    if not directory.startswith("/") or ".." in directory.split("/"):
        return None
    path = Path(directory)
    while not path.exists() and path != path.parent:
        path = path.parent
    return fileio.filesystem_megabytes(str(path))


def listed_rules(text: str) -> list[str]:
    """Return the rules that ``auditctl -l`` lists, one per line, without ``No rules``."""
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and line.strip() != NO_RULES and len(line) <= MAX_LINE_LENGTH
    ]
