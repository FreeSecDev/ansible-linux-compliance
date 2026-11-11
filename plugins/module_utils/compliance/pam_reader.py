"""Read PAM service files as libpam assembles and splits their lines (ADR 0027, FREES-212).

libpam reads a service file line by line in ``_pam_assemble_line`` of ``libpam/pam_handlers.c``
and splits each logical line with ``_pam_StrTok`` of ``libpam/pam_misc.c``. The two pinned
releases differ in the assembly: the Ubuntu 1.5.3 package keeps the fixed-buffer reader
(``buffer``), which skips blank and comment lines inside a continued line and splits a line of
1023 bytes or more into two, and 1.5.1 on Rocky Linux 9 uses the line-buffer reader (``getline``),
which ends a continued line at a blank or comment line. The ``faillock`` and ``pwhistory``
families (``plugins/filter/pam_conf.py``) and the ``pwquality`` family
(``plugins/module_utils/compliance/pwquality.py``) read the PAM stack with this module, so that
they read what libpam reads. ``tests/fixtures/pam_conf/reader_verdicts.json`` holds the logical
lines and tokens that libpam's own functions, compiled from the source packages of both Molecule
images, read from every service file of the corpus, and what the real libpam of both images passes
to ``pam_pwquality`` (``make pam-reader-verdicts``, ``tools/pam``).

Only the Python standard library is used, and nothing here touches a host.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

PAM_SPLIT: Final[str] = " \t\n"
PAM_TYPES: Final[frozenset[str]] = frozenset({"auth", "account", "password", "session"})
PAM_DIRECTORIES: Final[tuple[str, ...]] = ("/etc/pam.d", "/usr/lib/pam.d", "/usr/share/pam.d")
PAM_LINE_LIMIT: Final[int] = 1023
ASSEMBLY_VARIANTS: Final[tuple[str, ...]] = ("buffer", "getline")


def byte_length(text: str) -> int:
    """Return the length of a text in the bytes that C(fgets) counts."""
    return len(text.encode("utf-8", "surrogateescape"))


def _newline_lines(text: str) -> list[str]:
    lines = [line + "\n" for line in text.split("\n")]
    lines[-1] = lines[-1][:-1]
    return [line for line in lines if line]


def assembled_lines(text: str, variant: str = "buffer", *, exact: bool = False) -> Iterator[str]:
    """Yield the logical lines of a PAM service file as C(_pam_assemble_line) joins them.

    C(buffer) is the fixed-buffer reader of the Ubuntu 1.5.3 package, which skips blank and
    comment lines inside a continued line; C(getline) is the line-buffer reader of 1.5.1 on Rocky
    Linux, which ends a continued line at a blank or comment line. libpam drops a continued line
    at the end of the file; unless C(exact), it is yielded, so a decision reads at least what pam
    reads.
    """
    lines = _buffer_lines(text) if variant == "buffer" else _getline_lines(text)
    for line, complete in lines:
        if complete or not exact:
            yield line


def _buffer_lines(text: str) -> Iterator[tuple[str, bool]]:
    logical: str | None = None
    for raw in _newline_lines(text):
        stripped = raw.lstrip(PAM_SPLIT)
        if not stripped or stripped.startswith("#"):
            continue
        if "#" in stripped:
            yield (logical or "") + stripped.split("#", 1)[0], True
            logical = None
            continue
        body = stripped.rstrip(PAM_SPLIT)
        if body.endswith("\\"):
            logical = (logical or "") + body[:-1] + " "
            continue
        yield (logical or "") + stripped, True
        logical = None
    if logical is not None:
        yield logical, False


def _getline_lines(text: str) -> Iterator[tuple[str, bool]]:
    assembled: str | None = None
    for raw in _newline_lines(text):
        body = raw.rstrip(PAM_SPLIT)
        continued = body.endswith("\\")
        content = body[:-1] + " " if continued else raw
        start = content.lstrip(" \t")
        start = start.split("#", 1)[0]
        if continued and "#" not in raw:
            if start:
                assembled = (assembled or "") + start
            continue
        if assembled is not None or (start and not start.startswith("\n")):
            assembled = (assembled or "") + start
        if assembled:
            yield assembled, True
        assembled = None
    if assembled is not None:
        yield assembled, False


def strtok(line: str) -> list[str]:
    r"""Split a logical line into tokens as libpam's C(_pam_StrTok) does.

    A token that starts with C([) runs to the first C(]) that is not escaped as C(\]), and the
    next token starts right after that C(]); any other token ends at a blank, tab or newline.
    """
    found: list[str] = []
    position = 0
    while True:
        while position < len(line) and line[position] in PAM_SPLIT:
            position += 1
        if position >= len(line):
            return found
        if line[position] == "[":
            token: list[str] = []
            end = position + 1
            while end < len(line) and line[end] != "]":
                if line[end] == "\\" and end + 1 < len(line) and line[end + 1] == "]":
                    end += 1
                token.append(line[end])
                end += 1
            found.append("".join(token))
        else:
            end = position
            while end < len(line) and line[end] not in PAM_SPLIT:
                end += 1
            found.append(line[position:end])
        position = end + 1


@dataclass(frozen=True)
class ModuleLine:
    """One logical line of a service file, read the way C(_pam_parse_conf_file) reads it."""

    module: str | None
    arguments: tuple[str, ...]
    include: str | None


def _token(tokens: list[str], index: int) -> str | None:
    return tokens[index] if index < len(tokens) else None


def module_lines(text: str, variant: str) -> Iterator[ModuleLine]:
    """Yield the module and include lines of a service file for one assembly variant.

    C(@include) is taken in any case and with a leading C(-), as the Ubuntu 1.5.3 package takes
    it; libpam 1.5.1 on Rocky Linux refuses such a line as an illegal type, so reading it as an
    include on both platforms reads at least what either libpam reads.
    """
    for line in assembled_lines(text, variant):
        tokens = strtok(line)
        kind = (_token(tokens, 0) or "").removeprefix("-").lower()
        control = (_token(tokens, 1) or "").lower()
        if kind == "@include":
            yield ModuleLine(None, (), _token(tokens, 1))
        elif kind not in PAM_TYPES or not control:
            continue
        elif control in {"include", "substack"}:
            yield ModuleLine(None, (), _token(tokens, 2))
        elif _token(tokens, 2) is not None:
            yield ModuleLine(_token(tokens, 2), tuple(tokens[3:]), None)


def module_arguments(text: str, module: str) -> Iterator[list[str]]:
    """Yield the arguments of every line of a service file that loads C(module), in either variant.

    libpam compares the type without case and drops one leading C(-); the control is a word or a
    bracketed list, which may be followed by the module path without a blank.
    """
    seen: set[tuple[str, ...]] = set()
    for variant in ASSEMBLY_VARIANTS:
        for line in module_lines(text, variant):
            if line.module is None or line.module.rsplit("/", 1)[-1] != module + ".so":
                continue
            if line.arguments not in seen:
                seen.add(line.arguments)
                yield list(line.arguments)


def unassembled(text: str) -> bool:
    """Return whether a service file has a NUL byte or a line of 1023 bytes or more.

    The fixed-buffer reader of the Ubuntu 1.5.3 package splits such a line into two lines and runs
    the second one, also when the first is a comment, and both readers stop a line's text at a NUL
    byte; the collection does not model either, so a family refuses on such a file.
    """
    return "\0" in text or any(byte_length(line) >= PAM_LINE_LIMIT for line in text.split("\n"))


def _winners(stack: Mapping[str, str]) -> dict[str, str]:
    """Return the service files that libpam opens by name: the first directory that has the name."""
    effective: dict[str, str] = {}
    names: dict[str, tuple[int, str]] = {}
    for path in sorted(stack):
        directory, _slash, name = path.rpartition("/")
        if directory not in PAM_DIRECTORIES:
            effective[path] = stack[path]
            continue
        rank = PAM_DIRECTORIES.index(directory)
        if name not in names or names[name][0] > rank:
            names[name] = (rank, path)
    effective.update({path: stack[path] for _rank, path in names.values()})
    return effective


def _targets(text: str) -> set[str]:
    """Return the include and substack targets of a service file that name a directory."""
    return {
        line.include
        for variant in ASSEMBLY_VARIANTS
        for line in module_lines(text, variant)
        if line.include is not None and "/" in line.include
    }


def effective_stack(stack: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
    """Return the service files that libpam reads and what the collection cannot read for it.

    A service name is read from the first of C(/etc/pam.d), C(/usr/lib/pam.d) and
    C(/usr/share/pam.d) that has it; an include or substack of an absolute path, or of a path
    with a directory, reads that file, which must be one of the files read. A file with a line of
    1023 bytes or more, which the Ubuntu reader splits into two lines, or with a NUL byte, is not
    read either.
    """
    effective = _winners(stack)
    problems: set[str] = set()
    pending = list(effective)
    while pending:
        path = pending.pop()
        text = effective[path]
        if unassembled(text):
            problems.add(f"{path} has a NUL byte or a line of {PAM_LINE_LIMIT} bytes or more")
            continue
        for target in sorted(_targets(text)):
            candidates = (
                [target] if target.startswith("/") else [f"{d}/{target}" for d in PAM_DIRECTORIES]
            )
            found = next((candidate for candidate in candidates if candidate in stack), None)
            if found is None:
                problems.add(f"{path} includes {target}, which the collection does not read")
            elif found not in effective:
                effective[found] = stack[found]
                pending.append(found)
    return effective, sorted(problems)
