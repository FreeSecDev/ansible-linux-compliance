"""Read ``pwquality.conf`` and its drop-ins exactly as libpwquality reads them (FREES-200).

libpwquality 1.4.4 (Rocky Linux 9) and 1.4.5 (Ubuntu 24.04) read the configuration in
``pwquality_read_config`` of ``src/settings.c``: every name of ``/etc/security/pwquality.conf.d``
that contains ``.conf`` only at its end, in ``strcmp`` order, and then the main file. Each file is
read with ``fgets`` into a buffer of 1024 bytes, and the first line that the library cannot read
stops the whole configuration: a later drop-in and the main file are then not read at all, and the
settings read until then stay. ``pam_pwquality`` logs that error and goes on with those settings,
and then applies its own module arguments with ``pwquality_set_option``, which override the files.

This module reproduces that reader on the bytes of the files, so that the ``pwquality`` family of
the remediate role decides as the library does. ``tests/fixtures/pwquality_readers/verdicts.json``
holds what the real library read for every case in both Molecule images, and
``tests/unit/tools/test_pwquality_verdicts.py`` checks this reader and the decisions against every
row. The texts arrive as the ``b64decode`` filter of Ansible returns them, so a byte that is not
UTF-8 is a lone surrogate that :func:`text_bytes` turns back into it.

Only the Python standard library is used, and nothing here touches a host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pam_reader,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

ERROR_INTEGER: Final[int] = -2
ERROR_MALFORMED: Final[int] = -4
ERROR_UNKNOWN_SETTING: Final[int] = -5
ERROR_NAMES: Final[Mapping[int, str]] = {
    ERROR_INTEGER: "a value that is not an integer",
    ERROR_MALFORMED: "a line that is too long or holds a NUL byte",
    ERROR_UNKNOWN_SETTING: "an unknown setting",
}
LINE_BYTES: Final[int] = 1023
OPTION_NAME_BYTES: Final[int] = 79
SPACE: Final[bytes] = b" \t\n\v\f\r"
INT_MAX: Final[int] = 2**31 - 1
INT_MIN: Final[int] = -(2**31)
MIN_LENGTH_FLOOR: Final[int] = 6
CLASSES: Final[int] = 4
INTEGER: Final[str] = "int"
TEXT: Final[str] = "str"
FLAG: Final[str] = "set"
SETTINGS: Final[Mapping[str, str]] = {
    "difok": INTEGER,
    "minlen": INTEGER,
    "dcredit": INTEGER,
    "ucredit": INTEGER,
    "lcredit": INTEGER,
    "ocredit": INTEGER,
    "minclass": INTEGER,
    "maxrepeat": INTEGER,
    "maxclassrepeat": INTEGER,
    "maxsequence": INTEGER,
    "gecoscheck": INTEGER,
    "dictcheck": INTEGER,
    "usercheck": INTEGER,
    "usersubstr": INTEGER,
    "enforcing": INTEGER,
    "badwords": TEXT,
    "dictpath": TEXT,
    "retry": INTEGER,
    "enforce_for_root": FLAG,
    "local_users_only": FLAG,
}
DEFAULTS: Final[Mapping[str, int]] = {
    "difok": 1,
    "minlen": 8,
    "dcredit": 0,
    "ucredit": 0,
    "lcredit": 0,
    "ocredit": 0,
    "minclass": 0,
    "maxrepeat": 0,
    "maxclassrepeat": 0,
    "maxsequence": 0,
    "gecoscheck": 0,
    "dictcheck": 1,
    "usercheck": 1,
    "usersubstr": 0,
    "enforcing": 1,
    "retry": 1,
    "enforce_for_root": 0,
    "local_users_only": 0,
}
INTEGER_TEXT: Final[str] = r"[+-]?[0-9]+"
UNRECORDABLE: Final[str] = (
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ud800-\udfff]"
)
SURROGATE: Final[str] = r"[\ud800-\udfff]"
PAM_MODULE: Final[str] = "pam_pwquality.so"
MODULE_DIRECTORIES: Final[Mapping[str, Mapping[str, str]]] = {
    "RedHat": {"x86_64": "/usr/lib64/security/", "aarch64": "/usr/lib64/security/"},
    "Debian": {
        "x86_64": "/usr/lib/x86_64-linux-gnu/security/",
        "aarch64": "/usr/lib/aarch64-linux-gnu/security/",
    },
}
ISA_MARK: Final[str] = "$ISA"
NEWLINE: Final[str] = "\n"
DROPIN_SUFFIX: Final[str] = ".conf"
FILE: Final[str] = "file"
DIRECTORY: Final[str] = "directory"
MISSING: Final[str] = "missing"


@dataclass(frozen=True)
class Assignment:
    """One setting that libpwquality read: the file, its line number from 0 and the value."""

    path: str
    line: int
    name: str
    value: int | None


@dataclass(frozen=True)
class Reading:
    """What libpwquality read from a sequence of files.

    Attributes:
        assignments: Every setting read, in order, until the first error.
        error: The error code of ``pwquality_read_config``, 0 without error.
        error_path: The file that holds the line that stopped the reading.
        error_line: That line, numbered from 0.
    """

    assignments: tuple[Assignment, ...]
    error: int = 0
    error_path: str | None = None
    error_line: int | None = None

    def last(self, name: str) -> Assignment | None:
        """Return the assignment of ``name`` that takes effect, or ``None`` for the default."""
        found = [item for item in self.assignments if item.name == name]
        return found[-1] if found else None

    def value(self, name: str) -> int | None:
        """Return the value of an integer or flag setting as the library holds it."""
        item = self.last(name)
        return DEFAULTS.get(name) if item is None else item.value


def text_bytes(text: str) -> bytes:
    """Return the bytes of ``text`` as Ansible decoded them, a lone surrogate being one byte."""
    return text.encode("utf-8", "surrogateescape")


def is_space(byte: int) -> bool:
    """Return whether ``isspace`` of the C locale holds for ``byte``."""
    return byte in SPACE


def _strip(data: bytes) -> bytes:
    start = 0
    end = len(data)
    while start < end and is_space(data[start]):
        start += 1
    while end > start and is_space(data[end - 1]):
        end -= 1
    return data[start:end]


def split_name_value(line: bytes) -> tuple[bytes, bytes] | None:
    """Return the name and the value of a line as ``read_config_file`` splits it.

    ``line`` is what the library holds after ``strlen``: the comment from the first ``#`` on is
    removed, white space around the line is skipped, the name ends at the first white space or
    ``=``, and white space and at most one ``=`` are skipped before the value. ``None`` means
    that the line is empty or a comment.
    """
    hash_index = line.find(b"#")
    content = _strip(line if hash_index < 0 else line[:hash_index])
    if not content:
        return None
    index = 0
    equals = False
    while index < len(content):
        byte = content[index]
        if is_space(byte) or byte == ord("="):
            equals = byte == ord("=")
            break
        index += 1
    name = content[:index]
    index += 1
    while index < len(content):
        byte = content[index]
        if byte != ord("=") or equals:
            if not is_space(byte):
                break
        else:
            equals = True
        index += 1
    return name, content[index:]


def setting_value(name: bytes, value: bytes) -> tuple[int, str | None, int | None]:
    """Return the error code, the setting and its value as ``set_name_value`` stores them."""
    setting = name.decode("ascii", "replace").lower()
    kind = SETTINGS.get(setting) if name.isascii() else None
    if kind is None:
        return ERROR_UNKNOWN_SETTING, None, None
    if kind == FLAG:
        return 0, setting, 1
    if kind == TEXT:
        return 0, setting, None
    text = value.decode("ascii", "replace") if value.isascii() else ""
    if re.fullmatch(INTEGER_TEXT, text) is None:
        return ERROR_INTEGER, setting, None
    number = int(text)
    if not INT_MIN < number < INT_MAX:
        return ERROR_INTEGER, setting, None
    if setting == "minlen":
        number = max(number, MIN_LENGTH_FLOOR)
    if setting == "minclass":
        number = min(number, CLASSES)
    return 0, setting, number


def _chunks(data: bytes) -> list[tuple[int, bytes, bool]]:
    """Return what each ``fgets`` call reads: the line number, the bytes and whether EOF was hit."""
    chunks: list[tuple[int, bytes, bool]] = []
    position = 0
    line = 0
    while position < len(data):
        newline = data.find(b"\n", position, position + LINE_BYTES)
        if newline >= 0:
            chunks.append((line, data[position : newline + 1], False))
            position = newline + 1
            line += 1
            continue
        chunk = data[position : position + LINE_BYTES]
        position += len(chunk)
        chunks.append((line, chunk, len(chunk) < LINE_BYTES))
    return chunks


def read_file(path: str, data: bytes) -> Reading:
    """Return what ``read_config_file`` reads from ``data``, the content of ``path``."""
    assignments: list[Assignment] = []
    for line, chunk, end_of_file in _chunks(data):
        nul = chunk.find(b"\x00")
        held = chunk if nul < 0 else chunk[:nul]
        if held and held[-1:] != b"\n" and not end_of_file:
            return Reading(tuple(assignments), ERROR_MALFORMED, path, line)
        split = split_name_value(held)
        if split is None:
            continue
        error, setting, value = setting_value(*split)
        if error:
            return Reading(tuple(assignments), error, path, line)
        if setting is not None and SETTINGS[setting] != TEXT:
            assignments.append(Assignment(path, line, setting, value))
    return Reading(tuple(assignments))


def is_dropin_name(name: str) -> bool:
    """Return whether ``filter_conf`` of libpwquality selects the directory entry ``name``."""
    index = name.find(DROPIN_SUFFIX)
    return index >= 0 and index + len(DROPIN_SUFFIX) == len(name)


def read_config(files: Sequence[tuple[str, bytes | None]]) -> Reading:
    """Return what ``pwquality_read_config`` reads from ``files``, in reading order.

    ``None`` stands for a file that the library cannot open, which it skips.
    """
    assignments: list[Assignment] = []
    for path, data in files:
        if data is None:
            continue
        reading = read_file(path, data)
        assignments.extend(reading.assignments)
        if reading.error:
            return Reading(
                tuple(assignments), reading.error, reading.error_path, reading.error_line
            )
    return Reading(tuple(assignments))


def setting_lines(text: str, setting: str) -> list[tuple[int, str]]:
    """Return the number and the text of every line of ``text`` that sets ``setting``.

    Each line is read as libpwquality reads one line, in any case and with any spacing.
    """
    found: list[tuple[int, str]] = []
    for number, line in enumerate(text.split(NEWLINE)):
        split = split_name_value(text_bytes(line).split(b"\x00", 1)[0])
        if split is not None and split[0].isascii() and split[0].decode("ascii").lower() == setting:
            found.append((number, line))
    return found


def option_value(argument: bytes) -> tuple[str, int | None] | None:
    """Return the setting and the value that ``pwquality_set_option`` stores for ``argument``.

    The library splits the argument at its first ``=``, refuses a name of more than 79 bytes and
    then reads the name and the value as a line of the file; ``None`` means that it refuses.
    """
    name, _separator, value = argument.partition(b"=")
    if len(name) > OPTION_NAME_BYTES:
        return None
    error, setting, number = setting_value(name, value)
    return None if error or setting is None else (setting, number)


def option_override(argument: bytes, setting: str, required: int) -> bool:
    """Return whether a ``pam_pwquality`` argument sets ``setting``, not to ``required``.

    An argument that names the setting and that the library refuses is counted as an override
    too, so that the rule refuses.
    """
    name = argument.partition(b"=")[0]
    if not name.isascii() or name.decode("ascii").lower() != setting:
        return False
    found = option_value(argument)
    return found is None or found[1] != required


def module_directory(os_family: str, architecture: str) -> str | None:
    """Return the directory that libpam loads a module of a relative path from, or None.

    ``_pam_add_handler`` of ``libpam/pam_handlers.c`` puts ``DEFAULT_MODULE_PATH`` in front of a
    module path that does not start with ``/``: ``/usr/lib64/security/`` in the pam package of
    Rocky Linux 9, ``/usr/lib/x86_64-linux-gnu/security/`` in that of Ubuntu 24.04 (read from
    ``libpam.so.0`` of both Molecule images). Where the directory is not known, the family
    cannot tell which module a line loads, so it refuses.
    """
    return MODULE_DIRECTORIES.get(os_family, {}).get(architecture)


def module_path(module: str, directory: str) -> str | None:
    """Return the path that libpam loads for the module path of a PAM line, or None.

    libpam takes a path that starts with ``/`` as it is and puts ``directory`` in front of any
    other; it replaces ``$ISA`` in a path that it cannot load, which the collection does not
    model, so such a path is None.
    """
    if ISA_MARK in module:
        return None
    return module if module.startswith("/") else directory + module


@dataclass(frozen=True)
class Modules:
    """Which file the module path of every PAM line loads, as the role inspected it on the host.

    Attributes:
        directory: The directory that libpam loads a relative module path from
            (:func:`module_directory`), or None when it is not known.
        stats: The ``ansible.builtin.stat`` with ``follow: true`` and the SHA-256 ``checksum``
            of every path that :func:`module_paths` returns, by path, or a mapping with only the
            ``msg`` of a stat that failed.
    """

    directory: str | None
    stats: Mapping[str, Mapping[str, object]]

    def _checksum(self, path: str) -> tuple[str | None, str | None]:
        """Return the checksum of the regular file at ``path``, or why the module is unknown.

        A path that does not exist, or is not a regular file, has no checksum and no problem:
        libpam cannot load it.
        """
        if path not in self.stats:
            return None, f"{path} was not inspected"
        stat = self.stats[path]
        if "exists" not in stat:
            message = stat.get("msg")
            detail = f": {message}" if isinstance(message, str) and message else ""
            return None, f"stat could not inspect {path}{detail}"
        if stat.get("exists") is not True or stat.get("isreg") is not True:
            return None, None
        checksum = stat.get("checksum")
        if not isinstance(checksum, str) or not checksum:
            return None, f"{path} could not be read to compare it with {PAM_MODULE}"
        return checksum, None

    def identify(self, module: str) -> bool | str:
        """Return whether a module path loads ``pam_pwquality``, or why it cannot be told.

        A path that libpam resolves to ``pam_pwquality.so`` in the module directory loads it,
        also when that file is missing (the arguments are read then, which can only refuse). Any
        other path loads it when it is a regular file with the checksum of that file: a link, a
        hard link or a copy of the module under another name, as libpam loads it (FREES-212). A
        path that does not exist or is not a regular file loads nothing. Without the module
        directory, with ``$ISA`` in the path, or when a file that must be compared could not be
        inspected, the text is the reason why the family cannot tell.
        """
        if self.directory is None:
            return (
                f"the collection does not know the directory that libpam loads {module} from on"
                " this platform"
            )
        path = module_path(module, self.directory)
        if path is None:
            return f"{module} holds {ISA_MARK}, which libpam replaces and the collection does not"
        return path == self.directory + PAM_MODULE or self._same_as_module(path, self.directory)

    def _same_as_module(self, path: str, directory: str) -> bool | str:
        """Return whether ``path`` is a regular file with the checksum of ``pam_pwquality.so``."""
        checksum, problem = self._checksum(path)
        if problem is not None:
            return problem
        if checksum is None:
            return False
        expected, problem = self._checksum(directory + PAM_MODULE)
        return problem if problem is not None else checksum == expected


@dataclass(frozen=True)
class PamStack:
    """The PAM files with their text, and which file the module path of each line loads.

    Attributes:
        files: ``(path, text)`` of every PAM file that the role read.
        modules: The module directory and the stat of every module path (:class:`Modules`).
    """

    files: Sequence[tuple[str, str]]
    modules: Modules


def module_paths(files: Sequence[tuple[str, str]], directory: str | None) -> list[str]:
    """Return every path that a PAM line of ``files`` makes libpam load, and ``pam_pwquality.so``.

    Every line that names a module, of any type and in both assembly variants, is taken; a
    path with ``$ISA`` is left out (:meth:`Modules.identify` refuses it). The role inspects each
    path, so that :meth:`Modules.identify` can compare it with ``pam_pwquality.so`` of the
    module directory. Without a module directory there is nothing to inspect.
    """
    if directory is None:
        return []
    paths = {directory + PAM_MODULE}
    for _path, text in files:
        for variant in pam_reader.ASSEMBLY_VARIANTS:
            for line in pam_reader.module_lines(text, variant):
                found = None if line.module is None else module_path(line.module, directory)
                if found is not None:
                    paths.add(found)
    return sorted(paths)


@dataclass(frozen=True)
class PamReading:
    """What libpam passes to ``pam_pwquality``, as both of its line readers read the PAM files.

    Attributes:
        arguments: ``(file, argument)`` for every argument of every line that loads
            ``pam_pwquality`` (:meth:`Modules.identify`), of any type.
        includes: ``<file> includes <target>`` for every ``include``, ``substack`` and
            ``@include`` (in any case, with or without a leading ``-``) of a target with a ``/``.
        problems: Every file that the collection cannot read as libpam does, and why.
    """

    arguments: tuple[tuple[str, str], ...]
    includes: tuple[str, ...]
    problems: tuple[str, ...]


def _kept(
    path: str, text: str, variant: str, modules: Modules, problems: list[str]
) -> tuple[pam_reader.ModuleLine, ...]:
    """Return the lines of one variant that include a file or load ``pam_pwquality``.

    A line whose module cannot be identified adds its reason to ``problems``.
    """
    kept: list[pam_reader.ModuleLine] = []
    for line in pam_reader.module_lines(text, variant):
        found = True if line.module is None else modules.identify(line.module)
        if isinstance(found, str):
            problem = f"{path} loads the module {line.module}, but {found}"
            if problem not in problems:
                problems.append(problem)
        elif found:
            kept.append(line)
    return tuple(kept)


def read_pam(stack: PamStack) -> PamReading:
    """Return what libpam passes to ``pam_pwquality`` from the files, or why it cannot be told.

    Every file is read as both line readers of libpam read it (:mod:`pam_reader`, the reader of
    the ``faillock`` and ``pwhistory`` families): the fixed-buffer reader of the Ubuntu 1.5.3
    package and the line-buffer reader of 1.5.1 on Rocky Linux 9. A continued line is joined, a
    comment line ends where libpam ends it (also when it ends with a backslash), each logical line
    is split with ``_pam_StrTok``, the type is compared without case and with one leading ``-``
    dropped, and ``@include`` is taken in any case and with a leading ``-`` on both platforms,
    although only the Ubuntu libpam accepts it (Rocky Linux's refuses the line as an illegal type):
    reading it as an include can only add a refusal. Every line of every file is read, also of
    a file that libpam does not open, which can only add a refusal too. Which lines load
    ``pam_pwquality`` is decided by the file that libpam loads for the module path
    (:meth:`Modules.identify`), not by its name; a line whose module cannot be identified is a
    problem.

    A file with a NUL byte or a line of 1023 bytes or more is a problem: the Ubuntu reader splits
    such a line into two and runs the second part, also after a comment. So is a file whose lines
    that load ``pam_pwquality`` or include a file differ between the two readers, for example a
    continued line with a blank or comment line inside it, because the collection cannot tell
    which reader the host's libpam has.

    The reading says nothing about whether libpam runs ``pam_pwquality`` at all: a line of
    another type than ``password``, a jump or a ``sufficient`` module before it, or a stack
    without it are not looked at, so the family decides the values that ``pam_pwquality`` would
    use, not whether it is used (FREES-212).
    """
    arguments: list[tuple[str, str]] = []
    includes: list[str] = []
    problems: list[str] = []
    for path, text in stack.files:
        if pam_reader.unassembled(text):
            problems.append(
                f"{path} has a NUL byte or a line of {pam_reader.PAM_LINE_LIMIT} bytes or more, "
                "which libpam does not read as one line"
            )
            continue
        identified: list[str] = []
        readings = {
            _kept(path, text, variant, stack.modules, identified)
            for variant in pam_reader.ASSEMBLY_VARIANTS
        }
        if identified:
            problems.extend(identified)
            continue
        if len(readings) > 1:
            problems.append(
                f"{path} has lines that load pam_pwquality or include a file, which the line "
                "readers of libpam 1.5.1 and 1.5.3 assemble differently"
            )
            continue
        for line in readings.pop():
            if line.include is None:
                arguments.extend((path, argument) for argument in line.arguments)
            elif "/" in line.include:
                includes.append(f"{path} includes {line.include}")
    return PamReading(tuple(arguments), tuple(includes), tuple(problems))


def pam_overrides(stack: PamStack, setting: str, required: int) -> list[str]:
    """Return ``<file>: <argument>`` for each ``pam_pwquality`` argument overriding ``setting``.

    The arguments are those of :func:`read_pam`.
    """
    return [
        f"{path}: {argument}"
        for path, argument in read_pam(stack).arguments
        if option_override(text_bytes(argument), setting, required)
    ]


def pam_enforcing_off(stack: PamStack) -> list[str]:
    """Return ``<file>: <argument>`` for each ``pam_pwquality`` argument that sets enforcing to 0.

    The value is read as ``pwquality_set_option`` reads it, with ``strtol``, so ``enforcing=00``,
    ``ENFORCING=+00``, ``enforcing=-0`` and ``enforcing=000`` are all 0.
    """
    return [
        f"{path}: {argument}"
        for path, argument in read_pam(stack).arguments
        if option_value(text_bytes(argument)) == ("enforcing", 0)
    ]


@dataclass(frozen=True)
class Rule:
    """A rule of the pwquality family as the role plans it.

    Attributes:
        setting: The setting, in lower case.
        value: The profile value as text, empty for a flag such as ``enforce_for_root``.
        method: ``main_file`` or ``dropin``.
        main: The path of the main file.
        dropin: The path of the rule's own drop-in.
        content: What the rule writes into its drop-in.
    """

    setting: str
    value: str
    method: str
    main: str
    dropin: str
    content: str

    @property
    def required(self) -> int:
        """Return the value that the library must hold after the rule is applied."""
        return 1 if SETTINGS.get(self.setting) == FLAG else int(self.value)

    @property
    def line(self) -> str:
        """Return the line that the rule writes."""
        return self.setting if not self.value else f"{self.setting} = {self.value}"


def _files(
    dropins: Sequence[Mapping[str, object]], main: str | None, rule: Rule, *, dropin: str | None
) -> tuple[list[tuple[str, bytes | None]], list[str]]:
    """Return the files in reading order and the drop-ins that the collection cannot read."""
    entries = {str(entry["path"]): entry for entry in dropins}
    if dropin is not None:
        entries[rule.dropin] = {"path": rule.dropin, "type": FILE, "content": dropin}
    ordered: list[tuple[str, bytes | None]] = []
    unread: list[str] = []
    for path in sorted(entries, key=lambda item: item.rsplit("/", 1)[-1].encode("utf-8")):
        entry = entries[path]
        if not is_dropin_name(path.rsplit("/", 1)[-1]) or entry.get("type") == DIRECTORY:
            continue
        content = entry.get("content")
        if entry.get("type") != FILE or not isinstance(content, str):
            unread.append(path)
            continue
        ordered.append((path, text_bytes(content)))
    ordered.append((rule.main, None if main is None else text_bytes(main)))
    return ordered, unread


def _where(reading: Reading) -> str:
    return (
        f"line {(reading.error_line or 0) + 1} of {reading.error_path}, "
        f"{ERROR_NAMES.get(reading.error, 'an error')}"
    )


def why_not_effective(reading: Reading, rule: Rule, path: str, line: int | None) -> str | None:
    """Return why the setting does not take effect from ``path`` (and ``line``), or ``None``."""
    item = reading.last(rule.setting)
    if item is not None and item.path == path and (line is None or item.line == line):
        return (
            None
            if item.value == rule.required
            else (
                f"libpwquality reads {rule.setting} {item.value} from {path}, not {rule.required}"
            )
        )
    if reading.error:
        return (
            f"libpwquality stops reading the configuration at {_where(reading)}, so it never reads "
            f"the {rule.setting} that the collection would write"
        )
    if item is None:
        return f"libpwquality does not read {rule.setting} from {path}"
    return (
        f"libpwquality reads {rule.setting} {item.value} from line {item.line + 1} of {item.path} "
        f"after {path}"
    )


def loosening(reading: Reading, pam: PamStack, rule: Rule) -> tuple[str | None, str | None]:
    """Return why ``enforcing`` turns the rule into a warning, and a note on ``local_users_only``.

    With ``enforcing = 0`` libpwquality only warns and accepts every password, so no other rule
    takes effect; with ``local_users_only`` the setting applies to local users only.
    """
    refusal = None
    if rule.setting != "enforcing":
        sources = [] if reading.value("enforcing") != 0 else ["the files"]
        sources += pam_enforcing_off(pam)
        if sources:
            refusal = (
                "enforcing is 0 in "
                + "; ".join(sources)
                + ", so libpwquality only warns and accepts every"
                f" password, and {rule.setting} does not take effect"
            )
    local = reading.value("local_users_only") == 1 or any(
        option_value(text_bytes(argument)) == ("local_users_only", 1)
        for _path, argument in read_pam(pam).arguments
    )
    note = (
        f"local_users_only is set, so {rule.setting} applies to local users only" if local else None
    )
    return refusal, note


def decide(
    rule: Rule,
    dropins: Sequence[Mapping[str, object]],
    main: str | None,
    pam: PamStack,
    directory: str = DIRECTORY,
) -> dict[str, object]:
    """Decide a rule from the files as libpwquality and ``pam_pwquality`` read them.

    Returns the ``status`` (``compliant``, ``applied``, ``overridden``, ``duplicate_setting``,
    ``not_directory``, ``unreadable_file`` or ``unreadable_value``), the ``reason`` of a refusal,
    a ``note`` on a rule that applies, the ``line`` that the rule writes, the setting line found in
    the main file (``found``) and, for the main file method, the new ``text`` of the main file with
    every other byte unchanged. A rule is ``applied`` or ``compliant`` only when the library,
    reading the files as they are or will be, takes the required value from what the rule writes,
    no ``pam_pwquality`` argument overrides it and ``enforcing`` is not 0. ``directory`` is the
    kind of the drop-in directory: ``directory``, ``missing``, ``link`` or ``other``.
    ``pam`` holds the PAM files and which of their lines load ``pam_pwquality``
    (:meth:`Modules.identify`).
    """
    result: dict[str, object] = {
        "line": rule.line,
        "found": None,
        "text": None,
        "reason": None,
        "note": None,
    }
    refusal = _refusal(rule, main, pam, directory)
    if refusal is not None:
        return result | refusal
    if rule.method == "dropin":
        decided, files = _decide_dropin(rule, dropins, main, result)
    else:
        decided, files = _decide_main(rule, dropins, main or "", result)
    if files is None:
        return decided
    loose, note = loosening(read_config(files), pam, rule)
    if loose is not None:
        return decided | {"status": "overridden", "reason": loose, "text": None}
    return decided | {"note": note}


def unreadable_refusal(rule: Rule, unreadable: Sequence[str]) -> dict[str, object] | None:
    """Return the decision that refuses the rule on PAM entries that the collection cannot read.

    ``unreadable`` holds the description (``pam_files.describe``) of every entry that libpam may
    read but the collection does not, one for each kind of ``pam_files.KINDS``: a symbolic link
    that resolves to nothing (``broken_link``), a link to something that is neither a regular
    file nor a directory (``link``), a link that ``stat`` could not follow (``unfollowed_link``),
    an entry that is none of a regular file, a directory and a link (``special``), an entry or a
    PAM directory that ``find`` could not inspect (``unlisted``), a PAM directory that ``stat``
    could not inspect (``uninspected_directory``) (all FREES-213), a link or a PAM directory that
    resolves, or whose target points, below ``/proc``, ``/sys`` or ``/dev`` (``virtual_file``),
    a link whose target is reached through a further link (``indirect_link``), and
    ``/etc/pam.conf`` when libpam reads it instead of the PAM directories
    (``pam_conf_fallback``) (all three FREES-212). The error message of a failed ``stat``, the
    path below ``/proc``, ``/sys`` or ``/dev`` and the target of an indirect link follow the
    description. A ``pam_pwquality`` argument in any of them could override the file, so the
    rule is ``overridden``, as for an include that the collection does not read. Returns ``None``
    when there is none.
    """
    if not unreadable:
        return None
    return {
        "line": rule.line,
        "found": None,
        "text": None,
        "note": None,
        "status": "overridden",
        "reason": "; ".join(unreadable) + ", which libpam may open but the collection does not"
        " read, so a pam_pwquality argument there could override the file",
    }


def _refusal(
    rule: Rule, main: str | None, pam: PamStack, directory: str
) -> dict[str, object] | None:
    """Return the refusal that does not depend on reading the files, or ``None``."""
    if directory not in (DIRECTORY, MISSING):
        return {
            "status": "not_directory",
            "reason": f"{rule.dropin.rsplit('/', 1)[0]} is a symbolic link or not a"
            " directory, which"
            " libpwquality reads through but the collection does not",
        }
    if main is not None and re.search(SURROGATE, main) is not None:
        return {
            "status": "unreadable_file",
            "reason": f"{rule.main} is not UTF-8 text, so it cannot be rewritten exactly",
        }
    read = read_pam(pam)
    if read.problems:
        return {
            "status": "overridden",
            "reason": "; ".join(read.problems) + ", so the collection cannot tell which"
            " pam_pwquality arguments libpam passes, and an argument there could override the file",
        }
    if read.includes:
        return {
            "status": "overridden",
            "reason": "; ".join(read.includes) + ", which the collection does not read, so a"
            " pam_pwquality argument there could override the file",
        }
    overrides = pam_overrides(pam, rule.setting, rule.required)
    if overrides:
        return {
            "status": "overridden",
            "reason": "pam_pwquality arguments override the file: " + "; ".join(overrides),
        }
    return None


def _decide_dropin(
    rule: Rule,
    dropins: Sequence[Mapping[str, object]],
    main: str | None,
    result: dict[str, object],
) -> tuple[dict[str, object], list[tuple[str, bytes | None]] | None]:
    files, unread = _files(dropins, main, rule, dropin=rule.content)
    if unread:
        return result | {
            "status": "unreadable_file",
            "reason": "libpwquality reads "
            + ", ".join(unread)
            + ", which the collection does not read: a symbolic link or not a regular file",
        }, None
    reason = why_not_effective(read_config(files), rule, rule.dropin, None)
    if reason is None:
        current = [entry for entry in dropins if entry.get("path") == rule.dropin]
        same = bool(current) and current[0].get("content") == rule.content
        return result | {"status": "compliant" if same else "applied"}, files
    return result | {"status": _status_of(reason), "reason": reason}, None


def _status_of(reason: str) -> str:
    """Return the status of a rule whose value would not take effect for ``reason``."""
    return "unreadable_file" if "stops reading" in reason else "overridden"


def _main_refusal(
    rule: Rule, main: str, found: Sequence[tuple[int, str]]
) -> dict[str, object] | None:
    """Return the refusal of a main file that the rule cannot rewrite exactly, or ``None``."""
    if len(found) > 1:
        return {
            "status": "duplicate_setting",
            "reason": f"{rule.main} sets {rule.setting} on {len(found)} lines",
        }
    if found and re.search(UNRECORDABLE, found[0][1]) is not None:
        return {
            "status": "unreadable_value",
            "reason": f"the line {found[0][1]!r} of {rule.main} holds a control character other"
            " than a tab or a carriage return, which the state ledger cannot record",
        }
    if "\x00" in main:
        return {
            "status": "unreadable_file",
            "reason": f"{rule.main} holds a NUL byte, so it cannot be rewritten exactly",
        }
    return None


def compose(main: str, line: str, found: Sequence[tuple[int, str]]) -> tuple[int, str]:
    """Return the number of the setting's line and the main file with ``line`` in its place.

    The one line that sets the setting is replaced in place; without one, the line is appended,
    after a line break when the file does not end with one. Every other byte stays as it is.
    """
    lines = main.split(NEWLINE)
    if found:
        number = found[0][0]
        return number, NEWLINE.join([*lines[:number], line, *lines[number + 1 :]])
    if main[-1:] in ("", NEWLINE):
        return len(lines) - 1, main + line + NEWLINE
    return len(lines), main + NEWLINE + line


def _decide_main(
    rule: Rule,
    dropins: Sequence[Mapping[str, object]],
    main: str,
    result: dict[str, object],
) -> tuple[dict[str, object], list[tuple[str, bytes | None]] | None]:
    found = setting_lines(main, rule.setting)
    result = result | {"found": found[0][1] if len(found) == 1 else None}
    refusal = _main_refusal(rule, main, found)
    if refusal is not None:
        return result | refusal, None
    number, text = compose(main, rule.line, found)
    files, unread = _files(dropins, text, rule, dropin=None)
    reason = (
        why_not_effective(read_config(files), rule, rule.main, number)
        if not unread
        else "libpwquality reads "
        + ", ".join(unread)
        + " before the main file, which the collection does not read: a symbolic link or not a"
        " regular file"
    )
    if reason is not None:
        return result | {
            "status": "unreadable_file" if unread else _status_of(reason),
            "reason": reason,
        }, None
    if found and found[0][1] == rule.line:
        return result | {"status": "compliant"}, files
    return result | {"status": "applied", "text": text}, files


def restore(text: str, setting: str, written: str, prior: str | None) -> dict[str, object]:
    """Return how the main file is restored: the reason it cannot be, and the text to write.

    The setting must still be set on exactly one line equal to ``written``; that line is replaced
    by ``prior`` in place, or removed with its line break when the setting was absent before, so
    that every other byte stays as it is. A file that already sets the setting exactly as before is
    ``already`` restored and left alone.
    """
    found = setting_lines(text, setting)
    if [line for _number, line in found] == ([] if prior is None else [prior]):
        return {"reason": None, "already": True, "text": text}
    if [line for _number, line in found] != [written]:
        return {"reason": "modified_since_apply", "already": False, "text": text}
    lines = text.split(NEWLINE)
    number = found[0][0]
    kept = [*lines[:number], *([] if prior is None else [prior]), *lines[number + 1 :]]
    return {"reason": None, "already": False, "text": NEWLINE.join(kept)}
