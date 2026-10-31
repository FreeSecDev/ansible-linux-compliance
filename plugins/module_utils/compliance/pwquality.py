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
PAM_MODULE: Final[bytes] = b"pam_pwquality"
PAM_SEPARATORS: Final[str] = r"[ \t\n\v\f\r\[\]]+"
NEWLINE: Final[str] = "\n"
DROPIN_SUFFIX: Final[str] = ".conf"
FILE: Final[str] = "file"
DIRECTORY: Final[str] = "directory"


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


def pam_overrides(files: Sequence[tuple[str, str]], setting: str, required: int) -> list[str]:
    """Return ``<file>: <argument>`` for each ``pam_pwquality`` argument overriding ``setting``.

    Every line of every PAM file that names ``pam_pwquality`` and is not a comment line is read,
    with lines continued by a trailing backslash joined, and its words are split at white space
    and brackets, so that more is found than PAM passes to the module and never less.
    """
    found: list[str] = []
    for path, text in files:
        logical: list[bytes] = []
        pending = b""
        for line in text_bytes(text).split(b"\n"):
            joined = pending + line
            if _strip(joined).endswith(b"\\"):
                pending = _strip(joined)[:-1] + b" "
                continue
            pending = b""
            logical.append(joined)
        logical.append(pending)
        for line in logical:
            if PAM_MODULE not in line or _strip(line).startswith(b"#"):
                continue
            words = re.split(PAM_SEPARATORS, line.decode("utf-8", "replace"))
            found.extend(
                f"{path}: {word}"
                for word in words
                if word and option_override(text_bytes(word), setting, required)
            )
    return found


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


def decide(
    rule: Rule,
    dropins: Sequence[Mapping[str, object]],
    main: str | None,
    pam: Sequence[tuple[str, str]],
) -> dict[str, object]:
    """Decide a rule from the files as libpwquality and ``pam_pwquality`` read them.

    Returns the ``status`` (``compliant``, ``applied``, ``overridden``, ``duplicate_setting``,
    ``unreadable_file`` or ``unreadable_value``), the ``reason`` of a refusal, the ``line`` that the
    rule writes, the setting line found in the main file (``found``) and, for the main file method,
    the new ``text`` of the main file with every other byte unchanged. A rule is ``applied`` or
    ``compliant`` only when the library, reading the files as they are or will be, takes the
    required value from what the rule writes, and no ``pam_pwquality`` argument overrides it.
    """
    result: dict[str, object] = {"line": rule.line, "found": None, "text": None, "reason": None}
    if main is not None and re.search(SURROGATE, main) is not None:
        return result | {
            "status": "unreadable_file",
            "reason": f"{rule.main} is not UTF-8 text, so it cannot be rewritten exactly",
        }
    overrides = pam_overrides(pam, rule.setting, rule.required)
    if overrides:
        return result | {
            "status": "overridden",
            "reason": "pam_pwquality arguments override the file: " + "; ".join(overrides),
        }
    if rule.method == "dropin":
        return _decide_dropin(rule, dropins, main, result)
    return _decide_main(rule, dropins, main or "", result)


def _decide_dropin(
    rule: Rule,
    dropins: Sequence[Mapping[str, object]],
    main: str | None,
    result: dict[str, object],
) -> dict[str, object]:
    files, unread = _files(dropins, main, rule, dropin=rule.content)
    if unread:
        return result | {
            "status": "unreadable_file",
            "reason": "libpwquality reads "
            + ", ".join(unread)
            + ", which the collection does not read: a symbolic link or not a regular file",
        }
    reason = why_not_effective(read_config(files), rule, rule.dropin, None)
    if reason is None:
        current = [entry for entry in dropins if entry.get("path") == rule.dropin]
        same = bool(current) and current[0].get("content") == rule.content
        return result | {"status": "compliant" if same else "applied"}
    return result | {"status": _status_of(reason), "reason": reason}


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
) -> dict[str, object]:
    found = setting_lines(main, rule.setting)
    result = result | {"found": found[0][1] if len(found) == 1 else None}
    refusal = _main_refusal(rule, main, found)
    if refusal is not None:
        return result | refusal
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
        }
    if found and found[0][1] == rule.line:
        return result | {"status": "compliant"}
    return result | {"status": "applied", "text": text}


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
