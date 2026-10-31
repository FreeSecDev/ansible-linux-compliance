"""Read ``/etc/audit/auditd.conf`` the way auditd reads it, or refuse (FREES-110).

This helper uses only the Python standard library and syntax that runs on Python 3.9. It never
runs a process and never touches a file: it classifies the bytes of a configuration file.

auditd itself is the oracle. ``tools/molecule/auditd_conf_verdicts.py`` runs the auditd of each
Molecule image on crafted files and commits what it read and whether it accepted the file as
``tests/fixtures/auditd_conf/verdicts.json``; the unit tests check this reader against that table.
What the table shows, for auditd 3.1.2 (Ubuntu 24.04) and 3.1.5 (Rocky Linux 9):

* A line is read into a buffer of 160 bytes up to its newline. A line longer than 158 bytes and a
  last line without a newline are skipped (``too long``); the rest of the file is still read. A
  NUL byte ends the line early, so auditd also skips the line after it: this reader refuses a
  file with a NUL byte.
* Leading spaces are ignored; a line that is empty after them is skipped, and so is a line whose
  first other character is ``#``. Any other line must be three words separated by spaces:
  the keyword, ``=`` and the value. A tab, CR, VT or FF is part of a word, never a separator.
* Keywords are compared without regard to case, and values of a choice too; an unknown keyword,
  a missing ``=``, a missing or extra word, or a value outside the keyword's form refuses the
  whole file, and auditd does not start.
* When a keyword is set twice, auditd reads both lines and the last one wins.
* After reading, auditd refuses a ``space_left`` that is not larger than ``admin_space_left``
  (both 0 when not set; percentages converted with the size of the log's file system) and
  incremental flushing with ``freq`` 0 (``freq`` is 0 when not set).

Every form that the table does not cover, such as the ``exec`` actions, is reported as unknown,
so that the caller refuses instead of guessing.
"""

from __future__ import annotations

import re
from typing import Final, NamedTuple, cast

MAX_LINE_BYTES: Final[int] = 158
MAX_FILE_BYTES: Final[int] = 1024 * 1024
SEPARATOR: Final[str] = "="
COMMENT: Final[str] = "#"
DIGITS: Final[str] = r"[0-9]{1,10}"
PATH: Final[str] = r"/[A-Za-z0-9._/-]{0,127}"
NAME: Final[str] = r"[A-Za-z0-9._-]{1,64}"
BOOLEAN: Final[tuple[str, ...]] = ("yes", "no")
DISK_ACTIONS: Final[tuple[str, ...]] = ("ignore", "syslog", "rotate", "suspend", "single", "halt")
SPACE_ACTIONS: Final[tuple[str, ...]] = (*DISK_ACTIONS, "email")
ERROR_ACTIONS: Final[tuple[str, ...]] = ("ignore", "syslog", "suspend", "single", "halt")
LARGEST: Final[int] = 1_000_000_000
SPACE: Final[str] = "space"
WORDS: Final[int] = 3
MAX_PERCENT: Final[int] = 100
MAX_SPACE_DIGITS: Final[int] = 9


class Form(NamedTuple):
    """The values that auditd accepts for a keyword, as the verdict table shows them.

    ``choices`` are compared without regard to case. A ``pattern`` value that matches is accepted
    when it is one of ``known`` (or ``known`` is empty); one that does not match, or is not known,
    cannot be told. A number between ``minimum`` and ``maximum`` is accepted, one above ``refused``
    is refused, any other cannot be told; ``lenient`` keywords (which one platform ignores and the
    other checks) never count as refused. ``SPACE`` is a number or a percentage below 100.
    """

    choices: tuple[str, ...] = ()
    pattern: str = ""
    known: tuple[str, ...] = ()
    minimum: int = 0
    maximum: int = LARGEST
    refused: int | None = None
    lenient: bool = False


NUMBER_FORM: Final[Form] = Form(pattern=DIGITS)
KEYWORDS: Final[dict[str, Form]] = {
    "local_events": Form(BOOLEAN),
    "write_logs": Form(BOOLEAN),
    "log_file": Form(pattern=PATH),
    "log_group": Form(pattern=NAME, known=("root", "adm")),
    "log_format": Form(("raw", "enriched")),
    "flush": Form(("none", "incremental", "incremental_async", "data", "sync")),
    "freq": NUMBER_FORM,
    "max_log_file": NUMBER_FORM,
    "num_logs": Form(pattern=DIGITS, maximum=999, refused=999),
    "priority_boost": Form(pattern=DIGITS, minimum=1),
    "name_format": Form(("none", "hostname", "fqd", "numeric", "user")),
    "name": Form(pattern=NAME),
    "max_log_file_action": Form(("ignore", "syslog", "suspend", "rotate", "keep_logs")),
    "verify_email": Form(BOOLEAN),
    "action_mail_acct": Form(pattern=NAME),
    "space_left": Form(pattern=SPACE),
    "space_left_action": Form(SPACE_ACTIONS),
    "admin_space_left": Form(pattern=SPACE),
    "admin_space_left_action": Form(SPACE_ACTIONS),
    "disk_full_action": Form(DISK_ACTIONS),
    "disk_error_action": Form(ERROR_ACTIONS),
    "use_libwrap": Form(BOOLEAN),
    "tcp_listen_queue": Form(pattern=DIGITS, minimum=1, maximum=65535, lenient=True),
    "tcp_max_per_addr": Form(pattern=DIGITS, minimum=1, maximum=1000, lenient=True),
    "tcp_client_max_idle": Form(pattern=DIGITS, lenient=True),
    "transport": Form(("tcp", "krb5")),
    "enable_krb5": Form(BOOLEAN),
    "krb5_principal": Form(pattern=NAME),
    "distribute_network": Form(BOOLEAN),
    "q_depth": Form(pattern=DIGITS, maximum=65536, refused=99999),
    "overflow_action": Form(ERROR_ACTIONS),
    "max_restarts": NUMBER_FORM,
    "plugin_dir": Form(pattern=PATH),
    "end_of_event_timeout": NUMBER_FORM,
}


class Setting(NamedTuple):
    """A line that auditd reads: its number (from 1), keyword in lower case, value and text."""

    line: int
    keyword: str
    value: str
    text: str


class Reading(NamedTuple):
    """What auditd makes of a file.

    ``accepted`` is ``True`` when auditd reads the file and starts with ``settings``, ``False``
    when it refuses the file and ``None`` when this reader cannot tell; ``reason`` says why for
    the last two. ``settings`` maps each keyword to the lines that auditd reads for it, in order
    (the last one wins); ``skipped`` holds the numbers of the lines that auditd skips.
    """

    accepted: bool | None
    reason: str
    settings: dict[str, list[Setting]]
    skipped: list[int]


def _space_verdict(value: str) -> bool | None:
    found = re.fullmatch(r"([0-9]{1,10})(%?)", value)
    if found is None or (found.group(2) and int(found.group(1)) >= MAX_PERCENT):
        return False
    return True if len(found.group(1)) <= MAX_SPACE_DIGITS else None


def _number_verdict(form: Form, value: str) -> bool | None:
    if re.fullmatch(r"[0-9]+", value) is None:
        return None if form.lenient else False
    if re.fullmatch(DIGITS, value) is None:
        return None
    number = int(value)
    if form.minimum <= number <= form.maximum:
        return True
    return False if form.refused is not None and number > form.refused else None


def _value_verdict(form: Form, value: str) -> bool | None:
    if form.choices:
        return value.lower() in form.choices
    if form.pattern == SPACE:
        return _space_verdict(value)
    if form.pattern == DIGITS:
        return _number_verdict(form, value)
    if re.fullmatch(form.pattern, value) is None:
        return None
    return True if not form.known or value in form.known else None


def _shape(words: list[str], number: int) -> tuple[bool | None, str]:
    keyword = words[0].lower() if words else ""
    if len(words) < WORDS:
        return False, f"line {number} does not have a keyword, = and a value"
    if words[1] != SEPARATOR:
        return False, f"line {number} misses the = after the keyword"
    if keyword not in KEYWORDS:
        return False, f"line {number} sets a keyword that auditd does not know"
    if len(words) > WORDS:
        if keyword.endswith("_action") and words[2].lower() == "exec":
            return None, f"line {number} uses the exec form, which the collection does not read"
        return False, f"line {number} has more than one value"
    return True, ""


def _line_verdict(text: str, number: int) -> tuple[bool | None, str, Setting | None]:
    rest = text.lstrip(" ")
    if not rest or rest.startswith(COMMENT):
        return True, "", None
    words = [word for word in rest.split(" ") if word]
    verdict, reason = _shape(words, number)
    if verdict is not True:
        return verdict, reason, None
    keyword = words[0].lower()
    found = _value_verdict(KEYWORDS[keyword], words[2])
    if found is None:
        return None, f"line {number}: the collection cannot tell whether auditd accepts it", None
    if not found:
        return False, f"line {number} gives {keyword} a value that auditd refuses", None
    return True, "", Setting(number, keyword, words[2], text)


def _space(value: str, size: int | None) -> tuple[bool, int | None]:
    """Return whether ``value`` is a percentage auditd converts, and its size in MiB if known."""
    number = int(value.rstrip("%"))
    if value.endswith("%") and number > 0:
        return True, None if size is None else number * size // 100
    return False, number


def _sanity(settings: dict[str, list[Setting]], size: int | None) -> tuple[bool | None, str]:
    def last(keyword: str, fallback: str) -> str:
        found = settings.get(keyword, [])
        return found[-1].value if found else fallback

    space, admin = last("space_left", "0"), last("admin_space_left", "0")
    space_percent, space_size = _space(space, size)
    admin_percent, admin_size = _space(admin, size)
    if not space_percent and not admin_percent:
        if cast("int", space_size) <= cast("int", admin_size):
            return False, f"space_left {space} is not larger than admin_space_left {admin}"
    elif space_size is None or admin_size is None:
        return None, (
            f"space_left {space} and admin_space_left {admin} are compared in MiB, and the size of"
            " the file system of the log is unknown; the collection cannot tell"
        )
    elif space_size <= admin_size:
        return None, (
            f"space_left {space} is not larger than admin_space_left {admin} in MiB; auditd only"
            " logs this when it starts, and the collection cannot tell"
        )
    flush = last("flush", "none").lower()
    if flush in ("incremental", "incremental_async") and int(last("freq", "0")) == 0:
        return False, "flush is incremental, but freq is 0"
    return True, ""


def read(data: bytes, log_megabytes: int | None = None) -> Reading:
    """Return what auditd makes of the configuration file ``data``.

    ``log_megabytes`` is the size of the file system of the log in MiB, which auditd uses to
    convert a ``space_left`` or ``admin_space_left`` in percent; ``None`` when unknown.
    """
    if len(data) > MAX_FILE_BYTES:
        return Reading(None, "the file is larger than 1 MiB", {}, [])
    lines = data.split(b"\n")
    complete = lines[:-1]
    settings: dict[str, list[Setting]] = {}
    skipped = [len(lines)] if lines[-1] else []
    for index, raw in enumerate(complete, start=1):
        if b"\x00" in raw:
            return Reading(
                None, f"line {index} holds a NUL byte, after which auditd skips a line", {}, []
            )
        if len(raw) > MAX_LINE_BYTES:
            skipped.append(index)
            continue
        text = raw.decode("latin-1")
        if re.search(r"[^\x00-\x7f]", text):
            return Reading(None, f"line {index} holds bytes outside ASCII", settings, skipped)
        accepted, reason, setting = _line_verdict(text, index)
        if accepted is not True:
            return Reading(accepted, reason, settings, sorted(skipped))
        if setting is not None:
            settings.setdefault(setting.keyword, []).append(setting)
    accepted, reason = _sanity(settings, log_megabytes)
    return Reading(accepted, reason, settings, sorted(skipped))


def value(reading: Reading, keyword: str) -> str | None:
    """Return the value that auditd uses for ``keyword``: that of its last line, or ``None``."""
    found = reading.settings.get(keyword, [])
    return found[-1].value if found else None
