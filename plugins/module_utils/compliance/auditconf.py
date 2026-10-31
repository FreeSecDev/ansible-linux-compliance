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
* The four disk space and disk error actions take more words, an option that auditd ignores
  unless the action is ``exec`` (a fifth word is only logged); every other keyword refuses a
  fourth word.
* ``log_file`` must lie in a directory whose name has at least four characters; auditd opens that
  directory and the file when it reads the line. This reader knows only the default
  ``/var/log/audit/audit.log``, which the table shows, and cannot tell for any other file.
* ``action_mail_acct`` must have at least two characters while ``verify_email`` (``yes`` until a
  line sets it) is on when auditd reads the line.
* After reading, auditd refuses a ``space_left`` that is not larger than ``admin_space_left``
  (both 0 when not set; percentages converted with the size of the log's file system),
  incremental flushing with ``freq`` 0 (``freq`` is 0 when not set), and a ``log_group`` other
  than root for a ``log_file`` directly in ``/var/log`` (``sanity_check``).

The table vouches for ``load_config`` only: in a container without capabilities auditd stops
right after it, before it starts. One check that auditd makes later, when it starts, comes from
its source (``resolve_node``) and is tested on its own: ``name_format = user`` without ``name``
stops auditd, so this reader refuses it. ``fqd`` and ``numeric`` resolve the host name when
auditd starts, which no reading of the file can tell.

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
ANY: Final[str] = r"[!-~]{1,128}"
PORTS: Final[str] = r"([0-9]{1,5})(?:-([0-9]{1,5}))?"
DEFAULT_LOG_FILE: Final[str] = "/var/log/audit/audit.log"
SYSTEM_LOG_DIRECTORY: Final[str] = "/var/log"
MIN_DIRECTORY_CHARACTERS: Final[int] = 4
MIN_MAIL_CHARACTERS: Final[int] = 2
MAX_PORT: Final[int] = 65535
OPTION_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"space_left_action", "admin_space_left_action", "disk_full_action", "disk_error_action"}
)
START_REASON: Final[str] = "auditd reads the file but stops when it starts"
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
    "tcp_listen_port": Form(pattern=DIGITS, minimum=1, maximum=MAX_PORT, lenient=True),
    "tcp_client_ports": Form(pattern=PORTS, lenient=True),
    "krb5_key_file": Form(pattern=ANY),
    "dispatcher": Form(pattern=ANY),
    "disp_qos": Form(pattern=ANY),
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


def _ports_verdict(form: Form, value: str) -> bool | None:
    found = re.fullmatch(form.pattern, value)
    if found is None:
        return None
    low = int(found.group(1))
    high = int(found.group(2)) if found.group(2) is not None else low
    return True if low <= high <= MAX_PORT else None


def c_dirname(path: str) -> str:
    """Return the directory of ``path`` as the C library's ``dirname`` names it."""
    stripped = path.rstrip("/")
    if not stripped:
        return "/"
    head = stripped.rsplit("/", 1)[0] if "/" in stripped else "."
    return head.rstrip("/") or "/"


def _value_verdict(form: Form, value: str) -> bool | None:
    if form.choices:
        return value.lower() in form.choices
    if form.pattern == SPACE:
        return _space_verdict(value)
    if form.pattern == DIGITS:
        return _number_verdict(form, value)
    if form.pattern == PORTS:
        return _ports_verdict(form, value)
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
        if keyword in OPTION_KEYWORDS and words[2].lower() == "exec":
            return None, f"line {number} uses the exec form, which the collection does not read"
        if keyword not in OPTION_KEYWORDS:
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
    if keyword == "log_file" and len(c_dirname(words[2])) < MIN_DIRECTORY_CHARACTERS:
        return False, f"line {number} puts log_file in a directory whose name is too short", None
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


def _last(settings: dict[str, list[Setting]], keyword: str, fallback: str) -> str:
    found = settings.get(keyword, [])
    return found[-1].value if found else fallback


def _space_sanity(settings: dict[str, list[Setting]], size: int | None) -> tuple[bool | None, str]:
    space, admin = _last(settings, "space_left", "0"), _last(settings, "admin_space_left", "0")
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
    return True, ""


def _start_sanity(settings: dict[str, list[Setting]]) -> tuple[bool | None, str]:
    flush = _last(settings, "flush", "none").lower()
    if flush in ("incremental", "incremental_async") and int(_last(settings, "freq", "0")) == 0:
        return False, "flush is incremental, but freq is 0"
    log_file = _last(settings, "log_file", DEFAULT_LOG_FILE)
    group = _last(settings, "log_group", "root")
    if group != "root" and c_dirname(log_file) == SYSTEM_LOG_DIRECTORY:
        return False, f"log_group is not root, but log_file {log_file} is directly in /var/log"
    if _last(settings, "name_format", "none").lower() == "user" and not settings.get("name"):
        return False, f"name_format is user, but name is not set; {START_REASON} (resolve_node)"
    if log_file != DEFAULT_LOG_FILE:
        return None, (
            f"auditd opens the directory and the file of log_file {log_file} when it reads it; the"
            f" collection only knows {DEFAULT_LOG_FILE} and cannot tell"
        )
    return True, ""


def _sanity(settings: dict[str, list[Setting]], size: int | None) -> tuple[bool | None, str]:
    accepted, reason = _space_sanity(settings, size)
    if accepted is not True:
        return accepted, reason
    return _start_sanity(settings)


def _mail_verdict(setting: Setting, settings: dict[str, list[Setting]]) -> tuple[bool, str]:
    """Refuse a short mail account while ``verify_email`` is on at the line that sets it."""
    verify = settings.get("verify_email", [])
    verifying = not verify or verify[-1].value.lower() == "yes"
    short = len(setting.value) < MIN_MAIL_CHARACTERS
    if setting.keyword == "action_mail_acct" and verifying and short:
        return False, f"line {setting.line} gives action_mail_acct fewer than two characters"
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
        if accepted is True and setting is not None:
            accepted, reason = _mail_verdict(setting, settings)
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
