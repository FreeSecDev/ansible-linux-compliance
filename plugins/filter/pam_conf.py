"""Filter that decides a faillock.conf or pwhistory.conf setting as linux-pam reads it."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

DOCUMENTATION = r"""
---
name: pam_conf_decision
short_description: Decide one faillock.conf or pwhistory.conf setting as linux-pam reads it
version_added: "0.1.0"
description:
  - Reads the text of C(/etc/security/faillock.conf) or C(/etc/security/pwhistory.conf) the way
    the readers of linux-pam 1.5.1 and 1.5.3 do (C(read_config_file) and C(set_conf_opt) of
    pam_faillock, C(pam_modutil_search_key) of pam_pwhistory), and the module lines of the PAM
    service files the way libpam assembles them (both C(_pam_assemble_line) variants) and splits
    them (C(_pam_StrTok)), with the service files of C(/etc/pam.d), C(/usr/lib/pam.d) and
    C(/usr/share/pam.d) taken in libpam's order.
  - Returns the status of the rule (C(applied), C(compliant), C(overridden), C(unreadable_stack),
    C(hidden_setting), C(duplicate_setting), C(stricter_setting), C(unreadable_file),
    C(unreadable_value) or C(unsupported_value)), its reason, the physical line to write, the
    one physical line of the setting that the collection would replace and, for C(applied), the
    exact new text of the file, every other byte unchanged.
  - A time that the profile requires above 604800 seconds is C(unsupported_value), because
    pam_faillock ignores such a value and keeps its default; the collection never writes one.
  - The model is checked against a verdict table that the real readers produce in the Molecule
    images (C(make pam-reader-verdicts), C(tools/pam)).
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, rule, stack
options:
  _input:
    description: The text of the configuration file.
    type: str
    required: true
  rule:
    description:
      - The rule, with exactly C(reader) (C(faillock) or C(pwhistory)), C(setting), C(comparison)
        (C(present), C(at_most) or C(at_least)), C(required) (the profile value as decimal
        digits, empty for C(present)) and C(stack_checked) (whether the check of the rule also
        reads the setting on a module line).
    type: dict
    required: true
  stack:
    description: The text of every file of the PAM service directories, by path.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Decide deny
  ansible.builtin.set_fact:
    decision: >-
      {{ text | freesecdev.linux_compliance.pam_conf_decision({'reader': 'faillock',
         'setting': 'deny', 'comparison': 'at_most', 'required': '4', 'stack_checked': true},
         stack) }}
"""

RETURN = r"""
_value:
  description: The decision.
  type: dict
  contains:
    status:
      description: The status of the rule.
      type: str
    reason:
      description: Why the rule is refused, or null.
      type: str
    line:
      description: The line to write.
      type: str
    setting_line:
      description: The one line of the setting that the collection would replace, or null.
      type: str
    new_text:
      description: The text of the file after the change, or null when nothing is written.
      type: str
"""

C_SPACE: Final[str] = " \t\n\v\f\r"
PAM_SPLIT: Final[str] = " \t\n"
FAILLOCK_BUFFER: Final[int] = 1024
MAX_TIME: Final[int] = 604800
INT_MAX: Final[int] = 2**31 - 1
ULONG_MAX: Final[int] = 2**64 - 1
READERS: Final[dict[str, tuple[str, str]]] = {
    "faillock": ("pam_faillock", "auth"),
    "pwhistory": ("pam_pwhistory", "password"),
}
COMPARISONS: Final[frozenset[str]] = frozenset({"present", "at_most", "at_least"})
SETTINGS: Final[dict[str, frozenset[str]]] = {
    "faillock": frozenset(
        {
            "deny",
            "fail_interval",
            "unlock_time",
            "root_unlock_time",
            "even_deny_root",
            "audit",
            "silent",
        }
    ),
    "pwhistory": frozenset({"remember", "enforce_for_root"}),
}
NEVER_SETTINGS: Final[frozenset[str]] = frozenset({"unlock_time", "root_unlock_time"})
TIME_SETTINGS: Final[frozenset[str]] = frozenset(
    {"fail_interval", "unlock_time", "root_unlock_time"}
)
FAILLOCK_FLAGS: Final[frozenset[str]] = frozenset({"even_deny_root", "audit", "silent"})
NUMBER: Final[str] = r"(0|[1-9][0-9]{0,8})"
PAM_TYPES: Final[frozenset[str]] = frozenset({"auth", "account", "password", "session"})
PAM_DIRECTORIES: Final[tuple[str, ...]] = ("/etc/pam.d", "/usr/lib/pam.d", "/usr/share/pam.d")
PAM_LINE_LIMIT: Final[int] = 1023
MAX_DENY: Final[int] = 65535
ASSEMBLY_VARIANTS: Final[tuple[str, ...]] = ("buffer", "getline")
BIDI_CONTROLS: Final[frozenset[str]] = frozenset(
    chr(code) for code in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)
)
RULE_KEYS: Final[frozenset[str]] = frozenset(
    {"reader", "setting", "comparison", "required", "stack_checked"}
)


def scan_unsigned(value: str, bits: int) -> int | None:
    """Return what glibc C(sscanf) with C(%u) (32 bits) or C(%hu) (16 bits) stores, or None."""
    match = re.match(r"[ \t\n\v\f\r]*([+-]?)([0-9]+)", value)
    if match is None:
        return None
    number = int(match.group(2))
    if number > ULONG_MAX:
        number = ULONG_MAX
    elif match.group(1) == "-":
        number = (ULONG_MAX + 1 - number) % (ULONG_MAX + 1)
    return number & ((1 << bits) - 1)


def byte_length(text: str) -> int:
    """Return the length of a text in the bytes that C(fgets) counts."""
    return len(text.encode("utf-8", "surrogateescape"))


def _faillock_line(line: str) -> tuple[str, str] | None:
    """Return the key and the value of one line as C(read_config_file) splits it, or None."""
    text = line.split("#", 1)[0].rstrip(C_SPACE).lstrip(C_SPACE)
    if not text:
        return None
    end = 0
    while end < len(text) and text[end] not in C_SPACE and text[end] != "=":
        end += 1
    name = text[:end]
    rest = text[end + 1 :] if end < len(text) else ""
    equals = end < len(text) and text[end] == "="
    position = 0
    while position < len(rest):
        if rest[position] != "=" or equals:
            if rest[position] not in C_SPACE:
                break
        else:
            equals = True
        position += 1
    return name, rest[position:]


def faillock_lines(text: str) -> tuple[list[tuple[int, str, str]], bool]:
    """Return the key lines of faillock.conf and whether pam can read the file at all."""
    found: list[tuple[int, str, str]] = []
    physical = text.split("\n")
    terminated = [index < len(physical) - 1 for index in range(len(physical))]
    for index, line in enumerate(physical):
        if not line and not terminated[index]:
            continue
        if byte_length(line) >= FAILLOCK_BUFFER - 1 or ("\0" in line and terminated[index]):
            return found, False
        parsed = _faillock_line(line.split("\0", 1)[0])
        if parsed is not None:
            found.append((index, parsed[0], parsed[1]))
    return found, True


def _faillock_set(options: dict[str, int], name: str, value: str) -> None:
    """Apply one key as C(set_conf_opt) does."""
    if name == "deny":
        number = scan_unsigned(value, 16)
        if number is not None:
            options["deny"] = number
    elif name in TIME_SETTINGS:
        number = 0 if value == "never" and name in NEVER_SETTINGS else scan_unsigned(value, 32)
        if number is not None and number <= MAX_TIME:
            options[name] = number
    elif name in FAILLOCK_FLAGS:
        options[name] = 1


def read_faillock(text: str, args: tuple[str, ...] = ()) -> dict[str, int] | None:
    """Return the options that pam_faillock takes from the file and the module arguments."""
    options = {
        "deny": 3,
        "fail_interval": 900,
        "unlock_time": 600,
        "root_unlock_time": -1,
        "even_deny_root": 0,
        "audit": 0,
        "silent": 0,
    }
    lines, readable = faillock_lines(text)
    if not readable:
        return None
    for _index, name, value in lines:
        _faillock_set(options, name, value)
    for argument in args:
        if argument in {"preauth", "authfail", "authsucc"} or argument.startswith("conf="):
            continue
        name, _equals, value = argument[: FAILLOCK_BUFFER - 1].partition("=")
        _faillock_set(options, name, value)
    if options["root_unlock_time"] == -1:
        options["root_unlock_time"] = options["unlock_time"]
    return options


def _pwhistory_line(line: str) -> tuple[str, str] | None:
    """Return the key and the value of one line as C(pam_modutil_search_key) splits it, or None."""
    text = line.split("\0", 1)[0].split("#", 1)[0].lstrip(C_SPACE)
    if not text:
        return None
    match = re.match(r"([^ \t=]*)([ \t=]?)(.*)", text, re.DOTALL)
    if match is None or not match.group(2):
        return (text, "")
    return match.group(1), match.group(3).lstrip(C_SPACE + "=")


def pwhistory_lines(text: str) -> list[tuple[int, str, str]]:
    """Return the key lines of pwhistory.conf in order."""
    found: list[tuple[int, str, str]] = []
    for index, line in enumerate(text.split("\n")):
        parsed = _pwhistory_line(line)
        if parsed is not None:
            found.append((index, parsed[0], parsed[1]))
    return found


def _first(lines: list[tuple[int, str, str]], key: str) -> str | None:
    return next((value for _index, name, value in lines if name.lower() == key), None)


def read_pwhistory(text: str, args: tuple[str, ...] = ()) -> dict[str, int]:
    """Return the options that pam_pwhistory takes from the file and the module arguments."""
    lines = pwhistory_lines(text)
    options = {"remember": 10, "enforce_for_root": 0}
    remember = _first(lines, "remember")
    if remember is not None:
        number = scan_unsigned(remember, 32)
        if number is not None:
            options["remember"] = number - 2**32 if number > INT_MAX else number
    if _first(lines, "enforce_for_root") is not None:
        options["enforce_for_root"] = 1
    for argument in args:
        if argument.lower().startswith("remember="):
            match = re.match(r"[ \t\n\v\f\r]*([+-]?[0-9]+)", argument[9:])
            number = int(match.group(1)) if match else 0
            options["remember"] = min(max(number, 0), 400)
        elif argument.lower() == "enforce_for_root":
            options["enforce_for_root"] = 1
    return options


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
            token = []
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
    """Yield the module and include lines of a service file for one assembly variant."""
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
        if "\0" in text or any(byte_length(line) >= PAM_LINE_LIMIT for line in text.split("\n")):
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


def overrides(argument: str, reader: str, setting: str) -> bool:
    """Return whether a module argument redirects or sets what the rule writes into the file."""
    if argument.startswith("conf="):
        return True
    if reader == "faillock":
        name = argument.partition("=")[0]
        return name == setting or name.endswith("_" + setting)
    if setting == "remember":
        return argument.lower().startswith("remember=")
    return argument.lower() == setting


def stack_overrides(
    stack: Mapping[str, str], reader: str, setting: str, *, checked: bool
) -> list[str]:
    """Return the service files whose module lines override the setting in the file.

    C(stack) holds the service files that libpam reads (see C(effective_stack)).
    """
    module = READERS[reader][0]
    found: list[str] = []
    for path in sorted(stack):
        for arguments in module_arguments(stack[path], module):
            if any(
                argument.startswith("conf=") or (checked and overrides(argument, reader, setting))
                for argument in arguments
            ):
                found.append(path)
                break
    return found


def _strict(line: str, setting: str, *, flag: bool) -> bool:
    pattern = rf"[ \t]*{setting}[ \t]*" if flag else rf"[ \t]*{setting}[ \t]*=[ \t]*{NUMBER}[ \t]*"
    return re.fullmatch(pattern, body_of(line)) is not None


def _editable(line: str, setting: str) -> bool:
    return re.match(rf"[ \t]*{setting}(?:[ \t=]|$)", body_of(line)) is not None


def body_of(line: str) -> str:
    """Return a physical line without the carriage return of a CRLF line ending."""
    return line.removesuffix("\r")


def recordable(text: str) -> bool:
    """Return whether the state ledger records a text: no control character but tab and CR."""
    return not any(
        character in BIDI_CONTROLS
        or unicodedata.category(character) == "Cs"
        or (unicodedata.category(character) == "Cc" and character not in "\t\r")
        for character in text
    )


def edited_lines(text: str, setting: str) -> list[int]:
    """Return the indexes of the physical lines that the collection edits for a setting."""
    return [index for index, line in enumerate(text.split("\n")) if _editable(line, setting)]


def written_text(text: str, index: int | None, line: str) -> str:
    """Return the text with the physical line at C(index) replaced by C(line), or C(line) appended.

    The line is written without a carriage return, which pam_pwhistory would read as part of a
    flag's name; a file without a final newline keeps having none, so the cleanup that removes
    the line gives back the same bytes.
    """
    lines = text.split("\n")
    if index is not None:
        lines[index] = line
    elif text == "":
        lines = [line, ""]
    elif lines[-1] == "":
        lines.insert(len(lines) - 1, line)
    else:
        lines.append(line)
    return "\n".join(lines)


def satisfies(setting: str, comparison: str, number: int, required: int) -> bool:
    """Return whether the value that pam reads satisfies the profile, never looser than it."""
    if comparison == "at_most":
        return 1 <= number <= required
    if setting in NEVER_SETTINGS and required == 0:
        return number == 0
    if setting in TIME_SETTINGS and (
        number > MAX_TIME or (setting in NEVER_SETTINGS and number == 0)
    ):
        return False
    return required <= number <= INT_MAX


def _value_of(reader: str, setting: str, value: str) -> int | None:
    """Return the number that pam stores for the value of the line, or None if it ignores it."""
    if reader == "faillock" and setting in NEVER_SETTINGS and value == "never":
        return 0
    number = scan_unsigned(value, 16 if setting == "deny" else 32)
    if number is None or (setting in TIME_SETTINGS and number > MAX_TIME):
        return None
    return number


@dataclass(frozen=True)
class Rule:
    """The setting of one rule, the comparison of its check and the profile's value."""

    reader: str
    setting: str
    comparison: str
    required: str
    checked: bool

    @property
    def flag(self) -> bool:
        """Return whether the setting is a flag without a value."""
        return self.comparison == "present"

    @property
    def line(self) -> str:
        """Return the line that the profile's value gives."""
        return self.setting if self.flag else f"{self.setting} = {self.required}"


def _decision(
    status: str, reason: str | None, line: str, setting_line: str | None
) -> dict[str, object]:
    return {
        "status": status,
        "reason": reason,
        "line": line,
        "setting_line": setting_line,
        "new_text": None,
    }


def _rule(value: object) -> Rule:
    """Return the rule of the filter's second argument, or fail."""
    shown = repr(value)[:120]
    given = cast("dict[object, object]", value) if isinstance(value, dict) else {}
    reader, setting = given.get("reader"), given.get("setting")
    comparison, required = given.get("comparison"), given.get("required")
    checked = given.get("stack_checked")
    valid = (
        all(isinstance(key, str) for key in given)
        and frozenset(str(key) for key in given) == RULE_KEYS
        and isinstance(reader, str)
        and reader in READERS
        and setting in SETTINGS[reader]
        and comparison in COMPARISONS
    )
    value_valid = (
        isinstance(required, str)
        and isinstance(checked, bool)
        and (comparison == "present") == (required == "")
        and (comparison == "present" or re.fullmatch(NUMBER, required) is not None)
    )
    if not (valid and value_valid):
        message = (
            f"pam_conf_decision needs a rule with exactly {sorted(RULE_KEYS)}: a known reader and "
            "setting, a comparison, a decimal profile value unless the setting is a flag and a "
            f"boolean stack_checked, got {shown}"
        )
        raise ValueError(message)
    return Rule(str(reader), str(setting), str(comparison), str(required), checked is True)


def pam_conf_decision(text: object, rule: object, stack: object) -> dict[str, object]:
    """Return the decision for one rule; see the documentation of the filter."""
    if not isinstance(text, str) or not isinstance(stack, dict):
        message = "pam_conf_decision needs the text of the file and the texts of the PAM files"
        raise TypeError(message)
    decided = _rule(rule)
    if decided.setting in TIME_SETTINGS and int(decided.required) > MAX_TIME:
        reason = (
            f"the profile requires {decided.setting} = {decided.required}, above the {MAX_TIME} "
            "seconds that pam_faillock accepts: it ignores the value and keeps its default, so "
            "nothing is written"
        )
        return _decision("unsupported_value", reason, decided.line, None)
    if decided.setting == "deny" and int(decided.required) > MAX_DENY:
        reason = (
            f"the profile requires deny = {decided.required}, above the {MAX_DENY} that "
            "pam_faillock stores in 16 bits, so it would read another value; nothing is written"
        )
        return _decision("unsupported_value", reason, decided.line, None)
    files = {str(key): str(value) for key, value in cast("dict[object, object]", stack).items()}
    effective, problems = effective_stack(files)
    if problems:
        unread = "; ".join(problems)
        reason = (
            f"libpam reads service files that the collection cannot read as it does ({unread}), "
            f"so it cannot tell whether a {READERS[decided.reader][0]} line overrides the file; "
            "nothing is written"
        )
        return _decision("unreadable_stack", reason, decided.line, None)
    overriding = stack_overrides(
        effective, decided.reader, decided.setting, checked=decided.checked
    )
    if overriding:
        names = ", ".join(overriding)
        reason = (
            f"the {READERS[decided.reader][0]} lines of {names} redirect the module "
            f"to another file with conf= or set {decided.setting} as an argument, which takes "
            "precedence over the file; the collection does not edit the PAM stack"
        )
        return _decision("overridden", reason, decided.line, None)
    decision = _file_decision(text, decided)
    if decision["status"] == "applied":
        index = decision.pop("index")
        decision["new_text"] = written_text(text, cast("int | None", index), str(decision["line"]))
    decision.pop("index", None)
    return decision


def _file_refusal(text: str, rule: Rule) -> dict[str, object] | None:
    """Return the refusal for a file that the collection cannot decide or write, or None."""
    readable = faillock_lines(text)[1]
    if "\0" in text or (rule.reader == "faillock" and not readable):
        reason = (
            "the file holds a NUL character or a line of 1023 bytes or more: pam_faillock "
            "fails on such a file instead of using any setting, and a rewrite could turn a NUL "
            "that pam still skips into one that breaks it; nothing is written"
        )
        return _decision("unreadable_file", reason, rule.line, None)
    if any("\udc80" <= character <= "\udcff" for character in text):
        reason = (
            "the file is not valid UTF-8, so the collection cannot write it back with every other "
            "byte unchanged; nothing is written"
        )
        return _decision("unreadable_file", reason, rule.line, None)
    read = _read_lines(text, rule)
    edited = edited_lines(text, rule.setting)
    if read != edited:
        reason = (
            f"pam reads {len(read)} line(s) of {rule.setting}, {len(edited)} of them in the form "
            "the collection edits; the others start with or contain a vertical tab, form feed or "
            "carriage return, or name the setting in another case, so nothing is written"
        )
        return _decision("hidden_setting", reason, rule.line, None)
    if len(read) > 1:
        winner = "last" if rule.reader == "faillock" else "first"
        reason = f"the file sets {rule.setting} on {len(read)} lines and pam takes the {winner}"
        return _decision("duplicate_setting", reason, rule.line, None)
    current = text.split("\n")[read[0]] if read else ""
    if not recordable(current):
        reason = (
            f"the line {current!r} holds a control character that the state ledger does not "
            "record, so the line could not be restored exactly; nothing is written"
        )
        return _decision("unreadable_value", reason, rule.line, None)
    return None


def _read_lines(text: str, rule: Rule) -> list[int]:
    """Return the indexes of the lines of the setting that pam reads."""
    if rule.reader == "faillock":
        return [index for index, name, _value in faillock_lines(text)[0] if name == rule.setting]
    return [index for index, name, _value in pwhistory_lines(text) if name.lower() == rule.setting]


def _file_decision(text: str, rule: Rule) -> dict[str, object]:
    """Return the decision from the lines of the file that pam reads for the setting."""
    refusal = _file_refusal(text, rule)
    if refusal is not None:
        return refusal
    read = _read_lines(text, rule)
    if not read:
        return {**_decision("applied", None, rule.line, None), "index": None}
    current = text.split("\n")[read[0]]
    if rule.flag:
        status = "compliant" if _strict(current, rule.setting, flag=True) else "applied"
        return {**_decision(status, None, rule.line, current), "index": read[0]}
    return {**_number_decision(rule, current), "index": read[0]}


def _number_decision(rule: Rule, current: str) -> dict[str, object]:
    """Return the decision for the one line of a numeric setting."""
    parsed = _faillock_line(current) if rule.reader == "faillock" else _pwhistory_line(current)
    number = _value_of(rule.reader, rule.setting, parsed[1]) if parsed is not None else None
    required = int(rule.required)
    literal = re.match(r"[ \t\n\v\f\r]*\+?([0-9]+)", parsed[1]) if parsed is not None else None
    if rule.setting == "deny" and literal is not None and int(literal.group(1)) > MAX_DENY:
        reason = (
            f"deny is {literal.group(1)}, above the {MAX_DENY} that pam_faillock stores in 16 "
            f"bits: pam reads {number} while the check reads {literal.group(1)}, so the "
            "collection cannot tell which the site meant; nothing is written"
        )
        return _decision("unreadable_value", reason, rule.line, current)
    if number == 0 and rule.setting in NEVER_SETTINGS and required > 0:
        reason = (
            f"{rule.setting} = 0 never unlocks, which is stricter than the {required} that the "
            "profile and the check require; the collection does not loosen it"
        )
        return _decision("stricter_setting", reason, rule.line, current)
    if number is not None and satisfies(rule.setting, rule.comparison, number, required):
        if _strict(current, rule.setting, flag=False):
            return _decision("compliant", None, rule.line, current)
        return _decision("applied", None, f"{rule.setting} = {number}", current)
    return _decision("applied", None, rule.line, current)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"pam_conf_decision": pam_conf_decision}
