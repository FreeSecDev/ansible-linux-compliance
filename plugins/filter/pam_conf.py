"""Filter that decides a faillock.conf or pwhistory.conf setting as linux-pam reads it."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

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
    pam_faillock, C(pam_modutil_search_key) of pam_pwhistory), and the module lines of every
    PAM service file the way libpam assembles and splits them.
  - Returns the status of the rule (C(applied), C(compliant), C(overridden), C(hidden_setting),
    C(duplicate_setting), C(stricter_setting), C(unreadable_file) or C(unsupported_value)), its
    reason, the line to write and the one line of the setting that the collection would replace.
  - A time that the profile requires above 604800 seconds is C(unsupported_value): pam_faillock
    ignores such a value and keeps its default, so the collection never writes one.
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
    description: The text of every PAM service file, by path.
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
        if len(line) >= FAILLOCK_BUFFER - 1 or ("\0" in line and terminated[index]):
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
    for _, name, value in lines:
        _faillock_set(options, name, value)
    for argument in args:
        if argument in {"preauth", "authfail", "authsucc"} or argument.startswith("conf="):
            continue
        name, _, value = argument[: FAILLOCK_BUFFER - 1].partition("=")
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
    return next((value for _, name, value in lines if name.lower() == key), None)


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


def assembled_lines(text: str) -> Iterator[str]:
    """Yield the logical lines of a PAM service file as C(_pam_assemble_line) joins them."""
    logical = ""
    pending = False
    for line in text.split("\n"):
        stripped = line.lstrip(PAM_SPLIT)
        if not stripped or stripped.startswith("#"):
            continue
        if "#" in stripped:
            yield logical + stripped.split("#", 1)[0]
            logical, pending = "", False
            continue
        stripped = stripped.rstrip(PAM_SPLIT)
        if stripped.endswith("\\"):
            logical += stripped[:-1] + " "
            pending = True
            continue
        yield logical + stripped
        logical, pending = "", False
    if pending:
        yield logical


def _tokens(text: str) -> list[str]:
    """Split the arguments of a module line as C(_pam_mkargv) does, with brackets kept together."""
    found: list[str] = []
    position = 0
    while position < len(text):
        while position < len(text) and text[position] in PAM_SPLIT:
            position += 1
        if position >= len(text):
            break
        if text[position] == "[":
            end = position + 1
            while end < len(text) and not (text[end] == "]" and text[end - 1] != "\\"):
                end += 1
            found.append(text[position + 1 : end].replace("\\]", "]"))
            position = end + 1
            continue
        end = position
        while end < len(text) and text[end] not in PAM_SPLIT:
            end += 1
        found.append(text[position:end])
        position = end
    return found


MODULE_LINE: Final[str] = r"[ \t\n]*([^ \t\n]+)[ \t\n]+(?:\[[^\]]*\]|[^ \t\n]+)[ \t\n]+(.*)"


def module_arguments(text: str, module: str) -> Iterator[list[str]]:
    """Yield the arguments of every line of a PAM service file that loads C(module).

    libpam compares the type without case and drops one leading C(-); the control is a word or
    a bracketed list that may contain blanks.
    """
    for line in assembled_lines(text):
        match = re.match(MODULE_LINE, line, re.DOTALL)
        if match is None:
            continue
        kind = match.group(1)
        kind = kind.removeprefix("-")
        parts = _tokens(match.group(2))
        if kind.lower() in PAM_TYPES and parts and parts[0].rsplit("/", 1)[-1] == module + ".so":
            yield parts[1:]


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
    """Return the PAM service files whose module lines override the setting in the file."""
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
    return re.fullmatch(pattern, line) is not None


def _editable(line: str, setting: str) -> bool:
    return re.match(rf"[ \t]*{setting}(?:[ \t=]|$)", line) is not None


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
    return {"status": status, "reason": reason, "line": line, "setting_line": setting_line}


def _rule(value: object) -> Rule:
    """Return the rule of the filter's second argument, or fail."""
    given = value if isinstance(value, dict) else {}
    reader, setting = given.get("reader"), given.get("setting")
    comparison, required = given.get("comparison"), given.get("required")
    checked = given.get("stack_checked")
    valid = (
        set(given) == RULE_KEYS
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
            f"boolean stack_checked, got {repr(value)[:120]}"
        )
        raise ValueError(message)
    return Rule(reader, str(setting), str(comparison), required, checked)


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
    files = {str(key): str(value) for key, value in stack.items()}
    overriding = stack_overrides(files, decided.reader, decided.setting, checked=decided.checked)
    if overriding:
        names = ", ".join(overriding)
        reason = (
            f"the {READERS[decided.reader][0]} lines of {names} redirect the module "
            f"to another file with conf= or set {decided.setting} as an argument, which takes "
            "precedence over the file; the collection does not edit the PAM stack"
        )
        return _decision("overridden", reason, decided.line, None)
    return _file_decision(text, decided)


def _file_decision(text: str, rule: Rule) -> dict[str, object]:
    """Return the decision from the lines of the file that pam reads for the setting."""
    lines, readable = faillock_lines(text)
    if "\0" in text or (rule.reader == "faillock" and not readable):
        reason = (
            "the file holds a NUL character or a line of 1023 characters or more: pam_faillock "
            "fails on such a file instead of using any setting, and a rewrite could turn a NUL "
            "that pam still skips into one that breaks it; nothing is written"
        )
        return _decision("unreadable_file", reason, rule.line, None)
    if rule.reader == "faillock":
        read = [index for index, name, _ in lines if name == rule.setting]
    else:
        read = [index for index, name, _ in pwhistory_lines(text) if name.lower() == rule.setting]
    physical = text.split("\n")
    edited = [index for index, value in enumerate(physical) if _editable(value, rule.setting)]
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
    current = physical[read[0]] if read else None
    if current is None:
        return _decision("applied", None, rule.line, None)
    if rule.flag:
        status = "compliant" if _strict(current, rule.setting, flag=True) else "applied"
        return _decision(status, None, rule.line, current)
    return _number_decision(rule, current)


def _number_decision(rule: Rule, current: str) -> dict[str, object]:
    """Return the decision for the one line of a numeric setting."""
    parsed = _faillock_line(current) if rule.reader == "faillock" else _pwhistory_line(current)
    number = _value_of(rule.reader, rule.setting, parsed[1]) if parsed is not None else None
    required = int(rule.required)
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
