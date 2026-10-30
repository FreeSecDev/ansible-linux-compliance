#!/usr/bin/python

"""Read the audit status, load the audit rules or reload auditd (FREES-110)."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: audit_control
short_description: Read the audit status, load the audit rules or reload auditd
version_added: "0.1.0"
description:
  - With O(action=status), reports whether C(auditctl) is installed, what C(auditctl -s) and
    C(auditctl -l) say about the kernel (whether auditing is enabled or locked with C(-e 2), the
    process of auditd and the loaded rules), and the rule lines of every file below
    C(/etc/audit/rules.d) that C(augenrules) reads. Nothing is changed.
  - With O(action=load), refuses to load when two places of C(/etc/audit/rules.d) hold the same
    rule (C(auditctl -R) would stop at the second and leave every later rule unloaded) or when the
    loaded rules are locked (C(enabled 2)). Otherwise runs C(augenrules --load), exactly as
    C(auditd.service) does when it starts, and checks that every line of O(expect) is among the
    rules that C(auditctl -l) lists afterwards.
  - With O(action=reload), asks a running auditd to read C(/etc/audit/auditd.conf) again
    (C(auditctl --signal reload)) and checks that the same process still runs afterwards.
  - The executables are resolved only from the trusted system directories and run through the
    audited process helper of the collection (ADR 0004) in exact argument forms, with a minimal
    environment and a timeout. No rule, file or option is passed on their command line.
author:
  - FreeSecDev contributors (@FreeSecDev)
options:
  action:
    description: What to do.
    type: str
    required: true
    choices: [status, load, reload]
  expect:
    description:
      - Rule lines, as a rule file holds them, that must be loaded after O(action=load); with
        O(action=status), the lines whose loading is reported in RV(missing).
      - A line matches a rule of C(auditctl -l) when both are equal after C(-F key=) is read as
        C(-k), C(auid!=-1) as C(auid!=unset) and spaces are collapsed. For a line without C(-S),
        the system calls that the kernel lists for the rule are not compared, because the kernel
        derives them from the rule's fields.
    type: list
    elements: str
    default: []
attributes:
  check_mode:
    support: partial
    description: Can run in check mode.
    details: O(action=status) behaves exactly like a normal run; O(action=load) and
      O(action=reload) change nothing and report RV(check_mode).
  diff_mode:
    support: none
    description: The module changes no file, so there is no difference to show.
notes:
  - In a container without the capability to control the kernel's audit system, C(auditctl -s)
    fails; the module then reports C(kernel=false) and loads nothing.
  - C(augenrules --load) keeps the previous generated file as C(/etc/audit/audit.rules.prev); the
    remediate role puts that file back as it was.
seealso:
  - module: freesecdev.linux_compliance.control_state
"""

EXAMPLES = r"""
- name: Read the audit status and the rule files
  freesecdev.linux_compliance.audit_control:
    action: status
  register: audit_status

- name: Load the rules of /etc/audit/rules.d and check that the new watch is loaded
  freesecdev.linux_compliance.audit_control:
    action: load
    expect:
      - -w /etc/localtime -p wa -k time-change
"""

RETURN = r"""
check_mode:
  description: Whether the module ran in check mode, in which a load or reload changes nothing.
  returned: success
  type: bool
  sample: false
available:
  description: Whether C(auditctl) was found in the trusted directories.
  returned: success
  type: bool
  sample: true
kernel:
  description: Whether C(auditctl -s) could read the kernel's audit status.
  returned: success
  type: bool
  sample: true
enabled:
  description: The C(enabled) flag of the kernel, C(2) when the loaded rules are locked, or null.
  returned: success
  type: int
  sample: 1
pid:
  description: The process of auditd that the kernel knows, C(0) when none runs, or null.
  returned: success
  type: int
  sample: 726
rules:
  description: The rules that C(auditctl -l) lists, empty when the kernel cannot be read.
  returned: success
  type: list
  elements: str
  sample: ["-w /etc/localtime -p wa -k time-change"]
files:
  description: Every file of C(/etc/audit/rules.d) that C(augenrules) reads, with its rule lines.
  returned: when O(action=status)
  type: list
  elements: dict
  sample: [{"path": "/etc/audit/rules.d/audit.rules", "regular": true, "lines": []}]
duplicates:
  description: Rule lines that two places of C(/etc/audit/rules.d) hold, with the files.
  returned: when O(action=load)
  type: list
  elements: dict
  sample: [{"line": "-w /var/log/lastlog -p wa -k logins", "paths": ["/etc/audit/rules.d/a.rules"]}]
loaded:
  description: Whether the load ran, succeeded and left every line of O(expect) loaded.
  returned: when O(action=load)
  type: bool
  sample: true
ran:
  description: Whether C(augenrules --load) ran, which changes the loaded rules even when it fails.
  returned: when O(action=load)
  type: bool
  sample: true
missing:
  description: The lines of O(expect) that no loaded rule matches, after the load for a load.
  returned: when O(action=status) or O(action=load)
  type: list
  elements: str
  sample: []
reloaded:
  description: Whether auditd was asked to reload and still runs as the same process.
  returned: when O(action=reload)
  type: bool
  sample: true
message:
  description: What the tools printed or why nothing was done, at most 2048 printable characters.
  returned: success
  type: str
  sample: "Error sending add rule data request (Rule exists)"
"""

import re
from typing import Final, cast

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditrules,
    process,
)

TIMEOUT_SECONDS: Final[float] = 30.0
LOAD_TIMEOUT_SECONDS: Final[float] = 300.0
MAX_OUTPUT_BYTES: Final[int] = 1024 * 1024
MAX_MESSAGE: Final[int] = 2048
MAX_EXPECT: Final[int] = 512
UNPRINTABLE: Final[str] = r"[^\x20-\x7e]+"
LOCKED: Final[int] = 2


class ControlError(RuntimeError):
    """The audit tools could not be run safely; nothing was done."""


def printable(text: str) -> str:
    """Return ``text`` with every run of unprintable characters as one space, bounded."""
    return re.sub(UNPRINTABLE, " ", text).strip()[:MAX_MESSAGE]


def _run(executable: str, arguments: tuple[str, ...], timeout: float) -> process.CommandResult:
    spec = process.CommandSpec(executable, arguments, timeout, max_output_bytes=MAX_OUTPUT_BYTES)
    try:
        return process.run(spec)
    except process.ProcessError as error:
        raise ControlError(printable(str(error))) from error


def _text(result: process.CommandResult) -> str:
    return (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")


def available() -> bool:
    """Return whether ``auditctl`` is in a trusted directory; refuse an unsafe one."""
    try:
        process.resolve_executable("auditctl")
    except process.ProcessExecutionError:
        return False
    except process.ProcessPolicyError as error:
        raise ControlError(printable(str(error))) from error
    return True


def kernel_status() -> dict[str, object]:
    """Return the kernel fields of ``auditctl -s`` and the rules of ``auditctl -l``."""
    status = _run("auditctl", ("-s",), TIMEOUT_SECONDS)
    fields = auditrules.parse_status(_text(status))
    if status.timed_out or status.returncode != 0 or "enabled" not in fields:
        return {
            "kernel": False,
            "enabled": None,
            "pid": None,
            "rules": [],
            "message": printable(_text(status)),
        }
    listing = _run("auditctl", ("-l",), TIMEOUT_SECONDS)
    if listing.timed_out or listing.returncode != 0:
        message = f"auditctl -l failed: {printable(_text(listing))}"
        raise ControlError(message)
    return {
        "kernel": True,
        "enabled": fields["enabled"],
        "pid": fields.get("pid"),
        "rules": auditrules.listed_rules(listing.stdout.decode("utf-8", "replace")),
        "message": "",
    }


def unavailable() -> dict[str, object]:
    """Return the result fields when ``auditctl`` is not installed."""
    return {
        "available": False,
        "kernel": False,
        "enabled": None,
        "pid": None,
        "rules": [],
        "message": "auditctl is not installed in a trusted directory",
    }


def status(expect: list[str]) -> dict[str, object]:
    """Return the status fields, the rule files and the lines of ``expect`` not loaded."""
    try:
        files = auditrules.read_rule_files()
    except (auditrules.RulesFileError, OSError) as error:
        raise ControlError(printable(str(error))) from error
    fields = unavailable() if not available() else {"available": True, **kernel_status()}
    missing = auditrules.missing_rules(expect, cast("list[str]", fields["rules"]))
    return {**fields, "files": files, "missing": missing}


def load(expect: list[str], *, check_mode: bool) -> dict[str, object]:
    """Refuse a set with duplicate rules or locked rules, else load it and check ``expect``."""
    try:
        found = auditrules.duplicates(auditrules.read_rule_files())
    except (auditrules.RulesFileError, OSError) as error:
        raise ControlError(printable(str(error))) from error
    if not available():
        return {
            **unavailable(),
            "loaded": False,
            "missing": expect,
            "duplicates": found,
            "ran": False,
        }
    before = kernel_status()
    refusal = (
        "the kernel's audit status cannot be read: " + str(before["message"])
        if not before["kernel"]
        else "the loaded rules are locked (enabled 2); they change at the next boot"
        if before["enabled"] == LOCKED
        else "two places of /etc/audit/rules.d hold the same rule, so auditctl would stop there: "
        + "; ".join(
            f"{item['line']} in {', '.join(cast('list[str]', item['paths']))}" for item in found
        )
        if found
        else "check mode, nothing was loaded"
        if check_mode
        else ""
    )
    if refusal:
        return {
            "available": True,
            **before,
            "loaded": False,
            "missing": auditrules.missing_rules(expect, cast("list[str]", before["rules"])),
            "duplicates": found,
            "ran": False,
            "message": printable(refusal),
        }
    loading = _run("augenrules", ("--load",), LOAD_TIMEOUT_SECONDS)
    after = kernel_status()
    listed = cast("list[str]", after["rules"])
    missing = auditrules.missing_rules(expect, listed)
    loaded = (
        not loading.timed_out and loading.returncode == 0 and bool(after["kernel"]) and not missing
    )
    message = printable(
        ("augenrules --load did not finish in time. " if loading.timed_out else "")
        + ("" if loaded else f"augenrules --load exited with {loading.returncode}. ")
        + (f"Not loaded afterwards: {'; '.join(missing)}. " if missing else "")
        + _text(loading)
    )
    return {
        "available": True,
        **after,
        "loaded": loaded,
        "missing": missing,
        "duplicates": [],
        "ran": True,
        "message": message,
    }


def reload(*, check_mode: bool) -> dict[str, object]:
    """Ask a running auditd to read its configuration again and check that it still runs."""
    if not available():
        return {**unavailable(), "reloaded": False}
    before = kernel_status()
    pid = before["pid"]
    if not before["kernel"] or not isinstance(pid, int) or pid <= 0:
        return {"available": True, **before, "reloaded": False, "message": "auditd is not running"}
    if check_mode:
        return {
            "available": True,
            **before,
            "reloaded": False,
            "message": "check mode, not reloaded",
        }
    signal = _run("auditctl", ("--signal", "reload"), TIMEOUT_SECONDS)
    after = kernel_status()
    reloaded = not signal.timed_out and signal.returncode == 0 and after["pid"] == pid
    return {
        "available": True,
        **after,
        "reloaded": reloaded,
        "message": printable(_text(signal)),
    }


def expected(raw: object) -> list[str]:
    """Return the expected rules, or raise :class:`ValueError` for malformed ones."""
    items = cast("list[object]", raw) if isinstance(raw, list) else []
    if len(items) > MAX_EXPECT:
        message = f"at most {MAX_EXPECT} expected rules are accepted"
        raise ValueError(message)
    lines: list[str] = []
    for item in items:
        if (
            not isinstance(item, str)
            or not item.startswith("-")
            or len(item) > auditrules.MAX_LINE_LENGTH
        ):
            message = "every expected rule must be one line that starts with -"
            raise ValueError(message)
        if re.search(UNPRINTABLE, item):
            message = "an expected rule must be printable text without line breaks"
            raise ValueError(message)
        lines.append(item)
    return lines


def main() -> None:
    """Run the module."""
    module = AnsibleModule(
        argument_spec={
            "action": {"type": "str", "required": True, "choices": ["status", "load", "reload"]},
            "expect": {"type": "list", "elements": "str", "default": []},
        },
        supports_check_mode=True,
    )
    action = module.params["action"]
    try:
        lines = expected(module.params["expect"])
    except ValueError as error:
        module.fail_json(msg=str(error), changed=False)
    try:
        if action == "status":
            outcome = status(lines)
        elif action == "load":
            outcome = load(lines, check_mode=module.check_mode)
        else:
            outcome = reload(check_mode=module.check_mode)
    except ControlError as error:
        module.fail_json(msg=f"the audit tools could not be run safely: {error}", changed=False)
    if action == "status":
        module.exit_json(
            changed=False,
            check_mode=module.check_mode,
            available=outcome["available"],
            kernel=outcome["kernel"],
            enabled=outcome["enabled"],
            pid=outcome["pid"],
            rules=outcome["rules"],
            message=outcome["message"],
            files=outcome["files"],
            missing=outcome["missing"],
        )
    elif action == "load":
        module.exit_json(
            changed=bool(outcome["ran"]),
            check_mode=module.check_mode,
            available=outcome["available"],
            kernel=outcome["kernel"],
            enabled=outcome["enabled"],
            pid=outcome["pid"],
            rules=outcome["rules"],
            message=outcome["message"],
            loaded=outcome["loaded"],
            ran=outcome["ran"],
            missing=outcome["missing"],
            duplicates=outcome["duplicates"],
        )
    module.exit_json(
        changed=bool(outcome["reloaded"]),
        check_mode=module.check_mode,
        available=outcome["available"],
        kernel=outcome["kernel"],
        enabled=outcome["enabled"],
        pid=outcome["pid"],
        rules=outcome["rules"],
        message=outcome["message"],
        reloaded=outcome["reloaded"],
    )


if __name__ == "__main__":
    main()
