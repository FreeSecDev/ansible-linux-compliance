#!/usr/bin/python

"""Validate the effective OpenSSH server configuration with ``sshd -t`` (FREES-109)."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: sshd_validate
short_description: Validate the effective OpenSSH server configuration with sshd -t
version_added: "0.1.0"
description:
  - Runs C(sshd -t -f /etc/ssh/sshd_config) on the managed host, the configuration test mode of the
    OpenSSH server, and reports whether the effective configuration is valid. sshd reads the main
    file, every file that it includes and the host keys, and exits; no daemon is started and nothing
    is written.
  - Each entry of O(settings) is passed as C(-o keyword=value). sshd uses the first value that it
    obtains for most keywords, and command-line options come first, so the test validates the
    configuration exactly as it would be with these settings in a drop-in that sshd reads before
    every other file. The remediate role uses it to validate a change before it writes it, so a
    configuration that sshd would refuse is never installed.
  - The executable is resolved only from the trusted system directories and runs through the audited
    process helper of the collection (ADR 0004), with a fixed argument form, a minimal environment
    and a timeout. The path of the main file cannot be changed.
author:
  - FreeSecDev contributors (@FreeSecDev)
options:
  settings:
    description:
      - Settings to test on top of the configuration on disk.
      - Only the keywords of the native ssh rules of the collection are accepted, and every value
        must be a single word of letters, digits and C(@.,:/_+-) that does not start with C(-).
    type: list
    elements: dict
    default: []
    suboptions:
      keyword:
        description: The sshd keyword, for example C(PermitRootLogin).
        type: str
        required: true
      value:
        description: The value, for example C(no).
        type: str
        required: true
attributes:
  check_mode:
    support: full
    description: The module only reads, so check mode behaves exactly like a normal run.
  diff_mode:
    support: none
    description: The module changes nothing, so there is no difference to show.
notes:
  - sshd refuses the test when it finds no host key or, on Debian and Ubuntu, when its privilege
    separation directory C(/run/sshd) is missing. The module then reports C(valid=false) with the
    message of sshd; it never creates either.
  - Only an sshd that is not found in the trusted directories is reported as C(available=false). An
    sshd that the helper refuses to run (wrong owner, writable by group or others, a symbolic link
    that leaves the trusted directories) or that cannot be started makes the module fail.
seealso:
  - module: freesecdev.linux_compliance.control_state
"""

EXAMPLES = r"""
- name: Validate the configuration with PermitRootLogin set to no before writing a drop-in
  freesecdev.linux_compliance.sshd_validate:
    settings:
      - keyword: PermitRootLogin
        value: "no"
  register: sshd_check

- name: Validate the configuration on disk
  freesecdev.linux_compliance.sshd_validate:
"""

RETURN = r"""
available:
  description: Whether the sshd executable was found in the trusted directories.
  returned: success
  type: bool
  sample: true
valid:
  description: Whether sshd accepted the configuration with the settings.
  returned: success
  type: bool
  sample: true
message:
  description: What sshd printed, at most 2048 printable characters, empty when it printed nothing.
  returned: success
  type: str
  sample: "/etc/ssh/sshd_config.d/99-site.conf: line 1: Bad configuration option: Foo"
arguments:
  description: The C(-o) arguments that were tested, in order.
  returned: success
  type: list
  elements: str
  sample: ["PermitRootLogin=no"]
"""

import re
from typing import Final, cast

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    process,
)

KEYWORDS: Final[frozenset[str]] = frozenset(process.SSHD_KEYWORDS)
VALUE: Final[str] = process.SSHD_VALUE
MAX_SETTINGS: Final[int] = 30
TIMEOUT_SECONDS: Final[float] = 30.0
MAX_OUTPUT_BYTES: Final[int] = 65536
MAX_MESSAGE: Final[int] = 2048
UNPRINTABLE: Final[str] = r"[^\x20-\x7e]+"


class SettingError(ValueError):
    """A setting that the module does not pass to sshd."""


class ValidationError(RuntimeError):
    """sshd could not be run safely; nothing was validated."""


def arguments(settings: object) -> list[str]:
    """Return the ``-o`` values for ``settings``, or raise :class:`SettingError`."""
    if not isinstance(settings, list):
        message = "settings must be a list"
        raise SettingError(message)
    items = cast("list[object]", settings)
    if len(items) > MAX_SETTINGS:
        message = f"at most {MAX_SETTINGS} settings can be tested at once"
        raise SettingError(message)
    found: list[str] = []
    for setting in items:
        if not isinstance(setting, dict):
            message = "every setting must be a mapping with keyword and value"
            raise SettingError(message)
        entry = cast("dict[str, object]", setting)
        keyword = entry.get("keyword")
        value = entry.get("value")
        if not isinstance(keyword, str) or keyword not in KEYWORDS:
            message = f"keyword {keyword!r} is not a keyword of a native ssh rule"
            raise SettingError(message)
        if not isinstance(value, str) or re.fullmatch(VALUE, value) is None:
            message = f"the value of {keyword} must be one word of letters, digits and @.,:/_+-"
            raise SettingError(message)
        found.append(f"{keyword}={value}")
    return found


def printable(text: str) -> str:
    """Return ``text`` with every run of unprintable characters as one space, bounded."""
    return re.sub(UNPRINTABLE, " ", text).strip()[:MAX_MESSAGE]


def validate(options: list[str]) -> dict[str, object]:
    """Run ``sshd -t`` with ``options`` and return the result fields of the module."""
    args: list[str] = ["-t", "-f", process.SSHD_CONFIG_PATH]
    for option in options:
        args.extend(("-o", option))
    spec = process.CommandSpec(
        "sshd", tuple(args), TIMEOUT_SECONDS, max_output_bytes=MAX_OUTPUT_BYTES
    )
    try:
        process.resolve_executable("sshd")
    except process.ProcessExecutionError as error:
        return {"available": False, "valid": False, "message": printable(str(error))}
    except process.ProcessPolicyError as error:
        raise ValidationError(printable(str(error))) from error
    try:
        result = process.run(spec)
    except process.ProcessError as error:
        raise ValidationError(printable(str(error))) from error
    text = printable((result.stderr + b"\n" + result.stdout).decode("utf-8", "replace"))
    if result.timed_out:
        return {
            "available": True,
            "valid": False,
            "message": printable(f"sshd -t did not finish within {TIMEOUT_SECONDS:g} s. {text}"),
        }
    return {"available": True, "valid": result.returncode == 0, "message": text}


def main() -> None:
    """Run the module."""
    module = AnsibleModule(
        argument_spec={
            "settings": {
                "type": "list",
                "elements": "dict",
                "default": [],
                "options": {
                    "keyword": {"type": "str", "required": True, "no_log": False},
                    "value": {"type": "str", "required": True},
                },
            },
        },
        supports_check_mode=True,
    )
    try:
        options = arguments(module.params["settings"])
    except SettingError as error:
        module.fail_json(msg=str(error), changed=False)
    try:
        outcome = validate(options)
    except ValidationError as error:
        module.fail_json(msg=f"sshd could not be run safely: {error}", changed=False)
    module.exit_json(
        changed=False,
        arguments=options,
        available=outcome["available"],
        valid=outcome["valid"],
        message=outcome["message"],
    )


if __name__ == "__main__":
    main()
