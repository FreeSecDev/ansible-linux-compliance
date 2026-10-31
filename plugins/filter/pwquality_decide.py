"""Filter that decides a pwquality rule as libpwquality and pam_pwquality read the files."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pwquality,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: pwquality_decide
short_description: Decide a pwquality rule as libpwquality and pam_pwquality read the files
version_added: "0.2.0"
description:
  - Reads C(/etc/security/pwquality.conf) and the entries of C(/etc/security/pwquality.conf.d)
    exactly as C(pwquality_read_config) of libpwquality 1.4 reads them, and the arguments of
    C(pam_pwquality) in every PAM file, and decides whether the rule is C(compliant), can be
    C(applied), or must be refused with a reason (C(overridden), C(duplicate_setting),
    C(unreadable_file), C(unreadable_value)).
  - A rule is C(compliant) or C(applied) only when the library, reading the files as they are or as
    they will be, takes the profile's value from the line or the drop-in that the rule writes, and
    no C(pam_pwquality) argument sets the setting to another value (FREES-200).
  - For the main file method it also returns the new text of the main file, with the setting's line
    replaced in place or appended, and every other byte unchanged.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, dropins, main, pam, directory
options:
  _input:
    description:
      - The rule, with C(setting), C(value) (empty for a flag), C(method) (C(main_file) or
        C(dropin)), C(main) (the path of the main file), C(dropin) (the path of its drop-in) and
        C(content) (what it writes into the drop-in).
    type: dict
    required: true
  dropins:
    description:
      - Every entry of the drop-in directory, with C(path), C(type) (C(file), C(directory), C(link)
        or C(other)) and, for a regular file, its C(content) as text.
    type: list
    elements: dict
    required: true
  main:
    description: The text of the main file, or C(None) when it does not exist.
    type: str
    required: true
  pam:
    description: Every PAM file, with C(path) and C(content).
    type: list
    elements: dict
    required: true
  directory:
    description:
      - The kind of the drop-in directory, C(directory), C(missing), C(link) or C(other). A link or
        anything else than a directory makes the rule C(not_directory) with both methods, because
        libpwquality reads through it.
    type: str
    default: directory
"""

EXAMPLES = r"""
- name: Decide the minlen rule
  ansible.builtin.set_fact:
    decision: >-
      {{ {'setting': 'minlen', 'value': '14', 'method': 'main_file',
          'main': '/etc/security/pwquality.conf',
          'dropin': '/etc/security/pwquality.conf.d/50-freesecdev-minlen.conf', 'content': ''}
         | freesecdev.linux_compliance.pwquality_decide([], main_text, pam_files) }}
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
      description: Why the rule is refused, or C(None).
      type: str
    note:
      description: A remark on a rule that is applied or compliant, for example C(local_users_only).
      type: str
    line:
      description: The line that the rule writes.
      type: str
    found:
      description: The line of the main file that sets the setting now, or C(None).
      type: str
    text:
      description: The new text of the main file when the main file method applies the rule.
      type: str
"""


class DecisionInputError(ValueError):
    """The filter received input of the wrong shape."""


def _text(value: object, what: str) -> str:
    if not isinstance(value, str):
        message = f"{what} must be a string"
        raise DecisionInputError(message)
    return value


def pwquality_decide(
    rule: object, dropins: object, main: object, pam: object, directory: object = "directory"
) -> dict[str, object]:
    """Return the decision of :func:`pwquality.decide` for the rule and the files."""
    if not isinstance(rule, Mapping) or not isinstance(dropins, (list, tuple)):
        message = "the rule must be a mapping and the drop-ins a list"
        raise DecisionInputError(message)
    if not isinstance(pam, (list, tuple)) or (main is not None and not isinstance(main, str)):
        message = "the PAM files must be a list and the main file a text or None"
        raise DecisionInputError(message)
    fields = cast("Mapping[str, object]", rule)
    planned = pwquality.Rule(
        setting=_text(fields.get("setting"), "setting"),
        value=_text(fields.get("value"), "value"),
        method=_text(fields.get("method"), "method"),
        main=_text(fields.get("main"), "main"),
        dropin=_text(fields.get("dropin"), "dropin"),
        content=_text(fields.get("content"), "content"),
    )
    entries: list[Mapping[str, object]] = []
    for entry in cast("list[object]", dropins):
        if not isinstance(entry, Mapping):
            message = "every drop-in must be a mapping"
            raise DecisionInputError(message)
        entries.append(cast("Mapping[str, object]", entry))
    files: list[tuple[str, str]] = []
    for item in cast("list[object]", pam):
        if not isinstance(item, Mapping):
            message = "every PAM file must be a mapping"
            raise DecisionInputError(message)
        found = cast("Mapping[str, object]", item)
        files.append((_text(found.get("path"), "path"), _text(found.get("content"), "content")))
    return pwquality.decide(planned, entries, main, files, _text(directory, "directory"))


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"pwquality_decide": pwquality_decide}
