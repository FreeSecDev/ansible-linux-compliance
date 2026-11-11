"""Filter that decides a pwquality rule as libpwquality and pam_pwquality read the files."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pam_files,
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
  - The PAM files are read with the reader of the C(faillock) and C(pwhistory) families
    (C(pam_reader)), as both line readers of libpam 1.5.1 and 1.5.3 assemble and split them. A PAM
    file with a NUL byte or a line of 1023 bytes or more, a file whose lines that load
    C(pam_pwquality) or include a file the two readers assemble differently, and an include,
    substack or C(@include) of a path in any form that libpam accepts make the rule C(overridden)
    (FREES-212).
  - For the main file method it also returns the new text of the main file, with the setting's line
    replaced in place or appended, and every other byte unchanged.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, dropins, main, pam, modules
options:
  _input:
    description:
      - The rule, with C(setting), C(value) (empty for a flag), C(method) (C(main_file) or
        C(dropin)), C(main) (the path of the main file), C(dropin) (the path of its drop-in),
        C(content) (what it writes into the drop-in) and C(directory).
      - C(directory) is the kind of the drop-in directory, C(directory) (the default), C(missing),
        C(link) or C(other). A link or anything else than a directory makes the rule
        C(not_directory) with both methods, because libpwquality reads through it.
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
    description:
      - Every PAM file, with C(path) and C(content). The role passes every regular file of
        C(/etc/pam.d), C(/usr/lib/pam.d) and C(/usr/share/pam.d), also one that libpam does not
        open because a file of the same name comes first, so that an argument in any of them
        refuses the rule (FREES-211), and every symbolic link there that resolves to a regular
        file, read through the link under its name in the PAM directory (FREES-213). A PAM
        directory that is itself a symbolic link to a directory is read through the link.
      - An entry with C(path) and C(kind) instead of C(content) is one that the collection
        cannot read, as the C(pam_service_files) filter returns it, for example a link that
        resolves to nothing or to something that is neither a regular file nor a directory.
        Any such entry makes the rule C(overridden) before anything else is decided, because
        libpam may open it and a C(pam_pwquality) argument there could override the file
        (FREES-213).
      - So do a link or a PAM directory that resolves below C(/proc), C(/sys) or C(/dev), and
        C(/etc/pam.conf) when libpam reads it instead of the PAM directories, with the C(detail)
        of the entry in the reason (FREES-212).
    type: list
    elements: dict
    required: true
  modules:
    description:
      - Which file the module path of every PAM line loads, with C(directory), the module
        directory that the C(pwquality_pam_modules) filter returns (or C(None)), and C(stats),
        the C(ansible.builtin.stat) with C(follow=true) and the SHA-256 C(checksum) of every path
        that it returns, by path, or a mapping with only the C(msg) of a stat that failed.
      - The arguments of a line count as C(pam_pwquality) arguments when the file name of the
        path that libpam loads for it holds C(pam_pwquality), in any directory (a build of the
        module installed elsewhere, such as C(/usr/local/lib/security/pam_pwquality.so)), or
        when that path is a regular file with the checksum of C(pam_pwquality.so) of the module
        directory, such as a link or a copy under another name (FREES-212). A line whose module
        cannot be told, because the module directory is not known, the path holds C($ISA), a
        path that must be compared was not inspected or could not be read, or
        C(pam_pwquality.so) is missing from the module directory (which may then not be the one
        that libpam loads from), makes the rule C(overridden).
      - Whether libpam runs C(pam_pwquality) at all is not decided. A line of another type than
        C(password), a jump or a C(sufficient) module before it, or a stack without it are not
        looked at; the rule decides the values that C(pam_pwquality) would use.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Decide the minlen rule
  ansible.builtin.set_fact:
    decision: >-
      {{ {'setting': 'minlen', 'value': '14', 'method': 'main_file',
          'main': '/etc/security/pwquality.conf',
          'dropin': '/etc/security/pwquality.conf.d/50-freesecdev-minlen.conf', 'content': ''}
         | freesecdev.linux_compliance.pwquality_decide([], main_text, pam_files, pam_modules) }}
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


def _pam(pam: list[object]) -> tuple[list[tuple[str, str]], list[str]]:
    """Return the PAM files with their text and the description of every unreadable entry."""
    files: list[tuple[str, str]] = []
    unreadable: list[object] = []
    for item in pam:
        if not isinstance(item, Mapping):
            message = "every PAM file must be a mapping"
            raise DecisionInputError(message)
        found = cast("Mapping[str, object]", item)
        if "kind" in found:
            unreadable.append(dict(found))
            continue
        files.append((_text(found.get("path"), "path"), _text(found.get("content"), "content")))
    try:
        return files, pam_files.describe(unreadable)
    except pam_files.PamEntryError as error:
        raise DecisionInputError(str(error)) from error


def _stats(value: object) -> dict[str, Mapping[str, object]]:
    """Return the module stats by path, each a mapping."""
    if not isinstance(value, Mapping):
        message = "the stats of the modules must be a mapping"
        raise DecisionInputError(message)
    stats: dict[str, Mapping[str, object]] = {}
    for path, stat in cast("Mapping[object, object]", value).items():
        if not isinstance(path, str) or not isinstance(stat, Mapping):
            message = "every module stat must be a mapping under its path"
            raise DecisionInputError(message)
        stats[path] = cast("Mapping[str, object]", stat)
    return stats


def _modules(modules: object) -> pwquality.Modules:
    """Return the module directory and stats that the role passes."""
    if not isinstance(modules, Mapping):
        message = "the modules must be a mapping with directory and stats"
        raise DecisionInputError(message)
    fields = cast("Mapping[str, object]", modules)
    directory = fields.get("directory")
    if directory is not None and not (isinstance(directory, str) and directory.endswith("/")):
        message = "the module directory must be None or a path that ends with a slash"
        raise DecisionInputError(message)
    return pwquality.Modules(directory, _stats(fields.get("stats")))


def _dropins(dropins: list[object]) -> list[Mapping[str, object]]:
    """Return the drop-in entries, each a mapping."""
    entries: list[Mapping[str, object]] = []
    for entry in dropins:
        if not isinstance(entry, Mapping):
            message = "every drop-in must be a mapping"
            raise DecisionInputError(message)
        entries.append(cast("Mapping[str, object]", entry))
    return entries


def pwquality_decide(
    rule: object, dropins: object, main: object, pam: object, modules: object
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
    entries = _dropins(cast("list[object]", dropins))
    identities = _modules(modules)
    files, described = _pam(cast("list[object]", pam))
    refused = pwquality.unreadable_refusal(planned, described)
    if refused is not None:
        return refused
    directory = _text(fields.get("directory", pwquality.DIRECTORY), "directory")
    stack = pwquality.PamStack(files, identities)
    return pwquality.decide(planned, entries, main, stack, directory)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"pwquality_decide": pwquality_decide}
