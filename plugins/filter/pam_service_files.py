"""Filter that sorts the PAM directory entries into the files to read and those that refuse."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pam_files,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

DOCUMENTATION = r"""
---
name: pam_service_files
short_description: Sort the entries of the PAM directories as libpam opens them
version_added: "0.1.0"
description:
  - Takes the entries of C(/etc/pam.d), C(/usr/lib/pam.d) and C(/usr/share/pam.d) that
    C(ansible.builtin.find) lists with C(file_type=any) and C(follow=false), and the
    C(ansible.builtin.stat) with C(follow=true) of every entry that is a symbolic link, and
    returns the paths to read and the entries that the collection cannot read (FREES-213).
  - libpam opens a service file with C(fopen), which follows symbolic links. A regular file, or a
    link that resolves to one, is read under its name in the PAM directory. A directory, or a link
    to one, is left out, because libpam reads no line from it. A link that resolves to nothing, a
    link to anything else, an entry that is neither a regular file, a directory nor a link, and an
    entry that C(find) could not inspect are unreadable; the C(pwquality), C(faillock) and
    C(pwhistory) families refuse their rules on any of them.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, targets, skipped
options:
  _input:
    description: The C(files) of the find, each with C(path), C(isreg), C(isdir) and C(islnk).
    type: list
    elements: dict
    required: true
  targets:
    description: The C(stat) through the link of every entry that is a symbolic link, by path.
    type: dict
    required: true
  skipped:
    description: The C(skipped_paths) of the find.
    type: dict
    default: {}
"""

EXAMPLES = r"""
- name: Sort the PAM entries
  ansible.builtin.set_fact:
    pam_entries: >-
      {{ found.files
         | freesecdev.linux_compliance.pam_service_files(link_stats, found.skipped_paths) }}
"""

RETURN = r"""
_value:
  description: The entries, sorted.
  type: dict
  contains:
    read:
      description: The sorted paths of the files to read.
      type: list
      elements: str
    unreadable:
      description: Every entry that the collection cannot read, with C(path) and C(kind).
      type: list
      elements: dict
"""


def pam_service_files(
    entries: object, targets: object, skipped: object = None
) -> dict[str, list[object]]:
    """Return the outcome of :func:`pam_files.sort_entries`."""
    if not isinstance(entries, (list, tuple)):
        message = "the PAM directory entries must be a list"
        raise pam_files.PamEntryError(message)
    if not isinstance(targets, dict):
        message = "the stats of the links must be a mapping"
        raise pam_files.PamEntryError(message)
    if skipped is not None and not isinstance(skipped, dict):
        message = "the skipped paths must be a mapping"
        raise pam_files.PamEntryError(message)
    return pam_files.sort_entries(
        list(cast("list[object]", entries)),
        cast("Mapping[str, object]", targets),
        list(cast("dict[object, object]", skipped or {})),
    )


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., dict[str, list[object]]]]:
        """Return the filters of this plugin."""
        return {"pam_service_files": pam_service_files}
