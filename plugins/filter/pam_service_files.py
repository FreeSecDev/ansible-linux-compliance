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
    C(ansible.builtin.stat) with C(follow=true) of every entry that is a symbolic link and of
    every PAM directory, and returns the paths to read and the entries that the collection
    cannot read (FREES-213).
  - libpam opens a service file with C(fopen), which follows symbolic links. A regular file, or a
    link that resolves to one, is read under its name in the PAM directory. A directory, or a link
    to one, is left out, because libpam reads no line from it. A link that resolves to nothing, a
    link to anything else, a link that C(stat) could not follow, an entry that is neither a
    regular file, a directory nor a link, an entry that C(find) could not inspect, and a PAM
    directory that C(stat) could not inspect are unreadable; the C(pwquality), C(faillock) and
    C(pwhistory) families refuse their rules on any of them.
  - A link, or a PAM directory, that resolves to a path below C(/proc), C(/sys) or C(/dev) is
    unreadable too, because such a file can read differently in the process that calls libpam
    (C(/proc/self/environ) is the environment of whichever process opens it). When neither
    C(/etc/pam.d) nor C(/usr/lib/pam.d) is a directory, libpam reads C(/etc/pam.conf) instead,
    which the collection does not read, so C(/etc/pam.conf) is returned as unreadable (FREES-212).
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, targets, skipped, directories, resolved
options:
  _input:
    description: The C(files) of the find, each with C(path), C(isreg), C(isdir) and C(islnk).
    type: list
    elements: dict
    required: true
  targets:
    description:
      - The C(stat) through the link of every entry that is a symbolic link, by path.
      - The stat task runs with C(failed_when=false), because C(ansible.builtin.stat) fails on a
        link that loops or passes through something that is not a directory. Such a result has
        no C(stat); the caller passes a mapping with only its C(msg) for it, and a link whose
        value has no C(exists), or that has no value at all, is unreadable as
        C(unfollowed_link), never read, with the C(msg) as its C(detail).
    type: dict
    required: true
  skipped:
    description:
      - The C(skipped_paths) of the find. It has no default, so that a caller cannot leave the
        entries that C(find) could not inspect out by mistake; pass an empty mapping when there
        are none.
    type: dict
    required: true
  directories:
    description:
      - The C(stat) with C(follow=true) of every PAM directory, by path.
      - The stat task runs with C(failed_when=false), because C(ansible.builtin.stat) fails on a
        directory that is a link loop. The caller passes a mapping with only the C(msg) for a
        result without C(stat); such a directory is unreadable as C(uninspected_directory), with
        the C(msg) as its C(detail), and the families refuse their rules on it. A directory that
        does not exist or is not a directory is left out, as libpam leaves it out. When neither
        C(/etc/pam.d) nor C(/usr/lib/pam.d) is a directory, C(/etc/pam.conf) is unreadable as
        C(pam_conf_fallback).
    type: dict
    required: true
  resolved:
    description:
      - The C(stat) with C(follow=false) of every PAM directory and of every entry that is a
        symbolic link, by path, whose C(lnk_source) is the path that a link resolves to.
      - A PAM directory or a link to a regular file that resolves below C(/proc), C(/sys) or
        C(/dev) is unreadable as C(virtual_file), with that path as its C(detail); nothing below
        such a directory is read. A PAM directory or a link to a regular file that has no value
        here, or whose stat failed (a mapping with only its C(msg)), is unreadable too, as
        C(uninspected_directory) or C(unfollowed_link). It has no default, so that a caller
        cannot leave the resolution out by mistake.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Sort the PAM entries
  ansible.builtin.set_fact:
    pam_entries: >-
      {{ found.files
         | freesecdev.linux_compliance.pam_service_files(link_stats, found.skipped_paths,
                                                         directory_stats, resolutions) }}
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
      description: Every entry that the collection cannot read, sorted by path.
      type: list
      elements: dict
      contains:
        path:
          description: The path of the entry in the PAM directory.
          type: str
        kind:
          description:
            - Why the collection cannot read it. C(broken_link) is a symbolic link that resolves
              to nothing. C(link) is a link to something that is neither a regular file nor a
              directory, such as a FIFO or a device. C(unfollowed_link) is a link that C(stat)
              could not follow, such as a loop or a path through something that is not a
              directory. C(special) is an entry that is neither a regular file, a directory nor a
              link. C(unlisted) is an entry, or a PAM directory, that C(find) could not inspect.
              C(uninspected_directory) is a PAM directory that C(stat) could not inspect, such as
              a link loop. C(virtual_file) is a link or a PAM directory that resolves below
              C(/proc), C(/sys) or C(/dev). C(pam_conf_fallback) is C(/etc/pam.conf), which libpam
              reads when neither C(/etc/pam.d) nor C(/usr/lib/pam.d) is a directory.
          type: str
          choices: [broken_link, link, pam_conf_fallback, special, unfollowed_link,
                    uninspected_directory, unlisted, virtual_file]
        detail:
          description:
            - The error message of the failed C(stat) of an C(unfollowed_link) or an
              C(uninspected_directory), or the path below C(/proc), C(/sys) or C(/dev) of a
              C(virtual_file). Absent when there is none.
          type: str
"""


def pam_service_files(
    entries: object, targets: object, skipped: object, directories: object, resolved: object
) -> dict[str, list[object]]:
    """Return the outcome of :func:`pam_files.sort_entries`."""
    if not isinstance(entries, (list, tuple)):
        message = "the PAM directory entries must be a list"
        raise pam_files.PamEntryError(message)
    if not isinstance(targets, dict):
        message = "the stats of the links must be a mapping"
        raise pam_files.PamEntryError(message)
    if not isinstance(skipped, dict):
        message = "the skipped paths must be a mapping"
        raise pam_files.PamEntryError(message)
    if not isinstance(directories, dict):
        message = "the stats of the PAM directories must be a mapping"
        raise pam_files.PamEntryError(message)
    if not isinstance(resolved, dict):
        message = "the resolutions of the PAM directories and links must be a mapping"
        raise pam_files.PamEntryError(message)
    return pam_files.sort_entries(
        list(cast("list[object]", entries)),
        cast("Mapping[str, object]", targets),
        list(cast("dict[object, object]", skipped)),
        cast("Mapping[str, object]", directories),
        cast("Mapping[str, object]", resolved),
    )


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., dict[str, list[object]]]]:
        """Return the filters of this plugin."""
        return {"pam_service_files": pam_service_files}
