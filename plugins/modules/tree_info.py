#!/usr/bin/python
"""Ansible module that lists every entry below directories with its metadata, without content."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: tree_info
short_description: List every entry below directories with its metadata, without reading content
version_added: "0.1.0"
description:
  - Walks every directory below each of O(paths) without following symbolic links and returns,
    for every entry below it, its path, type, mode, uid, gid, size, inode, mtime and ctime.
  - Used by the Molecule harness of this collection to record C(/usr) for its no-change
    snapshots and whole-instance records (FREES-180, ADR 0031), where it replaces an
    C(ansible.builtin.find) without checksums that took about fifteen seconds per record.
  - Reads no file content. A directory that cannot be listed, or an entry whose metadata cannot be
    read, fails the module, so that no entry is left out without notice.
  - The result is one text, so that the controller does not decode one object per entry.
author:
  - FreeSecDev (@FreeSecDev)
options:
  paths:
    description:
      - Absolute paths of existing directories, which are not symbolic links. The entries below
        each are listed; the directory itself is not.
    type: list
    elements: path
    required: true
attributes:
  check_mode:
    support: full
    description: Only reads metadata, in check mode as otherwise.
  diff_mode:
    support: none
    description: Reports no change, so there is no difference to show.
notes:
  - Entries are listed as C(ansible.builtin.find) lists them with C(recurse), C(hidden) and
    C(file_type=any), that is every entry below each directory, hidden ones too, across mount
    points, without descending into a symbolic link.
seealso:
  - module: ansible.builtin.find
"""

EXAMPLES = r"""
- name: List every entry below /usr with its metadata
  freesecdev.linux_compliance.tree_info:
    paths:
      - /usr
  register: usr_listing
"""

RETURN = r"""
listing:
  description:
    - The fields of every entry, each followed by a NUL character, nine fields per entry in the
      order of RV(fields). A path cannot contain a NUL character, so the text splits without
      ambiguity.
  type: str
  returned: success
  sample: "/usr/bin\x00directory\x000755\x000\x000\x0036864\x00131\x001.7e9\x001.7e9\x00"
fields:
  description: The names of the nine fields of an entry, in order.
  type: list
  elements: str
  returned: success
  sample: [path, kind, mode, uid, gid, size, inode, mtime, ctime]
count:
  description: The number of entries.
  type: int
  returned: success
  sample: 70000
error_type:
  description: C(not_absolute), C(not_a_directory) or C(unreadable).
  type: str
  returned: on failure
  sample: unreadable
path:
  description: The path that the failure is about.
  type: str
  returned: on failure
  sample: /usr/lib/private
"""

import stat
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from ansible.module_utils.basic import AnsibleModule

if TYPE_CHECKING:
    from collections.abc import Iterator

FIELDS: Final[tuple[str, ...]] = (
    "path",
    "kind",
    "mode",
    "uid",
    "gid",
    "size",
    "inode",
    "mtime",
    "ctime",
)
SEPARATOR: Final[str] = "\x00"
NOT_ABSOLUTE: Final[str] = "not_absolute"
NOT_A_DIRECTORY: Final[str] = "not_a_directory"
UNREADABLE: Final[str] = "unreadable"


class TreeError(Exception):
    """Raised when a path cannot be listed."""

    def __init__(self, error_type: str, path: str, message: str) -> None:
        """Keep the stable error type and the path of the failure."""
        super().__init__(message)
        self.error_type = error_type
        self.path = path


def kind(mode: int) -> str:
    """Return the type of an entry as the lifecycle records name it."""
    if stat.S_ISLNK(mode):
        return "link"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


def root(text: str) -> Path:
    """Return ``text`` as a directory to list, or raise ``TreeError``."""
    path = Path(text)
    if not path.is_absolute():
        message = f"{text} is not an absolute path"
        raise TreeError(NOT_ABSOLUTE, text, message)
    try:
        info = path.lstat()
    except OSError as error:
        message = f"{text} cannot be read: {error.strerror}"
        raise TreeError(UNREADABLE, text, message) from error
    if not stat.S_ISDIR(info.st_mode):
        message = f"{text} is not a directory, or is a symbolic link"
        raise TreeError(NOT_A_DIRECTORY, text, message)
    return path


def fields(top: Path) -> Iterator[str]:
    """Yield the fields of every entry below ``top``, without following a symbolic link."""
    pending = [top]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir())
        except OSError as error:
            message = f"{directory} cannot be listed: {error.strerror}"
            raise TreeError(UNREADABLE, str(directory), message) from error
        for child in children:
            try:
                info = child.lstat()
            except OSError as error:
                message = f"{child} cannot be read: {error.strerror}"
                raise TreeError(UNREADABLE, str(child), message) from error
            yield str(child)
            yield kind(info.st_mode)
            yield f"{stat.S_IMODE(info.st_mode):04o}"
            yield str(info.st_uid)
            yield str(info.st_gid)
            yield str(info.st_size)
            yield str(info.st_ino)
            yield str(info.st_mtime)
            yield str(info.st_ctime)
            if stat.S_ISDIR(info.st_mode):
                pending.append(child)


def listing(paths: list[str]) -> tuple[str, int]:
    """Return the listing of every entry below ``paths`` and the number of entries."""
    tops = [root(path) for path in paths]
    values = [value for top in tops for value in fields(top)]
    text = "".join(value + SEPARATOR for value in values)
    return text, len(values) // len(FIELDS)


def main() -> None:
    """Run the module."""
    module = AnsibleModule(
        argument_spec={"paths": {"type": "list", "elements": "path", "required": True}},
        supports_check_mode=True,
    )
    try:
        text, count = listing(cast("list[str]", module.params["paths"]))
    except TreeError as error:
        module.fail_json(msg=str(error), error_type=error.error_type, path=error.path)
    module.exit_json(changed=False, listing=text, fields=list(FIELDS), count=count)


if __name__ == "__main__":
    main()
