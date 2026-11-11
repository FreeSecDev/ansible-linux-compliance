"""Filter that lists the module paths that libpam loads for the PAM lines of the pwquality rules."""

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
name: pwquality_pam_modules
short_description: List the module paths that libpam loads for the PAM lines of the pwquality family
version_added: "0.2.0"
description:
  - Returns the directory that libpam loads a module of a relative path from on the platform,
    and every path that a line of the PAM files makes libpam load, with C(pam_pwquality.so) of
    that directory, so that the role can inspect each path with C(ansible.builtin.stat) and its
    SHA-256 checksum.
  - The C(pwquality_decide) filter then counts the arguments of a line as C(pam_pwquality)
    arguments when the file name of the path that libpam loads for it holds C(pam_pwquality),
    in any directory, or when that path is a regular file with the checksum of
    C(pam_pwquality.so) of the module directory, such as a link or a copy of the module under
    another name (FREES-212). When C(pam_pwquality.so) is missing from the module directory, any
    other module path refuses the rule.
  - libpam takes a module path that starts with a slash as it is and puts its module directory in
    front of any other. The directory is C(/usr/lib64/security/) on the C(RedHat) family and
    C(/usr/lib/<multiarch>/security/) on the C(Debian) family, for C(x86_64) and C(aarch64).
    On any other platform it is C(None), no path is returned, and C(pwquality_decide) refuses
    every rule, because the collection cannot tell which module a line loads.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, os_family, architecture
options:
  _input:
    description:
      - The PAM files as the role passes them to C(pwquality_decide), each with C(path) and
        C(content); an entry with C(kind) instead of C(content) is skipped.
    type: list
    elements: dict
    required: true
  os_family:
    description: The C(ansible_os_family) fact of the host, for example C(RedHat) or C(Debian).
    type: str
    required: true
  architecture:
    description: The C(ansible_architecture) fact of the host, for example C(x86_64).
    type: str
    required: true
"""

EXAMPLES = r"""
- name: List the module paths to inspect
  ansible.builtin.set_fact:
    modules: >-
      {{ pam_files | freesecdev.linux_compliance.pwquality_pam_modules('RedHat', 'x86_64') }}
"""

RETURN = r"""
_value:
  description: The module directory and the paths to inspect.
  type: dict
  contains:
    directory:
      description: The directory that libpam loads a relative module path from, or C(None).
      type: str
    paths:
      description:
        - The sorted paths that the PAM lines make libpam load, with C(pam_pwquality.so) of the
          module directory. A path that holds C($ISA) is left out, because the decision refuses
          it.
      type: list
      elements: str
"""


class ModulePathsInputError(ValueError):
    """The filter received input of the wrong shape."""


def pwquality_pam_modules(
    pam: object, os_family: object, architecture: object
) -> dict[str, object]:
    """Return the module directory and :func:`pwquality.module_paths` of the PAM files."""
    if not isinstance(pam, (list, tuple)):
        message = "the PAM files must be a list"
        raise ModulePathsInputError(message)
    if not isinstance(os_family, str) or not isinstance(architecture, str):
        message = "the OS family and the architecture must be strings"
        raise ModulePathsInputError(message)
    files: list[tuple[str, str]] = []
    for item in cast("list[object]", pam):
        if not isinstance(item, Mapping):
            message = "every PAM file must be a mapping"
            raise ModulePathsInputError(message)
        found = cast("Mapping[str, object]", item)
        if "kind" in found:
            continue
        path, content = found.get("path"), found.get("content")
        if not isinstance(path, str) or not isinstance(content, str):
            message = "every PAM file needs a text path and content"
            raise ModulePathsInputError(message)
        files.append((path, content))
    directory = pwquality.module_directory(os_family, architecture)
    return {"directory": directory, "paths": pwquality.module_paths(files, directory)}


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"pwquality_pam_modules": pwquality_pam_modules}
