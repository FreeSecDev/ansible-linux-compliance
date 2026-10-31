"""Filter that reads every line of an sshd configuration file as sshd reads it (FREES-200)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sshd_config,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: sshd_config_lines
short_description: Read every line of an sshd configuration file as sshd reads it
version_added: "0.2.0"
description:
  - Reads each line split at LF as C(load_server_config) and C(process_server_config_line_depth)
    of OpenSSH 9.6 and 9.9 read it, with C(strdelim) for the keyword. Leading blanks, tabs and CRs
    are dropped, a C(") anywhere in the keyword is removed up to the next C("), one C(=) after
    white space and a C(=) at the start of the line are skipped, the keyword is compared without
    case, and C(DSAAuthentication) is read as C(PubkeyAuthentication) (FREES-200).
  - Returns C(exact=false) when the text holds a NUL byte, which makes sshd join two lines, or a
    byte that is not UTF-8, so that the caller refuses to rewrite it.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input
options:
  _input:
    description: The text of the file.
    type: str
    required: true
"""

EXAMPLES = r"""
- name: Find the lines that set PermitRootLogin
  ansible.builtin.set_fact:
    root_lines: >-
      {{ (text | freesecdev.linux_compliance.sshd_config_lines).lines
         | selectattr('keyword', 'equalto', 'permitrootlogin') | list }}
"""

RETURN = r"""
_value:
  description: C(exact) and one entry per line with C(keyword), C(error), C(arguments) and C(value).
  type: dict
"""


class SshdLinesInputError(ValueError):
    """The filter received something that is not text."""


def sshd_config_lines(text: object) -> dict[str, object]:
    """Return :func:`sshd_config.read_lines` of ``text``."""
    if not isinstance(text, str):
        message = "the text of an sshd configuration file must be a string"
        raise SshdLinesInputError(message)
    return sshd_config.read_lines(text)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object], dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"sshd_config_lines": sshd_config_lines}
