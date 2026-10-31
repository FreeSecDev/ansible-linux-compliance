#!/usr/bin/python

"""Read the modprobe configuration as kmod itself reads it (FREES-190)."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: modprobe_config
short_description: Read the modprobe configuration with kmod's own reader
version_added: "0.1.0"
description:
  - Runs C(modprobe -c) (C(--showconfig)) on the managed host, which parses the configuration with
    kmod's own reader and prints the directives that kmod keeps, normalised as kmod normalises
    them, in the order in which kmod applies them. Backslashes are already resolved, continued
    lines joined, comments dropped, C(-) turned into C(_) in module names, and lines that kmod
    rejects left out. Nothing is loaded, unloaded or run.
  - The module runs C(modprobe -c -d /dev -C <file>) once for every file of O(files), so that every
    C(install) and C(blacklist) directive is known with the file it came from, and C(modprobe -c
    -d /dev) once for the default configuration directories. C(-d /dev) points kmod at a root
    without C(lib/modules), so it dumps no module index after the configuration.
  - kmod also takes directives from the kernel command line (C(modprobe.blacklist=)) in every run,
    and parses the command line after every file, so its blacklist entries come last. The module
    reads them once with C(-C /dev/null), a configuration without files, and removes them from the
    end of every other run, so that each file's directives are its own. The command line never
    adds an install directive.
  - A file that is not C(/dev/null) or a configuration file of a modprobe directory once every
    symbolic link is resolved is not passed to modprobe (kmod echoes the first word of every line
    that it rejects); the result is then not C(consistent).
  - The result is C(consistent) only when every run succeeded and the directives of O(files), in
    that order, are exactly those of the default configuration. A caller that passes the files it
    believes kmod reads therefore learns whether kmod agrees, and refuses to act when it does not.
  - The executable is resolved only from the trusted system directories and runs through the
    audited process helper of the collection (ADR 0004), with a fixed argument form, a minimal
    environment and a timeout.
author:
  - FreeSecDev contributors (@FreeSecDev)
options:
  files:
    description:
      - The configuration files that kmod reads, in the order in which it reads them.
      - Every file must be an absolute, normalised path directly inside C(/etc/modprobe.d),
        C(/run/modprobe.d), C(/usr/local/lib/modprobe.d), C(/usr/lib/modprobe.d) or
        C(/lib/modprobe.d), with a name that ends in C(.conf) or C(.alias) and does not start with
        a dot.
    type: list
    elements: str
    default: []
attributes:
  check_mode:
    support: full
    description: The module only reads, so check mode behaves exactly like a normal run.
  diff_mode:
    support: none
    description: The module changes nothing, so there is no difference to show.
notes:
  - Only a modprobe that is not found in the trusted directories is reported as C(available=false).
    A modprobe that the helper refuses to run (wrong owner, writable by group or others, a symbolic
    link that leaves the trusted directories) or that cannot be started makes the module fail.
seealso:
  - module: freesecdev.linux_compliance.control_state
"""

EXAMPLES = r"""
- name: Read the install and blacklist directives of every file that modprobe reads
  freesecdev.linux_compliance.modprobe_config:
    files:
      - /etc/modprobe.d/blacklist.conf
      - /usr/lib/modprobe.d/systemd.conf
  register: modprobe
"""

RETURN = r"""
available:
  description: Whether the modprobe executable was found in the trusted directories.
  returned: success
  type: bool
  sample: true
consistent:
  description: Whether every run succeeded and the directives of the files, in order, are exactly
    those of the default configuration.
  returned: success
  type: bool
  sample: true
message:
  description: Why the result is not consistent, at most 2048 printable characters, or empty.
  returned: success
  type: str
  sample: ""
files:
  description: The directives of each file, in the order of O(files).
  returned: success
  type: list
  elements: dict
  contains:
    path:
      description: The file.
      type: str
    install:
      description: The install directives, each with the normalised module name or pattern and the
        command.
      type: list
      elements: dict
    blacklist:
      description: The normalised module names that the file blacklists.
      type: list
      elements: str
merged:
  description: The install and blacklist directives of the default configuration, in kmod's order.
  returned: success
  type: dict
"""

import os.path
import re
from pathlib import PurePosixPath
from typing import Final, cast

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    process,
)

DIRECTORIES: Final[frozenset[str]] = process.MODPROBE_CONFIG_DIRECTORIES
NAME: Final[str] = process.MODPROBE_CONFIG_NAME
MAX_FILES: Final[int] = 256
TIMEOUT_SECONDS: Final[float] = 30.0
MAX_OUTPUT_BYTES: Final[int] = 4 * 1024 * 1024
MAX_MESSAGE: Final[int] = 2048
END_OF_CONFIGURATION: Final[str] = "# End of configuration files."
NO_FILES: Final[str] = process.MODPROBE_NO_FILES
INSTALL_WORDS: Final[int] = 3
BLACKLIST_WORDS: Final[int] = 2
UNPRINTABLE: Final[str] = r"[^\x20-\x7e]+"


class FileError(ValueError):
    """A file that the module does not pass to modprobe."""


class ReadError(RuntimeError):
    """modprobe could not be run safely; nothing was read."""


def checked_files(files: object) -> list[str]:
    """Return ``files`` when every one is a configuration file that kmod reads, or raise."""
    if not isinstance(files, list):
        message = "files must be a list"
        raise FileError(message)
    items = cast("list[object]", files)
    if len(items) > MAX_FILES:
        message = f"at most {MAX_FILES} files can be read at once"
        raise FileError(message)
    found: list[str] = []
    for item in items:
        if (
            not isinstance(item, str)
            or os.path.normpath(item) != item
            or str(PurePosixPath(item).parent) not in DIRECTORIES
            or re.fullmatch(NAME, PurePosixPath(item).name) is None
            or re.search(UNPRINTABLE, item) is not None
        ):
            message = f"{repr(item)[:128]} is not a configuration file of a modprobe directory"
            raise FileError(message)
        found.append(item)
    return found


def printable(text: str) -> str:
    """Return ``text`` with every run of unprintable characters as one space, bounded."""
    return re.sub(UNPRINTABLE, " ", text).strip()[:MAX_MESSAGE]


def directives(text: str) -> dict[str, list[object]]:
    """Return the install and blacklist directives that ``modprobe -c`` printed in ``text``."""
    install: list[object] = []
    blacklist: list[object] = []
    for line in text.split("\n"):
        if line.startswith(END_OF_CONFIGURATION):
            break
        words = line.split(" ", 2)
        if words[0] == "install" and len(words) == INSTALL_WORDS:
            install.append({"module": words[1], "command": words[2].strip()})
        elif words[0] == "blacklist" and len(words) >= BLACKLIST_WORDS:
            blacklist.append(words[1])
    return {"install": install, "blacklist": blacklist}


def show(args: tuple[str, ...]) -> tuple[dict[str, list[object]] | None, str]:
    """Run ``modprobe`` with ``args`` and return its directives, or ``None`` and why not."""
    spec = process.CommandSpec("modprobe", args, TIMEOUT_SECONDS, max_output_bytes=MAX_OUTPUT_BYTES)
    try:
        result = process.run(spec)
    except process.ProcessError as error:
        raise ReadError(printable(str(error))) from error
    command = "modprobe " + " ".join(args)
    if result.timed_out:
        return None, f"{command} did not finish within {TIMEOUT_SECONDS:g} s"
    if result.returncode != 0:
        detail = printable(result.stderr.decode("utf-8", "replace"))
        return None, f"{command} exited with {result.returncode}: {detail}"
    if result.stdout_truncated:
        return None, f"{command} printed more than {MAX_OUTPUT_BYTES} bytes"
    return directives(result.stdout.decode("utf-8", "replace")), ""


def without(
    parsed: dict[str, list[object]], baseline: dict[str, list[object]]
) -> dict[str, list[object]] | None:
    """Return ``parsed`` without the directives of ``baseline`` at its end, or ``None``.

    kmod parses the kernel command line after every file, so the command line's directives are
    the last of each list.
    """
    kept: dict[str, list[object]] = {}
    for kind, entries in baseline.items():
        cut = len(parsed[kind]) - len(entries)
        if cut < 0 or parsed[kind][cut:] != entries:
            return None
        kept[kind] = parsed[kind][:cut]
    return kept


def read(files: list[str]) -> dict[str, object]:
    """Read the default configuration and every file, and compare them."""
    try:
        process.resolve_executable("modprobe")
    except process.ProcessExecutionError as error:
        return {
            "available": False,
            "consistent": False,
            "message": printable(str(error)),
            "files": [],
            "merged": {"install": [], "blacklist": []},
        }
    except process.ProcessPolicyError as error:
        raise ReadError(printable(str(error))) from error
    empty: dict[str, list[object]] = {"install": [], "blacklist": []}
    baseline, problem = show((*process.MODPROBE_SHOW_CONFIG, "-C", NO_FILES))
    baseline = baseline if baseline is not None else empty
    shown, why = show(process.MODPROBE_SHOW_CONFIG)
    problem = problem or why
    merged = without(shown, baseline) if shown is not None else None
    if shown is not None and merged is None:
        problem = problem or "the directives of the kernel command line are not at the end"
    found: list[object] = []
    joined: dict[str, list[object]] = {"install": [], "blacklist": []}
    parsed: dict[str, list[object]] | None
    for path in files:
        if not process.is_modprobe_config(path):
            problem = problem or (
                f"{path} is not a configuration file of a modprobe directory once its links are "
                "resolved, so it is not passed to modprobe"
            )
            output, why = None, ""
        else:
            output, why = show((*process.MODPROBE_SHOW_CONFIG, "-C", path))
        parsed = without(output, baseline) if output is not None else None
        if parsed is None:
            problem = problem or why or f"the directives of {path} do not end with the command line"
            parsed = {"install": [], "blacklist": []}
        found.append({"path": path, **parsed})
        joined["install"].extend(parsed["install"])
        joined["blacklist"].extend(parsed["blacklist"])
    if not problem and joined != merged:
        problem = (
            "the directives of the files differ from the configuration that modprobe reads, "
            "so a file that kmod reads is missing from the list, or one that it skips is in it"
        )
    return {
        "available": True,
        "consistent": not problem,
        "message": printable(problem),
        "files": found,
        "merged": merged if merged is not None else empty,
    }


def main() -> None:
    """Run the module."""
    module = AnsibleModule(
        argument_spec={"files": {"type": "list", "elements": "str", "default": []}},
        supports_check_mode=True,
    )
    try:
        files = checked_files(module.params["files"])
    except FileError as error:
        module.fail_json(msg=str(error), changed=False)
    try:
        outcome = read(files)
    except ReadError as error:
        module.fail_json(msg=f"modprobe could not be run safely: {error}", changed=False)
    module.exit_json(
        changed=False,
        available=outcome["available"],
        consistent=outcome["consistent"],
        message=outcome["message"],
        files=outcome["files"],
        merged=outcome["merged"],
    )


if __name__ == "__main__":
    main()
