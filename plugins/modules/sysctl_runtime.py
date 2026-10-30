#!/usr/bin/python

"""Read and set running kernel parameters below /proc/sys (FREES-107)."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: sysctl_runtime
short_description: Read and set the running value of kernel parameters
version_added: "0.1.0"
description:
  - Reads the running value of kernel parameters from their files below C(/proc/sys) and, for the
    entries of O(set), writes a new value there, as C(sysctl -w) does. No external program runs.
  - The persistent value of a parameter belongs to a file below C(/etc/sysctl.d); this module
    changes only the running kernel. The remediate role uses it to set the value that a native
    sysctl rule requires and to restore the value that its ledger recorded (ADR 0024).
  - A path is used only when it is the parameter's own regular file on the file system of
    C(/proc/sys), reached without a symbolic link. Every value is read back after it is written;
    when the kernel keeps another value, the module writes the value before back and fails.
author:
  - FreeSecDev contributors (@FreeSecDev)
options:
  read:
    description:
      - Parameters whose running value to return, for example C(kernel.dmesg_restrict).
      - One component may be C(*), which stands for every entry that exists there, for example
        C(net.ipv4.conf.*.forwarding) for every interface.
      - As for C(sysctl), a C(/) inside a component stands for a C(.) of the file name.
    type: list
    elements: str
    default: []
  probe:
    description:
      - Parameters to test for writing, without writing to them. A parameter that does not exist,
        or that a read-only C(/proc/sys) refuses, is reported as not writable.
    type: list
    elements: str
    default: []
  set:
    description:
      - Parameters to set, in order. A parameter whose running value already equals the value,
        apart from whitespace between its fields, is left alone.
    type: list
    elements: dict
    default: []
    suboptions:
      name:
        description: The parameter, without C(*).
        type: str
        required: true
      value:
        description: The value, at most 255 printable characters or tabs, without a line break.
        type: str
        required: true
attributes:
  check_mode:
    support: full
    description: Reports which parameters would change and writes nothing.
  diff_mode:
    support: none
    description: The returned C(set) list shows each value before and after.
notes:
  - Needs root with the capabilities that the kernel requires for the parameter; in an
    unprivileged container C(/proc/sys) is read-only and O(probe) reports every parameter as not
    writable.
seealso:
  - module: freesecdev.linux_compliance.control_state
"""

EXAMPLES = r"""
- name: Read two parameters and the forwarding flag of every IPv4 interface
  freesecdev.linux_compliance.sysctl_runtime:
    read:
      - kernel.dmesg_restrict
      - net.ipv4.ip_forward
      - net.ipv4.conf.*.forwarding
  register: running

- name: Set a parameter
  freesecdev.linux_compliance.sysctl_runtime:
    set:
      - name: kernel.dmesg_restrict
        value: "1"
  become: true
"""

RETURN = r"""
running:
  description:
    - The running value of every parameter of O(read), O(probe) and O(set) as it was before this
      run, without the final line break; C(null) for a parameter that does not exist. Wildcards are
      expanded to the parameters that exist.
  returned: success
  type: dict
  sample: {"kernel.dmesg_restrict": "0", "net.ipv4.conf.lo.forwarding": "0"}
writable:
  description: For every parameter of O(probe), whether it could be opened for writing.
  returned: success
  type: dict
  sample: {"kernel.dmesg_restrict": true}
set:
  description: One entry per entry of O(set), in order.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description: The parameter.
      type: str
    before:
      description: The running value before.
      type: str
    after:
      description: The running value after, the value before in check mode or when unchanged.
      type: str
    changed:
      description: Whether the value was (or, in check mode, would be) written.
      type: bool
"""

from typing import TYPE_CHECKING, cast

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sysctl,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

MAX_PARAMETERS = 256
INVALID_NAME = "invalid_name"


class RuntimeChangeError(RuntimeError):
    """A value could not be set; ``changed`` names the values that this run did set."""

    def __init__(self, message: str, changed: list[str]) -> None:
        """Store the message, which names the changed values too, and the changed values."""
        super().__init__(f"{message}; values changed by this run: {', '.join(changed) or 'none'}")
        self.changed = list(changed)


def _names(values: object, label: str, *, wildcard: bool) -> list[str]:
    items = cast("list[object]", values)
    if len(items) > MAX_PARAMETERS:
        message = f"at most {MAX_PARAMETERS} parameters can be named in {label}"
        raise sysctl.SysctlError(INVALID_NAME, message)
    for item in items:
        sysctl.components(item, wildcard=wildcard)
    return [str(item) for item in items]


def settings(values: object) -> list[tuple[str, str]]:
    """Return the validated ``(name, value)`` pairs of ``set``."""
    items = cast("list[dict[str, object]]", values)
    if len(items) > MAX_PARAMETERS:
        message = f"at most {MAX_PARAMETERS} parameters can be set at once"
        raise sysctl.SysctlError(INVALID_NAME, message)
    pairs: list[tuple[str, str]] = []
    for item in items:
        name = item.get("name")
        sysctl.components(name)
        pairs.append((str(name), sysctl.check_value(item.get("value"))))
    return pairs


def _set_one(name: str, value: str, before: str, done: list[str]) -> str:
    try:
        sysctl.write(name, value)
        after = sysctl.read(name)
    except sysctl.SysctlError as error:
        raise RuntimeChangeError(str(error), done) from error
    if after is None or sysctl.normalise(after) != sysctl.normalise(value):
        try:
            sysctl.write(name, before)
        except sysctl.SysctlError as error:
            message = (
                f"the kernel kept {after!r} for {name} after {value!r} was written, and the value"
                f" before, {before!r}, could not be written back: {error}"
            )
            raise RuntimeChangeError(message, [*done, name]) from error
        message = (
            f"the kernel kept {after!r} for {name} after {value!r} was written; the value before,"
            f" {before!r}, was written back"
        )
        raise RuntimeChangeError(message, done)
    return after


def apply(pairs: list[tuple[str, str]], *, check_mode: bool) -> list[dict[str, object]]:
    """Set every pair whose running value differs and return the ``set`` entries.

    Each value is read just before it is compared, because writing one parameter can change
    another: ``net.ipv4.ip_forward`` sets the forwarding flag of every interface, so the flag of
    an interface is restored only after the global value.
    """
    done: list[str] = []
    entries: list[dict[str, object]] = []
    for name, value in pairs:
        try:
            before = sysctl.read(name)
        except sysctl.SysctlError as error:
            raise RuntimeChangeError(str(error), done) from error
        if before is None:
            message = f"{name} does not exist on this kernel"
            raise RuntimeChangeError(message, done)
        changed = sysctl.normalise(before) != sysctl.normalise(value)
        after = before
        if changed and not check_mode:
            after = _set_one(name, value, before, done)
            done.append(name)
        entries.append({"name": name, "before": before, "after": after, "changed": changed})
    return entries


def run(params: Mapping[str, object], *, check_mode: bool) -> dict[str, object]:
    """Return the result fields of the module for ``params``."""
    read = _names(params["read"], "read", wildcard=True)
    probe = _names(params["probe"], "probe", wildcard=False)
    pairs = settings(params["set"])
    values: dict[str, str | None] = {}
    for pattern in read:
        expanded = sysctl.expand(pattern)
        if sysctl.WILDCARD not in pattern.split(".") and not expanded:
            values[pattern] = None
        for name in expanded:
            values[name] = sysctl.read(name)
    for name in [*probe, *(name for name, _ in pairs)]:
        if name not in values:
            values[name] = sysctl.read(name)
    writable = {name: sysctl.writable(name) for name in probe}
    entries = apply(pairs, check_mode=check_mode)
    return {
        "changed": any(bool(entry["changed"]) for entry in entries),
        "running": values,
        "writable": writable,
        "set": entries,
    }


def main() -> None:
    """Run the module."""
    module = AnsibleModule(
        argument_spec={
            "read": {"type": "list", "elements": "str", "default": []},
            "probe": {"type": "list", "elements": "str", "default": []},
            "set": {
                "type": "list",
                "elements": "dict",
                "default": [],
                "options": {
                    "name": {"type": "str", "required": True},
                    "value": {"type": "str", "required": True},
                },
            },
        },
        supports_check_mode=True,
    )
    try:
        outcome = run(module.params, check_mode=module.check_mode)
    except sysctl.SysctlError as error:
        module.fail_json(msg=str(error), reason=error.reason, changed=False)
    except RuntimeChangeError as error:
        module.fail_json(
            msg=str(error),
            reason="not_set",
            changed=bool(error.changed),
            changed_names=error.changed,
        )
    module.exit_json(
        changed=outcome["changed"],
        running=outcome["running"],
        writable=outcome["writable"],
        set=outcome["set"],
    )


if __name__ == "__main__":
    main()
