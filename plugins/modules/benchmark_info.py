#!/usr/bin/python

"""Describe the benchmark and profiles of a SCAP datastream."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: benchmark_info
short_description: Describe the benchmark and profiles of a SCAP datastream
version_added: "0.1.0"
description:
  - Reads a SCAP source datastream on the managed host and returns the identifier and version of its
    XCCDF benchmark and the profiles that it contains.
  - The SHA-256 of the file must equal O(expected_sha256), which comes from the pinned content
    manifest.
    On a mismatch the module fails and the content is never parsed.
  - The module is read-only and never changes the host. It runs no external program and never uses
    the network.
  - A profile is listed only if the datastream contains it. Nothing is inferred or substituted.
author:
  - FreeSecDev contributors (@FreeSecDev)
options:
  content_path:
    description:
      - Absolute path of the datastream file, or of a directory that holds exactly one C(*-ds.xml)
        file.
      - The final path component must not be a symbolic link. Paths containing C(..) are rejected.
      - Before the datastream is opened, the directory part is resolved to its real path. Every
        directory of the resolved chain must be owned by root or by the user that the module runs
        as and must not be writable by group or others unless its sticky bit is set; every
        symbolic link that is followed must have such an owner too. The datastream must have such
        an owner and must not be writable by group or others. Otherwise the module fails with
        C(unsafe_content_dir), because another user could replace the file, for example with a
        FIFO that blocks the task. Under C(become) the user is root, as in
        M(freesecdev.linux_compliance.compliance_scan).
    type: str
    required: true
  expected_sha256:
    description:
      - Pinned SHA-256 of the datastream file, 64 hexadecimal characters.
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
  - A datastream with more than one benchmark is rejected, because choosing one would be a guess.
  - A profile with C(extends), or one that selects a rule inside a deselected group, makes the
    module fail with
    C(unsupported_content) instead of returning a guessed list.
  - Datastreams larger than 256 MiB, with a DOCTYPE or entity declaration, or that are not UTF-8 are
    refused.
seealso:
  - module: freesecdev.linux_compliance.profile_info
"""

EXAMPLES = r"""
- name: Describe the pinned Ubuntu 24.04 datastream
  freesecdev.linux_compliance.benchmark_info:
    content_path: /opt/freesecdev/content/ssg-ubuntu2404-ds.xml
    expected_sha256: c4da7bea2e285326d692ade7c06c9f87750c0d6bd0e850a74c78220b893cb393
  register: benchmark

- name: Show the profile identifiers
  ansible.builtin.debug:
    msg: "{{ benchmark.profiles | map(attribute='profile_id') | list }}"
"""

RETURN = r"""
content_path:
  description: The real path of the datastream file that was read.
  returned: success
  type: str
  sample: /opt/freesecdev/content/ssg-ubuntu2404-ds.xml
content_sha256:
  description: The verified SHA-256 of the datastream file, in lower case.
  returned: success
  type: str
  sample: c4da7bea2e285326d692ade7c06c9f87750c0d6bd0e850a74c78220b893cb393
benchmark_id:
  description: Full XCCDF benchmark identifier.
  returned: success
  type: str
  sample: xccdf_org.example.synthetic_benchmark_demo
benchmark_version:
  description: Version of the benchmark content.
  returned: success
  type: str
  sample: 1.2.3
benchmark_title:
  description: Title of the benchmark, empty when the content has none.
  returned: success
  type: str
  sample: Synthetic demo benchmark
profiles:
  description: The profiles of the benchmark, in document order.
  returned: success
  type: list
  elements: dict
  contains:
    profile_id:
      description: Full XCCDF profile identifier.
      type: str
      sample: xccdf_org.example.synthetic_profile_baseline
    title:
      description: Profile title, empty when the content has none.
      type: str
      sample: Synthetic baseline
    rule_count:
      description: Number of rules that the profile selects.
      type: int
      sample: 2
error_type:
  description:
    - Stable identifier of the failure.
    - One of C(digest_mismatch), C(unsupported_content), C(unsafe_content_dir),
      C(script_check_content) or C(invalid_content).
    - C(script_check_content) means that the datastream holds a check or an embedded script
      that would make the scanner run a script of the content (such as a Script Check Engine
      check), or an XCCDF fix element (remediation code of the content); fetch the content
      with C(make content), which removes them.
  returned: failure
  type: str
  sample: digest_mismatch
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
)


def main() -> None:
    """Run the module."""
    module = AnsibleModule(
        argument_spec={
            "content_path": {"type": "str", "required": True},
            "expected_sha256": {"type": "str", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        report = catalog.benchmark_report(
            str(module.params["content_path"]), str(module.params["expected_sha256"])
        )
    except catalog.CatalogError as error:
        module.fail_json(msg=str(error), error_type=catalog.error_type(error), changed=False)
    module.exit_json(
        changed=False,
        content_path=report["content_path"],
        content_sha256=report["content_sha256"],
        benchmark_id=report["benchmark_id"],
        benchmark_version=report["benchmark_version"],
        benchmark_title=report["benchmark_title"],
        profiles=report["profiles"],
    )


if __name__ == "__main__":
    main()
