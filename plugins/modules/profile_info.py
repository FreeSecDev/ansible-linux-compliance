#!/usr/bin/python

"""List the rules that a profile of a SCAP datastream selects."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: profile_info
short_description: List the rules that a profile of a SCAP datastream selects
version_added: "0.1.0"
description:
  - Reads a SCAP source datastream on the managed host and returns one profile together with the
    rules that it
    selects, each with its severity and title.
  - The rule identifiers are the full XCCDF identifiers. Audit code uses them as the rules that a
    scan must
    report on.
  - The SHA-256 of the file must equal O(expected_sha256), which comes from the pinned content
    manifest.
    On a mismatch the module fails and the content is never parsed.
  - If the datastream does not contain O(profile_id) the module fails. No other profile or benchmark
    is ever
    substituted.
  - The module is read-only and never changes the host. It runs no external program and never uses
    the network.
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
  profile_id:
    description:
      - Full XCCDF profile identifier, for example
        C(xccdf_org.ssgproject.content_profile_cis_level1_server).
      - Short identifiers are not accepted.
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
  - A rule is selected when the last C(select) of the profile names it with C(selected) true, or
    when the profile does not mention it and the rule itself is selected by default.
  - A profile with C(extends), or one that selects a rule inside a deselected group, is rejected
    with
    C(unsupported_content) instead of returning a guessed list.
  - A profile that selects a rule the benchmark does not define is rejected.
  - A datastream with more than one benchmark is rejected, because choosing one would be a guess.
seealso:
  - module: freesecdev.linux_compliance.benchmark_info
"""

EXAMPLES = r"""
- name: List the rules of the Ubuntu 24.04 CIS Level 1 Server profile
  freesecdev.linux_compliance.profile_info:
    content_path: /opt/freesecdev/content/ssg-ubuntu2404-ds.xml
    expected_sha256: e311189ac70ff73be54121311fca324d6188f8c12ab53416090f595ff00e070c
    profile_id: xccdf_org.ssgproject.content_profile_cis_level1_server
  register: profile

- name: Keep the identifiers for the audit
  ansible.builtin.set_fact:
    expected_rule_ids: "{{ profile.rule_ids }}"
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
  sample: e311189ac70ff73be54121311fca324d6188f8c12ab53416090f595ff00e070c
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
profile_id:
  description: Full XCCDF identifier of the profile.
  returned: success
  type: str
  sample: xccdf_org.example.synthetic_profile_baseline
profile_title:
  description: Title of the profile, empty when the content has none.
  returned: success
  type: str
  sample: Synthetic baseline
rule_count:
  description: Number of rules that the profile selects.
  returned: success
  type: int
  sample: 2
rule_ids:
  description: Full XCCDF identifiers of the selected rules, sorted and unique.
  returned: success
  type: list
  elements: str
  sample:
    - xccdf_org.example.synthetic_rule_alpha
    - xccdf_org.example.synthetic_rule_beta
rules:
  description: The selected rules in the same order as C(rule_ids).
  returned: success
  type: list
  elements: dict
  contains:
    rule_id:
      description: Full XCCDF rule identifier.
      type: str
      sample: xccdf_org.example.synthetic_rule_alpha
    severity:
      description: One of C(unknown), C(info), C(low), C(medium) or C(high).
      type: str
      sample: medium
    title:
      description: Rule title, empty when the content has none.
      type: str
      sample: Synthetic alpha rule
    version:
      description:
        - The rule's own XCCDF C(version), empty when it has none. A DISA STIG benchmark records
          the STIG ID of the rule there, which the audit role uses to map the toggles to SCC.
      type: str
      sample: UBTU-24-100010
error_type:
  description:
    - Stable identifier of the failure.
    - One of C(digest_mismatch), C(profile_not_found), C(unsupported_content),
      C(unsafe_content_dir) or C(invalid_content).
  returned: failure
  type: str
  sample: profile_not_found
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
            "profile_id": {"type": "str", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        report = catalog.profile_report(
            str(module.params["content_path"]),
            str(module.params["expected_sha256"]),
            str(module.params["profile_id"]),
        )
    except catalog.CatalogError as error:
        module.fail_json(msg=str(error), error_type=catalog.error_type(error), changed=False)
    module.exit_json(
        changed=False,
        content_path=report["content_path"],
        content_sha256=report["content_sha256"],
        benchmark_id=report["benchmark_id"],
        benchmark_version=report["benchmark_version"],
        profile_id=report["profile_id"],
        profile_title=report["profile_title"],
        rule_count=report["rule_count"],
        rule_ids=report["rule_ids"],
        rules=report["rules"],
    )


if __name__ == "__main__":
    main()
