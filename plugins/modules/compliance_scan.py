#!/usr/bin/python

"""Audit a managed host against a pinned SCAP profile without changing it."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: compliance_scan
short_description: Audit a host against a pinned SCAP profile without changing it
version_added: "0.1.0"
description:
  - Evaluates one profile of a SCAP source datastream on the managed host and returns normalized
    findings (the C(scan_run) document of ADR 0013), the provenance of the scan and the paths of the
    evidence files.
  - The datastream must have the SHA-256 O(expected_sha256) from the pinned content manifest. It is
    verified before it is parsed. A profile that the datastream does not contain is an error and is
    never replaced by another one.
  - The scanner never reads O(content_path). The module copies the datastream into the private,
    root-only run directory (file mode C(0600)), computes the SHA-256 over exactly the bytes it
    writes and stops with C(digest_mismatch) unless they are the pinned content. The scanner reads
    only that copy, so a file swapped at O(content_path) after verification cannot change what is
    scanned. The copy is removed after the scan; its source path and SHA-256 are returned in
    RV(content).
  - The only backend is C(openscap). It runs C(oscap xccdf eval) through the audited process helper
    of the collection, with an argument list, no shell, a minimal environment, a timeout and
    validated arguments. It never remediates and never fetches remote resources.
  - The module never changes the configuration of the host and always returns C(changed=false).
    Outside check mode it writes evidence files below O(output_dir), which is reported separately in
    RV(evidence_written) and RV(evidence) and is not a change to the host.
  - A scanner that times out, crashes, exits with an unexpected status or writes results that are
    malformed, oversized or inconsistent produces a run whose RV(run_status) is C(failed) or
    C(timed_out) and in which every rule of the profile is an C(error) finding. Such a run is never
    reported as compliant.
  - Rules that operator toggles disable (ADR 0011) are excluded from the scan through a generated
    XCCDF tailoring file and reported as C(disabled) findings that name the controlling variable.
author:
  - FreeSecDev contributors (@FreeSecDev)
options:
  backend:
    description:
      - Scanner backend.
    type: str
    default: openscap
    choices:
      - openscap
  content_path:
    description:
      - Absolute path of the datastream file, or of a directory that holds exactly one C(*-ds.xml)
        file.
      - It is read only to verify it and to make the private copy that is scanned.
      - Paths containing C(..) are rejected and the file itself must not be a symbolic link.
      - The file name must match C([A-Za-z0-9._+-]{1,64}), because it labels the provenance.
    type: str
    required: true
  expected_sha256:
    description:
      - Pinned SHA-256 of the datastream file, 64 hexadecimal characters, from the content manifest.
    type: str
    required: true
  profile_id:
    description:
      - Full XCCDF profile identifier, for example
        C(xccdf_org.ssgproject.content_profile_cis_level1_server).
    type: str
    required: true
  host:
    description:
      - Identity of the scanned host, recorded in the scan run. Usually filled from gathered facts.
    type: dict
    required: true
    suboptions:
      hostname:
        description:
          - Host name, letters, digits and C(._:+-), at most 253 characters.
        type: str
        required: true
      distribution_id:
        description:
          - Lower-case distribution identifier, for example C(ubuntu) or C(redhat).
        type: str
        required: true
      distribution_version:
        description:
          - Distribution version, for example C(24.04).
        type: str
        required: true
      architecture:
        description:
          - Lower-case machine architecture, for example C(x86_64).
        type: str
        required: true
      machine_id:
        description:
          - Optional 32-character lower-case hexadecimal machine identifier.
        type: str
  output_dir:
    description:
      - Absolute, normalised directory below which each run gets its own directory C(<run_id>).
      - Missing components are created with mode C(0700). The directory must be owned by root and
        grant no permissions to group or others; an existing directory with other permissions is
        an error and is never repaired.
      - No component may be a symbolic link, and every ancestor must be owned by root and must not
        be writable by group or others unless its sticky bit is set.
    type: str
    default: /var/lib/freesecdev/linux_compliance/evidence
  run_id:
    description:
      - Identifier of the run and name of its directory.
      - It must match C([A-Za-z0-9][A-Za-z0-9._-]{0,63}).
      - Defaults to the UTC time with microseconds, for example C(20261025T100000.123456Z).
      - The run directory must not exist; evidence is never overwritten.
    type: str
  scan_timeout:
    description:
      - Wall-clock limit of the scan in seconds, above 0 and at most 3600.
      - When it expires the scanner process group is killed and the run is C(timed_out).
    type: float
    default: 1800
  max_result_bytes:
    description:
      - Largest XCCDF results document that is parsed, in bytes, at most 1 GiB.
      - A larger document makes the run C(failed).
    type: int
    default: 134217728
  disabled_rules:
    description:
      - Rules of the profile that operator toggles disable (ADR 0011).
      - Every rule must be selected by the profile, and at least one rule must stay enabled.
      - The per-rule and per-family toggle variables are generated from the rule catalogue
        (FREES-55); until then the caller lists the disabled rules here.
    type: list
    elements: dict
    default: []
    suboptions:
      rule_id:
        description:
          - Full XCCDF rule identifier.
        type: str
        required: true
      disabled_by:
        description:
          - Name of the controlling toggle variable, C(linux_compliance_<name>_enabled).
          - Defaults to C(linux_compliance_rule_<short id>_enabled), where the short identifier is
            the part of O(disabled_rules[].rule_id) after C(_rule_).
        type: str
  fail_on_incomplete:
    description:
      - Fail the task when the scan did not complete (RV(run_status) C(failed) or C(timed_out)).
      - The result, including the evidence, is returned either way.
      - Set it to V(false) to register the result and decide later, as the audit role does.
    type: bool
    default: true
attributes:
  check_mode:
    support: full
    description:
      - Check mode runs the same read-only scan and returns the real findings, but keeps no
        evidence. The scan runs in a private temporary directory C(<output_dir>/.check-<run_id>)
        (mode C(0700)), which is removed with every file in it before the module returns, also
        when the scan fails or times out. RV(evidence_written) is false and RV(evidence) is empty.
      - Check mode never creates O(output_dir). When it does not exist, no scan runs,
        RV(run_status) is C(not_run) and RV(msg) says why.
  diff_mode:
    support: none
    description: The module never changes the host, so there is no difference to show.
notes:
  - The module needs root, usually through C(become), because the output directory must be owned by
    root and the scanner reads system state.
  - Outside check mode each run writes C(<output_dir>/<run_id>/scan/results.xml) and
    C(results-arf.xml) (scanner output), C(<output_dir>/<run_id>/scan-run.json) (the normalized
    scan run) and, when rules are disabled, C(<output_dir>/<run_id>/tailoring.xml). Directories
    have mode C(0700), files C(0600).
  - Exit status 2 of C(oscap) means that rules failed; it is a completed scan. Any other non-zero
    status, a signal or a timeout is a scanner failure.
  - A scan result is evidence about one host, not a certification and not a claim of compliance
    with any framework.
seealso:
  - module: freesecdev.linux_compliance.profile_info
  - module: freesecdev.linux_compliance.benchmark_info
"""

EXAMPLES = r"""
- name: Audit the host against the Ubuntu 24.04 CIS Level 1 Server profile
  freesecdev.linux_compliance.compliance_scan:
    content_path: /opt/freesecdev/content/ssg-ubuntu2404-ds.xml
    expected_sha256: e311189ac70ff73be54121311fca324d6188f8c12ab53416090f595ff00e070c
    profile_id: xccdf_org.ssgproject.content_profile_cis_level1_server
    host:
      hostname: "{{ ansible_facts['hostname'] }}"
      distribution_id: "{{ ansible_facts['distribution'] | lower }}"
      distribution_version: "{{ ansible_facts['distribution_version'] }}"
      architecture: "{{ ansible_facts['architecture'] }}"
  become: true
  register: audit

- name: Audit with one rule disabled and decide about failures later
  freesecdev.linux_compliance.compliance_scan:
    content_path: /opt/freesecdev/content
    expected_sha256: e311189ac70ff73be54121311fca324d6188f8c12ab53416090f595ff00e070c
    profile_id: xccdf_org.ssgproject.content_profile_cis_level1_server
    host:
      hostname: web01
      distribution_id: ubuntu
      distribution_version: "24.04"
      architecture: x86_64
    scan_timeout: 3600
    disabled_rules:
      - rule_id: xccdf_org.ssgproject.content_rule_package_aide_installed
    fail_on_incomplete: false
  become: true
  register: audit

- name: Stop unless the scan completed
  ansible.builtin.assert:
    that:
      - audit.run_status == 'completed'
"""

RETURN = r"""
msg:
  description: Short summary of what ran and where the evidence is, or why no scan ran.
  returned: always
  type: str
  sample: scan finished with run_status completed; evidence in /var/lib/freesecdev/evidence/run-1
changed:
  description: Always false. Writing evidence is not a change to the host; see RV(evidence_written).
  returned: always
  type: bool
  sample: false
evidence_written:
  description: Whether evidence files were kept. Always false in check mode.
  returned: always
  type: bool
  sample: true
run_id:
  description: Identifier of the run and name of its directory.
  returned: success
  type: str
  sample: 20261025T100000.123456Z
run_status:
  description:
    - C(completed), C(failed) or C(timed_out) after a scan, also in check mode.
    - C(not_run) in check mode when O(output_dir) does not exist.
    - Only a C(completed) run says anything about the rules; read it before any count.
  returned: success
  type: str
  sample: completed
summary:
  description:
    - Number of findings per outcome, the total and the run status. Null when no scan ran.
    - It never states compliance. A run that did not complete has only C(error) findings.
  returned: success
  type: dict
  sample:
    run_status: completed
    pass: 1
    fail: 1
    notapplicable: 0
    notchecked: 0
    error: 0
    waived: 0
    disabled: 1
    total: 3
scan_run:
  description:
    - The normalized scan run (findings model schema 1.0, ADR 0013), with its provenance
      (C(scanner), C(content) with the verified SHA-256 and the tailoring digest, C(host), times).
    - Findings are sorted by rule identifier. Null when no scan ran.
  returned: success
  type: dict
  sample:
    schema_version: "1.0"
    run_id: 20261025T100000.123456Z
    status: completed
    error_message: null
    benchmark_id: xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04
    profile_id: xccdf_org.ssgproject.content_profile_cis_level1_server
    scanner:
      name: openscap
      version: 1.3.10
    content:
      source: ssg-ubuntu2404-ds.xml
      content_version: 0.1.82
      content_sha256: e311189ac70ff73be54121311fca324d6188f8c12ab53416090f595ff00e070c
    findings:
      - rule_id: xccdf_org.ssgproject.content_rule_package_aide_installed
        outcome: fail
        evaluated_outcome: fail
        severity: medium
        message: null
        evidence: []
        exception:
          state: none
          exception_id: null
          reason: null
          expires_at: null
        remediation: null
        disabled_by: null
        flags: []
evidence:
  description: The run directory and the evidence files written in it.
  returned: success
  type: dict
  contains:
    directory:
      description: The run directory, null in check mode.
      type: str
      sample: /var/lib/freesecdev/linux_compliance/evidence/20261025T100000.123456Z
    skipped:
      description:
        - Entries that the scanner wrote that are not regular files, with their C(path) and
          C(type) (C(symlink), C(directory), C(fifo), C(socket) or C(other)). They are not changed
          and not recorded as evidence. Empty in check mode.
      type: list
      elements: dict
    files:
      description: The evidence files, sorted by path. Empty in check mode.
      type: list
      elements: dict
      contains:
        path:
          description: Absolute path of the file.
          type: str
        kind:
          description: C(scanner_output), C(tailoring) or C(scan_run).
          type: str
        sha256:
          description: SHA-256 of the file when it was recorded.
          type: str
        size:
          description: Size in bytes.
          type: int
content:
  description:
    - The datastream that was scanned. Null when no scan ran.
    - C(source_path) and C(sha256) identify the verified file on the host; C(private_copy) is the
      copy in the run directory that the scanner read, and C(copy_removed) is always true because
      the copy is deleted after the scan so that evidence does not hold the datastream again.
  returned: success
  type: dict
  sample:
    source_path: /opt/freesecdev/content/ssg-ubuntu2404-ds.xml
    sha256: e311189ac70ff73be54121311fca324d6188f8c12ab53416090f595ff00e070c
    size: 12645122
    private_copy: /var/lib/freesecdev/evidence/run-1/content/ssg-ubuntu2404-ds.xml
    copy_removed: true
disabled_rules:
  description: The disabled rules with their controlling variables, sorted by rule identifier.
  returned: success
  type: list
  elements: dict
  sample:
    - rule_id: xccdf_org.ssgproject.content_rule_package_aide_installed
      disabled_by: linux_compliance_rule_package_aide_installed_enabled
planned:
  description:
    - What the scan does; C(run_dir) is where a run outside check mode keeps its evidence.
  returned: success
  type: dict
  sample:
    backend: openscap
    benchmark_id: xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04
    benchmark_version: 0.1.82
    content_path: /opt/freesecdev/content/ssg-ubuntu2404-ds.xml
    content_sha256: e311189ac70ff73be54121311fca324d6188f8c12ab53416090f595ff00e070c
    profile_id: xccdf_org.ssgproject.content_profile_cis_level1_server
    evaluated_profile_id: xccdf_org.example.content_profile_demo_freesecdev_audit_tailored
    rule_count: 200
    expected_rule_count: 199
    disabled_rule_count: 1
    output_dir: /var/lib/freesecdev/linux_compliance/evidence
    output_root_exists: true
    run_dir: /var/lib/freesecdev/linux_compliance/evidence/20261025T100000.123456Z
    run_id: 20261025T100000.123456Z
    scan_timeout: 1800.0
    tailoring: true
error_type:
  description:
    - Stable identifier of the failure.
    - C(invalid_argument), C(unsafe_output_dir), C(output_exists), C(nothing_to_scan),
      C(unknown_backend), C(invalid_request), C(evidence_write_failed), C(cleanup_failed),
      C(scan_incomplete),
      C(digest_mismatch), C(profile_not_found), C(unsupported_content) or C(invalid_content).
  returned: failure
  type: str
  sample: digest_mismatch
"""

from datetime import datetime, timezone

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
)

SCAN_INCOMPLETE = "scan_incomplete"


def argument_spec() -> dict[str, object]:
    """Return the argument specification of the module."""
    return {
        "backend": {"type": "str", "default": audit.DEFAULT_BACKEND, "choices": ["openscap"]},
        "content_path": {"type": "str", "required": True},
        "expected_sha256": {"type": "str", "required": True},
        "profile_id": {"type": "str", "required": True},
        "host": {
            "type": "dict",
            "required": True,
            "options": {
                "hostname": {"type": "str", "required": True},
                "distribution_id": {"type": "str", "required": True},
                "distribution_version": {"type": "str", "required": True},
                "architecture": {"type": "str", "required": True},
                "machine_id": {"type": "str"},
            },
        },
        "output_dir": {"type": "str", "default": audit.DEFAULT_OUTPUT_ROOT},
        "run_id": {"type": "str"},
        "scan_timeout": {"type": "float", "default": 1800},
        "max_result_bytes": {"type": "int", "default": 134217728},
        "disabled_rules": {
            "type": "list",
            "elements": "dict",
            "default": [],
            "options": {
                "rule_id": {"type": "str", "required": True},
                "disabled_by": {"type": "str"},
            },
        },
        "fail_on_incomplete": {"type": "bool", "default": True},
    }


def main() -> None:
    """Run the module."""
    module = AnsibleModule(argument_spec=argument_spec(), supports_check_mode=True)
    auditor = audit.Auditor()
    try:
        job = audit.build_job(module.params, datetime.now(timezone.utc))
        result = auditor.run(job, check_mode=module.check_mode)
    except audit.AuditError as error:
        module.fail_json(
            msg=str(error),
            error_type=error.error_type,
            changed=False,
            evidence_written=error.evidence_dir is not None,
            evidence_dir=error.evidence_dir,
        )
    status = result["run_status"]
    incomplete = status not in {"completed", audit.RUN_STATUS_NOT_RUN}
    if incomplete and module.params["fail_on_incomplete"]:
        module.fail_json(
            msg=f"the scan did not complete: run_status is {status}",
            error_type=SCAN_INCOMPLETE,
            changed=False,
            evidence_written=result["evidence_written"],
            evidence=result["evidence"],
            content=result["content"],
            disabled_rules=result["disabled_rules"],
            planned=result["planned"],
            run_id=result["run_id"],
            run_status=status,
            scan_run=result["scan_run"],
            summary=result["summary"],
        )
    module.exit_json(
        msg=result["msg"],
        changed=False,
        evidence_written=result["evidence_written"],
        evidence=result["evidence"],
        content=result["content"],
        disabled_rules=result["disabled_rules"],
        planned=result["planned"],
        run_id=result["run_id"],
        run_status=status,
        scan_run=result["scan_run"],
        summary=result["summary"],
    )


if __name__ == "__main__":
    main()
