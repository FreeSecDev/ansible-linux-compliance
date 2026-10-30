# 0025. Remediation is our own Ansible only; scanner remediation content is never used

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** lead architect; project owner (requirement of 2026-10-30: remediation is written in Ansible by this
  project, and the code of the scanner content is not trusted)
- **Jira:** FREES-188
- **Pull requests:** introduced by the pull request for FREES-188
- **Related:** [ADR 0003](0003-native-module-remediation.md) (made stricter here),
  [ADR 0004](0004-audited-process-execution.md), [ADR 0011](0011-control-toggles-and-cleanup.md),
  [ADR 0015](0015-content-acquisition-and-pinning.md), [ADR 0021](0021-native-banners-pwquality-and-profile-values.md)
  and [ADR 0022](0022-native-sudo-drop-ins.md) (both amended here), [native remediation guide](../native-remediation-guide.md)

## Context

The collection audits with OpenSCAP and the ComplianceAsCode (SSG) datastreams. The same release archive and the
same datastreams also carry the project's remediation: generated Ansible playbooks, Bash scripts, kickstart and
blueprint snippets, and `fix` elements inside every rule of the datastream. ADR 0003 already rules out running
upstream playbooks and `oscap --remediate`, and the process helper refuses the remediation words and the
`generate fix` sequence (ADR 0004). One path still read upstream remediation: since FREES-175 the catalogue generator
could take a profile value from the values that a rule's `fix` elements substitute (`profile_value_source: fix`),
which `sudo_require_reauthentication` used for `var_sudo_timestamp_timeout`. Its check accepts any non-negative
timeout and so does not export the value.

The owner's requirement is that every remediation is written in Ansible by this project and that the scanner
content's code is not trusted. A value read out of a fix is a decision taken by that code. Nothing checked that no
other path would come to rely on it.

## Decision

1. **Remediation is native Ansible only.** Every remediation is a task file of `roles/remediate` that uses only
   `ansible.builtin` modules and this collection's typed modules (ADR 0003). The collection never executes,
   imports, generates, copies or parses remediation content of ComplianceAsCode or OpenSCAP: no generated playbook,
   Bash fix, kickstart or blueprint snippet, no `fix` element of a datastream, no `oscap xccdf eval --remediate`,
   `oscap xccdf remediate`, `oscap xccdf generate fix` or `--fix-type`, and no script that the scanner or its content
   provides.
2. **The OVAL is for auditing and reference only.** The pinned datastreams are evaluated by the scanner to audit a
   host. The OVAL definitions are also read in golden tests (`tests/unit/tools/test_content_golden_native.py`) as the
   reference that pins what our own remediation writes, so that the audit agrees with it. They are never turned into
   remediation.
3. **Values come from the profile's XCCDF values through our own pinned mappings.** `make catalogue` resolves a
   rule's value from the selected profile's `refine-value` and the `Value`'s default and selector options, and from
   nothing else. The mapping from a rule to its `Value` is ours, in `content/catalogue.yml`:
   - `profile_value: <short id>` when the rule's checks export the value (`check-export`), which the generator
     verifies;
   - `profile_value_id: <full XCCDF Value id>` when the check accepts a range and exports nothing, as for
     `sudo_require_reauthentication` and `xccdf_org.ssgproject.content_value_var_sudo_timestamp_timeout`. A golden
     test pins that the identifier exists in every pinned datastream and the value of every profile that selects the
     rule (15 for the CIS profiles, 0 for the STIG profiles, 5 for CCN and PCI DSS), so a content update that changes
     either fails before it reaches a host.

   `profile_value_source` is removed. The generator refuses the key, and `tools/roles/profile_values.py` no longer
   reads `fix` elements at all.
4. **Without a native implementation a rule is scan-only.** Its catalogue strategy is `audit_only`; the audit
   evaluates it, and remediation reports it as `not_implemented` with `changed: false` (ADR 0011). It is never
   remediated by another tool.
5. **A repository guard enforces the decision.** The rule group `tools/lint/repo_rules/own_remediation.py` runs in
   `make lint-repo`, and so in `make lint` and `make ci`, on every tracked file. It refuses:
   - Python under `tools/` or `plugins/` that names the XCCDF `fix` element in any form (a constant, an f-string, a
     namespace or prefix, a path, markup, a `local-name()` test or a fix system URN);
   - any file that is ComplianceAsCode or OpenSCAP remediation content: the release archive's file names (`ssg-*`,
     `*-playbook-*.yml`, `*-script-*.sh`, `*-ks.cfg`), paths below `scap-security-guide*`, generated Bash fixes and
     playbook headers, XCCDF `fix` elements and fix systems, the OpenSCAP kickstart add-on, and task lists tagged like
     the generated playbooks. The collection ships only tracked files, so none of these can reach the tarball;
   - in tasks, playbooks, makefiles, workflows, scripts, container files and Python outside `tests/unit/`: the
     scanner's remediation options and sub-commands, also as consecutive items of an argument list, and running a
     script or playbook from the fetched content, the release archive, the SCC installation or the distribution's
     SSG directories.

   The guard pins three exceptions exactly, with their number per file: `fixtext` in
   `tools/reporting/stig_content.py`, which the STIG checklist export only displays to the reader (ADR 0020); the
   forbidden words and the `generate fix` sequence in `plugins/module_utils/compliance/process.py`, which exist to
   refuse them; and the `fix` object of a Grype vulnerability in `tools/reporting/parsers/grype.py`, which is not
   XCCDF. Any other occurrence, or a change in the number of a pinned one, fails.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Keep `profile_value_source: fix` and audit the fix text by hand | Still parses upstream remediation code and trusts what it substitutes |
| Hard-code `timestamp_timeout` per profile in the task file | The value would no longer follow the profile's XCCDF value, against ADR 0021 |
| Choose one timeout for every profile | Changes the current behaviour (STIG requires 0, CIS 15) and invents a value |
| Leave `sudo_require_reauthentication` `audit_only` | Loses a working native remediation; the value is available from the profile without the fix |
| Rely on review and the process helper only | Nothing would stop a future reader of `fix` elements or a committed upstream playbook |

## Benefits

- No code path reads, runs or ships ComplianceAsCode or OpenSCAP remediation. The guard fails closed on the first
  attempt, so this no longer depends on review alone.
- The generated catalogue is unchanged: every profile keeps the value it had (CIS 15, STIG 0, CCN and PCI DSS 5).
- The pinned mapping is visible in our own catalogue and checked against the content on every content update.

## Trade-offs

- A rule whose check exports nothing needs a reviewed `profile_value_id` and a golden test, instead of a value taken
  automatically from the content.
- The guard works on text and syntax. It does not stop a deliberately obfuscated reader, such as a name assembled at
  run time. Review and ADR 0004's process policy remain the other layers.

## Security implications

Upstream remediation content runs as root by design. Not reading it removes a path by which a change to the pinned
content could decide what the collection writes to a host. The audit still trusts the pinned datastream as a whole,
including the SCE check scripts that `oscap` runs while it audits (threat model T-AUDIT-2). Those are checks, the
guard does not stop them, and an operator can deselect the rules that use them. A change to the rule group or to
its pinned exceptions changes the repository guard and needs a security review.

## Operational consequences

- `make catalogue` fails for an entry that sets `profile_value_source`, and for a `profile_value_id` that a pinned
  datastream does not define.
- `make lint-repo` fails on any of the patterns above. A new exception needs a change to `PINNED_EXCEPTIONS` with a
  security review.
- The documentation says this plainly: [README](../../README.md), [remediation guide](../remediation.md) and
  [native remediation guide](../native-remediation-guide.md).
