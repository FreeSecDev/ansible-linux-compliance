# Audit

Scope: the `freesecdev.linux_compliance.compliance_scan` module and the `freesecdev.linux_compliance.audit` role.
Audience: operators, playbook authors and reviewers. Jira: FREES-49, FREES-136 (exceptions), FREES-138 and FREES-139 (content path). Decisions: [ADR 0004](adr/0004-audited-process-execution.md)
(process execution), [ADR 0011](adr/0011-control-toggles-and-cleanup.md) (toggles),
[ADR 0013](adr/0013-normalized-findings-model.md) (findings model) and
[ADR 0015](adr/0015-content-acquisition-and-pinning.md) (content pinning).

An audit evaluates one profile of a pinned SCAP datastream on a managed host and returns normalized findings. It
never changes the configuration of the host. A scan result is evidence about one host at one time; it is not a
certification and never a claim of compliance with CIS, STIG, NIST, PCI DSS, ISO 27001 or NIS2.

## Running an audit

```text
ansible-playbook -i inventory.yml freesecdev.linux_compliance.audit \
  -e linux_compliance_target_hosts=web01 \
  -e linux_compliance_discover_content_path=/opt/freesecdev/content/ssg-ubuntu2404-ds.xml \
  -e linux_compliance_discover_content_sha256=<sha256 from content/manifest.yml>
```

The playbook runs `discover` (verifies the datastream digest and lists the rules of the profile) and then `audit`.
The datastream must already be on the host; see [the discover role](../roles/discover/README.md) for how to fetch the
pinned content.

## What the role does

1. Validates its variables (also through `meta/argument_specs.yml`).
2. When `linux_compliance_exceptions_file` is set, reads and validates the exceptions file once on the controller; an
   invalid file fails the play before any host is scanned ([exceptions in the audit role](#exceptions-in-the-audit-role)).
3. Requires the fact `linux_compliance_discovered` from the `discover` role, for the same profile. The audit scans only
   content whose SHA-256 was verified and never substitutes another profile.
4. Resolves the disabled rules from the control toggles and `linux_compliance_audit_disabled_rules`
   ([disabled rules](#disabled-rules-adr-0011)); invalid toggles fail the host before any scan.
5. Requires gathered facts, which identify the host in the scan run.
6. Runs `compliance_scan` with `become: true` on that task only and `fail_on_incomplete: false`, so the result is
   always registered.
7. Publishes the fact `linux_compliance_audited` (`run_id`, `run_status`, `summary`, `scan_run`, `evidence`,
   `evidence_written`, `disabled_rules`, `planned`) for the evidence and verify roles. `summary` and `scan_run` are
   the raw result and are never changed afterwards.
8. Applies the exceptions file to the scan run of the host and adds the waived result as
   `linux_compliance_audited.exceptions`, next to the raw one.
9. Fails when the scan did not complete.
10. Fails when `linux_compliance_audit_fail_on_noncompliant` is true and the gate counts at least one rule: `fail` and
    `error` of the raw result by default, or `fail` of the waived result plus `error` with
    `linux_compliance_audit_fail_on_noncompliant_after_waivers` ([the gate](#the-failure-gate-and-waivers)). The
    decision is recorded as `linux_compliance_audited.gate`.

The variables are listed in the [role README](../roles/audit/README.md). The `evidence` role collects the evidence
of each run, with the waived evaluation, into a bundle on the controller ([evidence bundles](evidence.md)).

## What the module does

`compliance_scan` is a thin wrapper around `plugins/module_utils/compliance/audit.py`.

1. **Plan**. Validate every argument; resolve the real path of the datastream and vet it and the way to it
   ([content directory rules](#content-directory-rules)) before the file is opened; verify the datastream SHA-256 and
   parse it with the hardened catalog parser; find the profile (a missing profile is `profile_not_found`, never
   replaced); check that the datastream file name fits the provenance label (`[A-Za-z0-9._+-]{1,64}`); check that every
   disabled rule is selected by the profile and that at least one rule stays enabled; inspect the output directory
   without creating anything. Everything the backend would refuse is refused here, before anything is created.
2. **Execute** (outside check mode). Create missing components of the output directory (mode `0700`), create the run
   directory `<output_dir>/<run_id>` (mode `0700`, must not exist), make the private copy of the datastream (below),
   write the tailoring file when rules are disabled, run the backend on the copy, remove the copy, set every scanner
   output file to mode `0600`, and write the normalized scan run to `scan-run.json`.
3. **Preview** (check mode). Run the same scan into a private temporary directory and keep nothing; see below.

### The scanner reads only a private copy

`oscap` runs as root and reads the datastream, so the bytes it reads must be the pinned ones. Hashing the operator's
file before and after the scan does not prove that: a user who can write the file or its directory could swap it while
the scan runs and restore it afterwards. The module therefore never lets the scanner read `content_path`:

1. The run directory (or the check-mode directory) is root-only and `0700`. In it the module creates `content/`
   (`0700`) and copies the datastream to `content/<file name>` (`0600`, same file name, so the provenance label is
   unchanged).
2. The source is opened once as a regular file that is not a symlink and is at most 256 MiB, and the SHA-256 is computed
   over exactly the bytes written to the copy, in one pass. Unless it is the pinned digest the copy is deleted and the
   audit stops with `digest_mismatch` before any scanner runs; a source that cannot be read safely is `invalid_content`.
3. The backend is configured with the run directory as both its content root and its output root, and gets the copy as
   its datastream. The tailoring file is in the same directory and references no file; the copy is the only datastream
   on the `oscap` command line.
4. After the scan (also when it fails) the copy and `content/` are removed, so a run does not keep another 12 to 30 MB.
   The result reports `content`: `source_path`, `sha256` and `size` of what was copied, `private_copy` (the path the
   scanner read) and `copy_removed: true`. The backend still hashes the copy before and after the scan, and a completed
   run whose recorded digest is not the pinned one becomes `failed`.

Only root can change the copy, so a swap of `content_path` after verification cannot change what is scanned; the
regression tests swap the source during the scan and show that the scanner read the pinned bytes. The copy settles
integrity, but not availability: root still opens `content_path` (to verify it in the plan and to copy it), so the
directories above it must not let another user replace the file. The next section has the rules.

### Content directory rules

The audit runs as root and opens the datastream twice: once in the plan to verify and parse it, once to make the
private copy. `xmlsafe.RegularFile` checks with `lstat` that the path is a regular file, then opens it. It cannot use
`O_NOFOLLOW` or `O_NONBLOCK`, because the repository guard allows `os` only as `os.path` in plugins. A user who can
replace the file, or any directory or symlink on the way to it, could therefore swap it between the `lstat` and the
`open`:

- for a FIFO: root's `open` blocks until a writer appears, so the audit hangs (until Ansible's own timeout, if any);
- for a symlink: root copies the link's target, the digest does not match, the copy is deleted and the audit stops with
  `digest_mismatch`.

Neither gives a wrong result or discloses anything, but the hang is a denial of service by any local user. So before the
datastream is opened at all, the plan calls `catalog.vetted_content_path`, which resolves the real path once and vets
everything the resolution used:

- the directory part of `content_path` is resolved like `realpath`, walking from `/` with `lstat`. Every component of
  the resolved chain, from `/` to the directory that holds the datastream, must be a directory that is not a symlink,
  owned by root and not writable by group or others unless its sticky bit is set;
- every symlink that the resolution follows must be owned by root. The directory that holds it is a component of the
  resolved chain, so it obeys the rule above. A symlink that a non-root user owns, or that sits in a directory that a
  non-root user owns or can write, is refused, and so is a chain that resolves through such a directory. More than 40
  symlinks, which every loop reaches, are refused too;
- the final component of `content_path` is not followed: a symlink there is `invalid_content`, as before. A directory
  `content_path` must hold exactly one `*-ds.xml` file and obeys the directory rules;
- the datastream itself must be a regular file owned by root and not writable by group or others.

The audit then verifies, parses and copies the **resolved path**, and reports it as `planned.content_path` and
`content.source_path`; `content_path` as given is never opened. A violation fails with `unsafe_content_dir` before the
file is opened and before anything is created; a missing component or a dangling symlink is `invalid_content`. Nothing
is repaired.

A sticky directory is accepted because no other user can rename or remove a root-owned file or symlink in it; the file
and the link must be root-owned for exactly that reason, because the owner of an entry in a sticky directory can still
replace it. A symlink cannot be changed in place, only replaced, so a root-owned symlink in a root-controlled directory
points where root made it point. A hard link is not a separate object: ownership and mode belong to the inode, so the
owner and mode checks apply whatever name reaches the file, and another name gives no user more write access.

Typical locations such as `/usr/share/xml/scap/ssg/content` (`root:root`, `0755`) or `/opt/freesecdev/content` pass,
also on image-mode RHEL, where `/opt` is a root-owned symlink to `var/opt`, and on hosts where `/opt` or `/var` was
relocated through a root-owned symlink. Content fetched into a user's home directory or a group-writable share does not
pass and must be moved first.

This replaces two earlier rules. FREES-49 accepted every symlink above `content_path`, so a link that a non-root user
could repoint was followed. FREES-134 refused every symlink above `content_path` and said that a symlink could be
pointed anywhere; that holds only for a link that a non-root user owns or whose directory a non-root user controls. It
broke the layouts above without making the audit safer, and its suggested `/opt/freesecdev/content` failed on exactly
those hosts. FREES-139 refuses only what a non-root user could change.

Residual risk:

- The checks use paths, not descriptors, for the same reason as the output directory rules below. A component or a
  followed symlink can only be changed between the check and the `open` by root or by the owner of a vetted directory,
  which is root.
- Root itself, or a compromised root-owned service, can still plant a FIFO or repoint a root-owned symlink. That is
  outside this threat model: such an attacker controls the host and the audit.
- A file on a network or FUSE file system can block in `open` or `read` regardless of its type and permissions, and its
  server can report any owner and mode. Keep the content on a local file system.

### Discover modules

`benchmark_info` and `profile_info` (the `discover` role) read the same `content_path` and run the same check,
`catalog.vetted_content_path`, before they open anything, so they fail with the same `unsafe_content_dir` error and
report the resolved path as `content_path` (FREES-138). The check always applies. The owners it accepts are root and the
user that the module runs as, read from the owner of `/proc/self`; if that cannot be read, only root is accepted.

- Under `become` the module runs as root and the rules are exactly those of the audit.
- Without `become` the module also accepts content that the connecting user owns, for example in that user's home
  directory. Another non-root user still cannot change any part of the way to it, so no other user can make the task
  hang. The user's own files could, but that user can already stop their own task.

The audit playbook runs `discover` without `become` and `audit` with it, so content that passes the audit passes
discovery too.

### Scanner invocation

The scan runs through the backend registry (`backends.default_registry()`). The only backend is OpenSCAP, which runs
`oscap xccdf eval --profile <id> [--tailoring-file <run>/tailoring.xml] --results-arf <run>/scan/results-arf.xml
--results <run>/scan/results.xml <run>/content/<datastream>` through `process.run`: an argument list, `shell=False`, a binary from a
trusted root-owned directory, a minimal environment, a timeout and bounded output. `--remediate` and remote resources
are refused by the process policy.

`backend: scc` selects the SCAP Compliance Checker backend ([ADR 0019](adr/0019-scc-scanner-backend-and-ci-image.md),
amendment of FREES-145). It runs the operator-installed SCC 5.15 from its one fixed path under `/opt/scc` with exactly
one argument form (a per-run options file, a fresh user directory, quiet mode and the debug log) and `TZ=UTC0`, again
through `process.run`. SCC scans only content in its own content database, so `content_path` names the pinned stream
as SCC installed it; the backend checks that those bytes equal the verified private copy before and after the scan.
A run is `completed` only when SCC's debug log confirms that it loaded the per-run options with `downloadExternalFiles`,
`appCheckForUpdates` and `contentCheckForUpdates` at `0` and no configuration profile, and when exactly one session of
this run holds one XCCDF and one ARF results file for the requested benchmark and profile. SCC's exit status is 0 even
on failure and is never taken as completion. Anything else is `failed` with every rule `error`. The backend refuses
`disabled_rules` (FREES-146) and hosts for which no SCC benchmark is pinned, such as Ubuntu 26.04.

### Off-platform scans of Ubuntu 26.04 (FREES-161)

No DISA benchmark for Ubuntu 26.04 exists yet. `allow_off_platform_benchmark: true` is an explicit opt-in that lets
`backend: scc` scan an Ubuntu 26.04 host with the pinned Ubuntu 24.04 STIG benchmark
([ADR 0019](adr/0019-scc-scanner-backend-and-ci-image.md#amendment-2026-10-26-off-platform-opt-in-for-ubuntu-2604-frees-161)).

- **Off by default and exact.** The only allowed pair is the benchmark
  `xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG` on a host whose `distribution_id` is `ubuntu` and whose
  `distribution_version` is `26.04`. Every other combination is refused, with or without the opt-in. Without it a 26.04
  host is refused as before. `backend: openscap` refuses the option.
- **Labelled.** The scan run and every finding carry `off_platform` with `benchmark_platform` and `target_platform`,
  and the scan run has findings model schema 1.1. The results are scan evidence about the host under the 24.04
  benchmark, never compliance with an Ubuntu 26.04 baseline. Reports keep them out of every figure and list them
  separately ([reporting data model](reporting-data-model.md#off-platform-results)).
- **The release is checked.** For `backend: scc` the module reads `/etc/os-release` on the managed host and stops with
  `host_mismatch` unless its `ID` and `VERSION_ID` equal `host.distribution_id` and `host.distribution_version`.
- **The platform test is skipped.** The 24.04 stream's own CPE-OVAL platform test does not match an Ubuntu 26.04
  host. The per-run options of an off-platform scan therefore set SCC's documented `ignoreCPEOVALResults` ("Run all
  content regardless of applicability"). The scan completes only when SCC's debug log shows that setting as `1`, and
  every other scan requires it as `0`. SCC warns that such results may be incomplete or false positives.
- **Real results, checked in CI.** `make scc-integration` scans a pinned Ubuntu 26.04 image. It got real results:
  28 `pass`, 136 `fail`, 13 `notapplicable`, 16 `notchecked` and 1 `error` of 194 rules.
- **Labelled raw copies.** The raw copies are `scan/results.off-platform.xml` and `scan/results-arf.off-platform.xml`.
  The report refuses them as XCCDF or ARF inputs, and a fleet report does not count a host with only an off-platform
  scan as covered. The module's `summary` carries `off_platform`.
- **Mostly not applicable means failed.** As a safety net, a completed off-platform run in which more than 50 % of the
  profile's rules are `notapplicable` becomes `failed` with every rule `error`. SCC's own results stay in the evidence
  directory.

```yaml
- name: Scan an Ubuntu 26.04 host with the Ubuntu 24.04 STIG benchmark, labelled off-platform
  freesecdev.linux_compliance.compliance_scan:
    backend: scc
    allow_off_platform_benchmark: true
    content_path: /opt/scc/Resources/Content/SCAP12_Content/U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.xml
    expected_sha256: eac6f7a6a1e80c52d02c508d939eb09aa09b7fe6eaeb060b8aa21e095719c940
    profile_id: xccdf_mil.disa.stig_profile_MAC-1_Classified
    host:
      hostname: "{{ ansible_facts['hostname'] }}"
      distribution_id: ubuntu
      distribution_version: "26.04"
      architecture: x86_64
    fail_on_incomplete: false
  become: true
  register: off_platform_audit
```

Report such runs through `scan-run.json` or evidence bundles, which carry the marker.

### SCE check scripts run as root

The pinned datastreams embed Script Check Engine (SCE) check scripts: the Ubuntu 24.04 datastream has 81 `sce:script`
components, one per rule that has an SCE check. `oscap` writes them (mode `0700`, opened with `O_NOFOLLOW`) into a new
`mkdtemp` directory `/tmp/oscap.XXXXXX` and runs them as root during the audit, with `PATH=/bin:/sbin:/usr/bin:/usr/local/bin:/usr/sbin` and the `XCCDF_*` result variables as
their environment. They are shell scripts that only read the host, but nothing enforces that: they are trusted only
because the datastream's SHA-256 is pinned and the scanner reads only the verified private copy. They are audit checks,
not remediation, so [ADR 0003](adr/0003-native-module-remediation.md) still holds; `--remediate` stays refused.

Of those 81 rules, 63 also have an OVAL check, listed after the SCE check. OpenSCAP 1.3.9 takes the last check of a
rule whose system it supports, so it evaluates those 63 with OVAL and runs SCE only for the 18 rules that have no other
check; 16 of them are in `cis_level1_server`. The CI job `oscap-integration` asserts that no rule with an OVAL check is
reported with an SCE check.

The pinned `oscap` 1.3.9 has no option to turn SCE off: `oscap xccdf eval --help`, `oscap(8)` and the option table in
`utils/oscap-xccdf.c` have none. SCE is a plugin, `libopenscap_sce.so.25`, which `oscap` loads automatically
(`oscap --version` lists it under "Capabilities added by auto-loaded plugins"). On Ubuntu it ships in the same package
as the library itself (`libopenscap25t64`), so it cannot be uninstalled separately. The undocumented environment
variable `OSCAP_CHECK_ENGINE_PLUGIN_DIR` changes where it is loaded from, but the process helper passes only `PATH`,
`LC_ALL`, `LANG` and optionally `TZ` and `TMPDIR` ([ADR 0004](adr/0004-audited-process-execution.md)), and pointing
root's `dlopen` elsewhere would add a code-loading path, so it is not used. Without SCE, the 63 dual-check rules give the
same results through OVAL and the SCE-only rules become `notchecked`: in `cis_level1_server` that is 16 of 408 rules,
the iptables, ip6tables, nftables and ufw firewall rules and the file-system-wide checks for world-writable files and
for files without a known owner or group. To skip them today, list them in `disabled_rules`: the tailoring file
deselects them, `oscap` does not run their scripts, and they are reported as `disabled`. The threat model records this
as [T-AUDIT-2](security/threat-model.md#t-audit-2-sce-check-scripts-run-as-root).

### Exit status and failures

| Situation | `run_status` | Findings |
|---|---|---|
| Exit `0` and no failed or errored rule | `completed` | as evaluated |
| Exit `2` and at least one failed or errored rule (rule failures are a normal scan result) | `completed` | as evaluated |
| Exit `0` with failures, or `2` without any (the status contradicts the results) | `failed` | all `error` |
| Any other exit status, a signal, a missing or unstartable `oscap` | `failed` | all `error` |
| Timeout (`scan_timeout`, the process group is killed) | `timed_out` | all `error` |
| Missing, oversized, malformed or hostile results, results for another profile or benchmark, unexpected or duplicate rules | `failed` | all `error` |
| The datastream no longer has the pinned digest when it is copied | no run: `digest_mismatch`, nothing scanned | none |
| The backend records another digest for the copy than the pinned one | `failed` | all `error` |
| A rule of the profile has no result (exit `2`) | `completed` | that rule `error` |

A run that is not `completed` has an `error_message`, every rule of the profile (including disabled ones) is `error`,
and the summary shows `pass: 0`. It is never reported as compliant. With the default `fail_on_incomplete: true` the
module fails the task and still returns the full result; the role sets it to `false` and fails after publishing the
fact, so the evidence of a failed scan is never lost.

### `changed` and evidence

An audit never changes the configuration of the host, so `changed` is always `false`, including for the run that
writes evidence. Writing evidence is reported separately: `evidence_written` is `true` when a run directory was
created, and `evidence.files` lists every file with its kind (`scanner_output`, `tailoring`, `scan_run`), SHA-256 and
size. This follows AGENTS.md rule 7 and ADR 0013: a report must be able to distinguish "the host changed" from "the
audit recorded what it saw". A second run with the same inputs is idempotent with respect to the host: it reports
`changed: false` again and writes its evidence into a new run directory; it never overwrites an earlier run.

### Check mode

The scan only reads the host, and operators who run `--check` expect real findings, so check mode runs the same scan
(as the ansible-modules skill requires) but keeps nothing:

1. The plan runs as usual, including the digest, profile, disabled-rule and output directory checks.
2. When the output directory exists and passes the rules below, the scan runs into a new private directory
   `<output_dir>/.check-<run_id>` (mode `0700`, owner and permissions vetted like a run directory, must not exist; a
   run identifier can never start with `.`, so it cannot collide with a real run). The tailoring file and the scanner
   output are written there.
3. The results are parsed and returned in full (`scan_run`, `summary`, `run_status`).
4. In a `finally`, before the module returns, the directory and every file in it are removed, also when the scan failed,
   timed out or the backend refused the request. Symlinks inside it are removed, never followed, and nesting and entry
   counts are bounded. If removal fails, the task fails with `cleanup_failed` and names the directory.

The result has `evidence_written: false`, an empty `evidence.files`, `changed: false` and a `msg` that says no evidence
was kept. Check mode never creates the output directory: when it does not exist, no scan runs, `run_status` is
`not_run`, `scan_run` and `summary` are null, `planned` shows what would run, and `msg` says why. Residual: `oscap`
itself may use temporary files outside the run directory (for example in `/tmp`), which the module does not control.

### Output directory rules

The output directory (default `/var/lib/freesecdev/linux_compliance/evidence`) must be an absolute, normalised path
other than `/`. It is walked from `/` with `lstat` and every component is vetted:

- no component may be a symbolic link (also not a dangling one), and every component must be a directory;
- every ancestor must be owned by root and must not be writable by group or others unless its sticky bit is set;
- the output directory itself must be owned by root and grant no permission to group or others. An existing directory
  with other permissions is an error and is never repaired.

The run directory must not exist (`output_exists`), so a planted directory or symlink is never followed or reused.

Residual risk: the checks use paths, not descriptors, because the repository guard allows only `os.path` in plugins
and the descriptor-based file helper (`fileio.py`) may be imported only by the ledger. A component swapped between the
check and the use can only be swapped by root or by the owner of a vetted ancestor, which is root. `Path.chmod` on
Python 3.9 follows symlinks; every scanner output is checked to be a regular file with `lstat` first, inside a `0700`
root-owned directory that the run created.

## Exceptions in the audit role

Jira: FREES-136. The policy and the file format are in [Exceptions and waivers](exceptions.md). With
`linux_compliance_exceptions_file` set to the absolute path of an exceptions file on the controller, the audit role
applies it to every scanned host. With the default `null` nothing changes: no file is read, no waiver is applied and the
gate counts the raw result as before.

`linux_compliance_exceptions_file` has no role prefix on purpose: the `verify` role uses it with the same meaning
(FREES-54, waived mode), so it is a collection-wide variable like `linux_compliance_target_hosts`. It is the only
unprefixed role variable; `tools/roles/check_role_specs.py` allows exactly the names in its `SHARED_VARIABLES`.

### Reading and validating the file

1. **Once, on the controller, before any scan.** Right after its input checks the role reads the file with
   `lookup('ansible.builtin.file', path, rstrip=false)` and validates it with the
   `freesecdev.linux_compliance.validate_exceptions` filter. Both tasks use `run_once: true` and
   `any_errors_fatal: true`. A `run_once` task runs on the first host of the batch and Ansible copies its facts to every
   host of the batch, so the file is read and validated once and every host applies the same text. `rstrip=false`
   keeps the file byte for byte, so the recorded `source_sha256` is the SHA-256 of the file as stored in Git.
2. **An invalid file fails the play.** The validation task fails on the host that ran it, which is the only host the
   recap counts as `failed`. `any_errors_fatal` then stops the play for every host, including later `serial` batches.
   No host is scanned or evaluated, the plays after it do not run, and the playbook ends with exit status 2. The
   message names the entry or line.
3. **One file per play, also across `serial` batches.** Before reading, a `run_once` check resolves
   `linux_compliance_exceptions_file` for every host in `ansible_play_hosts_all` through `hostvars`. That includes the
   hosts of later batches, and covers inventory, `host_vars`, `group_vars`, facts and extra variables. The check fails
   the play (`any_errors_fatal`) unless all hosts resolve to the same value. Play variables and role parameters are not
   visible through `hostvars`; they are the same for every host unless they are templated per host. Every host also
   checks its own value against the file that was read for its batch. Set the variable in play variables or with `-e`,
   never per host.
4. **The applied text is the validated text.** After applying, each host checks that the SHA-256 of the text it applied
   (`evaluation.source_sha256`) equals the SHA-256 that was validated, and that its own path is the validated path.
   Otherwise the host fails before anything is published.
5. **Only the linear strategy.** The file is read and validated with `run_once`, which the `free` strategy does not
   honour: it runs the task on every host, and one host's facts can overwrite another's in the middle of the play.
   The `free` strategy is therefore not supported when `linux_compliance_exceptions_file` is set. The linear strategy,
   with or without `serial`, is the supported mode. Two checks refuse `free` (FREES-143):
   - Right after the read, a `run_once` task with `delegate_facts: true` records the host that ran it on that host
     only. Under linear this is the first host of the batch. Under `free` every host runs the task itself, and it
     finishes before that host's next task starts, so no timing can hide it. A host that is not the first host of its
     batch and finds its own name there fails.
   - Each host also checks that the shared fact naming the reader names the first host of its batch.

   Both fail with a message naming the free strategy. With two or more hosts in a batch, `free` always fails at least
   one host, so the playbook exits with status 2. Suppose no host failed: the batch stays the same, so a host other
   than the first one has its own name recorded and fails, which is a contradiction.

   Ansible exposes no strategy to tasks. A task cannot read the play's `strategy` keyword, and `ansible_play_batch` and
   `ansible_play_hosts_all` are the same under `linear` and `free`. Only Python plugin code can reach the keyword,
   through `Task.get_play()` in an action plugin, and the repository guard
   ([ADR 0004](adr/0004-audited-process-execution.md)) allows plugins to import only `ansible.module_utils` and this
   collection. Markers or barriers between hosts give no exact signal either: under `free` a host can run all of its
   tasks while the others are idle, or after they failed, and then it sees exactly what it would see under linear.
   So not every host is refused. One host, usually the first of the batch, or the next one after the first failed,
   can finish. That host reads, validates and applies the same file itself, and the check after applying (item 4)
   makes sure that the text it applied has the validated SHA-256. No host can apply a file that was not validated.
6. **Relative paths are refused.** `lookup('ansible.builtin.file')` searches a role's `files/` directory and the
   playbook directory for a relative name, so a relative path could resolve to an unexpected file. The path must be
   absolute.
7. **Framework without profiles.** For every exception whose scope has no `profiles` the role prints a `WARNING:`
   message once per play: `framework` is recorded but does not restrict matching, so the exception applies to every
   profile scanned on the hosts in its scope ([scope](exceptions.md#scope)). The identifiers are also published as
   `linux_compliance_audited.exceptions.framework_without_profiles`.

### Applying the file to each host

After the scan and the publication of the raw result, each host applies the validated text to its own scan run with
`freesecdev.linux_compliance.apply_exceptions`, matching scopes against `inventory_hostname` and the groups that the
`groups` magic variable lists for it (never the host name that the scanned host reports, and never `group_names`,
which an extra variable or an include parameter can replace; FREES-157). The filter takes the controller's clock: a scan start more than five
minutes after the controller time fails **that host** with a clear message, and the other hosts continue. Waivers are
applied only to a completed run:

| `exceptions.status` | When | Waived result |
|---|---|---|
| `not_requested` | `linux_compliance_exceptions_file` is null | none; use the raw result |
| `applied` | the run completed and the file was applied | `exceptions.evaluation.scan_run` and `exceptions.summary` |
| `not_run` | check mode ran no scan (`run_status: not_run`, `scan_run` null) | none; the role prints that waivers were not applied |
| `not_completed` | the run is `failed` or `timed_out` | none; every rule is `error`, which is never waived, and the role then fails as before |

The file is still validated in check mode, so a broken file is found before a real run.

### What the role publishes

The raw result is never changed or discarded. `linux_compliance_audited.scan_run` and `linux_compliance_audited.summary`
are exactly what the scanner reported. The waived result is added next to them:

| Key | Content |
|---|---|
| `exceptions.file` | The path, or null |
| `exceptions.status`, `exceptions.applied`, `exceptions.message` | See the table above; the message is also printed |
| `exceptions.source_sha256` | SHA-256 of the validated file, also when it was not applied (check mode) |
| `exceptions.framework_without_profiles` | `id` and `framework` of the exceptions without `profiles` |
| `exceptions.evaluation` | The evaluation document of `apply_exceptions` ([exceptions](exceptions.md#evaluation-document)); its `scan_run` is the waived scan run, with the exception identifier, reason and expiry on every waived finding |
| `exceptions.summary` | The count per outcome of the waived scan run, in the shape of `summary` (`freesecdev.linux_compliance.scan_summary`) |
| `gate` | Which result the failure gate counted, see below |

When the scan started more than 24 hours before the controller time, the evaluation is flagged with
`scan_lag_exceeded` and the role prints a warning.

### The failure gate and waivers

`linux_compliance_audit_fail_on_noncompliant` fails the play when the gate counts at least one rule. Which result it
counts is an explicit choice:

- **Default: the raw result.** The gate counts `fail` and `error` of `linux_compliance_audited.summary`, before any
  waiver. A waiver never silently passes the gate: a waived failure still fails it, and the message says how many
  failures were waived and how to opt in.
- **Opt-in: the waived result.** With `linux_compliance_audit_fail_on_noncompliant_after_waivers: true` the gate
  counts `fail` of `exceptions.summary`, so failures that an exception in effect covers no longer fail it. Expired or
  not yet effective exceptions leave the finding `fail`, so they still count. Without an exceptions file, or when
  nothing was applied (check mode, incomplete run), the gate falls back to the raw result.
- **`error` always counts**, in both modes, and is taken from the raw summary. An `error` is never waived, so a broken
  check can never pass the gate.

`linux_compliance_audited.gate` records `enabled`, `after_waivers`, `basis` (`raw` or `waived`), `counted` (false for
`not_run`) and the `fail`, `error` and `waived` counts that the gate used.

### Stale exceptions, once for all hosts

An exception is stale when it matched no finding on any evaluated host, which no single host can decide. The
aggregation therefore runs **once, after every host**, in a dedicated final play of `playbooks/audit.yml`:

```yaml
- name: Report exceptions that no audited host needed
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Aggregate the exceptions evaluations of every audited host once
      ansible.builtin.import_role:
        name: freesecdev.linux_compliance.audit
        tasks_from: stale.yml
      vars:
        linux_compliance_audit_stale_hosts: >-
          {{ query('ansible.builtin.inventory_hostnames',
                   linux_compliance_target_hosts | default('linux_compliance')) }}
```

A final play is used rather than a `run_once` task at the end of the role because of Ansible's execution model. With
`serial`, a `run_once` task runs once per batch and sees only the hosts evaluated so far; with the `free` strategy it
runs on every host as soon as that host reaches it. A play after the audit play starts only when every batch of the
audit play is done, so it sees every evaluation. Facts set with `set_fact` survive across plays, so the final play
reads them from `hostvars`. It runs on the controller (`localhost`, no facts, no connection to a managed host).

The `stale` entry point of the role takes the target host names (`linux_compliance_audit_stale_hosts`). The playbook
passes every host that the target pattern matches, independently of `--limit`. The entry point runs
`freesecdev.linux_compliance.stale_exceptions` once over the evaluations of the hosts where the file was applied, and
publishes `linux_compliance_audit_stale_exceptions` on the host that runs it:

| Key | Content |
|---|---|
| `computed` | Whether at least one host was evaluated |
| `complete` | Whether every target host was evaluated |
| `unmatched` | The sorted identifiers that are `unmatched` on every evaluated host, or null when nothing was evaluated |
| `stale` | Equal to `unmatched` when `complete` is true, otherwise null: an exception is called stale only when every target host was evaluated |
| `source_sha256` | The file all evaluations came from; evaluations of different files fail the task |
| `target_hosts`, `audited_hosts`, `evaluated_hosts` | The target hosts, those with an audit result and those with an evaluation |
| `not_evaluated_hosts` | Every target host without an evaluation: limited out with `--limit`, unreachable, failed before the scan, failed by a scan-time skew, or check mode without a scan |

When coverage is complete, the role prints `WARNING: <ids> matched no finding on any of the M target host(s), all of
them evaluated; review and remove them.` When it is partial, it never advises removal. It prints `WARNING: <ids>
unmatched on N of M target hosts; not covered: <hosts>`, followed by the statement that coverage is partial and is no
reason to remove an exception. An exception that a host outside the run still needs is therefore never reported as
removable. One limit follows from Ansible: when every host of the audit play fails (for example all of them fail the
gate), Ansible ends the playbook and the final play does not run.

### Entry points

| Entry point | Use |
|---|---|
| `main` | Validate, scan, publish the raw result, apply the exceptions, enforce the gates |
| `evaluate.yml` | Apply the exceptions file and the gates to an existing `linux_compliance_audited` fact, without scanning; used by the playbook test |
| `stale.yml` | Aggregate stale exceptions over the given target hosts, after the audit play |
| `deferred.yml` | `main` without the result gates; records `linux_compliance_audited.gate` as `{deferred: true, enforced: false}` |
| `evaluate_deferred.yml` | `evaluate.yml` without the result gates, recorded the same way |
| `enforce.yml` | Enforce the gates that `deferred.yml` or `evaluate_deferred.yml` deferred: record the decision with `deferred: true` and `enforced: true`, then fail the host as `main` would |

`main` and `evaluate.yml` always enforce the gates; no variable defers or skips them. Only the choice of the
`deferred.yml` or `evaluate_deferred.yml` entry point defers them, and `enforce.yml` must then run on the same hosts.
`playbooks/evidence.yml` uses the pair so that every audited host is collected before a gate can drop it from the run
([evidence bundles](evidence.md#running-it)). The gate record has `deferred` and `enforced` next to the decision, so
whatever reads the fact can tell a deferred gate that was never enforced.

A custom playbook that deliberately calls `deferred.yml` or `evaluate_deferred.yml` and never runs `enforce.yml`,
or that writes `linux_compliance_audited.gate` with its own `set_fact`, can still end without the gates. That is a
deliberate act by whoever writes the playbook, the same class as the documented residual of the `verify` role's
baseline marker; no variable from the inventory, `group_vars`, `host_vars`, `-e`, a role parameter or an include
parameter can defer a gate. Such a run never produces a bundle: the evidence role refuses an audit result whose
gate is recorded as deferred and not enforced, and the report refuses a manifest without an enforced gate.

The entry points are named with their file suffix (`tasks_from: evaluate.yml`), because the repository guard
(FREES-128) only scans role entry points that end in `.yml` or `.yaml`, and Ansible looks up the argument spec under
the literal `tasks_from` value.

### Verify compares like with like

The `verify` role (FREES-54, [verify guide](verify.md)) compares raw with raw (`scan_run` of the baseline and the
post-remediation audit) by default, or waived with waived (`exceptions.evaluation.scan_run` of both, from the same
exceptions file, `source_sha256` equal), never one with the other. It classifies rules on the evaluated outcome, so a
finding that is `fail` in the baseline and `waived` afterwards is `unchanged`, not an improvement: the rule still
fails, and a waiver never counts as a fix or as a pass. This rule was recorded on FREES-136 for FREES-54.
`playbooks/remediate.yml` runs the audit role twice through `audit.yml`; the role itself is unchanged by FREES-54.
Both `remediate.yml` and `verify.yml` refuse `linux_compliance_audit_fail_on_noncompliant: true` before any host is
audited, because the gate would fail hosts in the second audit before the verify role reports their regressions.

## Disabled rules (ADR 0011)

The `disabled_rules` option of `compliance_scan` lists the rules of the profile that are switched off, each with
`rule_id` (full XCCDF identifier) and an optional `disabled_by` (the controlling variable,
`linux_compliance_<name>_enabled`, default `linux_compliance_rule_<short id>_enabled`). The audit role builds it
before the scan (`tasks/toggles.yml`, FREES-55) from two sources:

1. **The control toggles.** The role loads the rule catalogue and the family registry of the remediate role
   (`roles/remediate/vars/rules.yml`), finds every variable that matches `^linux_compliance_.+_enabled$` and resolves
   each catalogued rule that the discovered profile selects, with or without a native remediation, with the filter
   `freesecdev.linux_compliance.audit_disabled_rules`. That filter and the `remediation_plan` filter of the remediate
   role use the same code (`plugins/module_utils/compliance/toggles.py`): the rule toggle when it is set, else on
   only when the umbrella toggle of the family (if any) and the family toggle are both on. A rule that is off is
   disabled with `disabled_by` set to the umbrella toggle when it is off, else to the family toggle when it is off,
   and to the rule toggle otherwise ([umbrellas](remediation-variables.md#umbrellas)). So `linux_compliance_auditd_enabled: false` in the inventory
   disables every auditd rule of the profile in the audit and in remediation at once, and names that variable in
   both: the catalogue holds every rule of the pinned profiles (FREES-53, [control families](control-families.md)).
   The global remediation opt-in plays no part: the audit honours the toggles whether or not remediation runs. The
   toggles are listed in the [remediation variable reference](remediation-variables.md).
2. **`linux_compliance_audit_disabled_rules`**, for rules that the catalogue does not contain (for example rules of
   user-supplied content or SCE checks, see above). A catalogued rule in that list fails the role before any scan, because the audit would then skip a
   rule that remediation still applies; the message names the toggle to use instead.

The toggles are validated as in the remediate role: an unknown family or rule toggle, a name in the namespace of a
role (for example the likely typo `linux_compliance_audit_enabled` for the auditd topic) and a value that is not a
boolean fail the role before any host is scanned. The audit role carries the same generated topic toggle defaults as
the remediate role (`make toggles` writes them into both); rule toggles are declared in neither role and follow their
family toggle when they are not set (ADR 0011, amendment of FREES-53). Set rule toggles as inventory, play, task or
`include_role` `vars`, or with `-e`, never as role parameters: the role argument validation rejects an undeclared
role parameter. So a value copied into the inventory, such as a
rule toggle set to `"{{ linux_compliance_<family>_enabled }}"` without the family toggle, resolves the same way in
both roles. Only catalogued rules have toggles; for the pinned profiles that is every rule. A topic toggle does not
disable rules of content that the catalogue does not describe; disable those through
`linux_compliance_audit_disabled_rules`. When a topic or umbrella toggle is `false` but no catalogued rule of the
families it governs is selected by the profile, the role prints a `WARNING:` that the toggle excludes nothing, and
the remediate role adds the same warning to its notices; when both roles run in one play, each prints it once. With the full catalogue this
happens only for a family without any rule in the profile, for example `auditd` with the Ubuntu 24.04
`cis_level1_server` profile.

As ADR 0011 requires, disabled rules are excluded from the scan through a generated XCCDF 1.2 tailoring file:

```xml
<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.freesecdev_tailoring_linux_compliance_audit">
  <xccdf:version time="2026-10-25T09:00:00Z">1</xccdf:version>
  <xccdf:Profile id="<profile id>_freesecdev_audit_tailored" extends="<profile id>">
    <xccdf:title>Rules disabled by freesecdev.linux_compliance toggles excluded</xccdf:title>
    <xccdf:select idref="<rule id>" selected="false"/>
  </xccdf:Profile>
</xccdf:Tailoring>
```

Every identifier in it is validated against the XCCDF identifier alphabet, which has no markup characters. The scanner
evaluates the tailored profile, the backend expects results only for the enabled rules (a result for a disabled rule
other than `notselected` fails the run) and records the tailoring file name and SHA-256 in `content.source`. The
reported scan run carries the requested `profile_id`, and each disabled rule is a `disabled` finding with
`disabled_by` set and a message that names the variable. It is never counted as passing and never silently dropped.
In a run that did not complete, disabled rules are `error` findings like every other rule, because the findings model
allows nothing else there; their message still names the variable. A disabled rule that the profile does not select is
an error, and disabling every rule is `nothing_to_scan`.

## Errors

| `error_type` | Meaning |
|---|---|
| `invalid_argument` | A malformed profile, rule, toggle, run identifier, host, timeout or size, or a disabled rule outside the profile |
| `unsafe_content_dir` | The datastream, a directory of its resolved chain or a followed symlink violates the [content directory rules](#content-directory-rules) |
| `unsafe_output_dir` | The output directory violates the rules above, or cannot be created |
| `output_exists` | The run directory already exists |
| `nothing_to_scan` | Every rule of the profile is disabled |
| `unknown_backend` | The backend is not registered |
| `digest_mismatch`, `profile_not_found`, `unsupported_content`, `invalid_content` | Content errors from the catalog, or from making the private copy |
| `invalid_request` | The backend refused the request; outside check mode `evidence_dir` names the run directory, in check mode it is null because the temporary directory is gone |
| `evidence_write_failed` | An evidence file could not be written, or the check-mode scan could not write its files |
| `cleanup_failed` | The private copy or the temporary check-mode directory could not be removed; `evidence_dir` names what is left |
| `scan_incomplete` | The scan did not complete and `fail_on_incomplete` is true; the full result is included |

## Tests

Unit tests (`tests/unit/plugins/module_utils/compliance/test_audit.py`, `tests/unit/plugins/modules/test_compliance_scan.py`)
use a fake process layer and never run `oscap`. They cover exit statuses 0, 1, 2, 137 and a signal, timeouts, a missing
scanner, contradicting results, malformed, hostile (billion laughs, external entity, DOCTYPE), oversized and foreign
results, a source swapped during the scan (the scanner still reads the pinned private copy), a source changed or
replaced by a symlink after verification (refused at copy time), copy write and removal failures, malicious profile, rule, toggle and run identifiers, path traversal,
symlinked output directories and ancestors, planted run directories, open permissions, foreign owners, races during
directory creation, tailoring, check mode (real findings, and nothing left behind on success, scanner failure, timeout,
a missing scanner, malformed results, planted symlinks and nested directories, a backend refusal and a write failure,
and no `evidence_dir` for errors after the temporary directory is gone), skipped non-regular scanner entries, XML
escaping of the tailoring file
and repeated runs. For the content directory rules they cover world- and group-writable content directories (with a
file and a directory as `content_path`), writable ancestors, sticky ancestors and a sticky content directory (accepted),
a content directory, an ancestor and a datastream with a non-root owner, a group- or world-writable datastream, a
symlinked content directory (refused when another user owns the link, scanned from its real path otherwise), an
image-mode `/opt` to `var/opt` layout, a symlink in a writable directory, production (root) ownership, components
that vanish or cannot be inspected, and that a refused datastream is never opened and nothing is created.
`tests/unit/plugins/module_utils/compliance/test_content_path.py` tests the shared check itself: relative, absolute,
chained and `..` link targets, a root-owned image-mode layout checked for root, links that another user owns, links
in writable, foreign and sticky directories, chains that resolve through a writable or foreign directory, loops and
the 40-link bound, dangling links, a final component that is a symlink, unreadable links, a group-writable inode
reached through a hard link, races, and `effective_uid`. The discover module tests cover the same refusals through
`benchmark_info` and `profile_info`. `audit.py`, `catalog.py` and the modules have 100% line and branch coverage.

The toggle resolution is covered by `tests/unit/plugins/module_utils/compliance/test_toggles.py` and
`tests/unit/plugins/filter/test_audit_disabled_rules.py` (a rule toggle, a topic toggle, a rule toggle that overrides
its disabled topic, a disruptive topic, the profile restriction, explicit entries, a catalogued explicit entry, unknown,
reserved and non-boolean toggles, and that the audit and remediation filters return the same disabled rules for the
same toggles, also with explicit rule toggles that follow a disabled family). `test_compliance_scan.py` checks that a rule disabled by
a topic toggle is a `disabled` finding that names that toggle. `tests/playbooks/remediate-check-mode.yml`
(`make test-remediate-check`) runs `tasks/toggles.yml` of the role next to the remediate role in check mode and checks
that both resolve the same disabled rules and controlling variable for a single rule switched off, a whole topic
switched off and a rule switched back on inside a disabled topic, and that the audit fails before any scan on
`linux_compliance_audit_enabled`, on a string toggle and on a catalogued rule in
`linux_compliance_audit_disabled_rules`. Further plays check that a rule toggle copied from its default without the
family toggle resolves the same way in both roles, that both roles warn about a topic toggle that excludes
nothing, and, with every catalogued rule in the profile, that `linux_compliance_auditd_enabled: false` disables every
auditd rule of the catalogue in both roles. The `oscap-integration` job runs `tests/playbooks/audit-toggles-oscap.yml`,
which scans the runner with the Ubuntu 24.04 `cis_level2_server` profile, the auditd topic off and the crontab rule
toggle off, and checks that every auditd rule of the profile and the crontab rule come back `disabled` with the
expected controlling variable and counts. These playbook tests do not run a scan, because the check-mode playbook runs without `oscap` and without
`become`. `tests/unit/roles/test_audit_tasks.py` pins the wiring that they cannot see: the `compliance_scan` task
passes exactly `{{ __linux_compliance_audit_toggles.disabled_rules }}`, `toggles.yml` is imported after the discover
check and before the scan, and it fails closed on errors.

`make test-oscap-integration` also runs `tests/playbooks/audit-toggles-oscap.yml`, which runs the `discover` and
`audit` roles, not only the module, against a root-owned copy of the pinned Ubuntu 24.04 datastream with
`linux_compliance_file_permissions_enabled: false` and `become`. It asserts that the completed scan reports
`file_permissions_crontab` as `disabled` with `disabled_by: linux_compliance_file_permissions_enabled`, that this is the
only disabled rule, and it removes the content copy and the evidence afterwards. Without `/usr/bin/oscap` the play
ends early, unless `FREESECDEV_REQUIRE_OSCAP=1` turns that into a failure, as in CI.

`make test-oscap-integration` (CI job `oscap-integration`) runs a real `oscap`. It fetches the pinned Ubuntu 24.04
datastream through `tools/content/fetch_content.py` (archive SHA-512 and datastream SHA-256 verified) and runs
`tests/system/test_oscap_integration.py` with the production backend and process helper:

- a check-mode scan of `cis_level1_server` without tailoring must complete with exactly the 408 rules recorded in
  `tests/fixtures/catalog/golden-rules.yml`, none of them missing a result, and leave nothing in the output directory;
- a normal scan with three disabled rules (the filesystem-wide checks `file_permissions_unauthorized_world_writable`,
  `file_permissions_ungroupowned` and `no_files_unowned_by_user`) must complete; the raw `results.xml` must report the
  tailored profile and `notselected` for exactly those rules and a result for every other selected rule; the normalized
  findings must show them as `disabled` with their toggle variable; the reported `profile_id` must be the original
  one; and `content.source` must carry the SHA-256 of the tailoring file that the evidence lists;
- the datastream must have 81 SCE scripts and 81 rules with an SCE check, 16 of the profile's rules must have only an
  SCE check, and no rule-result in `results.xml` may report an SCE check for a rule that also has an OVAL check (the
  rules evaluated through SCE are printed).

The tests copy the fetched datastream into a fresh temporary directory (`0755`, file `0644`) and vet it with
`catalog.vetted_content_path`, so the content directory rules hold regardless of how the CI checkout is laid out.

CI installs `openscap-scanner` from the Ubuntu 24.04 archive at the exact version `1.3.9+dfsg-1.1ubuntu2`, checks the
installed version and prints `oscap --version`, and sets `FREESECDEV_REQUIRE_OSCAP=1`, so the tests fail instead of
skipping when `oscap` or the content is missing. Locally they skip only when `/usr/bin/oscap` is absent. The scans run
as the unprivileged runner user (the tests pass the expected owner explicitly), so rules that need root may report
other results than on a managed host; the assertions are about the protocol, not about the host's compliance.

`make test-audit-exceptions` (CI job `test`, part of `make ci`) runs the exceptions path of the role without
`oscap`. It uses the `evaluate` and `stale` entry points against two local inventory hosts (`web01` in group `web`,
`db01` in group `db`, both `ansible_connection: local`) with synthetic scan runs whose start time is the current time,
and exceptions files written at run time with dates relative to today, so the test never ages out. It uses the
per-checkout `ANSIBLE_HOME` ([development guide](development.md#per-checkout-ansible-home)). `tests/playbooks/audit-exceptions.yml` checks that:

- waived findings appear in `exceptions.evaluation.scan_run` with their exception, that `exceptions.summary` counts
  them, and that the recorded SHA-256 is the digest of the file;
- the raw `scan_run` and `summary` are unchanged on every host, and that a host outside every scope has nothing waived;
- the stale aggregation runs once and reports exactly the exception that no host needed, and later lists a host
  without an evaluation as not covered;
- the gate counts the raw result by default, so waived failures still fail it; the opt-in passes when every failure is
  waived; and an `error` fails the gate in both modes;
- a check-mode result without a scan (`not_run`, `scan_run` null) skips the waivers, reports that, and is not counted
  by the gate;
- without an exceptions file nothing changes;
- a scan start one hour ahead of the controller fails only that host.

`tests/playbooks/audit-exceptions-limit.yml` runs with `--limit db01,localhost`. The stale aggregation must list
web01 under `not_evaluated_hosts` and set `complete` false and `stale` null. The Makefile requires the message
`unmatched on 1 of 2 target hosts; not covered: web01` and no `review and remove`. Three further playbooks must fail
with exit status 2:

- `audit-exceptions-invalid.yml`: an invalid file;
- `audit-exceptions-serial.yml`: `serial: 1`, with `host_vars` that give web01 and db01 different valid files. It must
  fail in the first batch with the cross-batch message before any host is evaluated;
- `audit-exceptions-free.yml`: the `free` strategy, which must print the free-strategy message. Which hosts are
  refused depends on timing, so the Makefile runs it `AUDIT_EXCEPTIONS_FREE_RUNS` times (default 10). In every
  second run db01 starts three seconds late, so that web01 can finish; in the other runs both hosts start together and
  are usually both refused. Each host records its outcome in its own file, through a `rescue` that records the
  refusal and then fails the host again. After each run, `audit-exceptions-free-check.yml` requires a record from every
  host. Each record must be either a failure with the free-strategy message and no published exceptions result, or
  `applied` with exactly the validated path, and a `source_sha256` and `evaluation.source_sha256` equal to the
  SHA-256 of the file as stored, which the check takes independently with `ansible.builtin.stat`. At least one host
  must have been refused. The check prints `AUDIT-EXCEPTIONS-FREE-OUTCOME` with the outcome of each host.
  `tests/unit/roles/test_audit_tasks.py` pins the marker task (`run_once`, `delegate_to` and `delegate_facts`) and
  its check, because the playbook test cannot tell which of the two checks refused a host. Before
  FREES-143 the test required a failure that, under `free`, depended on timing alone: merge-group run 40282529324
  finished with exit status 0.

`tests/playbooks/audit-exceptions-invalid.yml` runs without a rescue: the Makefile requires exit status 2, the
validation message, no task that applies exceptions in the output and no output from the play after it, which
shows that an invalid file stops every host of the play before any evaluation. The new filters `validate_exceptions`
and `scan_summary` and the changes to `tools/roles/check_role_specs.py` have unit tests at 100% line and branch
coverage.

Not covered yet: a Molecule scenario on a managed host that asserts that the audit role changes nothing, that check
mode leaves nothing behind and that a second run is idempotent. The Docker Molecule framework (FREES-59, pull request
14) had not merged when this was written, so that scenario is a follow-up for FREES-60. The same holds for a Molecule
step that runs the exceptions path through the main entry point with a real scan; it is still needed under FREES-60.
