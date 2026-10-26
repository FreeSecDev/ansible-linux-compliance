# Audit

Scope: the `freesecdev.linux_compliance.compliance_scan` module and the `freesecdev.linux_compliance.audit` role.
Audience: operators, playbook authors and reviewers. Jira: FREES-49. Decisions: [ADR 0004](adr/0004-audited-process-execution.md)
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
2. Requires the fact `linux_compliance_discovered` from the `discover` role, for the same profile. The audit scans only
   content whose SHA-256 was verified and never substitutes another profile.
3. Requires gathered facts, which identify the host in the scan run.
4. Runs `compliance_scan` with `become: true` on that task only and `fail_on_incomplete: false`, so the result is
   always registered.
5. Publishes the fact `linux_compliance_audited` (`run_id`, `run_status`, `summary`, `scan_run`, `evidence`,
   `evidence_written`, `disabled_rules`, `planned`) for the evidence and verify roles.
6. Fails when the scan did not complete.
7. Fails when `linux_compliance_audit_fail_on_noncompliant` is true and at least one rule is `fail` or `error`.

The variables are listed in the [role README](../roles/audit/README.md).

## What the module does

`compliance_scan` is a thin wrapper around `plugins/module_utils/compliance/audit.py`.

1. **Plan**. Validate every argument; resolve the content path; vet the datastream and every directory above it
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
private copy. `xmlsafe.open_regular` checks with `lstat` that the path is a regular file, then opens it. It cannot use
`O_NOFOLLOW` or `O_NONBLOCK`, because the repository guard allows `os` only as `os.path` in plugins. A user who can write
the directory that holds the datastream could therefore swap the file between the `lstat` and the `open`:

- for a FIFO: root's `open` blocks until a writer appears, so the audit hangs (until Ansible's own timeout, if any);
- for a symlink: root copies the link's target, the digest does not match, the copy is deleted and the audit stops with
  `digest_mismatch`.

Neither gives a wrong result or discloses anything, but the hang is a denial of service by any local user. So before the
datastream is opened at all, the plan (`audit.inspect_content_path`) resolves it (a directory `content_path` resolves to
its single `*-ds.xml` file) and walks the directory that holds it from `/` with `lstat`, applying the rules for the
ancestors of the output directory:

- no component may be a symbolic link (also not a dangling one), and every component must be a directory;
- every directory, including the one that holds the datastream, must be owned by root and must not be writable by group
  or others unless its sticky bit is set;
- the datastream itself must be a regular file that is not a symlink, owned by root and not writable by group or others.

A violation fails with `unsafe_content_dir` before the file is opened and before anything is created. Nothing is
repaired. A sticky directory is accepted because no other user can rename or remove a root-owned file in it; the file
must be root-owned for exactly that reason, because the owner of a file in a sticky directory can still replace it.
Typical locations such as `/usr/share/xml/scap/ssg/content` (`root:root`, `0755`) or `/opt/freesecdev/content` pass;
content fetched into a user's home directory or a group-writable share does not and must be moved first.

This replaces the FREES-49 rule that accepted symlinks in the directories above `content_path` because they no longer
mattered for integrity. They matter for the hang: a symlink in a directory that another user controls can be pointed
anywhere, so they are refused like in the output directory.

Residual risk:

- The checks use paths, not descriptors, for the same reason as the output directory rules below. A component can only
  be changed between the check and the `open` by root or by the owner of a vetted directory, which is root.
- Root itself, or a compromised root-owned service, can still plant a FIFO. That is outside this threat model: such an
  attacker controls the host and the audit.
- A file on a network or FUSE file system can block in `open` or `read` regardless of its type and permissions, and its
  server can report any owner and mode. Keep the content on a local file system.
- The `discover` modules (`benchmark_info`, `profile_info`) read the same path and do not vet the directories. They run
  as the connecting user unless the play sets `become`; under `become` the same hang is possible there. Follow-up:
  FREES-138.

### Scanner invocation

The scan runs through the backend registry (`backends.default_registry()`). The only backend is OpenSCAP, which runs
`oscap xccdf eval --profile <id> [--tailoring-file <run>/tailoring.xml] --results-arf <run>/scan/results-arf.xml
--results <run>/scan/results.xml <run>/content/<datastream>` through `process.run`: an argument list, `shell=False`, a binary from a
trusted root-owned directory, a minimal environment, a timeout and bounded output. `--remediate` and remote resources
are refused by the process policy.

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

## Disabled rules (ADR 0011)

`disabled_rules` (role variable `linux_compliance_audit_disabled_rules`) lists rules of the profile that operator
toggles disable, each with `rule_id` (full XCCDF identifier) and an optional `disabled_by` (the controlling variable,
`linux_compliance_<name>_enabled`, default `linux_compliance_rule_<short id>_enabled`). The per-rule and per-family
toggle variables are generated from the rule catalogue in FREES-55, which does not exist yet; until then the list is
passed explicitly, and FREES-55 will compute it from the toggles.

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
| `unsafe_content_dir` | The datastream or a directory above it violates the [content directory rules](#content-directory-rules) |
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
symlinked content directory, production (root) ownership, components that vanish or cannot be inspected, and that a
refused datastream is never opened and nothing is created. `audit.py` and the module have 100% line and branch
coverage.

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
`audit.inspect_content_path`, so the content directory rules hold regardless of how the CI checkout is laid out.

CI installs `openscap-scanner` from the Ubuntu 24.04 archive at the exact version `1.3.9+dfsg-1.1ubuntu2`, checks the
installed version and prints `oscap --version`, and sets `FREESECDEV_REQUIRE_OSCAP=1`, so the tests fail instead of
skipping when `oscap` or the content is missing. Locally they skip only when `/usr/bin/oscap` is absent. The scans run
as the unprivileged runner user (the tests pass the expected owner explicitly), so rules that need root may report
other results than on a managed host; the assertions are about the protocol, not about the host's compliance.

Not covered yet: a Molecule scenario on a managed host that asserts that the audit role changes nothing, that check
mode leaves nothing behind and that a second run is idempotent. The Docker Molecule framework (FREES-59, pull request
14) had not merged when this was written, so that scenario is a follow-up for FREES-60.
