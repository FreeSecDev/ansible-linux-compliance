# Evidence bundles

Scope: the `freesecdev.linux_compliance.evidence` role, the evidence bundle format and how the report reads a bundle.
Audience: operators, auditors who receive bundles, and reviewers. Jira: FREES-51 (FREES-132 asked for the waived
evaluation and the stale result in the bundle, FREES-142 for the collection summary). Decisions:
[ADR 0013](adr/0013-normalized-findings-model.md) (findings model),
[ADR 0016](adr/0016-report-schema-and-summary-semantics.md) (report schema; 2.1 adds the host coverage) and
[ADR 0018](adr/0018-evidence-bundle-provenance.md) (signing, still proposed).

An evidence bundle is a directory on the controller that holds the evidence of **one audit run of one host**: the raw
scan run, the raw XCCDF results, the tailoring file, a checksum file and a manifest with provenance. When exceptions
were applied it also holds the waived evaluation, the exceptions file it was made from and the stale result of the
play, so the report can show waived findings and exception statuses without anything being exported by hand.

A bundle is **not signed**. Its checksums show that nothing changed or went missing after the bundle was written; they
do not show who wrote it, because whoever can edit a file can also edit the checksums. The report therefore labels
nothing as verified (see [signing](#signing-adr-0018)).

## Running it

```text
ansible-playbook -i inventory.yml freesecdev.linux_compliance.evidence \
  -e linux_compliance_target_hosts=web01 \
  -e linux_compliance_discover_content_path=/opt/freesecdev/content/ssg-ubuntu2404-ds.xml \
  -e linux_compliance_discover_content_sha256=<sha256 from content/manifest.yml> \
  -e linux_compliance_exceptions_file=/srv/compliance/exceptions.yml \
  -e linux_compliance_evidence_output_dir=/srv/compliance/evidence
```

`playbooks/evidence.yml` has five plays, in this order:

1. `discover` and the audit role's `deferred.yml` entry point on the target hosts. `deferred.yml` runs every task of
   the main entry point except the result gates and records `linux_compliance_audited.gate` as
   `{deferred: true, enforced: false}`, so neither a scan that did not complete nor
   `linux_compliance_audit_fail_on_noncompliant` drops a host before its evidence is collected. Its `pre_tasks` run
   the evidence role's `reached.yml` entry point after fact gathering. It first refuses the run when any internal
   variable of the evidence role (`__linux_compliance_evidence_*`) is already set for any inventory host or for
   `localhost` (see [the collection marker](#the-collection-marker)). It then records the hosts of the play
   (`ansible_play_hosts_all`) once on `localhost`, and `linux_compliance_evidence_reached` on every host that
   completed fact gathering, so that the summary can tell unreachable and limited-out hosts apart. The deferral
   message starts with `WARNING:`, so a custom playbook that never runs `enforce.yml` stands out in the output.
2. The stale-exceptions aggregation on the controller, after every host and every `serial` batch.
3. On every target host, a `block` that runs the audit role's `enforce.yml` entry point, with a `rescue` section and
   an `always` section that runs the `evidence` role in a `block` with its own `rescue`. `enforce.yml` records the
   gate decision (`deferred: true`, `enforced: true`) and asserts it exactly as the main entry point would: for a
   scan that did not complete, and with `linux_compliance_audit_fail_on_noncompliant` for failed or errored rules.
   The `rescue` sections print a `WARNING` with the reason and keep the host in the play, and the `always` section
   collects the evidence whatever the gate decided, with the stale result of the run. **No host fails in this
   play.**
4. The evidence role's `summary.yml` entry point once on the controller over every target host. It gives every target
   host one status (see [the collection summary](#the-collection-summary)), writes the collection summary
   `collection-<collection_id>.json` next to the bundles, publishes `linux_compliance_evidence_collection` and prints
   a `WARNING` that names every target host without a bundle with its status, and the path of the summary.
5. On every target host, the audit role's `enforce.yml` again, which fails every host that a gate fails, and the
   evidence role's `collected.yml`, which fails every host whose evidence was written but not collected in this run.

Why the gates are deferred rather than collected in an `always` section of the audit play: the stale result is
computed after every host and every `serial` batch of the audit play, so the bundles can only include it when they are
collected in a later play, and a later play only sees the hosts that did not fail. Deferring the gates to the
collection play keeps both.

Why no host fails before the summary (FREES-142): Ansible ends the whole playbook when every host of a play has
failed or is unreachable. In a run with one gated host and one unreachable host, a collection play that failed the
gated host would end the run before the summary, and the unreachable host would never be named. Play 3 therefore only
decides and collects; the summary is written; play 5 enforces the same gates again from the recorded audit result and
fails the same hosts. `make test-evidence` runs such a run (`--limit web01,lost01,localhost`, every host of the play
fails) and checks that the summary names the unreachable host and the limited-out hosts.

The deferral is chosen only by the entry point. No variable defers or skips a gate: the main and `evaluate.yml` entry
points always enforce it, whatever the inventory, `group_vars`, `host_vars`, `-e`, role or include parameters say.
A custom playbook that deliberately calls `deferred.yml` or `evaluate_deferred.yml` and never runs `enforce.yml`,
or that writes `linux_compliance_audited.gate` with its own `set_fact`, can still end without the gates. That is a
deliberate act by whoever writes the playbook, the same class as the documented residual of the `verify` role's
baseline marker; no variable from the inventory, `group_vars`, `host_vars`, `-e`, a role parameter or an include
parameter can defer a gate. Such a run never produces a bundle: the evidence role refuses an audit result whose
gate is recorded as deferred and not enforced, and the report refuses a manifest without an enforced gate.

Hosts that are unreachable or limited out cannot be collected; the summary names them, and a report built with
`--evidence-collection` lists them as missing inputs ([in the report](#in-the-report)).

The plays on `localhost` (2 and 4) are subject to `--limit` like every play. Include `localhost` when you limit a run,
for example `--limit web01,localhost`; otherwise no stale result and no collection summary are written, and a report
over the bundles can only label its host coverage `unknown`. If every target host fails in the audit play (play 1),
Ansible ends the run there and no summary is written either; the run exits non-zero.

The role can also run on its own, after the `audit` role, in any play whose hosts have the fact
`linux_compliance_audited`.

## What the role does

All tasks except two run on the controller (`delegate_to: localhost`, `become: false`). Only `ansible.builtin.stat`
and `ansible.builtin.fetch` reach the managed host, with `become: "{{ linux_compliance_evidence_become }}"`; neither
changes it.

0. Refuse internal `__linux_compliance_evidence_*` variables supplied from outside the role, such as a forged
   output directory, with the generated `tasks/internal_variables.yml` (also the first task of `summary.yml`;
   FREES-153). A name passed as a parameter is refused whatever its value (FREES-157). The collection steps below
   are a block of `main.yml`, not a task file of their own, so `tasks_from` cannot start them without this guard
   and the output directory check.
1. Validate the variables and check that `linux_compliance_audited` exists.
2. Resolve the output directory (relative paths against the playbook directory) and require a normalised absolute path.
3. Skip the host with a message when the audit wrote no evidence (`evidence_written: false`: check mode, or no scan).
   With `--check` nothing is fetched or written; the role prints the bundle it would write (no test covers check
   mode yet).
4. Plan the bundle with `freesecdev.linux_compliance.evidence_plan` (below). The plan requires the gate record of
   the audit and refuses one that is deferred and not enforced yet.
5. Refuse an existing bundle (a bundle is never overwritten) and an existing output or host directory that is a
   symbolic link, not a directory or not mode `0700`. Nothing is repaired.
6. Create the output directory, the host directory and the bundle directory with mode `0700`, check that all three are
   owned by the controller user, and create the subdirectories of the plan.
7. Inspect every planned file on the host with `ansible.builtin.stat` (`follow: false`) and check it with
   `freesecdev.linux_compliance.evidence_host_files`: it must exist, must be a regular file and not a symbolic link,
   and must have exactly the size the audit recorded (at most 256 MiB). Nothing is transferred otherwise, so a
   symbolic link is never followed as root and an oversized file is never copied.
8. Fetch every planned file from the host with `ansible.builtin.fetch` (`flat`, `fail_on_missing`,
   `validate_checksum`), set it to mode `0600` and hash it on the controller with SHA-256.
9. Build the documents with `freesecdev.linux_compliance.evidence_documents` (below). This is where every fetched file
   is compared with the SHA-256 and size that the audit recorded on the host.
10. Write the documents (`ansible.builtin.copy`, mode `0600`, `force: false`), hash every file of the bundle again and
   check them with `freesecdev.linux_compliance.evidence_written`.
11. Write the manifest `bundle.json` **last** and check its SHA-256, mode and owner.
12. Publish `linux_compliance_evidence_bundle` (`directory`, `run_id`, `manifest_sha256`, `files`, `excluded`,
    `exceptions_applied`).

Steps 6 to 11 are one `block`. Any failure, including a checksum mismatch, removes the bundle directory that this run
created and fails the host with the reason. No partial bundle is kept.

### Atomic writes

- Every document and the manifest are written by `ansible.builtin.copy`, which writes a temporary file in the target
  directory and renames it over the target.
- `ansible.builtin.fetch` writes the file it fetches directly. That is safe here because the bundle directory is new,
  `0700` and owned by the controller user, and because a bundle is only complete when its manifest exists.
- The manifest is the commit record. A directory without `bundle.json` is not a bundle: the report refuses it, and
  `bundle.json` is written only after every other file was written and checked. If the controller dies before that,
  the directory has no manifest. Remove it; a new audit run has a new run ID and a new bundle directory.
- The bundle is a directory, not a tarball. No tarball is produced. Archive bundles with your own tool if you need
  one; the report reads directories only.

### Permissions

| Path | Mode | Owner |
|---|---|---|
| Output directory, host directory, bundle directory and its subdirectories | `0700` | the controller user |
| Every file of the bundle | `0600` | the controller user |

The role checks the owner and mode of every file after it is written. An existing output or host directory with
another mode is an error, never repaired.

## Format

Bundle format version `1.0` (`schema_version` in `bundle.json`). Readers refuse every other version.

```text
<linux_compliance_evidence_output_dir>/
  <inventory_hostname>/
    <run_id>/
      bundle.json                  manifest, written last
      SHA256SUMS                   sha256sum format, every file except bundle.json and itself
      raw/
        scan-run.json              the raw ScanRun JSON, byte for byte as the audit wrote it
        tailoring.xml              the tailoring file, when rules were disabled
        scan/
          results.xml              the raw XCCDF 1.2 results
          results-arf.xml          the raw ARF results, only with linux_compliance_evidence_include_arf
      exceptions/                  only when exceptions were applied
        evaluation.json            the evaluation document of apply_exceptions (the waived scan run)
        exceptions.yml             the exceptions file, byte for byte
        stale.json                 the stale result of the play, when it was supplied
```

Only these paths exist in a bundle. The host files come from a fixed allow-list of names directly inside the run
directory that the audit reported (`linux_compliance_audited.evidence.directory`):

| Host file (relative to the run directory) | Audit kind | Bundle path | Bundle kind |
|---|---|---|---|
| `scan-run.json` | `scan_run` | `raw/scan-run.json` | `scan_run` |
| `tailoring.xml` | `tailoring` | `raw/tailoring.xml` | `tailoring` |
| `scan/results.xml` | `scanner_output` | `raw/scan/results.xml` | `xccdf` |
| `scan/results-arf.xml` | `scanner_output` | `raw/scan/results-arf.xml` (opt-in) | `arf` |
| `scan/results.off-platform.xml` | `scanner_output` | `raw/scan/results.off-platform.xml` (an off-platform SCC scan, FREES-161) | `xccdf` |
| `scan/results-arf.off-platform.xml` | `scanner_output` | `raw/scan/results-arf.off-platform.xml` (opt-in, an off-platform SCC scan) | `arf` |

A recorded file with another name inside the run directory is not collected; it is listed under `excluded` with reason
`not_allow_listed`. A recorded path outside the run directory, or one that is not normalised (`..`), fails the host: a
tampered fact cannot make the role fetch the state ledger or any other file. A kind that does not match the name, a
file listed twice and a run without `scan-run.json` fail too.

### The manifest

`bundle.json` is JSON with sorted keys, two-space indentation, ASCII escapes and a trailing newline.

| Key | Content |
|---|---|
| `schema_version` | `"1.0"` |
| `kind` | `freesecdev.linux_compliance.evidence_bundle` |
| `collection` | `name` (`freesecdev.linux_compliance`) and `version` of the collection that collected the bundle |
| `collected_at` | Controller time at which the manifest was built, UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `host.inventory_hostname` | The controller's name for the host; the bundle directory is named after it |
| `host.machine_id` | The machine ID from the host's gathered facts (`ansible_facts['machine_id']`), or `null` |
| `host.reported` | The host identity the scan run reports (`hostname`, distribution, version, architecture, machine ID) |
| `run` | `run_id`, `status`, `started_at`, `finished_at` (reported by the host), `benchmark_id`, `profile_id` |
| `scanner` | Scanner `name` and `version` from the scan run |
| `content` | Datastream `source` (with the tailoring label of ADR 0013), `content_version` and `content_sha256` |
| `gate` | `deferred` and `enforced` (always `true`: a bundle is written only after the gate ran) and the `decision` the gate enforced: `enabled`, `after_waivers`, `basis` (`raw` or `waived`), `counted` (false for a scan that did not complete) and the `fail`, `error` and `waived` counts it used (null when nothing was counted) |
| `exceptions` | `status` (`not_requested`, `applied`, `not_run`, `not_completed`), `source_sha256` of the exceptions file (null without one), and the bundle paths `evaluation`, `file` and `stale` (null unless present) |
| `files` | Every file except `bundle.json` and `SHA256SUMS`, sorted by path: `path`, `kind`, `sha256`, `size`, `source` |
| `excluded` | Every recorded host file that was not collected: `source`, `audit_kind`, `sha256` and `size` as recorded, `reason` (`not_allow_listed`, `arf_not_requested`) |
| `checksums` | `path` (`SHA256SUMS`), `sha256` and `size` of the checksum file |

`source` is the path on the host for host files, the controller path of the exceptions file, and the fact the
document was written from (`linux_compliance_audited.exceptions.evaluation`,
`linux_compliance_audit_stale_exceptions`) for the evaluation and the stale result.

The machine ID of the facts and the one in the scan run must agree when both are set. Both come from the host and
are self-asserted; a machine ID is not a secret.

### The collection summary

`summary.yml` writes one collection summary per run, `<linux_compliance_evidence_output_dir>/collection-<collection_id>.json`,
with mode `0600` in the output directory (`0700`). It is built by the `freesecdev.linux_compliance.evidence_collection`
filter, written with `force: false` (an existing summary is never overwritten) and hashed again after writing. The
output directory is the one that holds the collected bundles; when no bundle was collected it is
`linux_compliance_evidence_output_dir` as `localhost` sees it, resolved against the playbook directory. Bundles of one
run in several output directories fail the summary. Check mode writes nothing and prints the path it would use.

JSON with sorted keys, two-space indentation, ASCII escapes and a trailing newline, format version `1.0`:

| Key | Content |
|---|---|
| `schema_version` | `"1.0"` |
| `kind` | `freesecdev.linux_compliance.evidence_collection` |
| `collection` | `name` and `version` of the collection that wrote the summary |
| `collection_id` | The run identity: the controller time at which the summary was built, `YYYYMMDDTHHMMSS.ffffffZ` |
| `collected_at` | The same time as `YYYY-MM-DDTHH:MM:SSZ` |
| `hosts` | Every target host, sorted by name: `inventory_hostname`, `status` and `bundle` (`run_id` and `manifest_sha256`, the SHA-256 of its `bundle.json`; `null` unless the host was collected) |

The target hosts are the inventory hosts of the run's host pattern (`linux_compliance_target_hosts`, the
`inventory_hostnames` lookup, which ignores `--limit`), so they come from the controller's inventory and never from a
managed host. Each has exactly one status, decided in this order:

| Status | Meaning |
|---|---|
| `collected` | The evidence role wrote and re-hashed a bundle of the host in this run (the [collection marker](#the-collection-marker)) |
| `limited_out` | The host is not a host of the audit play (`--limit`) |
| `unreachable` | The host is a host of the audit play but did not complete fact gathering (unreachable, or failed while gathering facts) |
| `no_audit_result` | The host has no `linux_compliance_audited` (it failed before the scan) |
| `no_evidence_written` | The audit wrote no evidence (check mode, or no scan) |
| `collection_failed` | The audit wrote evidence, but no bundle was collected in this run |

`summary.yml` refuses to write a summary when the audit play did not run `reached.yml` (FREES-154): without it, the
run has not checked that no collection marker came from outside, and `limited_out` and `unreachable` cannot be told
apart.

The summary is not signed. It names the hosts a report must account for and binds every collected bundle to the
SHA-256 of its manifest, which lists the SHA-256 of every file. Whoever can write the evidence directory can rewrite
it consistently, as for bundles: a summary rewritten to list fewer hosts, together with the bundles it lists, drops
the other hosts from every report built with it, and the report cannot detect that. Signing the summary
([ADR 0018](adr/0018-evidence-bundle-provenance.md), FREES-140) is the fix; until then, protect the evidence
directory (see [the threat model](security/threat-model.md#t-evidence-4-the-hosts-that-matter-most-have-no-bundle)).
The public facts set by the run (`linux_compliance_evidence_reached`, `linux_compliance_evidence_play_hosts`) can be
overridden with `-e`; that can change the status of a missing host, never make it present in a report: the report
accepts a bundle only when its own manifest has the digest that the summary lists.

### The collection marker

A host is `collected` only on the strength of the internal fact `__linux_compliance_evidence_run_bundle`, which the
evidence role sets, with the same content as `linux_compliance_evidence_bundle`, in the same task that publishes the
bundle, after the manifest was written and hashed again (FREES-154, the PR #37 review, N3). The public fact
`linux_compliance_evidence_bundle` does not count: a value of it from the inventory, `group_vars`, `host_vars` or an
extra variable, for a host whose real collection failed, leaves the host `collection_failed`, and `collected.yml` in
the last play fails it.

The marker is scoped to the run, as the `verify` role's baseline marker is:

- It is set with `set_fact` without `cacheable`, so no fact cache keeps it for a later run.
- `reached.yml` refuses the run in the audit play, before anything is audited or collected, when any variable whose
  name starts with `__linux_compliance_evidence_` is already in `hostvars` of any inventory host or of `localhost`. An
  extra variable (`-e`) outranks every `set_fact`, but it is also in `hostvars` of every host from the start, so the
  check detects it whatever its value. It uses only the magic variables `groups` and `hostvars` and literals, so no
  variable can change the condition, the same mechanism as the Molecule guard of FREES-150. It also refuses
  `inventory_hostname` set as an extra variable, which would make every host read the marker of one host.
- `summary.yml` and `collected.yml` read the marker through `hostvars[<host>]`, so a role or include parameter of the
  same name cannot stand in for it, and count it only when it is a mapping. `collected.yml` also requires its
  `run_id` to be the run of `linux_compliance_audited` and its `manifest_sha256` to be a SHA-256, so a marker of an
  earlier collection of the same host does not pass a later collection that failed; the summary filter validates
  every field of the marker, as it did for the public fact.
- The role guard of the evidence role (`internal_variables.yml`, FREES-153), which resets the role's internal facts
  to a sentinel string at the start of `main.yml` and `summary.yml`, leaves the marker alone. It is a run output of
  the generator (`RUN_OUTPUTS`, [development guide](development.md)): reset to the sentinel, it would be defined for
  a host whose collection then failed. The task that sets the marker is followed by a check that it is a mapping
  with the run ID and manifest digest of the bundle just written.

The marker is not defended against the playbook itself. A `set_fact` of `__linux_compliance_evidence_run_bundle` in
playbook code that runs after `reached.yml` is trusted playbook code, the same residual as the `verify` role's
baseline marker: whoever writes the playbook can also skip the collection. Inventory, `group_vars`, `host_vars`,
extra variables, role and include parameters and fact caches cannot set it.

A playbook that runs `playbooks/evidence.yml`'s plays twice in one `ansible-playbook` invocation is therefore refused
at the second audit play: the markers of the first run are still set.

### The stale result

`exceptions/stale.json` is `{"schema_version": "1.0", "kind": "freesecdev.linux_compliance.stale_exceptions",
"result": {...}}`, where `result` has the keys of `linux_compliance_audit_stale_exceptions` (`computed`, `complete`,
`unmatched`, `stale`, `source_sha256`, `target_hosts`, `audited_hosts`, `evaluated_hosts`, `not_evaluated_hosts`;
[audit guide](audit.md#stale-exceptions-once-for-all-hosts)). It must have been computed, from the same exceptions
file, and must list this host as evaluated. It is the same document in every bundle of one play; it records what the
play concluded, including which target hosts were not evaluated, which a report over a subset of bundles cannot know.
The report does not read it; it computes its own review verdicts from the evaluations it is given.

## What a bundle never contains

| Source of secrets | Why it cannot reach a bundle |
|---|---|
| Environment variables (`ansible_env`, the environment of the play, the controller environment) | Nothing from facts or the environment is written. The skeleton option `linux_compliance_evidence_include_host_facts` is removed. Only the machine ID is taken from the facts. |
| `no_log` values, vault values, inventory and host variables | The documents are built only from the fetched files, `linux_compliance_audited.exceptions.evaluation` (re-verified), the exceptions file and the stale result. No variable is dumped. |
| The state ledger (`/var/lib/freesecdev/linux_compliance/state.json`) and its sensitive prior values | It is not in the allow-list, and a recorded path outside the run directory fails the host. |
| Other files in or next to the run directory | Only the four allow-listed names are fetched; anything else the audit recorded is listed as excluded with its digest, never fetched. |
| OVAL system characteristics in the ARF results | Excluded by default. ARF holds the items that OVAL collected, for example matched lines of `/etc/shadow` with password hashes, `sshd` and PAM configuration, and environment variables. Collect it only with `linux_compliance_evidence_include_arf: true` and store such bundles like credentials. |

What a bundle does contain is host evidence. `raw/scan/results.xml` is the scanner's XCCDF output **copied verbatim**;
it is never parsed or filtered. Besides the rule results it carries:

- the `target`, `target-address` and `target-facts` of the scanned host: host names, every IP address and every MAC
  address;
- the standard output of the SCE check scripts, in `check-import import-name="stdout"`. Every SCE check of the pinned
  datastreams imports its output, and the SCE-only rules (18 on Ubuntu 24.04, 4 on RHEL 9) print firewall rule
  dumps, listening ports, and lists of world-writable, unowned or privileged files.

That is sensitive host data, not credentials, but it maps the host's attack surface. The scan run carries rule
results and identifiers, and with exceptions the exceptions file names owners, approvers and justifications. Share a
bundle like the report itself, and do not attach bundles to public tickets. `make test-evidence` plants an SCE output
line, an IP and a MAC address in the XCCDF fixture and checks that they **are** in the bundle, so this paragraph stays
true.

`make test-evidence` plants an environment variable, a `no_log` fact, a state ledger with a sensitive prior value, an
unlisted file in the scanner output directory and an ARF file with a shadow-like line, and checks that none of them is
in any file of the bundles and that none is printed.

## Verification

### On the host side, while collecting

- Every fetched file must have exactly the SHA-256 and size that the audit module recorded on the host
  (`linux_compliance_audited.evidence.files`). A mismatch fails the host with `checksum mismatch for <path>` and
  removes the bundle. `ansible.builtin.fetch` also compares the file it wrote with the bytes it received
  (`validate_checksum`); with `become` it reads the file through `slurp`, so that check is about the transfer only.
- The fetched `scan-run.json` must be the scan run of the fact.
- With exceptions applied, the exceptions file is read again, byte for byte (`rstrip=false`); its SHA-256 must still
  be the one that was applied, the evaluation must verify against it with `exceptions.verify_evaluation` (the same
  check the report makes) and must have been made from the raw scan run of this audit. A file changed since the audit
  fails the host.
- After writing, every file of the bundle is hashed again and must be what the manifest records.

The digests that the audit recorded come from the managed host. They detect a file that changed between the audit and
the fetch, or in transit; they cannot detect a host that lies consistently. A compromised host controls its own
evidence (see the [threat model](security/threat-model.md#t-evidence-2-a-host-or-a-file-on-the-way-changes-the-evidence)).

### In the report

`python -m tools.reporting --evidence-bundle DIR` (repeatable) reads a bundle directly:

```bash
python -m tools.reporting --scope fleet --output build/report/report.json --html build/report/report.html \
  --exceptions-file inventory/exceptions.yml \
  --evidence-bundle /srv/compliance/evidence/web01/20261026T080000.000000Z \
  --evidence-bundle /srv/compliance/evidence/db01/20261026T080001.000000Z
```

1. The bundle directory is opened component by component with `O_NOFOLLOW`; every entry is inspected without
   following links. A symbolic link, a FIFO or other special file, a directory other than `raw`, `raw/scan` and
   `exceptions`, more than 64 entries, an empty file or a file above `--max-bytes` is an error.
2. `evidence.check_bundle` verifies the bytes that were read:
   - the manifest is valid for format `1.0`;
   - the files are exactly the listed ones plus `bundle.json` and `SHA256SUMS`, so an unlisted file is an error;
   - every size and SHA-256 matches, and `SHA256SUMS` is exactly the file the manifest implies;
   - the scan run matches the run, host, scanner and content of the manifest;
   - the manifest records an enforced gate; a gate that was deferred and never enforced refuses the bundle;
   - with exceptions applied, the exceptions file has the recorded SHA-256, the evaluation verifies against it, names
     the bundle's inventory host and was made from the bundle's raw scan run.
3. The bundle then contributes **one** compliance input: its evaluation when exceptions were applied (which is also an
   input of the `exceptions` section, verified against the bundled exceptions file), otherwise its raw scan run. The
   XCCDF, ARF and tailoring files are verified but not parsed again, because they describe the same scan; passing them
   with `--xccdf` as well would add a second input for the same host.
4. A bundle whose exceptions were applied **requires `--exceptions-file`**, the reviewed file from Git. The bundle
   is not signed, so its own copy of the exceptions file is never the reference: a bundle built consistently from a
   made-up exceptions file would otherwise turn failures into waivers under a `verified` label. Every bundle's copy
   must be byte-identical to `--exceptions-file`, and the evaluation in it was verified against those bytes. A bundle
   with applied exceptions and no `--exceptions-file`, or with a copy that differs, makes the report exit with status
   2 and write nothing.

5. With `--evidence-collection FILE` (the collection summary of the same run, not repeatable), the report accounts
   for every target host ([report data model](reporting-data-model.md#host-coverage)):
   - every bundle that verified must be listed in the summary as `collected` with its inventory host, run ID and the
     SHA-256 of its `bundle.json`; a bundle that is not is an input `error`;
   - every target host without such a bundle in the report is a missing input (`unavailable`) with its status as the
     reason, in the compliance section and, when the report has exceptions evaluations, in the exceptions section,
     so that no exception is called stale because a host is missing;
   - while a host is missing, the compliance section is `partial` (or `unavailable` without any bundle), so it has no
     summary, group or pooled figure, and the command exits with status 1;
   - `sections.compliance.host_coverage` lists every target host with its status and whether it is in the report,
     and counts them.

   A summary that cannot be read or is not valid, or one supplied with `--scan-run`, `--xccdf`, `--arf` or
   `--exceptions-evaluation` (scans that the summary cannot account for), refuses the report with exit status 2.
   Without `--evidence-collection` the report is written as before and labels its host coverage `unknown`: it
   cannot tell whether a target host is missing, and says so.

6. **Gate on the host coverage with `--require-host-coverage`** (FREES-154). Without it, a report without a summary
   has coverage `unknown` and exits 0 when every input parsed, so a pipeline that gates only on the exit status
   cannot tell "every host covered" from "coverage unknown". With it, the report exits with status 1 unless
   `sections.compliance.host_coverage.status` is `complete`, and prints the coverage and its reason on standard
   error; the report and the dashboard are still written. Use it for every fleet report built from bundles, as below
   and as `make test-evidence` does.

The fleet workflow: run `playbooks/evidence.yml` with `localhost` in any `--limit`, then build the report from the
collection summary of that run and its bundles, and gate on the exit status:

```bash
python -m tools.reporting --scope fleet --output build/report/report.json --html build/report/report.html \
  --require-host-coverage \
  --exceptions-file inventory/exceptions.yml \
  --evidence-collection /srv/compliance/evidence/collection-20261026T080002.123456Z.json \
  --evidence-bundle /srv/compliance/evidence/web01/20261026T080000.000000Z \
  --evidence-bundle /srv/compliance/evidence/db01/20261026T080001.000000Z
```

#### Fleets of more than 1000 hosts

One report covers at most 1000 target hosts. The summary itself accepts up to 100 000, so a run over a larger host
pattern writes a valid summary, but the report refuses it with exit status 2 ("the evidence collection summary names
more than 1000 target hosts") and writes nothing. The limit counts the target hosts of the summary, not the bundles
supplied, so passing fewer bundles does not help, and leaving out the summary only turns the coverage `unknown`
(which `--require-host-coverage` refuses).

Split such a fleet into runs of at most 1000 target hosts, each with its own summary and its own report:

- **By inventory group:** run the playbook once per group, for example
  `-e linux_compliance_target_hosts=web` and then `-e linux_compliance_target_hosts=db`, each group at most 1000
  hosts. Each run writes its own `collection-<collection_id>.json`; build one report per summary, with the bundles that
  summary lists.
- **By batch:** define the batches as host patterns, for example inventory groups `batch01`, `batch02` and so on, or
  patterns such as `linux_compliance:&batch01`, and pass one per run as `linux_compliance_target_hosts`. Use the host
  pattern, not `--limit`, to cut a batch: the target hosts of a summary are the inventory hosts of the pattern and
  ignore `--limit`, so a run limited to 500 of 3000 target hosts writes a summary of 3000 hosts, 2500 of them
  `limited_out`, which the report still refuses.
- Use a separate `linux_compliance_evidence_output_dir` per run, or keep track of which summary belongs to which
  run: a report takes exactly one `--evidence-collection`, and a bundle that the summary does not list is an input
  error.

The fleet figure is then the set of reports, one per batch, each with `complete` coverage; no report pools the
batches.

A bundle that does not verify is an input `error` (exit status 1), and nothing from it is used. Unless its manifest is
readable and records that no exceptions were applied, the error is an `exceptions_evaluation` input, so the
`exceptions` section is in error too and a broken bundle cannot make an exception look stale. A missing bundle
directory is `unavailable` in the same way. A file named like a signature (`*.sigstore.json`, `*.sig`, `*.pem`,
`*.intoto.jsonl`, ...) is refused with a message that says the signature cannot be verified; it is never treated as an
unsigned bundle.

The report schema is `report-v2.json`, `schema_version` `"2.1"`: 2.1 adds `sections.compliance.host_coverage` and
the raw artifact format `evidence_collection` (FREES-142). Bundle inputs appear as
`exceptions_evaluation` or `scan_run` items whose artifact path is the file inside the bundle; `raw_artifacts` lists
those inputs and the exceptions file, not every file of the bundle. `exceptions_file` is always the file passed with
`--exceptions-file`, never a bundle's copy, and `exceptions_file.verified: true` keeps its 2.0 meaning: every
evaluation verified against that file. It says nothing about signatures.

## Signing (ADR 0018)

Signing is **not implemented** in this version, and [ADR 0018](adr/0018-evidence-bundle-provenance.md) stays proposed.
The layout leaves room for it: a signature would be one more file next to `bundle.json` over the manifest, which lists
every file with its SHA-256. Until a verifier exists, the report refuses such a file instead of ignoring it. What
blocks signing is recorded in the ADR's status update: there is no pinned signer on the controllers that run audits, no
signing identity for those runs (keyless OIDC exists only in CI, which collects synthetic fixtures), no decision about
publishing inventory host names in the public Rekor log, and no reviewed verifier dependency or report field for the
label. Follow-up: FREES-140.

## Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_evidence_output_dir` | `path` | `"evidence"` | Controller directory below which each host gets a directory and each run a bundle. A relative path is resolved against the playbook directory. Missing directories are created `0700`; an existing one must be `0700` and not a symbolic link. |
| `linux_compliance_evidence_include_arf` | `bool` | `false` | Also collect `scan/results-arf.xml`, which can hold credential material. |
| `linux_compliance_evidence_become` | `bool` | `true` | `become` on the fetch task. The audit evidence is root-owned `0600`; set `false` only when the connecting user can read it (tests). |
| `linux_compliance_evidence_stale_exceptions` | `dict` | `{}` | The stale result to include when exceptions were applied; `playbooks/evidence.yml` passes it. |
| `linux_compliance_evidence_summary_hosts` | `list` | required | `summary.yml` entry point only: the target hosts to account for. |

The entry points `reached.yml` (in the audit play, after fact gathering) and `collected.yml` (in the last play) take
no variables. `summary.yml` also reads `linux_compliance_evidence_output_dir` to place the summary when no bundle was
collected, and requires that the audit play ran `reached.yml`. No variable named `__linux_compliance_evidence_*` may
be supplied from outside the role; `reached.yml` refuses the run if one is.

The audit role's `deferred.yml` and `enforce.yml` entry points defer and enforce the result gates for
`playbooks/evidence.yml` ([audit guide](audit.md#entry-points)); there is no variable for it.

## Tests

- `tests/unit/plugins/module_utils/compliance/test_evidence.py`: the plan (allow-list, exclusions, paths outside the
  run directory, malformed facts), the documents (checksum, size, mode and owner mismatches, a changed exceptions file,
  an evaluation that does not verify or belongs to another run, the stale result), the manifest (every invalid field)
  and `check_bundle` (tampered, unlisted, missing and signature files, resealed bundles with inconsistent content).
  `evidence.py` and the three filters have 100% line and branch coverage.
- `tests/unit/tools/reporting/test_bundle.py`: the report reads waived findings and exception statuses from bundles,
  a bundle without exceptions, missing, tampered, symlinked, special-file and oversized bundles, conflicting exceptions
  files and the command line. The reporting package has 100% line and branch coverage.
- `tests/unit/plugins/module_utils/compliance/test_collection.py`: every host status, the observation and summary
  validation (unknown keys, duplicate and invalid hosts, bundle directories outside `<output>/<host>/<run_id>` or in
  several output directories, an invalid collection ID or time) and the filter. `collection.py` and the filter have
  100% line and branch coverage.
- `tests/unit/tools/reporting/test_host_coverage.py`: coverage `unknown` without a summary, `complete` with every
  figure kept, every missing host named with its status while the section is `partial` with no figure and the
  exceptions section `partial`, a bundle not listed or listed with another digest refused, a bundle that does not
  verify leaving its host missing, unusable summaries and mixed inputs refused with status 2, the bounds, the schema
  couplings of 2.1 and 2.0, and the dashboard on both versions. `tests/browser/test_dashboard_host_coverage.py`
  checks the dashboard text, escaping and axe in both themes.
- `tests/unit/roles/test_evidence_role.py`: only the host `stat` and the fetch reach the host and only they may
  become; modes; the collection version matches `galaxy.yml`; the allow-list uses the audit module's file names;
  `playbooks/evidence.yml` defers the gates, collects, summarises and only then runs `gate.yml`; the audit role defers
  its gates only on request.
- `make test-evidence` (part of `make ci` and the CI `test` job) runs `tests/playbooks/evidence.yml` on two local
  inventory hosts with synthetic `linux_compliance_audited` facts and fixture files, the audit role's `evaluate.yml` and
  `stale.yml`, and the evidence role. It checks the bundle content, provenance, permissions and owner, that no planted
  secret is in a bundle, that the XCCDF target facts and SCE output are carried, that a second collection of the same
  run is refused, and that a checksum mismatch, a recorded path outside the run directory, a symbolic link on the
  host and a changed exceptions file fail closed and leave no bundle. It then runs the report on both bundles with
  `--exceptions-file` and checks the waived counts and the exceptions section; checks that the same bundles without
  `--exceptions-file`, or with another file, are refused with exit status 2; and that a bundle with one changed byte is
  an input error.
- `tests/playbooks/evidence-gate.yml` (also in `make test-evidence`) runs the plays of `playbooks/evidence.yml` on
  four inventory hosts with `linux_compliance_audit_fail_on_noncompliant: true`, with `evaluate_deferred.yml` in place
  of a real scan: a host with failed rules and a host whose scan did not complete are both failed by `enforce.yml`
  in the last play and both get a bundle whose manifest records the enforced, deferred gate; a host without evidence
  and an unreachable host are named by the summary and the collection summary; the playbook exits non-zero; the
  report over the two bundles shows both hosts, one of them with run status `failed`, and labels its coverage
  `unknown`; with `--evidence-collection` it names the host without evidence and the unreachable host, has no
  figure and exits 1. A second run with `--limit web01,lost01,localhost`, in which every host of the play fails,
  still writes the summary, which names the unreachable host and the two limited-out hosts; its report names all
  three; and the bundle of the first run is refused against the summary of the second. With
  `--require-host-coverage` the report without a summary (coverage `unknown`) and both reports with missing hosts
  (`incomplete`) exit 1 with the coverage on standard error. A run that targets only the two audited hosts
  (`-e evidence_gate_hosts=web01:db01`) collects both, and its report with `--evidence-collection` and
  `--require-host-coverage` has coverage `complete`, keeps its figures and exits 0 (FREES-154).
- The same playbook, in two more runs, plants a `linux_compliance_evidence_bundle` for web01, once in the inventory
  (`tests/playbooks/inventory/evidence-planted.yml`) and once as an extra variable for every host, while the real
  collection of web01 fails (its host directory has mode `0755`). In both, the summary records web01 as
  `collection_failed` and db01 as `collected` with the SHA-256 of its real `bundle.json`, `collected.yml` fails web01
  in the last play, and the report with `--require-host-coverage` exits 1. Two further runs set the collection marker
  `__linux_compliance_evidence_run_bundle` itself, once as an extra variable and once in the inventory for the
  unreachable host; `reached.yml` refuses both at the start of the audit play, and nothing is collected or written
  (FREES-154). In the planted runs the role guard ran on web01 before its collection failed, and `collected.yml`
  still fails it. `tests/playbooks/evidence.yml` also collects web01 once, then lets a second collection of another
  run fail after the guard ran, and checks that the marker of the first collection is kept and that `collected.yml`
  fails web01 because the marker is not of the audited run.
- `tests/playbooks/audit-gate-routes.yml` (also in `make test-evidence`) runs `evaluate.yml` with the gate on for a
  host with failed rules and a scan that did not complete, once without and once each with the removed
  `linux_compliance_audit_defer_gate` and a forged `__linux_compliance_audit_gate_deferred` set through `-e`,
  `group_vars`, `host_vars`, include parameters and the parameters of a static role import. Every run must exit with
  status 2 and fail both hosts.

Not covered yet: a Molecule scenario that collects the bundle of a real scan from a managed host over SSH with
`become` (FREES-60).

## Limits

| Item | Limit |
|---|---|
| Files the audit may record per run | 64 |
| Size of one fetched file | 256 MiB |
| Entries in a bundle read by the report | 64 |
| Size of one bundle file read by the report | `--max-bytes`, 64 MiB by default |
| Size of `bundle.json` | 1 MiB |

- Unreachable and limited-out hosts cannot be collected; the collection summary names them, and a report names them
  only when it is built with `--evidence-collection`. A report covers at most 1000 target hosts; split a larger
  fleet into runs with separate summaries and reports ([fleets of more than 1000 hosts](#fleets-of-more-than-1000-hosts)).
- The collection summary is not signed until ADR 0018 (FREES-140); protect the evidence directory.
- A bundle is not signed; see [signing](#signing-adr-0018).
- `ansible.builtin.fetch` with `become` reads the whole file into memory on the controller (it uses `slurp`), so very
  large ARF files cost memory.

## Related

- [ADR 0013](adr/0013-normalized-findings-model.md), [ADR 0016](adr/0016-report-schema-and-summary-semantics.md),
  [ADR 0018](adr/0018-evidence-bundle-provenance.md)
- [Audit guide](audit.md), [exceptions](exceptions.md), [reporting data model](reporting-data-model.md),
  [threat model](security/threat-model.md), [role README](../roles/evidence/README.md)
- Jira: FREES-51, FREES-132, FREES-130, FREES-60, FREES-140, FREES-142, FREES-154
