# Evidence bundles

Scope: the `freesecdev.linux_compliance.evidence` role, the evidence bundle format and how the report reads a bundle.
Audience: operators, auditors who receive bundles, and reviewers. Jira: FREES-51 (FREES-132 asked for the waived
evaluation and the stale result in the bundle). Decisions: [ADR 0013](adr/0013-normalized-findings-model.md) (findings
model), [ADR 0016](adr/0016-report-schema-and-summary-semantics.md) (report schema, unchanged) and
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

`playbooks/evidence.yml` imports `playbooks/audit.yml` (`discover`, `audit`, then the stale-exceptions play on the
controller) and then runs the `evidence` role on every target host, passing it the stale result of the run
(`hostvars['localhost'].linux_compliance_audit_stale_exceptions`). The role can also run on its own, after the `audit`
role, in any play whose hosts have the fact `linux_compliance_audited`.

A host that fails the audit play (for example a scan that did not complete, or the failure gate) is removed from the
later plays by Ansible, so the playbook does not collect its bundle. Its evidence stays in the run directory on the
host. Collecting the evidence of failed scans in the same play is a follow-up (see [limits](#limits)).

## What the role does

All tasks except one run on the controller (`delegate_to: localhost`, `become: false`). The only task that reaches the
managed host is `ansible.builtin.fetch`, with `become: "{{ linux_compliance_evidence_become }}"`. The role never
changes the managed host.

1. Validate the variables and check that `linux_compliance_audited` exists.
2. Resolve the output directory (relative paths against the playbook directory) and require a normalised absolute path.
3. Skip the host with a message when the audit wrote no evidence (`evidence_written: false`: check mode, or no scan).
   With `--check` nothing is fetched or written; the role prints the bundle it would write (no test covers check
   mode yet).
4. Plan the bundle with `freesecdev.linux_compliance.evidence_plan` (below).
5. Refuse an existing bundle (a bundle is never overwritten) and an existing output or host directory that is a
   symbolic link, not a directory or not mode `0700`. Nothing is repaired.
6. Create the output directory, the host directory and the bundle directory with mode `0700`, check that all three are
   owned by the controller user, and create the subdirectories of the plan.
7. Fetch every planned file from the host with `ansible.builtin.fetch` (`flat`, `fail_on_missing`,
   `validate_checksum`), set it to mode `0600` and hash it on the controller with SHA-256.
8. Build the documents with `freesecdev.linux_compliance.evidence_documents` (below). This is where every fetched file
   is compared with the SHA-256 and size that the audit recorded on the host.
9. Write the documents (`ansible.builtin.copy`, mode `0600`, `force: false`), hash every file of the bundle again and
   check them with `freesecdev.linux_compliance.evidence_written`.
10. Write the manifest `bundle.json` **last** and check its SHA-256, mode and owner.
11. Publish `linux_compliance_evidence_bundle` (`directory`, `run_id`, `manifest_sha256`, `files`, `excluded`,
    `exceptions_applied`).

Steps 6 to 10 are one `block`. Any failure, including a checksum mismatch, removes the bundle directory that this run
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
| `exceptions` | `status` (`not_requested`, `applied`, `not_run`, `not_completed`), `source_sha256` of the exceptions file (null without one), and the bundle paths `evaluation`, `file` and `stale` (null unless present) |
| `files` | Every file except `bundle.json` and `SHA256SUMS`, sorted by path: `path`, `kind`, `sha256`, `size`, `source` |
| `excluded` | Every recorded host file that was not collected: `source`, `audit_kind`, `sha256` and `size` as recorded, `reason` (`not_allow_listed`, `arf_not_requested`) |
| `checksums` | `path` (`SHA256SUMS`), `sha256` and `size` of the checksum file |

`source` is the path on the host for host files, the controller path of the exceptions file, and the fact the
document was written from (`linux_compliance_audited.exceptions.evaluation`,
`linux_compliance_audit_stale_exceptions`) for the evaluation and the stale result.

The machine ID of the facts and the one in the scan run must agree when both are set. Both come from the host and
are self-asserted; a machine ID is not a secret.

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

What a bundle does contain is host evidence: the XCCDF results (rule results, target facts such as host names, IP and
MAC addresses), the scan run and, with exceptions, the exceptions file (owners, approvers, justifications). Share a
bundle like the report itself.

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
   - with exceptions applied, the exceptions file has the recorded SHA-256, the evaluation verifies against it, names
     the bundle's inventory host and was made from the bundle's raw scan run.
3. The bundle then contributes **one** compliance input: its evaluation when exceptions were applied (which is also an
   input of the `exceptions` section, verified against the bundled exceptions file), otherwise its raw scan run. The
   XCCDF, ARF and tailoring files are verified but not parsed again, because they describe the same scan; passing them
   with `--xccdf` as well would add a second input for the same host.
4. Every bundle with exceptions carries a copy of the exceptions file. All copies, and `--exceptions-file` when it is
   given, must be the same bytes, or the report exits with status 2. Without `--exceptions-file` the copy in the first
   bundle is the report's exceptions file.

A bundle that does not verify is an input `error` (exit status 1), and nothing from it is used. Unless its manifest is
readable and records that no exceptions were applied, the error is an `exceptions_evaluation` input, so the
`exceptions` section is in error too and a broken bundle cannot make an exception look stale. A missing bundle
directory is `unavailable` in the same way. A file named like a signature (`*.sigstore.json`, `*.sig`, `*.pem`,
`*.intoto.jsonl`, ...) is refused with a message that says the signature cannot be verified; it is never treated as an
unsigned bundle.

The report schema is unchanged (`report-v2.json`, `schema_version` `"2.0"`). Bundle inputs appear as
`exceptions_evaluation` or `scan_run` items whose artifact path is the file inside the bundle; `raw_artifacts` lists
those inputs and the exceptions file, not every file of the bundle. `exceptions_file.verified: true` keeps its 2.0
meaning: every evaluation verified against that file. It says nothing about signatures.

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

## Tests

- `tests/unit/plugins/module_utils/compliance/test_evidence.py`: the plan (allow-list, exclusions, paths outside the
  run directory, malformed facts), the documents (checksum, size, mode and owner mismatches, a changed exceptions file,
  an evaluation that does not verify or belongs to another run, the stale result), the manifest (every invalid field)
  and `check_bundle` (tampered, unlisted, missing and signature files, resealed bundles with inconsistent content).
  `evidence.py` and the three filters have 100% line and branch coverage.
- `tests/unit/tools/reporting/test_bundle.py`: the report reads waived findings and exception statuses from bundles,
  a bundle without exceptions, missing, tampered, symlinked, special-file and oversized bundles, conflicting exceptions
  files and the command line. The reporting package has 100% line and branch coverage.
- `tests/unit/roles/test_evidence_role.py`: only the fetch task reaches the host and only it may become; modes; the
  collection version matches `galaxy.yml`; the allow-list uses the audit module's file names.
- `make test-evidence` (part of `make ci` and the CI `test` job) runs `tests/playbooks/evidence.yml` on two local
  inventory hosts with synthetic `linux_compliance_audited` facts and fixture files, the audit role's `evaluate.yml` and
  `stale.yml`, and the evidence role. It checks the bundle content, provenance, permissions and owner, that no planted
  secret is in a bundle, that a second collection of the same run is refused, and that a checksum mismatch, a recorded
  path outside the run directory and a changed exceptions file fail closed and leave no bundle. It then runs the report
  on both bundles and checks the waived counts and the exceptions section, and checks that a bundle with one changed
  byte is an input error.

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

- Hosts that fail the audit play are not collected by `playbooks/evidence.yml`.
- A bundle is not signed; see [signing](#signing-adr-0018).
- `ansible.builtin.fetch` with `become` reads the whole file into memory on the controller (it uses `slurp`), so very
  large ARF files cost memory.

## Related

- [ADR 0013](adr/0013-normalized-findings-model.md), [ADR 0016](adr/0016-report-schema-and-summary-semantics.md),
  [ADR 0018](adr/0018-evidence-bundle-provenance.md)
- [Audit guide](audit.md), [exceptions](exceptions.md), [reporting data model](reporting-data-model.md),
  [threat model](security/threat-model.md), [role README](../roles/evidence/README.md)
- Jira: FREES-51, FREES-132, FREES-130, FREES-60, FREES-140
