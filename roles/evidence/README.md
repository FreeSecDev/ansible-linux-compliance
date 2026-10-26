# evidence

Scope: role `freesecdev.linux_compliance.evidence`. Audience: playbook authors and contributors.

Collects the evidence that the `audit` role recorded on a host into a versioned, checksummed bundle on the controller:
the raw scan run, the XCCDF results, the tailoring file, a manifest with provenance and, when exceptions were applied,
the waived evaluation, the exceptions file and the stale result. The format, the provenance fields and the
verification are documented in [docs/evidence.md](../../docs/evidence.md).

## Status

Implemented (FREES-51). The role runs in `make test-evidence` against local inventory hosts with synthetic audit
results; no Molecule scenario collects a bundle from a real managed host yet (FREES-60). The platforms in
`meta/main.yml` (Ubuntu 24.04 and RHEL 9 compatible, per [ADR 0010](../../docs/adr/0010-initial-os-and-benchmark-scope.md))
are intentions, not tested support. Bundles are not signed;
[ADR 0018](../../docs/adr/0018-evidence-bundle-provenance.md) is still proposed.

## Safety

- The role never changes the managed host. Only `ansible.builtin.stat` (with `follow: false`) and
  `ansible.builtin.fetch` reach it, with `become: "{{ linux_compliance_evidence_become }}"`; every other task runs on
  the controller with `become: false`. A symbolic link, a special file or a size other than the recorded one is
  refused on the host, before anything is transferred.
- Every fetched file must have the SHA-256 and size that the audit recorded; any mismatch fails the host and removes
  the incomplete bundle.
- Only the allow-listed files directly inside the reported run directory are fetched. A recorded path outside it fails
  the host. Nothing from facts, the environment, the inventory, `no_log` values or the state ledger is written.
- ARF results are excluded by default because they can hold credential material.
- Bundle files have mode `0600` in `0700` directories owned by the controller user. A bundle is never overwritten, and
  its manifest is written last.

## Order

0. Refuse internal `__linux_compliance_evidence_*` variables supplied from outside the role (the generated
   `tasks/internal_variables.yml`, also the first task of `summary.yml`; FREES-153).
1. Validate the inputs and check that `linux_compliance_audited` exists.
2. Resolve `linux_compliance_evidence_output_dir` and require a normalised absolute path.
3. Skip the host when the audit wrote no evidence; in check mode print the planned bundle and write nothing.
4. `tasks/collect.yml`: plan the bundle (`freesecdev.linux_compliance.evidence_plan`), refuse an existing bundle and
   unsafe directories, create the directories, inspect the host files without following links
   (`freesecdev.linux_compliance.evidence_host_files`), fetch, set modes, hash, check and build the documents
   (`freesecdev.linux_compliance.evidence_documents`), write them, check every file
   (`freesecdev.linux_compliance.evidence_written`), write `bundle.json` last and check it. A failure removes the
   bundle directory and fails the host.
5. Publish `linux_compliance_evidence_bundle` and, with the same content, the internal run marker
   `__linux_compliance_evidence_run_bundle` (not cacheable). Only the marker counts a host as collected in the
   summary and in `collected.yml`; a `linux_compliance_evidence_bundle` from the inventory or `-e` does not.

## Variables

Defined in `meta/argument_specs.yml` and `defaults/main.yml`, which must agree.

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_evidence_output_dir` | `path` | `"evidence"` | Controller directory that receives `<inventory host>/<run_id>` bundles. A relative path is resolved against the playbook directory. Missing directories are created with mode `0700`; an existing one must have mode `0700` and not be a symbolic link. |
| `linux_compliance_evidence_include_arf` | `bool` | `false` | Also collect the ARF results, which hold OVAL system characteristics such as matched lines of `/etc/shadow`. |
| `linux_compliance_evidence_become` | `bool` | `true` | `become` on the fetch task. Set `false` only when the connecting user can read the root-owned evidence, for example in tests. |
| `linux_compliance_evidence_stale_exceptions` | `dict` | `{}` | The fact `linux_compliance_audit_stale_exceptions`, written as `exceptions/stale.json` when exceptions were applied. `playbooks/evidence.yml` passes it. |

The skeleton option `linux_compliance_evidence_include_host_facts` is removed: host facts can carry the environment
and are never written to a bundle.

## Result

`linux_compliance_evidence_bundle` holds `directory`, `run_id`, `manifest_sha256`, `files` (the bundle paths except
`bundle.json`), `excluded` (the recorded host files that were not collected) and `exceptions_applied`.

## Running

Use `playbooks/evidence.yml`. It audits with the audit role's `deferred.yml` entry point (with the `reached.yml`
entry point of this role in its `pre_tasks`, which refuses the run when a `__linux_compliance_evidence_*` variable
is already set for any inventory host or `localhost`, and which `summary.yml` requires), then, in one play per host, decides the gates with `enforce.yml` and
collects the evidence in an `always` section; no host fails in that play. It then runs the `summary.yml` entry point,
which names every target host without a bundle and writes the collection summary `collection-<collection_id>.json`
next to the bundles, and finally fails the hosts that a gate fails (`enforce.yml` again) and the hosts whose
collection failed (`collected.yml`). The role refuses an audit result whose gate is recorded as deferred and not
enforced. The `summary.yml` entry point takes `linux_compliance_evidence_summary_hosts` and publishes
`linux_compliance_evidence_collection` (`target_hosts`, `collected_hosts`, `missing_hosts`, `unreachable`,
`limited_out`, `no_audit_result`, `no_evidence_written`, `collection_failed`, `statuses`, `bundles`,
`collection_id`, `document`, `sha256`, `output_dir`, `path`). Pass the summary to the report with
`--evidence-collection` so that it names every target host without a bundle
([docs/evidence.md](../../docs/evidence.md#the-collection-summary)). Select hosts with
`-e linux_compliance_target_hosts=<group or host>`. Pass booleans as JSON, for example
`-e '{"linux_compliance_evidence_include_arf": true}'`; `-e linux_compliance_evidence_include_arf=true` passes a string
and the input validation fails closed. Read a bundle into the report with
`python -m tools.reporting --exceptions-file <reviewed file> --evidence-bundle <bundle directory>` ([docs/evidence.md](../../docs/evidence.md#in-the-report)).
