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

1. Validate the inputs and check that `linux_compliance_audited` exists.
2. Resolve `linux_compliance_evidence_output_dir` and require a normalised absolute path.
3. Skip the host when the audit wrote no evidence; in check mode print the planned bundle and write nothing.
4. `tasks/collect.yml`: plan the bundle (`freesecdev.linux_compliance.evidence_plan`), refuse an existing bundle and
   unsafe directories, create the directories, inspect the host files without following links
   (`freesecdev.linux_compliance.evidence_host_files`), fetch, set modes, hash, check and build the documents
   (`freesecdev.linux_compliance.evidence_documents`), write them, check every file
   (`freesecdev.linux_compliance.evidence_written`), write `bundle.json` last and check it. A failure removes the
   bundle directory and fails the host.
5. Publish `linux_compliance_evidence_bundle`.

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

Use `playbooks/evidence.yml`. It runs the audit playbook with the result gates deferred
(`linux_compliance_audit_defer_gate`), collects every audited host, including hosts with failed rules and scans that
did not complete, runs the `summary.yml` entry point to name every target host without a bundle, and then enforces the
gates with the audit role's `gate.yml`. The `summary.yml` entry point takes `linux_compliance_evidence_summary_hosts`
and publishes `linux_compliance_evidence_collection` (`target_hosts`, `collected_hosts`, `missing_hosts`,
`no_audit_result`, `no_evidence_written`, `collection_failed`, `bundles`). Select hosts with
`-e linux_compliance_target_hosts=<group or host>`. Pass booleans as JSON, for example
`-e '{"linux_compliance_evidence_include_arf": true}'`; `-e linux_compliance_evidence_include_arf=true` passes a string
and the input validation fails closed. Read a bundle into the report with
`python -m tools.reporting --exceptions-file <reviewed file> --evidence-bundle <bundle directory>` ([docs/evidence.md](../../docs/evidence.md#in-the-report)).
