# evidence

Scope: role `freesecdev.linux_compliance.evidence`. Audience: playbook authors and contributors.

Exports findings and run metadata as an evidence bundle on the controller.

## Status

Skeleton only. The role validates its inputs and then fails with "not implemented yet". Implementation is
tracked in FREES-51. The intended platforms in `meta/main.yml` (Ubuntu 24.04 and RHEL 9 compatible, per
[ADR 0010](../../docs/adr/0010-initial-os-and-benchmark-scope.md)) are intentions, not tested support.

## Safety

The `evidence` role never changes the managed host; it writes only on the controller.

## Variables

Defined in `meta/argument_specs.yml` and `defaults/main.yml`, which must agree.

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_evidence_output_dir` | `path` | `"evidence"` | Controller directory that receives the evidence bundle. A relative path is resolved against the playbook directory. |
| `linux_compliance_evidence_include_host_facts` | `bool` | `false` | Include gathered host facts in the bundle. Facts can identify the host, so they are excluded by default. |
