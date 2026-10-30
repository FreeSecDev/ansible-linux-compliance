# discover

Scope: role `freesecdev.linux_compliance.discover`. Audience: playbook authors and contributors.

Verifies the pinned SCAP datastream on the managed host and describes it: the benchmark, its profiles and the rules
that the requested profile selects.

## Status

Implemented (FREES-43). The role calls the modules `benchmark_info` and `profile_info`. It fails, without parsing the
content, when the SHA-256 of the datastream differs from the pinned value, and fails when the requested profile is not
in the datastream. No other profile or benchmark is ever substituted. The intended platforms in `meta/main.yml`
(Ubuntu 24.04 and RHEL 9 compatible, per [ADR 0010](../../docs/adr/0010-initial-os-and-benchmark-scope.md)) are
intentions, not tested support.

## Safety

The `discover` role never changes the managed host. Both modules only read the datastream, and the only other task
sets a fact in the memory of the play.

## Variables

Defined in `meta/argument_specs.yml` and `defaults/main.yml`, which must agree.

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_discover_profile` | `str` | `"cis_level1_server"` | ComplianceAsCode profile short identifier, without the XCCDF prefix. The initial implementation scope is the CIS Level 1 Server profile on Ubuntu 24.04 (ADR 0010). A profile is never substituted silently for another benchmark. |
| `linux_compliance_discover_content_path` | `str` | `""` | Required. Absolute path on the managed host of the datastream file, or of a directory that holds exactly one `-ds.xml` file. Both modules and the `audit` role resolve its real path first and read it only if the file, every directory of the resolved chain and every symlink followed are owned by root (or, for the discover modules without `become`, by the connecting user) and the file and directories are not writable by group or others (directories may be sticky instead); otherwise they fail with `unsafe_content_dir`. A root-owned `/opt` to `var/opt` symlink, as on image-mode RHEL, is accepted. See the [content directory rules](../../docs/audit.md#content-directory-rules). |
| `linux_compliance_discover_content_sha256` | `str` | `""` | Required. Pinned SHA-256 of the datastream, from `content/manifest.yml`. |

## Obtaining the content

The repository does not contain datastreams. Fetch the pinned content on the controller with `make content` (it runs
`tools/content/fetch_content.py`; pass `--from-file <zip>` to it when offline), copy the datastream to the managed host
and pass its path and its `sha256` from `content/manifest.yml`
([ADR 0015](../../docs/adr/0015-content-acquisition-and-pinning.md)). That datastream has its Script Check Engine
checks and scripts removed. A datastream that still has them, such as one taken straight from a ComplianceAsCode
release, fails with `script_check_content` ([ADR 0026](../../docs/adr/0026-no-content-scripts-on-hosts.md)).

## Result

The role sets the fact `linux_compliance_discovered` with `content_path`, `content_sha256`, `benchmark_id`,
`benchmark_version`, `profiles`, `profile_id`, `rule_ids` (full XCCDF identifiers, sorted) and `rules` (identifier,
severity and title). The audit role uses `rule_ids` as the rules that a scan must report on.

## Running

Select hosts with `-e linux_compliance_target_hosts=<group or host>`. Only `-e` works: play `hosts:` is evaluated
before inventory variables apply, so setting it in `group_vars` has no effect. Pass booleans as JSON, for example
`-e '{"linux_compliance_remediate_enabled": true}'`; `-e linux_compliance_remediate_enabled=true` passes a string and
the input validation fails closed.
