# Collection design

The repository root is the collection root of `freesecdev.linux_compliance`. This page describes the skeleton and how
its tooling works. The component responsibilities are in the
[component map](../.agents/skills/architecture/references/component-map.md); the findings model is recorded in
[ADR 0013](adr/0013-normalized-findings-model.md).

Jira: FREES-39 (skeleton, metadata), FREES-26 (findings model), FREES-48 (OpenSCAP backend), FREES-69 (ansible-lint hook), FREES-40 (role skeletons), FREES-41 (playbooks).

## Layout

| Path | Purpose |
|---|---|
| `galaxy.yml` | Namespace `freesecdev`, name `linux_compliance`, Apache-2.0, repository links, tags and `build_ignore` |
| `meta/runtime.yml` | `requires_ansible: ">=2.20.0"` |
| `plugins/module_utils/compliance/` | Shared target-side code: `model.py` (findings model), `process.py` (process helper), `scanner.py` (backend interface and registry), `openscap.py` (OpenSCAP backend and XCCDF parser), `backends.py` (composition root) |
| `plugins/{modules,action,filter,lookup}/` | Created together with the first plugin of each kind; Git cannot track empty directories and Galaxy does not need placeholders |
| `changelogs/` | antsibull-changelog `config.yaml`, `changelog.yaml` and `fragments/`; one fragment per Jira issue |
| `tests/unit/plugins/` | Unit tests that run under pytest and `ansible-test units` |
| `tests/fixtures/` | Synthetic XCCDF results and hostile samples used by the unit tests; inert data, shipped with the tests in the tarball |
| `roles/` | The `discover`, `audit`, `remediate`, `verify` and `evidence` role skeletons (FREES-40) |
| `playbooks/` | Orchestration playbooks `audit.yml`, `remediate.yml` and `verify.yml` |
| `.ansible-lint` | ansible-lint `production` profile |

Everything else (`tools/`, `.agents/`, `.github/`, the Python tooling files, `docs/planning`, `docs/research`) supports
development and is listed in `build_ignore`, so it is not part of the tarball.

## Roles and playbooks

The roles are skeletons. Each one validates its inputs and then fails with a message that names the issue that
tracks its implementation, so a playbook can never report success for work that does not exist yet. They use only
`ansible.builtin.assert` and `ansible.builtin.fail`. The platforms in each `meta/main.yml` are intended targets
([ADR 0010](adr/0010-initial-os-and-benchmark-scope.md)); none is tested.

| Role | Changes the host | Tracked in | Variables (default) |
|---|---|---|---|
| `discover` | Never | FREES-43 | `linux_compliance_discover_profile` (`cis_level1_server`) |
| `audit` | Never | FREES-49 | `linux_compliance_audit_profile` (`cis_level1_server`), `linux_compliance_audit_fail_on_noncompliant` (`false`) |
| `remediate` | Only with explicit opt-in | FREES-52 | `linux_compliance_remediate_enabled` (`false`), `linux_compliance_remediate_allow_disruptive` (`[]`), `linux_compliance_remediate_profile` (`cis_level1_server`) |
| `verify` | Never | FREES-54 | `linux_compliance_verify_profile` (`cis_level1_server`), `linux_compliance_verify_fail_on_regression` (`true`) |
| `evidence` | Never; writes on the controller only | FREES-51 | `linux_compliance_evidence_output_dir` (`evidence`), `linux_compliance_evidence_include_host_facts` (`false`) |

Per-rule and per-family toggles do not exist yet; they are generated from the rule catalogue by FREES-55
([ADR 0011](adr/0011-control-toggles-and-cleanup.md)). The variables of each role are documented in its
`README.md` and in `meta/argument_specs.yml`.
`tools/roles/check_role_specs.py` (part of `make lint-ansible`) fails when a role's `defaults/main.yml` and
`meta/argument_specs.yml` disagree in names, types or values, when an option lacks a description or default, or when
a variable lacks the `linux_compliance_<role>_` prefix.

The playbooks `playbooks/audit.yml`, `playbooks/remediate.yml` and `playbooks/verify.yml` only reference roles by
FQCN, for example `freesecdev.linux_compliance.audit`. The target comes from the variable
`linux_compliance_target_hosts`, which defaults to the group `linux_compliance` so that no play ever targets `all` by accident (usage in
[playbooks](playbooks.md)). `become` is scoped to the role entry and is never set for the whole play; the
`discover` role runs without it.

## Supported versions

`requires_ansible` is `>=2.20.0`. The ansible-core support matrix lists 2.20 with managed-node Python 3.9 to 3.14, so
code in `plugins/modules` and `plugins/module_utils` must run on Python 3.9 and use only the standard library
([ADR 0013](adr/0013-normalized-findings-model.md)). The developer environment pins ansible-core 2.21.5, the latest
release that is at least seven days old, which is used by `ansible-lint`, `ansible-test` and `ansible-galaxy`.

## The temporary collection tree

`ansible-test` only runs inside a path of the form `ansible_collections/<namespace>/<name>`, and the repository is not
laid out that way. The repository is not restructured. Two generated trees under `build/` (ignored by Git) bridge the
gap:

- `make collection-tree` copies the collection files tracked by Git into
  `build/collection/ansible_collections/freesecdev/linux_compliance`, initializes a throwaway Git repository there so
  that `ansible-test` can enumerate the files, and excludes `tests/output`. It is a copy, not a symlink, because
  `ansible-test` resolves its working directory and rejects symlinks that leave the tree. Only collection content is
  copied, so developer tooling is never sanity-tested as collection code.
- `make collection-link` creates `build/collections/ansible_collections/freesecdev/linux_compliance/plugins`, a
  symlink to `plugins/`. pytest, mypy, Pyright and Pylint put `build/collections` on their search path so that tests
  import `ansible_collections.freesecdev.linux_compliance.plugins...`, the same name `ansible-test` uses. Coverage
  resolves the symlink, so measured files are the real ones.

The link directory also links `roles/`, so ansible-lint can resolve the role references in the playbooks. `make lint-ansible` and the ansible-lint hook set
`ANSIBLE_COLLECTIONS_PATH` to `build/collections` for that one invocation only; the repository has no `ansible.cfg`,
which would override users' own Ansible configuration, and `ansible.cfg` is listed in `build_ignore`.
`make install` creates the links; the targets that need them depend on it.

## Targets

| Target | What it does |
|---|---|
| `lint-ansible` | `ansible-lint` with the `production` profile, then `antsibull-changelog lint` |
| `test-unit`, `test-coverage` | pytest including the plugin tests; coverage requires 100% for `tools/` and `plugins/` |
| `test-sanity` | `ansible-test sanity --local` on the temporary tree, no Docker |
| `test-ansible-units` | `ansible-test units --venv` on Python 3.9, 3.12 and 3.14, no Docker |
| `package` | `ansible-galaxy collection build` repacked with a canonical `FILES.json`, into `dist/`, with `dist/SHA256SUMS` |
| `package-check` | Builds twice from differently ordered trees and compares the SHA-256 values |

`ansible-test sanity` runs with `--local` rather than `--venv`. Sanity tests install their own pinned requirements in
isolated virtual environments either way, and `--local` avoids a second delegation virtual environment inside the
tree, which adds minutes and files that the `symlinks` and `pylint` tests then inspect. The interpreters that
`compile` and `import` need (3.9, 3.10, 3.11, 3.13, 3.14) are installed with `uv python install`, so those tests run
on every managed-node Python version instead of being skipped. Units use `--venv` because each interpreter needs its
own pytest.

`package` builds from the temporary tree, so `build_ignore` is applied to a tree that already holds only collection
content. Two things in the `ansible-galaxy` output depend on the machine: it stamps the build time into the archive,
and it writes the `FILES.json` entries in `os.listdir` order, which differs between filesystems. The target therefore
unpacks the result, sorts the `FILES.json` entries by name, recomputes the `FILES.json` checksum in `MANIFEST.json`,
asserts that the order is sorted, and repacks with sorted members, owner 0, a zero modification time and a gzip header
without name or time. `make package-check`, which CI runs, builds twice from trees created in opposite file order and
fails unless the two SHA-256 values are identical. The remaining assumption is the same `tar`, `gzip` and `jq`
behaviour; byte-identical output across different machines was checked by comparing a local build with the CI build of
the same commit (see the pull request that introduced it).

## OpenSCAP backend

Jira: FREES-48. Code: `plugins/module_utils/compliance/scanner.py`, `openscap.py` and `backends.py`; the decisions are in
[ADR 0004](adr/0004-audited-process-execution.md) (process policy) and
[ADR 0013](adr/0013-normalized-findings-model.md) (outcomes).

### Interface

`scanner.py` is backend-neutral and standard library only (Python 3.9 or newer).

| Item | Contract |
|---|---|
| `ScanSettings` | `content_root`, `output_root` (absolute), `timeout_seconds` (default 1800, at most 3600) and `max_result_bytes` (default 128 MiB). Fixed when a backend is created |
| `ScanRequest` | `run_id`, `host`, `benchmark_id`, `profile_id`, `content_path`, `output_dir`, a required non-empty `expected_rule_ids` (the rules that the profile selects, supplied by the caller) and an optional `tailoring_path`. `benchmark_id`, `host` and `run_id` are required because a `ScanRun` needs them even when the scanner fails |
| `ScanBackend.audit(request)` | Returns a `model.ScanRun`. Raises `ScanRequestError` for an invalid or unsafe request, before anything runs |
| `BackendRegistry` | `register(name, factory)`, `create(name, settings)`, `names()`. Orchestration asks `backends.default_registry()` for a backend by name and never imports `openscap` |

The factory receives only `ScanSettings`. The `runner` and `clock` parameters of `OpenScapBackend` exist so that unit
tests can inject a fake process layer; they are not settings, are not reachable through the registry and are never
passed by production code. The repository rule that bans the `policies`, `trusted_dirs` and `owner_uid` keywords in
`plugins/` still applies.

### Running oscap

The backend builds `oscap xccdf eval --profile <id> [--tailoring-file <path>] --results-arf <dir>/results-arf.xml
--results <dir>/results.xml <datastream>` and runs it only through `process.run`. It never passes `--remediate` or
`--fetch-remote-resources`, and the helper would refuse both. Content, tailoring and output paths go through
`process.confined_path`, so `..` escapes and symlinks are rejected. The output directory is created by the backend
with mode 0700, must not exist, and is never reused, so existing files are never overwritten. The SHA-256 of the
datastream is recorded in `ScanRun.content`; the SHA-256 of a tailoring file goes into `content.source` next to the
datastream name. Both are computed before the scan and again afterwards, and a difference is a scanner failure.

| Situation | Result |
|---|---|
| Exit status `0` and results with no `fail` or `error` | `completed` |
| Exit status `2` and at least one `fail` or `error` | `completed`; a failed rule is a normal result |
| Exit status `0` with a failed or errored rule, or `2` with none | `failed`: the status contradicts the results |
| Any other exit status, including a signal | `failed` |
| Timeout | `timed_out` |
| `oscap` missing or not startable | `failed` |
| Unreadable, hostile or incomplete results, results for another profile or benchmark, a result for a rule the profile does not select, a duplicate result, or a rule-result or result in another namespace | `failed` |
| Exit status `2` and a rule of the profile without a result | `completed`; that rule is an `error` finding |

A `failed` or `timed_out` run carries an `error_message` and only `error` findings, one per `expected_rule_ids` entry.
A scanner failure is never `pass` or `fail`, and a run that is not `completed` counts every expected rule as `error` and
is never summarised as compliant (ADR 0013, amendment of FREES-48).

### XCCDF results parser

Results come from a host and are untrusted. The parser uses only the standard library and layers its defences:

1. The file must be a regular file and not a symlink. It is streamed in 1 MiB chunks into the parser and bounded by
   `max_result_bytes` before and while it is read, so memory does not grow with its size (about 25 MB peak for a 115 MB
   file with 1,000,000 elements and 4,600 rules, measured on Python 3.9 and 3.12).
2. Any `<!DOCTYPE` or `<!ENTITY` in the raw bytes is rejected before the chunk that holds it is parsed, including a marker
   split across two chunks, so entity expansion (billion laughs) and external entities (XXE) cannot occur. UTF-16 and
   UTF-32 byte order marks are rejected and the parser is told to read UTF-8, so other encodings are malformed.
3. The expat parser is created directly with `SetParamEntityParsing(XML_PARAM_ENTITY_PARSING_NEVER)` and has no
   external entity handler; its DOCTYPE, entity declaration and external entity handlers reject again if the byte check
   were bypassed. The standard library is safe enough here because of this layering, not because of the expat version:
   the amplification limits of expat 2.4.0 and later, and the differing expat builds of Python 3.9 to 3.14, are not
   relied upon.
4. Element count (default 2,000,000) and depth (default 64) are bounded while parsing.
5. Only the XCCDF 1.2 namespace is accepted; a missing or other namespace is an error, and a `rule-result` or `result`
   element in another namespace is an error instead of being dropped.
6. Elements are never stored. Each `rule-result` is reduced to its identifier, severity and result text when it ends.
   Text is read only before the first child element of an element (never merged from after a child), and a `result` or
   `ident` element with children is malformed.

`rule-result/result` values go through `model.map_xccdf_result`, so unknown values become `error` with a message.
The rule ID (full `xccdf_*_rule_*` form), severity (`unknown` when absent or unrecognised), profile ID, benchmark ID
and version, and the start and end times (normalised to UTC; a timestamp without a zone is an error) are read into
`model` types. A rule that appears twice, a rule ID that the model rejects, or a missing profile, version or time is a
parse error. Parse errors never produce a pass.

### Tests and what is not covered

Unit tests fake the process layer and run no `oscap`. They use hand-written synthetic XCCDF fixtures in
`tests/fixtures/xccdf/` and hostile samples in `tests/fixtures/adversarial/` (billion laughs, external entity, DOCTYPE,
parameter entity, oversized, deeply nested, unknown result value, missing namespace, truncated, non-UTF-8 stored as hex because sanity tooling rejects invalid text files); cases that
depend on the filesystem, such as a symlinked results path, are created inside the tests. A real `oscap`
run against real content belongs to a later Molecule story and is not covered here.

## Adding plugins

1. Put target-side logic in `plugins/module_utils/compliance/<area>.py`, standard library only and Python 3.9 compatible.
2. Add the module in `plugins/modules/`, with complete `DOCUMENTATION`, `EXAMPLES` and `RETURN`.
3. Mirror the tests under `tests/unit/plugins/`, keeping 100% line and branch coverage of `plugins/`.
4. Add a changelog fragment in `changelogs/fragments/`.
5. Run `make ci`.
