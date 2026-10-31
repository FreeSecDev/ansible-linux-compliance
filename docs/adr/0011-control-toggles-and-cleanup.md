# 0011. Per-rule and per-topic control toggles with cleanup on disable

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** project owner, lead architect
- **Jira:** pending (remediation epic)
- **Pull requests:** pending

## Context

The project owner requires that every security rule can be switched on or off through variables, individually or
per topic. For example, it must be possible to disable everything related to auditd. When a control that was
previously enabled and applied is disabled, the collection must clean up what it applied, not merely stop managing it.

Ansible variable precedence replaces dictionaries rather than merging them, so nested toggle dictionaries would be
overwritten wholesale by any inventory layer that sets one key.

## Decision

### Variables

- One topic toggle per control family: `linux_compliance_<family>_enabled`, for example
  `linux_compliance_auditd_enabled`, `linux_compliance_ssh_enabled`, `linux_compliance_sysctl_enabled`.
- One toggle per rule: `linux_compliance_rule_<rule_short_id>_enabled`, for example
  `linux_compliance_rule_sshd_disable_root_login_enabled`. Its default is the value of the rule's family toggle.
- All toggles are flat booleans, so any inventory layer can override a single rule or topic.
- A rule is **effective** when the global `linux_compliance_remediate_enabled` is true, its rule toggle is true, the
  rule belongs to the selected profile, and disruptive families are allow-listed.
- The rule catalogue (`roles/remediate/vars/rules.yml`) lists every implemented rule with its family, ComplianceAsCode
  identifier, disruptive flag and reversibility. Defaults and argument specs are generated from it and checked in CI,
  so no rule can exist without a toggle.

### Apply and revert

Every implemented rule has both an apply path and a revert path. The revert strategy is fixed per rule:

| Strategy | Used when | Revert action |
|---|---|---|
| Owned drop-in | The service supports drop-in directories (`/etc/sysctl.d`, `/etc/audit/rules.d`, `/etc/ssh/sshd_config.d`, `/etc/modprobe.d`, `/etc/security/*.d`) | Remove the collection-owned drop-in file and reload |
| Recorded value | A shared file or setting must be edited in place | Restore the prior value recorded in the state ledger |
| Recorded package or service state | A package is installed or removed, or a service is enabled, disabled or masked | Restore the recorded prior state |
| Irreversible | Partitioning, mount layout or similar | Never reverted automatically; cleanup reports a manual action and links the runbook |

Owned drop-ins are preferred, because cleanup then needs no history and remains correct even if the ledger is lost.

### State ledger

A typed module `freesecdev.linux_compliance.control_state` maintains
`/var/lib/freesecdev/linux_compliance/state.json`. The file is owned by root with mode `0600` and is written atomically.
For each applied rule it records the rule identifier, family, revert strategy, prior values, collection version and the
time it was applied. A rule is cleaned up when it is not effective but the ledger records it as applied. Successful
cleanup removes the ledger entry. If the ledger is missing or a prior value is unknown, cleanup removes owned drop-ins
and reports `cleanup incomplete` for the rest. It never guesses a previous value.

### Cleanup safety

- Cleanup runs in the remediate role and honours check mode and diff mode.
- Cleanup of a disruptive family requires the same allow-list entry as applying it, because reverting SSH, PAM or
  firewall settings can also lock operators out.
- Cleanup is idempotent: a second run with the same toggles reports zero changes.
- Package removal during cleanup happens only when the ledger shows the collection installed the package.

### Audit and reporting

Disabled rules are excluded from the scan through a generated XCCDF tailoring file. They are reported as
`disabled`, a distinct outcome that names the controlling variable. They are never reported as `pass` or silently
dropped. The exceptions report lists disabled rules that have no matching exception record, so governance can require
justification without blocking operators.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Nested toggle dictionaries | Replaced wholesale by Ansible variable precedence; one override silently drops the rest |
| Toggle only; no cleanup | Leaves previously applied hardening behind, contrary to the requirement |
| Infer prior state from distribution defaults | Guessing; wrong on customised hosts |
| Ansible tags for selection | Tags are run-time selection, not persistent configuration, and cannot drive cleanup |

## Benefits

Operators can turn off any rule or topic, and the host returns to its pre-collection state for that control.

## Trade-offs

Every rule needs a tested revert path, roughly doubling the remediation test surface. The ledger is new on-host state.

## Security implications

The ledger reveals which controls are applied, so it is root-only. Disabling a control reduces protection, so disabled
rules are always visible in reports. Cleanup of disruptive families is gated like their application.

## Operational consequences

Molecule gains a toggle-and-cleanup scenario for every family. It applies the family, disables it, asserts the
pre-collection state is restored, and asserts a further run changes nothing. The support matrix records reversibility
per rule.

## Amendment 2026-10-25: state ledger and file-I/O helper (FREES-56)

The ledger is implemented by `plugins/module_utils/compliance/ledger.py` (typed model, strict JSON, transactions),
`plugins/module_utils/compliance/fileio.py` (the single audited file-I/O helper) and the module
`plugins/modules/control_state.py`. Everything is standard-library only and runs on Python 3.9 to 3.14.

### Ledger format

`/var/lib/freesecdev/linux_compliance/state.json` is a JSON document with exactly the keys `schema_version` (integer,
currently `1`) and `entries` (a list sorted by `rule_id`). It is serialised deterministically (sorted keys, two-space
indent, ASCII, trailing newline). Each entry has exactly these keys:

| Key | Contract |
|---|---|
| `rule_id` | Full XCCDF rule identifier, unique in the ledger |
| `family` | Control family, a lower-case slug of at most 64 characters |
| `revert_strategy` | `owned_dropin`, `recorded_value`, `recorded_state` or `irreversible` (the `RevertStrategy` of the findings model) |
| `prior_values` | List of `{name, value, sensitive}` sorted by name, at most 64. `value` is a string of at most 4096 characters or `null` when the setting did not exist. `recorded_value` and `recorded_state` need at least one; `owned_dropin` and `irreversible` take none |
| `collection_version` | `MAJOR.MINOR.PATCH` with an optional pre-release or build suffix |
| `applied_at` | UTC `YYYY-MM-DDTHH:MM:SSZ` |

Reads are strict: at most 4 MiB and 4096 entries; invalid UTF-8, malformed JSON, duplicate keys at any depth, `NaN`,
`Infinity`, excessive nesting, unknown or missing keys, wrong types, a rule listed twice and invalid fields are
`corrupt` (a `schema_version` that is not an integer is `corrupt` too, and lone surrogates in values are invalid); another integer `schema_version` is `unsupported_schema`. A corrupt ledger is an error and is never reset, repaired
or replaced; the `cleanup incomplete` behaviour of this ADR applies only to a missing ledger. A ledger with a schema
version this collection does not know is not rewritten.

`record` is idempotent: an identical entry (ignoring `applied_at`) is left untouched, so the original time and prior
values survive repeated runs. A differing entry is a `conflict` unless `replace` is set, so the true prior value cannot
be overwritten by accident. Sensitive prior values are stored, because reverting needs them, in the root-only file. They
reach the module through `no_log` options and are redacted (`value: null`, `redacted: true`) from every return value,
diff and error unless `get` or `list` is called with `reveal_sensitive` (the task must then set `no_log`).

### File-I/O helper and guard exemption

The repository guard allows only `os.path` and bans `fcntl`, `errno` and `time` in `plugins/`. Safe state files need
`os.open` with `O_NOFOLLOW`, directory-relative operations, `fsync`, `rename`, `fchmod` and `flock`, so, as for
`process.py` (ADR 0004), exactly one file gets a narrow exemption: `plugins/module_utils/compliance/fileio.py`
(`FILE_IO_HELPER` in `tools/lint/repo_rules/names.py`).

- In that file only, `import os`, `import fcntl`, `import errno` and `import time` are allowed, and each may be used only
  as `module.attribute` with an attribute from `FILE_IO_ATTRIBUTES`: `os` (`O_RDONLY`, `O_WRONLY`, `O_CREAT`, `O_EXCL`,
  `O_NOFOLLOW`, `O_DIRECTORY`, `O_NONBLOCK`, `O_CLOEXEC`, `open`, `close`, `read`, `write`, `fstat`, `stat`, `fsync`,
  `fchmod`, `mkdir`, `rename`, `scandir`, `unlink`, `urandom`, `supports_dir_fd`), `fcntl` (`flock`, `LOCK_EX`, `LOCK_NB`),
  `errno` (`ELOOP`, `EMLINK`, `ENOTDIR`) and `time` (`monotonic`, `sleep`). Any other attribute, a bare name, an alias
  (`import os as o`) or a `from` import fails.
- Every other rule still applies to that file: process, fork, spawn and exec names, `getattr` with a computed name,
  banned keywords, dict splats and the comment ban. The attribute `__self__` is banned in all plugin code, because
  `os.open.__self__` is the whole `posix` module and would bypass the allow-list. No other file may import these
  modules; tests show this for several paths, and a repository test asserts that only the helper imports `fcntl`.
- Only `ledger.py` may import `fileio`, because `open_directory` takes the expected owner positionally (the guard bans
  the `owner_uid` keyword). Any other plugin file that imports it fails the guard, with tests for several paths and a
  repository test.
- The test-only keywords `state_dir` and `lock_timeout` join `owner_uid` in the banned keywords. The `Ledger` seams
  `state_dir`, `owner_uid` and `lock_timeout` are keyword-only, like those of `process.run`, so they cannot be passed
  positionally either (`Ledger('/tmp', 1)` is a `TypeError`). The module constructs `Ledger()` without arguments.
- Unit tests pin the attribute table and the exemption. Bandit, Ruff and `ansible-test sanity` need no suppression.

The helper's contract:

- `open_directory(path, owner_uid, create=...)` walks the path from `/` one component at a time with
  `O_NOFOLLOW | O_DIRECTORY` relative to the parent descriptor, so no component may be a symlink. The final directory
  must be owned by the expected user (root in production) with no group or world bits; missing components are created
  with mode `0700`. An existing directory is never repaired.
- `SafeDirectory` performs every operation relative to the directory descriptor, so replacing the path afterwards
  has no effect. `read` opens with `O_NOFOLLOW | O_NONBLOCK` and then vets the opened descriptor: regular file, owner,
  no group or world bits, one hard link, size within the bound, and a bound on the bytes actually read.
- `write` creates a temporary file in the same directory (`O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`, forced with
  `fchmod`), checks its owner, writes fully, `fsync`s it, renames it over the target and `fsync`s the directory. On any
  failure, including `KeyboardInterrupt`, the temporary file is removed and the old file is intact. A temporary name that
  already exists is an error and is never unlinked.
- `lock` takes an exclusive `flock` on the directory descriptor with a timeout (30 s), serialising concurrent runs
  without an extra lock file. Closing the descriptor releases it. Record and remove hold the lock across read, modify and
  write; reads rely on the atomic rename and do not lock.
- Failures are `SafeFileError` with a stable reason (`unsafe_path`, `symlink`, `not_regular`, `not_directory`,
  `wrong_owner`, `unsafe_mode`, `hardlinked`, `too_large`, `lock_timeout`, `io_error`, `unsupported_platform`), which the
  module returns as `error_type`. Platforms without directory-relative `open`, `mkdir`, `rename`, `stat` and `unlink`
  are refused rather than degraded.
- Check mode never creates or writes anything: it opens the directory without creating it and computes the result.

### Threat model

| Threat | Mitigation |
|---|---|
| Symlink planted at the ledger, the directory or an ancestor | `O_NOFOLLOW` on every component and on the file; a symlink is `symlink`, nothing is followed or replaced |
| Swap between check and use (TOCTOU) | No check by path: the descriptor that was opened is the one that is vetted and used; the directory is held by descriptor; tests swap the file and the directory during the operation |
| Hard link, FIFO or device as ledger | `st_nlink == 1`, regular file only, `O_NONBLOCK` so a FIFO cannot hang the run |
| Ledger written or read by another user | Owner must be root (injectable only in tests), no group or world bits on file and directory |
| Oversized, deeply nested or hostile JSON | 4 MiB bound before and during reading, recursion errors are `corrupt`, strict parser hooks |
| Torn write or crash | Write-to-temporary, `fsync`, atomic `rename`, directory `fsync`; the old ledger is intact after any failure |
| Lost update from concurrent runs | Exclusive `flock` across read-modify-write, with a timeout instead of an unbounded wait |
| Silent reset hiding applied controls | Corruption is an error; the ledger is never recreated automatically |
| Redirecting the ledger through module arguments | The module has no path or owner argument; `state_dir`, `owner_uid` and `lock_timeout` are keyword-only and banned keywords in plugin code, and only `ledger.py` may import the helper |
| Secret leakage | Sensitive values come from `no_log` options and are redacted from results, diffs and errors; the file is root-only |

Residual risks: an attacker who is root, or who can replace `/`, `/var` or `/var/lib`, already controls the host; the
ancestors are checked for symlinks but not for ownership. Network file systems may not honour `flock`; `/var/lib` is
expected to be local. A crash between creating and renaming a temporary file leaves a hidden `.state.json.<16 hex>.tmp` of
mode `0600` behind, which may hold a sensitive prior value. It is never read, and every write sweeps it away: while
holding the lock, `record` and `remove` call `SafeDirectory.sweep_temporaries`, which removes only entries named
exactly that pattern that are regular files owned by the expected user (symlinks, directories and other names are left
alone), through the directory descriptor. Check mode, unchanged records and failed operations do not sweep.
Platforms without `O_NOFOLLOW`, `O_DIRECTORY`, `fcntl.flock` or directory-relative operations fail with the structured
error `unsupported_platform` instead of an `AttributeError` or `ImportError`.

### Tooling consequences

- `ansible-test sanity validate-modules` demands a GPLv3 header in every module, while the collection is Apache-2.0.
  The header is not added, because it would misstate the licence of the file. Instead, `tests/sanity/ignore-2.20.txt`
  and `ignore-2.21.txt` gain exactly `plugins/modules/control_state.py validate-modules:missing-gplv3-license`; the
  repository test that pins the ignore files lists both entries, and every new module needs its own reviewed line.
- `validate-modules` also requires imports below `DOCUMENTATION`, `EXAMPLES` and `RETURN`. Ruff `E402` is therefore
  relaxed for `plugins/modules/**` only. Pylint `wrong-import-position` stays enabled: `make lint-pylint` runs Pylint
  twice, over `tools`, `tests` and `plugins` with `plugins/modules` ignored, and over `plugins/modules` alone with that
  one message disabled (the directory list is `PYLINT_MODULE_DIRECTORIES` in the Makefile). A unit test fails if the
  message enters the global disable list. Both are justified in `pyproject.toml`.
- ansible-core has no `py.typed` marker. `typings/ansible/module_utils/` holds minimal stubs for `AnsibleModule` and
  `patch_module_args`, which Pyright reads as its default `stubPath` and mypy through `mypy_path`. The directory is not
  part of the collection.

## Amendment 2026-10-25: disabled rules in the audit (FREES-49)

The audit side of this decision is implemented by `freesecdev.linux_compliance.compliance_scan` and
`plugins/module_utils/compliance/audit.py` ([audit guide](../audit.md)).

- The toggle variables are not generated yet (FREES-55). Until they are, the module takes a validated `disabled_rules`
  list (`rule_id`, optional `disabled_by`) and the audit role passes `linux_compliance_audit_disabled_rules`. The
  default `disabled_by` is `linux_compliance_rule_<short id>_enabled`; a short identifier that is not a valid variable
  name needs an explicit `disabled_by`, which must match `linux_compliance_<name>_enabled`. FREES-55 will compute the
  list from the toggles; the module interface does not change.
- Disabled rules are excluded through a generated XCCDF 1.2 tailoring file, as decided above: a profile with the
  identifier `<profile>_freesecdev_audit_tailored` that `extends` the requested profile and deselects each disabled rule.
  It is written into the new run directory with mode `0600`, passed with `--tailoring-file`, and its SHA-256 is recorded
  in the provenance (ADR 0013, amendment of FREES-48). The reported scan run keeps the requested profile identifier.
- Each disabled rule is a `disabled` finding with `disabled_by` set and a message that names the variable. In a run
  that did not complete it is an `error` finding instead, because ADR 0013 allows only `error` findings there; the
  message still names the variable. A disabled rule that the profile does not select is an argument error, and
  disabling every rule of a profile is `nothing_to_scan`. Nothing is silently dropped.

## Amendment 2026-10-26: remediation dispatcher (FREES-52)

The remediate role implements the dispatch side of this decision ([remediation guide](../remediation.md)). These
refinements apply.

- **Effective state.** The filter `freesecdev.linux_compliance.remediation_plan` resolves every catalogued rule. The
  toggle state is the rule toggle when it is set, else the family toggle when it is set, else on; the variable that
  switched a rule off is its `disabled_by`. The action is, in this order: `skip` when the global opt-in is false
  (nothing is read or changed, cleanup included); `skip` when the family is disruptive and not allow-listed (apply and
  cleanup alike; an applied rule is reported as `pending_cleanup`); `apply` when the toggle is on and the profile selects
  the rule; otherwise `cleanup` when the ledger records the rule, `manual` instead when the rule is irreversible, and
  `none` when nothing was applied. The ledger entry of a `manual` rule is kept.
- **Profile membership** comes from `linux_compliance_discovered.rule_ids`, the rules that the digest-verified
  datastream selects for the discovered profile, not from a list in the catalogue. With the opt-in the role requires
  that fact for the same profile, so remediation never applies a rule that the content does not select and never
  substitutes a profile. Switching to a profile that does not select an applied rule cleans that rule up.
- **Family toggles default to on.** Until FREES-55 generates the defaults, a toggle that is not set counts as on; the
  global opt-in is the gate. A rule toggle still wins over its family toggle in both directions.
- **Unknown names are errors.** Every variable matching `^linux_compliance_.+_enabled$` is examined. Only the declared
  role variable `linux_compliance_remediate_enabled` is ignored. A `linux_compliance_rule_*_enabled` name must be a
  catalogued rule toggle, a name in the namespace of a role (`audit`, `discover`, `evidence`, `remediate`, `verify`)
  that is not a declared variable of that role is an error (so `linux_compliance_audit_enabled`, a likely typo for
  the auditd topic, fails), every other name must be a registered family toggle, and every toggle must be a boolean.
  Family names may therefore not equal or start with a role name followed by `_`, nor be `rule` or start with `rule_`.
  The allow-list accepts only disruptive families of the registry.
- **Disruptive is a family property.** The registry in `roles/remediate/vars/rules.yml` flags each family, and every
  rule repeats the flag of its family, which the filter checks. `auditd` and `services` join the disruptive families of
  the `ansible-collection` skill (SSH, PAM, sudo, firewall, network, bootloader, mounts, crypto policy), because audit
  settings can halt the host when the log fills and disabling services can stop workloads. The filter pins these ten
  families (`DISRUPTIVE_FAMILIES`) and fails when a registry marks one of them non-disruptive, so overriding the
  registry with `-e`, `set_fact` or role parameters cannot bypass the allow-list. A skipped disruptive rule is
  `pending_cleanup` when the ledger records it and it would not be applied (toggled off or no longer in the profile).
- **Deterministic order.** Families are dispatched in registry order (non-disruptive first, bootloader last), and a
  family file cleans up before it applies; rules are sorted by identifier.
- **Ledger writes belong to family files.** The dispatcher reads the ledger once (`control_state` `list`) and passes
  each rule's entry to its family. The family records the prior state before the first change and only when no entry
  exists, so repeated runs never overwrite the true prior value, and removes the entry after a successful cleanup.
- **Orphaned ledger entries**, for rules that the catalogue of the running collection version does not contain, are
  reported and left alone rather than cleaned up by guesswork.
- **Tags do not select rules.** Every task of the role and of its family files carries the tag `always` and no other
  tag; toggles are the only selection mechanism, as decided above. After the dispatch the role fails unless every rule
  planned for `apply` or `cleanup` has exactly one result, so a task skipped by any means cannot be reported as done.
  `--skip-tags always` fails the role through two guard tasks tagged only `linux_compliance_remediate_guard`.
  `tools/roles/check_role_specs.py` permits them as the one exception to "every task in `tasks/main.yml` is tagged
  `always`". The exception is narrow: the guard tag is accepted only as the sole tag of a top-level
  `ansible.builtin.assert` or `ansible.builtin.fail`, or of the single `ansible.builtin.set_fact` that sets exactly
  `__linux_compliance_<role>_dispatched: false`. Such a task may have no other keys, and must be in the `tasks/main.yml`
  of the role the tag names. Anywhere else, including blocks, includes and `apply`, it is a finding. Combining
  `--tags <tag>` with `--skip-tags always` skips the guard too and remains unsupported. The role cannot close this
  gap, because every task that touches the host shares its tags with the completeness check.
- **Family files refuse direct use.** Each family file and helper first asserts the opt-in and checks its family and
  rule against the dispatcher's own plan (`__linux_compliance_remediate_plan`); the caller-supplied family context only
  selects work. `include_role` with `tasks_from` therefore cannot change a host without
  `linux_compliance_remediate_enabled: true`.
- **Family files load from the role.** The dispatcher includes `{{ role_path }}/tasks/<family>.yml`, and family files
  include their helpers the same way. A registered family without a task file therefore fails the run, instead of
  loading a file of the same name from the playbook directory. Since FREES-137 the include names each family file
  literally: `tasks/dispatch.yml`, generated from the registry, holds one static include per catalogued family, so
  a plan supplied from outside the role cannot choose the file (ADR 0004, FREES-137 amendment).
- **Incomplete cleanup keeps the record.** A cleanup that cannot restore the prior state (target absent, not a regular
  file, unusable record) keeps the ledger entry and reports `cleanup_incomplete` with the reason, and is retried on the
  next run. The record is never dropped silently.
- **A lost ledger cannot be detected.** `control_state` `list` returns the same empty list for a ledger that never
  existed and for one that was deleted. After a loss, a disabled `recorded_value` or `recorded_state` rule plans as
  `none` without a notice: the hardening stays and is not reverted, because the prior state is unknown and is never
  guessed. The `cleanup incomplete` reporting for a missing ledger that this ADR describes therefore applies only to
  owned drop-ins, whose cleanup needs no history (FREES-57). Operators must back up the ledger with the host
  configuration.
- **Catalogue shape.** Each rule has exactly `rule_id`, `family`, `disruptive`, `reversible`, `revert_strategy`, `toggle`
  (`linux_compliance_rule_<short id>_enabled`), `runbook` (required exactly for irreversible rules) and `parameters`
  (family-specific); anything else fails the role.

## Amendment 2026-10-26: generated toggles shared by audit and remediation (FREES-55)

The toggle variables are generated from the catalogue, and the audit role resolves them itself
([remediation variable reference](../remediation-variables.md)). These refinements apply.

- **Generated defaults.** `tools/roles/generate_toggles.py` (`make toggles`) writes, from
  `roles/remediate/vars/rules.yml`, `linux_compliance_<family>_enabled: true` for every registered family and
  `linux_compliance_rule_<rule_short_id>_enabled: "{{ linux_compliance_<family>_enabled }}"` for every catalogued rule
  into the remediate role defaults, a `bool` option with a description for each into `meta/argument_specs.yml`, and
  `docs/remediation-variables.md`. `make lint-toggles` (part of `make lint`) regenerates them in memory and fails on any
  difference. Families get a toggle even before they have rules, so `linux_compliance_auditd_enabled: false` can be set
  now and keeps applying as auditd rules are catalogued.
- **No default in the argument specification of a rule toggle.** Role argument validation applies the specification
  defaults and checks their types, so a template string as `default` of a `bool` option would fail every run. The
  rule toggle options therefore have no `default`; their description names the family toggle. `check_role_specs.py`
  accepts the toggles only in the remediate role, without the role prefix, and checks this shape.
- **The family-default rule replaces "not set counts as on".** The resolution order is unchanged (rule toggle, else
  family toggle, else on), but in the remediate role every toggle is now set. A templated rule toggle reaches the
  filter as the boolean of its family toggle; a value that is still not a boolean, such as a family toggle passed as
  the string `"false"`, fails the role as before.
- **Controlling variable.** Once templated, a rule toggle that follows a disabled family cannot be told apart from one
  set to `false` by the operator. `disabled_by` is therefore the family toggle whenever the family toggle is off, and
  the rule toggle otherwise. This replaces "the variable that switched a rule off" of the FREES-52 amendment for the case
  where both are off; it gives the same answer whether or not the defaults are loaded, which the audit role relies on.
- **One resolution for both roles.** The catalogue validation, the toggle validation and the resolution moved from the
  `remediation_plan` filter to `plugins/module_utils/compliance/toggles.py`. The remediate role uses it through
  `remediation_plan`; the audit role uses it through the new filter `freesecdev.linux_compliance.audit_disabled_rules`
  in `roles/audit/tasks/toggles.yml`, which loads the catalogue from `{{ role_path }}/../remediate/vars/rules.yml` and
  runs before the scan. The generator writes the same toggle defaults and argument specifications into the audit
  role, so a rule toggle copied from its default into the inventory without the family toggle resolves the same way
  in both roles (review of PR #28). The remediation opt-in plays no part in the audit: a rule switched off is excluded from the
  scan through the tailoring file of the FREES-49 amendment and reported as `disabled` with its `disabled_by`, whether
  or not remediation runs. The audit restricts the list to rules the discovered profile selects.
- **The audit validates toggles too.** Unknown family and rule toggles, names in a role namespace and non-boolean values
  fail the audit role before any scan, so a typo cannot make the audit and remediation disagree.
- **`linux_compliance_audit_disabled_rules` is for rules outside the catalogue.** It is still accepted and merged with
  the toggle result, for profile rules that have no toggle (for example SCE checks). A catalogued rule in it fails the
  audit role, because the audit would otherwise skip a rule that remediation still applies; the message names the
  toggle. The FREES-49 amendment's "FREES-55 will compute the list from the toggles" is implemented this way.
- **Scope of a topic toggle.** Only catalogued rules have toggles. A topic toggle does not disable profile rules that
  the catalogue does not contain, even when they concern the same topic, because the collection has no family data for
  them and never guesses one.
- **Exact specification check and empty-topic warning** (review of PR #28). `check_role_specs.py` compares the
  toggles of both roles with the generator's own output, so it does not depend on `make lint-toggles`. A topic toggle
  that is `false` while no catalogued rule of its family is selected by the profile produces a `WARNING:` in both roles,
  because it currently excludes nothing; full catalogue coverage is FREES-53. A structural test and an
  `oscap-integration` run of the audit role prove that the scan receives the toggle result.

## Amendment 2026-10-26: the full rule catalogue (FREES-53)

The catalogue now holds every rule that a pinned profile selects, so that every security rule can be switched off per
rule and per topic, in the audit as well as in remediation, before its native remediation exists (lead decisions on
FREES-53). The [control family reference](../control-families.md) lists the families, their rules per profile and
how many have a native remediation. These refinements apply.

- **Generated from the pinned content.** `tools/roles/generate_catalogue.py` (`make catalogue`) reads the datastreams of
  `content/manifest.yml` through `catalog.read_benchmarks`, which verifies the pinned SHA-256 before it parses a byte,
  and writes `roles/remediate/vars/rules.yml` and `docs/control-families.md`. All 25 pinned profiles are covered: the 5
  Ubuntu 24.04 and the 20 RHEL 9 profiles of ComplianceAsCode 0.1.82, 1203 distinct rules. A rule that several
  profiles or datastreams select is one entry with one toggle. The CI job `test` fetches the content
  (`make test-content-golden`), regenerates the catalogue in memory and fails on any difference, so the catalogue cannot
  drift from the pinned content. Only rule, group and profile identifiers of the BSD-3-Clause content are used; no
  benchmark prose and no rule titles are written.
- **Family assignment.** `content/catalogue.yml` maps ComplianceAsCode XCCDF groups and short rule identifier prefixes
  to families. A rule is assigned by the first of three steps that decides it: a *topic group* that contains it at any
  depth (`auditing` takes every auditd rule, including the audit log permissions and the `audit=1` boot argument), a
  *rule prefix* for rules whose mechanism defines the topic (`file_permissions_`, `sysctl_`, `kernel_module_`,
  `mount_option_`, `grub2_` and others), and otherwise the innermost listed *fallback group*. The generator fails on a
  rule below two topic groups, on a rule that nothing decides, on a rule that two datastreams assign to different
  families, on a group mapped twice, on overlapping prefixes, on a mapping entry that decides no rule and on a native rule
  that no profile selects. Nothing is guessed.
- **Families.** The registry grows from 12 to 21 families: `logging`, `banners`, `integrity`, `kernel_build_config`,
  `packages` (packages and updates), `desktop`, `kernel_modules`, `accounts` and `mandatory_access_control` join. The
  pinned `DISRUPTIVE_FAMILIES` grow from 10 to 15, each with a reason in the reference: `accounts` (password ageing,
  account expiry, root login restrictions and session time-outs can lock operators out), `kernel_modules`
  (blacklisting `overlay`, `squashfs` or `usb-storage` breaks container runtimes, snaps and devices),
  `mandatory_access_control` (enforcing SELinux or AppArmor can stop services and needs a relabel or reboot),
  `packages` (installing updates or changing repositories can restart or break software) and `desktop` (removing the
  display manager or forcing screen locks ends sessions). `sysctl` stays non-disruptive with network parameters in
  `network`; whether `user.max_user_namespaces` and `kernel.modules_disabled` need the allow-list is a decision for the
  kernel parameter family (FREES-107) before it implements them.
- **The strategy `audit_only`.** A rule without a native remediation has the strategy `audit_only`. Its toggles work
  exactly like those of a native rule, and the audit excludes it and reports it as `disabled` when it is off. The
  remediation plan never dispatches it to a family file. When it would be applied it is planned as `not_implemented`
  with the reason `audit_only`, and the dispatcher reports one result per such rule with the status
  `not_implemented` and `changed: false`, plus one notice with their number, so a run never reports it as remediated.
  This check comes before the allow-list check, because nothing would be changed either way. A ledger entry for an
  `audit_only` rule, which only an older collection version can have written, is a `manual` action with a notice; it
  is neither applied nor cleaned up. `audit_only` is never recorded in the ledger and is not a ledger revert strategy.
  `file_permissions_crontab` remains the only native rule.
- **Compact catalogue.** `__linux_compliance_remediate_rules` lists only the native rules, with every key of the
  FREES-52 amendment. `__linux_compliance_remediate_audit_only` maps every family, in registry order, to the sorted full
  identifiers of its `audit_only` rules, because they carry nothing but their family. `toggles.expand_audit_only`
  turns them into entries of the usual shape (the disruptive flag of the family, `reversible: true`,
  `revert_strategy: audit_only`, the derived toggle, no runbook, no parameters) before the shared validation runs. A
  rule listed in both, or a native entry with the strategy `audit_only`, is an error. Both filters take the mapping as
  the new option `audit_only`.
- **Toggle names.** ComplianceAsCode rule identifiers may hold `-` and capitals (`kernel_module_usb-storage_disabled`,
  `installed_OS_is_vendor_supported`), which Ansible variable names cannot. The rule toggle is therefore
  `linux_compliance_rule_<short id>_enabled` with the short identifier in lower case and every other character than a
  letter, digit or `_` replaced by `_`, and the catalogue fails when two rules would share a toggle. The pinned content
  has no such collision. The rule identifier pattern accepts `[A-Za-z0-9_.+-]` after the prefix, like the ledger.
- **Rule toggles are no longer declared** (this replaces the generated rule toggle defaults and argument
  specifications of the FREES-55 amendment). Measured on this workstation with ansible-core 2.21.5 and a check-mode
  playbook that runs the remediate role twice (without and with the opt-in, all 1203 rules in the profile) and the
  audit toggle resolution once with `linux_compliance_auditd_enabled: false`: the 12-family catalogue of `main` takes
  2.1 s. With 1203 declared rule toggles (a 629 KB argument specification and a 127 KB defaults file per role, a
  344 KB catalogue) it took 10.1 to 10.8 s: role argument validation 0.75 to 0.8 s per remediate run, catalogue loading
  0.5 to 0.7 s per load, and plan resolution 0.8 to 1.1 s, mostly templating the 1203 defaults. Without the rule toggle
  declarations it took 5.1 s, and with the compact catalogue as well 3.1 s, where no task of the roles exceeds 0.25 s.
  After the internal-variable guards of FREES-137, the same playbook takes 2.26 s on `main` and 3.2 s with this change.
  Only the topic toggles are therefore role defaults and argument specification options. A rule toggle that is not set
  follows its family toggle in `toggles.resolve_toggle`, exactly as its former default did, so the resolution order and
  `disabled_by` are unchanged; a rule toggle that is set is validated by both roles before anything is scanned or
  changed, as before. Every rule toggle stays documented in the generated
  [variable reference](../remediation-variables.md), per family. `check_role_specs.py` reports a declared rule toggle as
  a finding. The flat toggles of this ADR are unchanged.
- **Only families with native rules are dispatched.** A family whose rules are all `audit_only` gets no apply or cleanup
  work in the plan, needs no task file and must not be included. `generate_toggles.native_families` returns the
  families with at least one native rule, in registry order, using the same predicate as the plan
  (`toggles.is_native`); a generator of static dispatch includes (FREES-137) must use it. Today that is only
  `file_permissions`, and a unit test checks that exactly these families have task files and get planned work.
- **Generated allow-list choices.** `make toggles` also writes the `choices` of
  `linux_compliance_remediate_allow_disruptive` from the registry, so they cannot fall behind it.
- **Empty-topic warning.** The `WARNING:` of the FREES-55 amendment now fires only for a family that has no rule in the
  profile at all, such as `linux_compliance_auditd_enabled: false` with the Ubuntu 24.04 `cis_level1_server` profile,
  which selects no auditd rule. When both roles run in one play, each prints it once. When a rule toggle and its family
  toggle are both off, `disabled_by` names the family toggle (FREES-55 review items N3 and N5).
- **Testing.** Unit tests cover the generator against synthetic datastreams (every assignment step, mapping
  completeness and uniqueness, cross-datastream conflicts, unused entries, the compact rendering and the reference) and
  the repository mapping; `make test-content-golden` checks the catalogue against the pinned content and that every
  rule of every pinned profile is catalogued. `make test-remediate-check` runs check-mode plays in which one topic toggle
  switches off every auditd rule of the catalogue in both roles and every `audit_only` rule is reported as
  `not_implemented`. The `oscap-integration` job audits the runner with the Ubuntu 24.04 `cis_level2_server` profile,
  `linux_compliance_auditd_enabled: false` and the crontab rule toggle off, and checks that every auditd rule of the
  profile and the crontab rule come back `disabled` with the counts of the catalogue. Molecule scenarios remain FREES-60.

## Amendment 2026-10-26: disruptive skip end to end (FREES-153)

The FREES-52 check-mode play that showed a disruptive rule skipped without the allow-list set a synthetic catalogue,
which the internal-variable guard of FREES-137 refuses. With the FREES-53 catalogue every rule of a disruptive family
is `audit_only`, and the plan decides `audit_only` before the allow-list, as this ADR records, so the pinned catalogue
alone cannot show the gate. `make test-remediate-disruptive` (run by `make test-remediate-check`) copies the
collection into `build/test-remediate-disruptive/`, promotes the catalogued `ssh` rule `sshd_disable_root_login` to a
native rule in the copy with `tools/roles/promote_native_rule.py` (which refuses to rewrite the repository catalogue,
also through a symbolic link or, since FREES-157, a hard link, recognised by its device and inode numbers),
and runs the real remediate role against the copy in check mode. With the default toggles and allow-list the rule is
`skip` with the reason `disruptive_not_allowed` and one notice, and no family is dispatched. With `ssh` on the
allow-list the rule is planned for `apply`; the copy has no `ssh` task file, so the role fails closed at the
completeness check and nothing runs for the family. The precedence of `audit_only` over the allow-list is unchanged.

## Amendment 2026-10-26: subsystem topics and umbrella toggles (FREES-53, step 2)

The 21 families of the FREES-53 amendment grouped unrelated subsystems: SSSD, chrony and postfix were all `services`,
pam_pwquality and pam_faillock were both `pam`. The project owner requires a switch per subsystem, and the native
remediations with cleanup will be built per topic, so the boundaries are fixed before any of them exists. The
[control family reference](../control-families.md) lists every topic, its umbrella, its rules per profile and the
reason for its disruptive flag. These refinements apply.

- **Topics are families.** Each subsystem is a family of the registry, flat, with its own topic toggle
  `linux_compliance_<family>_enabled`, its own `disruptive` flag and, later, its own task file. Nothing about a family
  changes: the catalogue, the plan, the ledger and the dispatch still work per family. The registry grows from 21 to
  55 families (the bound was 64, raised to 256 when the auditd topics passed it, FREES-110); with the
  umbrellas there were 65 topic toggles.
- **Boundaries, taken from the rule identifiers and groups of the pinned content.** `services` becomes `sssd` (12
  rules), `time_sync` (chrony, ntpd, timesyncd, 19), `mail` (8), `cron` (cron and at, 7), `nfs` (NFS and rpcbind, 6),
  `usbguard` (5), `fapolicyd` (3) and `network_services` (59: telnet, tftp, rsh, NIS, FTP, HTTP, DNS, DHCP, Samba,
  SNMP, LDAP, IMAP, proxy, printing, Avahi, X11, kdump, apport). `accounts` becomes `password_aging` (9),
  `root_access` (19), `umask` (6), `user_sessions` (14), `smartcard` (pcscd, OpenSC and PAM smart card login, 9),
  `console_access` (7) and `user_accounts` (24). `pam` keeps the PAM stack, pam_unix, the hashing settings and the
  PAM packages (15) and gains `pwquality` (19), `pwhistory` (7) and `faillock` (pam_faillock and pam_faildelay, 14).
  `logging` becomes `journald` (19), `rsyslog` (rsyslog and the general logging rules, 19) and `logrotate` (3);
  `integrity` becomes `aide` (13), `software_integrity` (package verification, prelink, vendor support, 5) and
  `endpoint_security` (3); `packages` becomes `package_updates` (6), `package_sources` (repositories and signature
  checks, 6) and `system_packages` (12); `network` becomes `ipv4_parameters` (26), `ipv6_parameters` (19), `ipsec`
  (11), `wireless` (3) and `network_settings` (7); `kernel_modules` becomes `filesystem_modules` (9),
  `protocol_modules` (7) and `wireless_modules` (5); `firewall` becomes `firewalld` (10), `nftables` (11), `iptables`
  (12) and `ufw` (9), so a host that uses one firewall can switch the others off; `mandatory_access_control` becomes
  `selinux` (27) and `apparmor` (6); `mounts` becomes `autofs` (2), `mount_options` (34) and `partitioning` (12, the
  irreversible rules). `auditd`, `ssh`, `sudo` and `pam` stay topics; `file_permissions`, `sysctl`, `banners`,
  `kernel_build_config`, `desktop`, `crypto_policy` (FIPS mode sets the crypto policy, so the two cannot be switched
  independently) and `bootloader` (a host has one boot loader) are not split. The kernel parameter families are
  named `ipv4_parameters` and `ipv6_parameters`, because `linux_compliance_ipv6_enabled: false` would read as
  "disable IPv6".
- **pwquality, pwhistory and faillock are families of their own under the `pam` umbrella.** Each is a separate PAM
  module with its own configuration file (`/etc/security/pwquality.conf` and `pwquality.conf.d`, `pwhistory.conf`,
  `faillock.conf`), its own failure mode (rejected password changes, broken password rotation, locked-out accounts)
  and therefore its own remediation and cleanup. They are not topics of `accounts`: every one of them is a module in
  the PAM stack and needs the stack that `pam` manages, and `linux_compliance_pam_enabled: false` switched all of them
  off before the split and must keep doing so.
- **Where the content puts a rule decides its umbrella.** autofs is in the `mounting` group, not in `services`, and
  smart card login is in `accounts`, so `autofs` belongs to the `mounts` umbrella and `smartcard` to `accounts`
  (`sssd_enable_smartcards` stays in `sssd`). Moving a rule across umbrellas would make a former toggle, for example
  `linux_compliance_mounts_enabled: false`, stop switching off a rule it covered, which the next item forbids.
- **One level of umbrellas.** A family may name an `umbrella` in the registry (an optional key of a registry entry).
  The umbrella is either a name of its own (`services`, `accounts`, `logging`, `integrity`, `packages`, `network`,
  `kernel_modules`, `firewall`, `mandatory_access_control`, `mounts`) or a family that heads it (`pam`). A family
  that heads an umbrella cannot itself belong to one, and an umbrella name follows the rules of a family name. Each
  umbrella has a generated toggle `linux_compliance_<umbrella>_enabled`, default `true`, declared in both roles like
  a topic toggle; a heading family's topic toggle is its umbrella toggle. ADR 0011's semantics allow this cleanly,
  because the umbrella toggle is another flat boolean and the resolution stays a pure function of the toggles.
- **Precedence.** The rule toggle wins when it is set, in both directions, as before. Otherwise the rule is on only
  when its umbrella toggle and its family toggle are both on, a toggle that is not set counting as on: an umbrella
  toggle that is `false` switches off every family it groups, and a family toggle can only narrow its umbrella, never
  widen it. A family toggle has to be unable to widen, because both default to `true` and a generated default cannot
  be told apart from a value set by the operator. `disabled_by` names the most general toggle that is off: the
  umbrella toggle, else the family toggle, else the rule toggle, which extends the FREES-55 rule. The resolution is in
  `toggles.resolve_toggle`, shared by both roles as before.
- **Backward compatibility without aliases.** Every former family name is now either an unchanged family or an
  umbrella, and each switches off exactly the rules that it switched off before the split.
  `tests/fixtures/catalog/legacy-families.yml` records the 21 former families with the number and a SHA-256 of their
  sorted rule identifiers, taken from the catalogue of `main` before the split, and a test fails if a former toggle
  switches off a different set or stops being a declared default of either role. No toggle is renamed, deprecated or
  removed, so the change log has no `deprecated_features` entry; it records as a breaking change that the `family` of
  a rule in the plan, the results and the report now names the subsystem.
- **Allow-list.** An entry of `linux_compliance_remediate_allow_disruptive` may name a disruptive family or an
  umbrella that groups one; an umbrella allows every disruptive family that it groups, so an allow-list that names
  `services` or `pam` keeps its meaning. The generated `choices` are the disruptive families and these umbrellas. An
  umbrella that groups no disruptive family, such as `logging`, is refused like a non-disruptive family.
- **Disruptive flags.** A family split from another keeps the flag of the family it came from, so the split changes
  nothing that the allow-list gates, and the why column of the reference justifies the flag of each subsystem: `sssd`
  can lock out every directory user, `time_sync` can leave the clock unsynchronised, which breaks Kerberos and TLS,
  `pwquality`, `pwhistory` and `faillock` can reject password changes or lock out root, and so on. The journald,
  rsyslog, logrotate, AIDE and integrity topics stay non-disruptive. The pinned `DISRUPTIVE_FAMILIES` now hold the 45
  disruptive families; the umbrellas are not families and are not pinned, because the pin of each grouped family
  already prevents marking it non-disruptive.
- **Mapping refinements in `content/catalogue.yml`.** A rule below several topic groups is assigned to the innermost
  one when the families of all of them share an umbrella (`journald` inside `logging`, `aide` inside
  `software-integrity`); below topic groups of different umbrellas it is still an error. A heading family shares the
  umbrella it heads. `accounts-pam` moves from the topic groups to the fallback groups, so that rule prefixes can
  carve `pwhistory` and `faillock` out of the `locking_out_password_attempts` group, which mixes them; it decides the
  same rules as before, which the legacy fixture proves. The kernel module families use one prefix per module
  instead of `kernel_module_`, because prefixes must not overlap. Every former generator check still applies: no rule
  without a family, no rule in two families, no overlapping prefixes, no group mapped twice and no unused entry.
- **Ledger.** Ledger entries record the family. The only native rule, `file_permissions_crontab`, keeps the family
  `file_permissions`, so no ledger entry changes. A later split of a family that has native rules must migrate the
  recorded family, because the plan refuses a ledger entry whose family contradicts the catalogue (FREES-52).
- **Empty-topic warning.** The `WARNING:` of the FREES-55 amendment covers umbrellas: an umbrella or heading family
  toggle that is `false` warns when no catalogued rule of any family it governs is in the profile, and names those
  families. A family toggle still warns for its own family only.
- **Measured cost.** On this workstation, with ansible-core 2.21.5 and the check-mode playbook of the FREES-53
  amendment (the remediate role without and with the opt-in over all 1203 rules, then the audit toggle resolution
  with `linux_compliance_auditd_enabled: false`), measured as wall time of `uv run ansible-playbook`, interleaved
  with `main`: `main` took 3.77 to 4.03 s (median 3.91 s) and the first draft of this change 3.87 to 4.40 s (median
  4.05 s). Replacing the argument specifications of the draft with those of `main` brought it back to 3.71 to 3.86 s,
  so the cost was the size of the 65 topic toggle descriptions (71 KB instead of 21 KB in the remediate role). The
  generated descriptions are therefore four short lines that point to the variable reference (29 KB). In two
  further interleaved runs of ten, `main` took a median of 3.69 and 4.05 s and this change 3.97 and 4.12 s (fastest
  run 3.64 against 3.73 s): about 0.1 s more, within the budget of about 4 s and the noise of this host.
- **Testing.** `test_toggle_umbrellas.py` and `test_remediation_plan_umbrellas.py` cover the precedence table, the
  heading family, the allow-list, invalid and nested umbrellas and the warnings with synthetic registries.
  `tests/unit/roles/test_topic_toggles.py` checks on the real catalogue that every topic and umbrella toggle switches
  off exactly its rules in both filters, that an umbrella cannot be widened and can be narrowed, and the legacy
  fixture. `make test-content-golden` checks every topic and umbrella toggle against each of the 25 pinned profiles,
  including that it warns exactly when it excludes nothing. `make test-remediate-check` runs a check-mode play in
  which `linux_compliance_services_enabled: false` with `linux_compliance_sssd_enabled: true` switches off all 119
  service rules in both roles and names the umbrella, and `linux_compliance_sssd_enabled: false` alone switches off
  exactly the sssd rules.

## Amendment 2026-10-26: toggle lifecycle in Molecule (FREES-60)

The "toggle-and-cleanup scenario for every family" of the operational consequences is implemented as one data-driven
harness, `extensions/molecule/shared/lifecycle.yml`, rather than one scenario per family
([Molecule guide](../molecule.md#toggle-lifecycle-of-every-native-topic)). These refinements apply.

- **A step of the existing scenarios.** The harness is the `side_effect` step of `docker-ubuntu` and
  `docker-rhel-compatible`, after `verify` and before `destroy`, so it runs in the same disposable, guarded container
  and adds no image build or container to CI. It runs the real remediate role with public inputs only; the toggles are
  set as facts under the names the catalogue gives, which both roles find through `varnames` like inventory values.
- **Native topics, not every family.** Only families with a native rule (`generate_toggles.native_families`) get a
  lifecycle; an `audit_only` rule changes nothing and has nothing to clean up. Each needs one declaration,
  `extensions/molecule/shared/vars/topics/<family>.yml`, that names the files, packages, services, kernel parameters,
  users and groups to record, the expectations after apply and the pre-states. `make lint-lifecycle` and the harness
  itself fail when a native family has no declaration or a declaration has no native family.
- **What is proven.** Per topic, with the topic toggle and with the rule toggles, from every declared pre-state: check
  mode plans and reports the work and changes nothing; apply sets exactly the declared controls and records the prior
  state in the ledger; a second apply changes nothing; switching off plans the cleanup in check mode with the
  controlling `disabled_by`, restores the declared state and the ledger exactly and is reported as `disabled` by the
  audit; a further run changes nothing. A customised pre-state proves that cleanup restores the recorded value rather
  than a distribution default.
- **Restored exactly means the whole instance** (review of PR #50). Besides the declared items, the harness records
  every file below the system trees with its inode, times and SHA-256, every readable kernel parameter, every package,
  user, group and service, before each cycle and before the first, and the state after the cleanup and after the last
  cycle must equal it. The only allowed differences are listed in the harness and the Molecule guide: the times of the
  declared files and their directories, the ledger file, the evidence tree, the RPM database times and eleven kernel
  usage counters. A declaration must have at least one `applied` expectation, and a platform may skip a topic only
  when the declaration says so, never all platforms. Self-checks prove that both comparisons refuse what they must.
- **Disruptive families** opt in through their declaration (`disruptive: true` and a `containment` note) and get the
  allow-list for their own family and runs only. They run after every non-disruptive topic, the first failure ends the
  play, and the guard's connection test runs after every remediate run, so a topic that breaks the container fails
  there and cannot reach the host. A family whose controls need a real kernel, boot loader or init system cannot be
  proven in a container; it needs the libvirt scenarios (FREES-61) and a decision on where its lifecycle runs before
  its first native rule ships.

## Amendment 2026-10-27: subsystem tags (FREES-165)

The review of the topic split (PR #48, findings N1 to N4) showed that a subsystem toggle does not reach every rule about
its subsystem. The generator gives each rule one family, and for many rules that is the family of the mechanism the
rule uses: the permissions of `/var/log/sssd` are `file_permissions`, `sssd_enable_smartcards` is `sssd`, the GNOME lock
on smart card removal is `desktop`. The project owner expects `linux_compliance_sssd_enabled: false` to stop every rule
about SSSD. Moving such rules to their subsystem family would break the backward compatibility of the step-2 amendment
(`linux_compliance_file_permissions_enabled: false` would stop switching them off), so a rule keeps its one family and
gains secondary subsystem tags. These refinements apply.

- **Tags.** A subsystem tag is a family of the registry. A rule may carry any number of tags of families other than
  its own. The catalogue lists them as `__linux_compliance_remediate_tags`, a mapping of each tag to the sorted full
  identifiers of the rules it tags, and `toggles.check_tags` validates it (a registered family, a catalogued rule of
  another family, sorted lists). The filters take it as the new option `tags`.
- **Resolution.** A rule toggle that is set wins, as before. Otherwise a rule is on only when the toggles of all of its
  controlling topics are on (`toggles.controlling_topics`): the umbrella of its family, its family, and for every tag
  the umbrella of the tag and the tag. A tag can therefore only add a way to switch a rule off. A tag toggle that is
  `true`, such as its default, never switches a rule on, so a family toggle that is `false` still switches off a rule
  whatever its tags say. `linux_compliance_services_enabled: false` also reaches the rules tagged `sssd`, `time_sync`
  and `cron`, because the umbrella of a tag counts like the umbrella of a family.
- **Controlling variable.** `disabled_by` names the first controlling topic whose toggle is `false`, in this order: the
  umbrella of the family, the family, then the tags in alphabetical order, each preceded by its umbrella; a topic is
  listed once. When every topic is on and the rule toggle is `false`, it names the rule toggle. So a rule of
  `file_permissions` tagged `cron` with `file_permissions` and `cron` off names `file_permissions`, and with `cron` and
  `services` off names `services`. This extends the FREES-55 and step-2 rules and gives the same answer with or without
  the generated defaults, which the audit relies on.
- **Disruptiveness stays with the family.** The disruptive flag and the allow-list gate what remediation changes on the
  host, and the family decides that: its task file applies and cleans up the rule. A tag does not change it in either
  direction. `file_permissions_crontab`, the only native rule, is tagged `cron`, which is disruptive, but applying or
  cleaning it up only changes the mode of `/etc/crontab`, so it needs no allow-list entry and `allow_disruptive: [cron]`
  does not cover it. Making a tag disruptive would put chmod rules behind an allow-list for no change in risk, and would
  let an allow-list entry reach rules that its family file does not own.
- **Derived from the content.** `content/catalogue.yml` declares, per tag, `rule_patterns` (a pattern tags every
  catalogued rule whose short identifier, in lower case, contains it), `groups` (every rule below the group in any
  pinned datastream) and `exclusions` (rules that a pattern or group finds but that are not about the subsystem, each
  group of them with a reason). The generator derives the tags and writes them into the catalogue; the CI job `test`
  regenerates them from the pinned content. A rule of the tag's own family is never tagged.
- **Drift check.** `untagged_families` lists families whose rules are never tagged, with a reason. Generation fails when
  a pattern or group finds a rule of such a family that no exclusion lists, when a pattern or group finds no catalogued
  rule, and when an exclusion does not exclude a rule of another family that the tag finds. A new rule of a future
  content version that names a subsystem is therefore tagged automatically, unless it is an audit rule, which fails the
  generation until someone decides and records the reason.
- **Audit rules are never tagged.** `auditd` is the only untagged family. An audit rule records changes to a
  subsystem; it does not configure it. An operator who switches AppArmor or SELinux management off, because the host
  does not use it or another tool manages it, still wants changes to the MAC policy audited: an attacker who disables
  MAC first edits exactly the files that `audit_rules_mac_modification`, `audit_rules_mac_modification_etc_apparmor` and
  `audit_rules_mac_modification_etc_apparmor_d` watch, so switching the watches off with `apparmor` would weaken the
  detective control that matters most when the preventive one is absent. The same holds for the audit watches on cron,
  sudo, the faillock records, the journal and the SSH helpers. These rules stay switched off by
  `linux_compliance_auditd_enabled: false` and their rule toggles only, and the exclusions of the tags list each of them.
- **The tags of the pinned content.** Fifteen tags are declared: `aide`, `apparmor`, `cron`, `faillock`, `firewalld`,
  `journald`, `pwhistory`, `pwquality`, `rsyslog`, `selinux`, `smartcard`, `ssh`, `sssd`, `sudo` and `time_sync`. Ten of
  them tag 52 rules: `cron` 30 (the permissions and ownership of the cron and at files, `cron.deny`, `at.deny` and the
  native `file_permissions_crontab`), `ssh` 4 (the sshd crypto policy back-ends), `sssd` 3 (`/var/log/sssd`),
  `time_sync` 3 (`/etc/chrony.keys`), `journald` 3 (`/var/log/journal` and the journald and rsyslog exclusion), `sudo`
  3, `smartcard` 2 (`sssd_enable_smartcards`, `dconf_gnome_lock_screen_on_smartcard_removal`), `pwhistory` 2 (both
  pam_unix `remember` rules), `firewalld` 1 (`firewalld_sshd_port_enabled`) and `selinux` 1 (the SELinux context of the
  faillock directory). `aide`, `apparmor`, `faillock`, `pwquality` and `rsyslog` tag nothing today; their patterns guard
  against drift. 21 rules are excluded with a reason: 17 audit rules, the AIDE cron job, the rsyslog cron facility, the
  SSH confirmation banner and the SELinux boolean `ssh_sysadm_login`. `pam` is not a tag: it is a mechanism that many
  subsystems use, and a rule that configures another PAM module belongs to that subsystem. The
  [control family reference](../control-families.md#subsystem-tags) lists every tag, rule and exclusion.
- **Backward compatibility (replaces "exactly" of the step-2 amendment).** Every former family toggle still switches
  off every rule it switched off before, and the families it governs hold exactly those rules:
  `tests/fixtures/catalog/legacy-families.yml` still pins the count and SHA-256 of each family-only set. A former toggle
  may switch off more rules only through tags. The fixture lists every added rule (`added_by_tags`), a test checks that
  each former toggle switches off exactly the family-only set plus that list in both filters, and another that the
  reference lists each added rule. Eight former toggles widen: `services` by 36, `ssh` by 4, `sudo` by 3, `logging` by
  2, `accounts` by 2, `firewall`, `pam` and `mandatory_access_control` by 1 each; the other 13 are unchanged. The
  change log records the widening as a breaking change.
- **Password history (N2).** `accounts_password_pam_unix_remember` (family `pam`) and
  `accounts_password_pam_unix_no_remember` (family `user_accounts`) are tagged `pwhistory` instead of moved: a prefix
  cannot select a single rule identifier without a trailing `_`, and moving `no_remember` out of `accounts` would break
  that former toggle. `linux_compliance_pwhistory_enabled: false` now switches off all nine password-history rules.
- **`pam` is a topic and an umbrella (N3).** `linux_compliance_pam_enabled: false` switches off the `pam` family and
  `pwquality`, `pwhistory` and `faillock`, and `allow_disruptive: [pam]` allows all four. There is no toggle or
  allow-list entry for the `pam` family alone. The variable reference and the control family reference say so.
- **Ledger family aliases (N4).** `ledger_family_aliases` in `content/catalogue.yml`, generated into
  `__linux_compliance_remediate_family_aliases` and passed to `remediation_plan` as `family_aliases`, maps a former family
  name to the families its rules may belong to now (`toggles.check_family_aliases`: a valid family name, sorted
  registered families, not itself). `check_ledger` accepts an entry whose recorded family is the current family of its
  rule or a former name whose alias lists it, so moving a native rule keeps the entries of upgraded hosts cleanable;
  any other family is still an error. The entry is passed to the family file unchanged. No alias is declared, because
  no native rule has moved; the change that moves one must add its former family.
- **Empty-topic warning.** A rule that a toggle reaches through a tag counts as covered, so
  `linux_compliance_smartcard_enabled: false` does not warn for a profile that selects only `sssd_enable_smartcards`.
- **Role guard.** The two new catalogue keys are constants of `vars/rules.yml`, so `make role-guards` adds them to the
  internal-variable guard of the remediate role like the other catalogue keys.
- **Measured cost.** On this workstation, with ansible-core 2.21.5 and the check-mode playbook of the FREES-53
  amendment (the remediate role without and with the opt-in over all 1203 rules, then the audit toggle resolution with
  `linux_compliance_auditd_enabled: false`), measured as wall time of `uv run ansible-playbook` in ten interleaved runs
  against `main` at f3bfabc: `main` took 3.89 to 4.31 s (median 3.93 s) and this change 3.86 to 4.46 s (median 3.89 s),
  within the budget of about 4.5 s and the noise of this host.
- **Testing.** `test_toggle_tags.py` and `test_remediation_plan_tags.py` cover the validation, the precedence with two
  tags, tags that never switch a rule on, the warning and the ledger aliases on synthetic catalogues.
  `test_subsystem_tags.py` checks each reviewed example on the real catalogue in both filters, the audit watches on MAC
  policy, the precedence, and the cleanup of the native crontab rule with `cron` off and from a ledger entry under a
  former family name. `test_generate_catalogue_tags.py` covers the derivation, the drift check and every invalid source.
  `make test-content-golden` checks every topic and umbrella toggle, tags included, against each of the 25 pinned
  profiles, and each reviewed example in every profile that selects it. `make test-remediate-check` runs the remediate
  role and the audit toggle resolution in check mode with `services`, `sssd`, `cron` and `time_sync`, and `smartcard`,
  `apparmor`, `selinux` and `pwhistory` off.

## Amendment 2026-10-27: toggles for SCC (FREES-170)

The toggles also reach the DISA rules that the SCC backend scans
([ADR 0019](0019-scc-scanner-backend-and-ci-image.md#amendment-2026-10-27-toggles-and-control-families-for-scc-frees-170)).
The audit role resolves them with the same function as for OpenSCAP (`toggles.resolve_audit`, which the
`audit_disabled_rules` filter now calls too) for the ComplianceAsCode rules of the STIG mapping, and the
`scc_toggles` filter disables a DISA rule only when every ComplianceAsCode rule mapped to its STIG ID is disabled.
A DISA rule with no mapped rule is never disabled by a toggle. SCC tailors only from its installation directory, so
SCC's disabled rules are reported as `disabled` after the scan instead of through a tailoring file; they are never
counted as passing, as this ADR requires.

## Amendment 2026-10-27: the first native topics (FREES-53, step 3; FREES-57)

`banners` (15 rules) and `pwquality` (14 rules) become native, as decided in
[ADR 0021](0021-native-banners-pwquality-and-profile-values.md); 30 rules now have a native remediation. This replaces
"`file_permissions_crontab` remains the only native rule" of the FREES-53 amendment and "the only native rule" of the
step-2 and FREES-165 amendments; the statements about the crontab rule itself are unchanged. These refinements apply.

- **Profile values.** A native rule whose check exports an XCCDF value gets that value per pinned content and profile
  in its parameters, generated by `make catalogue`, and applies the value of the content and profile that the
  `discover` role verified. A rule without a value for them fails its family before anything changes.
- **Recorded values per attribute.** When several rules share one file, each records and restores only the attribute
  it changes (content, mode, uid or gid), so every rule toggle reverts exactly its own change.
- **Where the content checks.** `pwquality` writes one line per setting into the main file where the content checks
  only it (Ubuntu 24.04) and one drop-in per rule where it checks the drop-ins (RHEL 9), so the audit agrees with the
  remediation; both are `recorded_value`, the main file with the prior line and the file's mode, owner, group and
  hash. A drop-in directory that the collection had to create carries an empty marker and is removed with it once
  nothing else is in it; a directory without the marker is never removed.
- **Disruptive native topic.** `pwquality` is the first disruptive family with native rules. Its rules are `skip` with
  `disruptive_not_allowed` without `pwquality` or `pam` in the allow-list, which `make test-remediate-disruptive` now
  also checks on the pinned catalogue, and the toggle lifecycle applies and cleans it up with its allow-list entry.
- **Lifecycle harness.** The FREES-60 harness gains `rewritten` files, `unchanged` rules per pre-state and a
  per-topic narrowing of the verified profile, as ADR 0021 describes.
- **Cleanup from the entry, and only over the collection's own change.** A ledger entry records how its rule was
  applied (for pwquality, `method`), and cleanup follows the entry: an entry that the current method cannot restore is
  `cleanup_incomplete` (`method_changed`) and kept, never forgotten. Before restoring, cleanup checks that the target
  still holds what the collection wrote (`written_line`, `dropin_sha256`, the recorded mode and ownership); if an
  administrator changed it since, the result is `cleanup_incomplete` (`modified_since_apply`), nothing is changed and
  the entry is kept. "Restore the recorded prior value" therefore never overwrites a later change. The banner and
  crontab families restore a single attribute that only they change and keep their behaviour.
- **Lifecycle scenarios and CI legs.** The refinement "a step of the existing scenarios" no longer holds: with three
  native topics, the one lifecycle step per platform took 52 minutes in CI, past the merge queue's 30-minute limit.
  The harness is now the `side_effect` step of its own scenarios, `docker-ubuntu-lifecycle` and
  `docker-rhel-compatible-lifecycle` (same image, playbooks and guard, no `converge`), and CI runs one leg per
  platform, native topic and toggle mode, generated by `make molecule-matrix` with `native_families`, each in a fresh
  container and each required through `ci-gate`. A full local run still covers every topic and mode in one container
  ([Molecule guide](../molecule.md#ci-legs)).

## Amendment 2026-10-30: lifecycle per driver (FREES-61)

The FREES-60 amendment left open where the lifecycle of a family runs whose controls need a real kernel, boot loader or
init system. The libvirt scenarios of ADR 0009 answer it ([libvirt guide](../molecule-libvirt.md#driver-requirements-of-a-topic)).

- **Declared requirement.** A lifecycle declaration may name the drivers its topic needs (`requires: [libvirt]`), and a
  pre-state may do the same. Each cycle runs with one set of drivers: the pre-state's, else the topic's, else Docker
  only. The virtual machines therefore run only the cycles that a container cannot prove; the harness selects the
  pre-states by the driver of the instance that the guard verified and skips a topic, with its whole-instance records,
  on a driver that runs none of its cycles. A CI leg selects one topic and mode (`MOLECULE_LIFECYCLE_TOPIC`,
  `MOLECULE_LIFECYCLE_MODE`), and a leg whose topic runs no cycle with its driver fails, because it would prove nothing.
- **Tight coverage.** `make lint-lifecycle` fails when a cycle's driver has no lifecycle scenario on every platform
  that the topic does not list under `unselected_platforms`, so every declared cycle is exercised by some driver.
  `make molecule-matrix` plans the CI legs of each driver from the same map, so each such cycle runs in a leg that
  gates merges.
- **A virtual machine has more state than a container.** For a libvirt instance the whole-instance comparison ignores
  the contents and inode, but not the existence, mode or owner, of the system logs, the login accounting, the journal and
  three service state files that a running system rewrites by itself; the list and its reasons are in the libvirt guide.
- **A VM-only case.** The `file_permissions` declaration gains a pre-state that changes the owner and group of
  `/etc/crontab` and requires libvirt, because a container without `CAP_CHOWN` cannot set it. It proves that cleanup
  restores the recorded mode and leaves the ownership alone. Its other cycles run in the Docker scenarios only.

## Amendment 2026-10-30: only the affected lifecycle legs on pull requests (FREES-189)

Each native topic adds four to nine Docker lifecycle legs, plus libvirt legs where a cycle requires a virtual machine.
With five topics a run already has about 60 jobs (31 Docker lifecycle legs and 7 libvirt legs among them), the
organisation runs at most 60 jobs at a time, and the merge queue gives a check 30 minutes. Converting the 1163
`audit_only` rules into native topics cannot run the full matrix on every pull request and merge group. These
refinements apply ([Molecule guide](../molecule.md#affected-legs-on-pull-requests)).

- **Affected legs on `pull_request` and `merge_group`, the full matrix elsewhere.** `molecule-plan` still plans the full
  matrices with `make molecule-matrix`. On a pull request or a merge group it then keeps only the lifecycle legs of the
  topics that the diff against the base revision can affect, and the legs without a topic (the libvirt base scenarios
  and the libvirt self-test). The standard Docker scenarios, their self-test and every other job are unchanged. A push
  to `main`, the nightly `schedule` and `workflow_dispatch` always run the full matrix.
- **A computed, fail-safe mapping.** `tools/roles/affected_topics.py` derives the topics of a change from the topic
  declarations, the catalogue and the file names; nothing lists paths per topic by hand. A path belongs to a topic when
  it is a task file `roles/remediate/tasks/<family>.yml` or `<family>_*.yml`, the topic's declaration, or a file of
  `extensions/molecule/shared/tasks` that a regression group of the topic names; every file that includes such a file
  must belong to topics too, and their topics are added, so a file that a shared file includes plans the full matrix.
  `roles/remediate/vars/rules.yml` is compared per family (registry entry, rules, `audit_only` list, subsystem tags and
  the families of the rules a tag gains or loses), and a changed key of `roles/remediate/vars/main.yml` affects the
  topics of the files that use it. Generated files (the role guards, the family dispatch, `playbooks/run_start.yml`)
  and generator inputs (`content/catalogue.yml`) have no effect of their own: the required `lint` and `test` jobs
  check them against their generators, and their effect is classified through the files they are generated from. An
  argument-spec change that only rewrites descriptions has no effect. Documentation, changelog fragments, unit tests,
  check-mode playbooks and the reporting, lint, docs and IaC tools, the SCC and OpenSCAP image definitions have no lifecycle effect. Everything else plans
  the full matrix: the shared harness and its tasks, the images and their pins, plugins and `module_utils`, role
  defaults and entry points, the content pins, everything below `tools/roles` and `tools/molecule`, `ci.yml`, the
  `Makefile`, the Python lock, a symbolic link, and any path that the mapping does not know.
- **The base revision decides.** As `scc-changes` does for the SCC smoke test (ADR 0019), `molecule-plan` reads the base
  revision's `tools/molecule/plan-lifecycle.sh` with `git show` and runs it with `bash`. It exports the base revision
  with `git archive` and runs that revision's `make molecule-affected`, with its own lock file, over the head checkout
  and the `git diff --no-renames` of the two revisions. A pull request therefore cannot shrink its own matrix by
  editing the planner; a change to the planner or the mapping runs the full matrix and takes effect only after it
  merges. The step uses the answer only when it is a well-formed plan whose legs all come from the full matrices and
  that keeps every leg without a topic; any other answer, a failure, and a base revision without the planner (the pull
  request that introduces it) run the full matrices.
- **The queue diffs against the target branch.** In a merge group the base is the merge base of the group's head with
  the target branch, not the event's `base_sha`, which is the head of the previous group when pull requests queue
  behind each other. The diff then holds every pull request of the queue ahead of this one, and the planner comes from
  the target branch, never from a group that has not merged.
- **`ci-gate` stays the only required check.** It accepts the scope `affected` only for `pull_request` and
  `merge_group`, and a skipped `molecule-lifecycle` only when the plan of such an event has the scope `affected` and
  exactly zero lifecycle legs. Every planned leg must succeed; a leg that the plan leaves out is not a check at all.

Residual risk, accepted for the throughput it buys:

- **Cross-topic interactions are caught only on `main` and nightly.** A change that the mapping confines to one topic
  can still break another topic's legs, for example through state on the instance that both inspect, through a
  subsystem tag that the mapping does not see as changed, or through the order in which topics run. The full matrix on
  every push to `main` and every night catches it, after the merge; the fix is a follow-up pull request.
- **The full matrix itself comes from the head revision**, as before this amendment: a pull request that edits
  `make molecule-matrix` runs the full matrix that its own tool plans. Such a change plans the full scope and is
  reviewed like any other change of `tools/roles`.
- **The workflow and the head's code are trusted by review.** On `pull_request` GitHub runs the head's `ci.yml`, and
  the head's `make molecule-matrix` runs in the same job before the base planner. The base revision's planner protects
  against a careless or unnoticed change to the mapping, not against a pull request that rewrites the workflow; that is
  what review of every change to `.github/workflows` and `tools/roles` is for.
- **Only literal includes are seen.** The mapping finds includes by the file name in the text of the YAML files of
  `roles`, `extensions/molecule` and `playbooks` of both revisions. A file that a shared file includes only through a
  templated name, and that a topic also owns by its name, is attributed to that topic alone. Every literal form counts:
  the file name after any directory or template, and the stem after `tasks_from`. A role variable that another role
  variable uses plans the full matrix. The family dispatch and the
  regression dispatch name their files literally, and `make lint-lifecycle` and `make lint-role-guards` keep them so.
- **Generated files rely on their drift checks.** A generated file whose sources did not change in the same way is
  refused by the required `lint` or `test` job of the same run, so such a pull request cannot merge; the plan of that
  run may have been too small.
