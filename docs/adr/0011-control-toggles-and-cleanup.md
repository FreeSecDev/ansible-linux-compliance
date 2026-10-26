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
(`FILE_IO_HELPER` in `tools/lint/check_repo_rules.py`).

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
